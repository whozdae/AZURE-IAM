#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Groups, Microsoft.Graph.Users

<#
.SYNOPSIS
    Creates one dynamic security group per department so users land in their department group
    automatically, based on their Department attribute.

.DESCRIPTION
    Instead of adding people to groups by hand, each group carries a membership rule:
        (user.department -eq "Finance") and (user.accountEnabled -eq true)
    Entra keeps membership current: change someone's department (a mover) and they switch groups
    on their own; disable them (a leaver) and they drop out.

      1. Reads every user's Department and lists the distinct values (or uses -Departments).
      2. Shows the expected members per department before changing anything.
      3. Creates SG-Dept-<Department> as a dynamic security group (skips any that exist).
      4. Optionally waits for Entra to process the rules and compares actual vs. expected members.
      5. Logs every action to CSV.

    Dynamic groups require Entra ID P1 or higher. Supports -WhatIf. Idempotent.

.PARAMETER Departments
    Departments to create groups for. Default: every non-empty Department value found on users.

.PARAMETER GroupPrefix
    Group name prefix. Default: SG-Dept-

.PARAMETER VerifyMinutes
    How long to wait for rule processing before comparing members. 0 skips the check. Default: 5.

.PARAMETER Remove
    Rollback: deletes the groups this script created (identified by its description tag).
    Deleted groups can be restored from Deleted groups for 30 days.

.EXAMPLE
    .\new-department-dynamic-groups.ps1 -WhatIf

.EXAMPLE
    .\new-department-dynamic-groups.ps1 -Departments 'Finance','Security' -VerifyMinutes 10

.EXAMPLE
    .\new-department-dynamic-groups.ps1 -Remove

.NOTES
    Graph scopes (least privilege):
      User.Read.All       read each user's Department to preview and verify membership
      Group.ReadWrite.All create and (on -Remove) delete the groups
    Role: Groups Administrator or User Administrator is enough; Global Administrator is not required.

    Verify: Entra admin center > Groups > SG-Dept-<name> > Members (and "Dynamic membership rules" > Validate rules)
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [string[]]$Departments,
    [ValidatePattern('^[A-Za-z0-9-]+$')]
    [string]$GroupPrefix = 'SG-Dept-',
    [ValidateRange(0, 30)]
    [int]$VerifyMinutes = 5,
    [switch]$Remove,
    [string]$LogPath = (Join-Path $PSScriptRoot "..\output\department-groups-log-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv")
)

$ErrorActionPreference = 'Stop'
$tag = 'Dynamic department group. Managed by new-department-dynamic-groups.ps1'
$log = [System.Collections.Generic.List[object]]::new()
function Write-Log([string]$Item, [string]$Result, [string]$Detail = '') {
    $log.Add([pscustomobject]@{ TimestampUtc = (Get-Date).ToUniversalTime().ToString('s'); Item = $Item; Result = $Result; Detail = $Detail })
    $color = switch -Regex ($Result) { 'CREATED|MATCH|REMOVED' { 'Green' } 'EXISTS|SKIPPED|PLAN' { 'Gray' } default { 'Yellow' } }
    Write-Host ("  [{0,-9}] {1} {2}" -f $Result, $Item, $Detail) -ForegroundColor $color
}
function ConvertTo-Slug([string]$s) { ($s -replace '[^A-Za-z0-9]+', '-').Trim('-') }

try {
    Connect-MgGraph -Scopes 'User.Read.All', 'Group.ReadWrite.All' -NoWelcome
    $tenant = (Get-MgContext).TenantId
    Write-Host "`nTenant: ****$($tenant.Substring($tenant.Length - 4))`n" -ForegroundColor Cyan

    # --- Rollback --------------------------------------------------------------------------
    if ($Remove) {
        $mine = Get-MgGroup -Filter "startswith(displayName,'$GroupPrefix')" -All -Property Id, DisplayName, Description |
                Where-Object Description -eq $tag
        if (-not $mine) { Write-Log 'Groups' 'SKIPPED' 'none created by this script'; return }
        foreach ($g in $mine) {
            if ($PSCmdlet.ShouldProcess($g.DisplayName, 'Delete group (restorable for 30 days)')) {
                Remove-MgGroup -GroupId $g.Id
                Write-Log $g.DisplayName 'REMOVED'
            }
        }
        return
    }

    # --- 1/2. Read departments and preview expected membership --------------------------------
    $users = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, Department, AccountEnabled |
             Where-Object { $_.Department -and $_.AccountEnabled }
    if (-not $Departments) { $Departments = $users.Department | Sort-Object -Unique }
    if (-not $Departments) { throw 'No enabled users have a Department value. Set Department on users first.' }

    $plan = foreach ($d in $Departments) {
        $members = @($users | Where-Object { $_.Department -eq $d })
        [pscustomobject]@{
            Department = $d
            GroupName  = "$GroupPrefix$(ConvertTo-Slug $d)"
            Expected   = $members.Count
            Members    = ($members.DisplayName | Sort-Object) -join ', '
            Rule       = '(user.department -eq "{0}") and (user.accountEnabled -eq true)' -f ($d -replace '"', '\"')
        }
    }
    Write-Host 'Plan:' -ForegroundColor Cyan
    $plan | Format-Table GroupName, Expected, Members -AutoSize -Wrap | Out-Host

    # --- 3. Create groups ------------------------------------------------------------------
    foreach ($p in $plan) {
        $existing = Get-MgGroup -Filter "displayName eq '$($p.GroupName)'" -Property Id, DisplayName, GroupTypes, MembershipRule
        if ($existing) {
            $detail = if ($existing.GroupTypes -contains 'DynamicMembership') { "dynamic: $($existing.MembershipRule)" } else { 'STATIC group with this name exists; left untouched' }
            Write-Log $p.GroupName 'EXISTS' $detail
            continue
        }
        if (-not $PSCmdlet.ShouldProcess($p.GroupName, "Create dynamic group, rule: $($p.Rule)")) { Write-Log $p.GroupName 'PLAN' $p.Rule; continue }
        $g = New-MgGroup -BodyParameter @{
            displayName                   = $p.GroupName
            description                   = $tag
            mailEnabled                   = $false
            mailNickname                  = $p.GroupName.ToLower()
            securityEnabled               = $true
            groupTypes                    = @('DynamicMembership')
            membershipRule                = $p.Rule
            membershipRuleProcessingState = 'On'
        }
        Write-Log $p.GroupName 'CREATED' "id ...$($g.Id.Substring($g.Id.Length - 6)) rule: $($p.Rule)"
    }

    # --- 4. Verify actual vs. expected -------------------------------------------------------
    if ($VerifyMinutes -gt 0 -and -not $WhatIfPreference) {
        Write-Host "`nWaiting up to $VerifyMinutes min for Entra to process the rules..." -ForegroundColor Cyan
        $deadline = (Get-Date).AddMinutes($VerifyMinutes)
        do {
            Start-Sleep -Seconds 30
            $pending = foreach ($p in $plan) {
                $g = Get-MgGroup -Filter "displayName eq '$($p.GroupName)'" -Property Id
                $actual = @(Get-MgGroupMember -GroupId $g.Id -All).Count
                if ($actual -ne $p.Expected) { $p.GroupName }
            }
        } while ($pending -and (Get-Date) -lt $deadline)

        foreach ($p in $plan) {
            $g = Get-MgGroup -Filter "displayName eq '$($p.GroupName)'" -Property Id
            $actual = @(Get-MgGroupMember -GroupId $g.Id -All).Count
            $result = if ($actual -eq $p.Expected) { 'MATCH' } else { 'PENDING' }
            Write-Log $p.GroupName $result "expected $($p.Expected), actual $actual"
        }
        if ($log.Result -contains 'PENDING') { Write-Host "`nSome groups are still processing. Rerun with -VerifyMinutes 10 in a few minutes; it won't recreate anything." -ForegroundColor Yellow }
    }
}
catch {
    Write-Log 'FATAL' 'ERROR' $_.Exception.Message
    throw
}
finally {
    if ($log.Count) {
        $dir = Split-Path $LogPath
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $log | Export-Csv -Path $LogPath -NoTypeInformation
        Write-Host "`nLog: $LogPath" -ForegroundColor DarkGray
    }
}
