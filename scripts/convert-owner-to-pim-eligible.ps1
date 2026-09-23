#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.Resources

<#
.SYNOPSIS
    Remediates the audit finding "standing Owner at subscription scope" by making that access
    PIM-eligible (activate on demand, time-limited) instead of permanent.

.DESCRIPTION
    Order of operations, so you can never lock yourself out:

      1. Confirms Entra ID P2 (PIM requires it) and that you can read role assignments.
      2. Lists every PERMANENT Owner at subscription scope.
      3. Verifies a break-glass account exists and holds permanent Owner. The script refuses to
         remove your standing Owner unless a second, separate account still has it.
      4. Creates a PIM ELIGIBLE Owner assignment for the target user (no expiry on the eligibility
         itself; activations are time-boxed by the role policy).
      5. Verifies the eligible assignment exists.
      6. Only with -RemoveStanding: removes the permanent Owner assignment for that user.

    Always dry-run with -WhatIf first. Nothing here touches the break-glass account.

.PARAMETER SubscriptionId
    Target subscription. Defaults to the current Az context.

.PARAMETER PrincipalUpn
    The user whose standing Owner becomes eligible. Defaults to the signed-in account.

.PARAMETER BreakGlassUpn
    A separate emergency-access account that keeps permanent Owner. Required with -RemoveStanding.

.PARAMETER RemoveStanding
    Remove the permanent Owner assignment after the eligible assignment is verified.
    Run once WITHOUT this switch, activate the role in the portal to prove activation works,
    and only then rerun with it.

.EXAMPLE
    .\convert-owner-to-pim-eligible.ps1 -WhatIf

.EXAMPLE
    .\convert-owner-to-pim-eligible.ps1 -BreakGlassUpn breakglass@contoso.onmicrosoft.com -RemoveStanding

.NOTES
    Requires: Owner or User Access Administrator on the subscription, and Entra ID P2.
    Activation (as the eligible user):
        Portal: Entra admin center > Privileged Identity Management > Azure resources > Eligible assignments > Activate
        PowerShell: New-AzRoleAssignmentScheduleRequest -RequestType SelfActivate ...
    Rollback: rerun without -RemoveStanding and re-add the permanent assignment with
        New-AzRoleAssignment -ObjectId <id> -RoleDefinitionName Owner -Scope /subscriptions/<id>
    Approval, maximum activation duration, MFA and justification on activation are set by the role
    management policy, not by this script. Configure them in PIM > Azure resources > Settings > Owner.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$SubscriptionId,

    [ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$')]
    [string]$PrincipalUpn,

    [ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$')]
    [string]$BreakGlassUpn,

    [switch]$RemoveStanding,

    # PIM role policies usually forbid permanent eligibility (ExpirationRule). ISO-8601 duration.
    [ValidatePattern('^P\d+[DMY]$')]
    [string]$EligibilityDuration = 'P365D',

    [string]$ReportPath = (Join-Path $PSScriptRoot "..\evidence\pim-remediation-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv")
)

$ErrorActionPreference = 'Stop'
$env:SuppressAzurePowerShellBreakingChangeWarnings = 'true'
try { Update-AzConfig -DisplayBreakingChangeWarning $false -Scope Process | Out-Null } catch { }

$log = [System.Collections.Generic.List[object]]::new()
function Write-Log([string]$Step, [string]$Result, [string]$Detail = '') {
    $log.Add([pscustomobject]@{ TimestampUtc = (Get-Date).ToUniversalTime().ToString('s'); Step = $Step; Result = $Result; Detail = $Detail })
    $color = switch -Regex ($Result) { 'OK|CREATED|VERIFIED|REMOVED' { 'Green' } 'EXISTS|SKIPPED|PLAN' { 'Gray' } 'BLOCKED|FAIL' { 'Red' } default { 'Yellow' } }
    Write-Host ("  [{0,-9}] {1} {2}" -f $Result, $Step, $Detail) -ForegroundColor $color
}

try {
    $ctx = Get-AzContext
    if (-not $ctx) { Connect-AzAccount | Out-Null; $ctx = Get-AzContext }
    if ($SubscriptionId -and $ctx.Subscription.Id -ne $SubscriptionId) { $ctx = (Set-AzContext -Subscription $SubscriptionId).Context }
    $subId  = $ctx.Subscription.Id
    $scope  = "/subscriptions/$subId"
    $shown  = "/subscriptions/****$($subId.Substring($subId.Length - 4))"
    if (-not $PrincipalUpn) { $PrincipalUpn = $ctx.Account.Id }
    Write-Host "`nSubscription: $shown   Target: $PrincipalUpn`n" -ForegroundColor Cyan

    # --- 1. Is PIM usable at this scope? ------------------------------------------------
    # Probe the scoped endpoint. An unscoped call returns HTTP 400 and says nothing about licensing.
    try {
        Get-AzRoleEligibilitySchedule -Scope $scope -ErrorAction Stop | Out-Null
        Write-Log 'PIM availability' 'OK' 'roleEligibilitySchedules readable at this scope'
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match 'AadPremiumLicenseRequired|not licensed|TenantNotOnboarded') {
            throw "PIM is not available on this tenant: $msg"
        }
        Write-Log 'PIM availability' 'WARN' "could not read eligible schedules: $msg"
    }

    # --- 2. Who holds permanent Owner? -------------------------------------------------------
    $owners = @(Get-AzRoleAssignment -Scope $scope -RoleDefinitionName 'Owner' | Where-Object { $_.Scope -eq $scope })
    Write-Log 'Permanent Owners at subscription scope' 'OK' "$($owners.Count) found"
    $owners | ForEach-Object { Write-Host "        - $($_.DisplayName) ($($_.ObjectType))" -ForegroundColor DarkGray }

    $target = Get-AzADUser -UserPrincipalName $PrincipalUpn
    if (-not $target) { throw "User '$PrincipalUpn' not found." }
    $targetStanding = $owners | Where-Object ObjectId -eq $target.Id

    # --- 3. Break-glass guard ---------------------------------------------------------------
    if ($RemoveStanding) {
        if (-not $BreakGlassUpn) { throw '-RemoveStanding requires -BreakGlassUpn. Never remove the last permanent Owner.' }
        $bg = Get-AzADUser -UserPrincipalName $BreakGlassUpn
        if (-not $bg) { throw "Break-glass account '$BreakGlassUpn' not found. Create it first (cloud-only, long unique password, excluded from Conditional Access, credentials stored offline)." }
        if ($bg.Id -eq $target.Id) { throw 'Break-glass account and target user are the same account.' }
        if (-not ($owners | Where-Object ObjectId -eq $bg.Id)) {
            throw "Break-glass account does not hold permanent Owner at this scope. Assign it first: New-AzRoleAssignment -ObjectId $($bg.Id) -RoleDefinitionName Owner -Scope $scope"
        }
        Write-Log 'Break-glass check' 'OK' 'separate account holds permanent Owner'
    }

    # --- 4. Create the eligible assignment ---------------------------------------------------
    $roleDef = Get-AzRoleDefinition -Name 'Owner'
    $roleDefId = "/subscriptions/$subId/providers/Microsoft.Authorization/roleDefinitions/$($roleDef.Id)"

    $existingEligible = @(Get-AzRoleEligibilitySchedule -Scope $scope -Filter "principalId eq '$($target.Id)'" -ErrorAction SilentlyContinue |
                          Where-Object { $_.RoleDefinitionId -eq $roleDefId })
    if ($existingEligible) {
        Write-Log 'Eligible Owner assignment' 'EXISTS' $PrincipalUpn
    }
    elseif ($PSCmdlet.ShouldProcess("$shown", "Create PIM-eligible Owner for $PrincipalUpn")) {
        $req = New-AzRoleEligibilityScheduleRequest -Name ([guid]::NewGuid().ToString()) `
            -Scope $scope `
            -PrincipalId $target.Id `
            -RoleDefinitionId $roleDefId `
            -RequestType AdminAssign `
            -ScheduleInfoStartDateTime (Get-Date -Format o) `
            -ExpirationType AfterDuration `
            -ExpirationDuration $EligibilityDuration `
            -Justification 'Remediating standing Owner found by the RBAC audit: eligible instead of permanent.' `
            -ErrorAction Stop
        if (-not $req) { throw 'The eligibility request returned nothing - check PIM > Settings > Owner for policy rules.' }
        Write-Log 'Eligible Owner assignment' 'CREATED' ("{0} (eligible for {1}, status {2})" -f $PrincipalUpn, $EligibilityDuration, $req.Status)
    }
    else { Write-Log 'Eligible Owner assignment' 'PLAN' $PrincipalUpn }

    # --- 5. Verify before removing anything --------------------------------------------------
    $verified = $false
    if (-not $WhatIfPreference) {
        foreach ($i in 1..6) {
            Start-Sleep -Seconds 10
            $verified = @(Get-AzRoleEligibilitySchedule -Scope $scope -Filter "principalId eq '$($target.Id)'" -ErrorAction SilentlyContinue |
                          Where-Object { $_.RoleDefinitionId -eq $roleDefId }).Count -gt 0
            if ($verified) { break }
        }
        Write-Log 'Eligible assignment verified' $(if ($verified) { 'VERIFIED' } else { 'FAIL' }) $(if ($verified) { 'visible in PIM' } else { 'not visible yet - check the portal before removing standing access' })
    }

    # --- 6. Remove the standing assignment ---------------------------------------------------
    if ($RemoveStanding) {
        if (-not $verified -and -not $WhatIfPreference) { throw 'Refusing to remove standing Owner: the eligible assignment did not verify.' }
        if (-not $targetStanding) { Write-Log 'Standing Owner' 'SKIPPED' "$PrincipalUpn has no permanent Owner at this scope" }
        elseif ($PSCmdlet.ShouldProcess($shown, "Remove PERMANENT Owner from $PrincipalUpn")) {
            Remove-AzRoleAssignment -ObjectId $target.Id -RoleDefinitionName 'Owner' -Scope $scope | Out-Null
            Write-Log 'Standing Owner' 'REMOVED' $PrincipalUpn
        }
    }
    else {
        Write-Log 'Standing Owner' 'SKIPPED' 'left in place (rerun with -RemoveStanding after testing activation)'
    }

    Write-Host "`nNext:" -ForegroundColor Cyan
    Write-Host "  1. PIM > Azure resources > Settings > Owner: set max activation duration (e.g. 4h), require justification, require approval."
    Write-Host "  2. Activate the role as the eligible user and confirm it works BEFORE removing standing access."
    Write-Host "  3. Rerun this script with -BreakGlassUpn <account> -RemoveStanding."
    Write-Host "  4. Rerun deploy-rbac-least-privilege.ps1 to show the audit now flags 0 standing Owners for this user."
}
catch {
    Write-Log 'FATAL' 'FAIL' $_.Exception.Message
    throw
}
finally {
    if ($log.Count) {
        $dir = Split-Path $ReportPath
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $log | Export-Csv -Path $ReportPath -NoTypeInformation
        Write-Host "`nLog: $ReportPath" -ForegroundColor DarkGray
    }
}
