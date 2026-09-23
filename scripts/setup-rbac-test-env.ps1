#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.Resources, Az.KeyVault

<#
.SYNOPSIS
    Builds the minimal lab environment for enforcement tests TC01-TC06: one resource group,
    one RBAC-mode Key Vault, and RG-scoped assignments of the two custom roles to two EXISTING test users.

.DESCRIPTION
    Run this as the lab admin. It does not create users or passwords; pick two existing
    non-admin lab users (for example, two from the access review lab).

      1. Creates the resource group (if missing).
      2. Creates a Key Vault that uses the Azure RBAC permission model (DataActions only apply in that mode)
         and verifies the model instead of assuming it.
      3. Assigns "Custom Key Vault Secrets Officer" to -KeyVaultTesterUpn at the RESOURCE GROUP scope.
      4. Assigns "Custom Network Security Admin" to -NetworkTesterUpn at the RESOURCE GROUP scope.
      5. Verifies each assignment and logs every action to a CSV.

    Idempotent: existing objects are reported as [EXISTS] and left alone. Supports -WhatIf.
    RBAC changes can take up to ~10 minutes to take effect; wait before running the tests.

.PARAMETER SubscriptionId
    Target subscription. Defaults to the current Az context.

.PARAMETER ResourceGroupName
    Lab resource group. Default: RG-IAMLab-Test

.PARAMETER Location
    Azure region. Default: westus2

.PARAMETER KeyVaultName
    Globally unique vault name (3-24 chars, letters/digits/hyphens). Default: kv-iamlab-<random>.

.PARAMETER KeyVaultTesterUpn
    Existing non-admin user who gets the Key Vault custom role (TC01, TC02).

.PARAMETER NetworkTesterUpn
    Existing non-admin user who gets the Network custom role (TC03, TC06).

.PARAMETER LogPath
    CSV action log. Default: ..\output\setup-log-<timestamp>.csv (git-ignored).

.EXAMPLE
    .\setup-rbac-test-env.ps1 -KeyVaultTesterUpn kv.tester@contoso.onmicrosoft.com -NetworkTesterUpn net.tester@contoso.onmicrosoft.com -WhatIf

.NOTES
    Required: Owner or User Access Administrator on the subscription (role assignments) and
    Contributor (resource group + vault). Az module only; no Graph scopes needed.

    Verify:   Get-AzRoleAssignment -ResourceGroupName RG-IAMLab-Test | Select DisplayName, RoleDefinitionName, Scope
    Rollback: .\setup-rbac-test-env.ps1 ... -Remove   (removes the two assignments, then the resource group)
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$SubscriptionId,

    [string]$ResourceGroupName = 'RG-IAMLab-Test',

    [string]$Location = 'westus2',

    [ValidatePattern('^[a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]$')]
    [string]$KeyVaultName = ('kv-iamlab-' + -join ((97..122) + (48..57) | Get-Random -Count 8 | ForEach-Object { [char]$_ })),

    [Parameter(Mandatory)][ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$')]
    [string]$KeyVaultTesterUpn,

    [Parameter(Mandatory)][ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$')]
    [string]$NetworkTesterUpn,

    [switch]$Remove,

    [string]$LogPath = (Join-Path $PSScriptRoot "..\output\setup-log-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv")
)

$ErrorActionPreference = 'Stop'
$env:SuppressAzurePowerShellBreakingChangeWarnings = 'true'
# The env var alone doesn't silence every Az warning; this does, for this session only
try { Update-AzConfig -DisplayBreakingChangeWarning $false -Scope Process | Out-Null } catch { }
$log = [System.Collections.Generic.List[object]]::new()
function Write-Log([string]$Step, [string]$Result, [string]$Detail = '') {
    $log.Add([pscustomobject]@{ TimestampUtc = (Get-Date).ToUniversalTime().ToString('s'); Step = $Step; Result = $Result; Detail = $Detail })
    $color = switch -Regex ($Result) { 'OK|CREATED|ASSIGNED|REMOVED' { 'Green' } 'EXISTS|SKIPPED' { 'Gray' } default { 'Yellow' } }
    Write-Host ("  [{0,-8}] {1} {2}" -f $Result, $Step, $Detail) -ForegroundColor $color
}

$assignments = @(
    @{ Upn = $KeyVaultTesterUpn; Role = 'Custom Key Vault Secrets Officer' },
    @{ Upn = $NetworkTesterUpn;  Role = 'Custom Network Security Admin' }
)

try {
    # --- Context ------------------------------------------------------------------------
    $ctx = Get-AzContext
    if (-not $ctx) { Connect-AzAccount | Out-Null; $ctx = Get-AzContext }
    if ($SubscriptionId -and $ctx.Subscription.Id -ne $SubscriptionId) { $ctx = (Set-AzContext -Subscription $SubscriptionId).Context }
    $subId = $ctx.Subscription.Id
    Write-Host "`nSubscription: ****$($subId.Substring($subId.Length - 4))  Account: $($ctx.Account.Id)`n" -ForegroundColor Cyan

    # --- Custom roles must already exist (deployed by deploy-rbac-least-privilege.ps1) -------
    foreach ($a in $assignments) {
        if (-not (Get-AzRoleDefinition -Name $a.Role -ErrorAction SilentlyContinue)) {
            throw "Custom role '$($a.Role)' not found. Run deploy-rbac-least-privilege.ps1 first."
        }
    }

    # --- Resolve test users; refuse anyone holding a high-risk role at subscription scope --
    foreach ($a in $assignments) {
        $u = Get-AzADUser -UserPrincipalName $a.Upn
        if (-not $u) { throw "User '$($a.Upn)' not found in this tenant." }
        $a.ObjectId = $u.Id
        $risky = Get-AzRoleAssignment -ObjectId $u.Id -Scope "/subscriptions/$subId" -ErrorAction SilentlyContinue |
                 Where-Object RoleDefinitionName -in 'Owner', 'Contributor', 'User Access Administrator'
        if ($risky) { throw "Test user '$($a.Upn)' already holds $($risky.RoleDefinitionName -join ', ') at subscription scope. A denial test would be meaningless. Pick a non-admin user." }
    }
    $rgScope = "/subscriptions/$subId/resourceGroups/$ResourceGroupName"
    # Masked copy for console output, so screenshots don't leak the subscription ID
    $rgScopeShown = "/subscriptions/****$($subId.Substring($subId.Length - 4))/resourceGroups/$ResourceGroupName"

    # --- Rollback path --------------------------------------------------------------------
    if ($Remove) {
        foreach ($a in $assignments) {
            $existing = Get-AzRoleAssignment -ObjectId $a.ObjectId -RoleDefinitionName $a.Role -Scope $rgScope -ErrorAction SilentlyContinue
            if ($existing -and $PSCmdlet.ShouldProcess($rgScopeShown, "Remove '$($a.Role)' from $($a.Upn)")) {
                Remove-AzRoleAssignment -ObjectId $a.ObjectId -RoleDefinitionName $a.Role -Scope $rgScope | Out-Null
                Write-Log "Assignment $($a.Role)" 'REMOVED' $a.Upn
            }
        }
        if ((Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue) -and
            $PSCmdlet.ShouldProcess($ResourceGroupName, 'Delete resource group (vault goes to soft-delete)')) {
            Remove-AzResourceGroup -Name $ResourceGroupName -Force | Out-Null
            Write-Log "Resource group $ResourceGroupName" 'REMOVED' 'Key Vault is soft-deleted; purge with Remove-AzKeyVault -InRemovedState if needed'
        }
        return
    }

    # --- 0. Resource providers -----------------------------------------------------------
    # A test user with only a custom role cannot register a provider (that needs subscription
    # write), so TC06 fails with "subscription is not registered to use namespace ..." unless
    # the admin registers it here first.
    foreach ($ns in 'Microsoft.KeyVault', 'Microsoft.Network') {
        $rp = Get-AzResourceProvider -ProviderNamespace $ns | Select-Object -First 1
        if ($rp.RegistrationState -eq 'Registered') { Write-Log "Provider $ns" 'EXISTS' 'Registered'; continue }
        if ($PSCmdlet.ShouldProcess($ns, 'Register resource provider')) {
            Register-AzResourceProvider -ProviderNamespace $ns | Out-Null
            $deadline = (Get-Date).AddMinutes(5)
            do {
                Start-Sleep -Seconds 15
                $state = (Get-AzResourceProvider -ProviderNamespace $ns | Select-Object -First 1).RegistrationState
            } while ($state -ne 'Registered' -and (Get-Date) -lt $deadline)
            Write-Log "Provider $ns" $(if ($state -eq 'Registered') { 'OK' } else { 'PENDING' }) $state
        }
    }

    # --- 1. Resource group ------------------------------------------------------------------
    if (Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue) {
        Write-Log "Resource group $ResourceGroupName" 'EXISTS'
    } elseif ($PSCmdlet.ShouldProcess($ResourceGroupName, "Create resource group in $Location")) {
        New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Tag @{ purpose = 'iam-rbac-enforcement-tests' } | Out-Null
        Write-Log "Resource group $ResourceGroupName" 'CREATED' $Location
    }

    # --- 2. Key Vault in RBAC mode -----------------------------------------------------------
    $kv = Get-AzKeyVault -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($kv) {
        $KeyVaultName = $kv.VaultName
        Write-Log "Key Vault $KeyVaultName" 'EXISTS'
    } elseif ($PSCmdlet.ShouldProcess($KeyVaultName, 'Create Key Vault (Azure RBAC permission model)')) {
        $kvParams = @{ Name = $KeyVaultName; ResourceGroupName = $ResourceGroupName; Location = $Location }
        # Older Az.KeyVault needs -EnableRbacAuthorization; 6.0+ uses RBAC by default and dropped the switch.
        if ((Get-Command New-AzKeyVault).Parameters.ContainsKey('EnableRbacAuthorization')) { $kvParams.EnableRbacAuthorization = $true }
        $kv = New-AzKeyVault @kvParams
        Write-Log "Key Vault $KeyVaultName" 'CREATED'
    }
    if ($kv) {
        $kv = Get-AzKeyVault -VaultName $KeyVaultName
        if (-not $kv.EnableRbacAuthorization) {
            throw "Key Vault '$KeyVaultName' uses access policies, not Azure RBAC. DataActions in the custom role will not apply. Fix: Update-AzKeyVault -VaultName $KeyVaultName -ResourceGroupName $ResourceGroupName -EnableRbacAuthorization `$true"
        }
        Write-Log "Key Vault permission model" 'OK' 'Azure RBAC'
    }

    # --- 3/4. Role assignments at RG scope ----------------------------------------------------
    foreach ($a in $assignments) {
        $existing = Get-AzRoleAssignment -ObjectId $a.ObjectId -RoleDefinitionName $a.Role -Scope $rgScope -ErrorAction SilentlyContinue
        if ($existing) { Write-Log "Assignment $($a.Role)" 'EXISTS' $a.Upn; continue }
        if ($PSCmdlet.ShouldProcess($rgScopeShown, "Assign '$($a.Role)' to $($a.Upn)")) {
            New-AzRoleAssignment -ObjectId $a.ObjectId -RoleDefinitionName $a.Role -Scope $rgScope | Out-Null
            $check = Get-AzRoleAssignment -ObjectId $a.ObjectId -RoleDefinitionName $a.Role -Scope $rgScope
            if (-not $check) { throw "Assignment of '$($a.Role)' to $($a.Upn) did not verify." }
            Write-Log "Assignment $($a.Role)" 'ASSIGNED' "$($a.Upn) @ RG scope"
        }
    }

    Write-Host "`nNext:" -ForegroundColor Cyan
    Write-Host "  1. Wait ~10 minutes for RBAC to propagate."
    Write-Host "  2. Open a NEW PowerShell window and sign in as a test user:  Connect-AzAccount"
    Write-Host "  3. Run: .\invoke-rbac-enforcement-tests.ps1 -TestSet KeyVault -KeyVaultName $KeyVaultName -ResourceGroupName $ResourceGroupName"
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
