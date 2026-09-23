#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.Resources, Az.KeyVault, Az.Network

<#
.SYNOPSIS
    Runs the least-privilege enforcement tests while signed in AS A TEST USER, and records
    expected vs. actual (Allowed / Denied) for each one.

.DESCRIPTION
    Proving a custom role exists is not proof it enforces anything. Each test attempts a real
    operation and classifies the outcome:
        Allowed  - the call succeeded
        Denied   - Azure refused it for authorization (AuthorizationFailed / Forbidden / 403)
        Error    - anything else (typo, propagation delay, missing resource). Not a pass.

    TestSet KeyVault (sign in as the Key Vault tester):
        TC01  Write a secret version (setSecret DataAction)          Expected: Allowed
        TC02  Delete the Key Vault (vaults/delete is in NotActions)   Expected: Denied
    TestSet Network (sign in as the Network tester):
        TC06  Create a Network Security Group                         Expected: Allowed
        TC03  Grant yourself Reader on the RG (Authorization write)   Expected: Denied

    If a "Denied" test is unexpectedly ALLOWED, the script reverts the change it made
    (removes the NSG / role assignment) and marks the test FAIL. TC02 cannot be reverted
    automatically; the vault would sit in soft-delete (recover with Undo-AzKeyVaultRemoval).

    Results go to ..\evidence\enforcement-results-<set>.csv with the UPN and subscription redacted.

.PARAMETER TestSet
    KeyVault or Network.

.PARAMETER ResourceGroupName
    Lab resource group created by setup-rbac-test-env.ps1. Default: RG-IAMLab-Test

.PARAMETER KeyVaultName
    Vault created by the setup script (required for the KeyVault set).

.EXAMPLE
    # New PowerShell window, signed in as the Key Vault tester
    Connect-AzAccount
    .\invoke-rbac-enforcement-tests.ps1 -TestSet KeyVault -KeyVaultName kv-iamlab-ab12cd34

.EXAMPLE
    .\invoke-rbac-enforcement-tests.ps1 -TestSet Network -WhatIf

.NOTES
    Required: nothing beyond what the role under test grants - that's the point.
    Refuses to run if the signed-in account holds Owner / Contributor / User Access Administrator
    at subscription scope, because a denial test run as an admin proves nothing.
    If a result is Error with "not found" right after setup, wait for RBAC propagation (~10 min) and rerun.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateSet('KeyVault', 'Network')]
    [string]$TestSet,

    [string]$ResourceGroupName = 'RG-IAMLab-Test',

    [string]$KeyVaultName,

    [string]$Location = 'westus2',

    [string]$EvidencePath = (Join-Path $PSScriptRoot "..\evidence\enforcement-results-$($TestSet.ToLower()).csv")
)

$ErrorActionPreference = 'Stop'
$env:SuppressAzurePowerShellBreakingChangeWarnings = 'true'
# The env var alone doesn't silence every Az warning; this does, for this session only
try { Update-AzConfig -DisplayBreakingChangeWarning $false -Scope Process | Out-Null } catch { }
if ($TestSet -eq 'KeyVault' -and -not $KeyVaultName) { throw '-KeyVaultName is required for the KeyVault test set.' }

$ctx = Get-AzContext
if (-not $ctx) { throw 'Not signed in. Run Connect-AzAccount as the TEST USER first.' }
$subId = $ctx.Subscription.Id
$me    = Get-AzADUser -SignedIn
$rgScope = "/subscriptions/$subId/resourceGroups/$ResourceGroupName"

# Guard: a denial test run by an admin proves nothing.
$adminRoles = Get-AzRoleAssignment -ObjectId $me.Id -ErrorAction SilentlyContinue |
    Where-Object { $_.RoleDefinitionName -in 'Owner', 'Contributor', 'User Access Administrator' }
if ($adminRoles) { throw "Signed-in account holds $($adminRoles.RoleDefinitionName -join ', '). Sign in as the test user instead." }

Write-Host "`nRunning '$TestSet' tests as $($me.UserPrincipalName) on subscription ****$($subId.Substring($subId.Length - 4))`n" -ForegroundColor Cyan
$results = [System.Collections.Generic.List[object]]::new()

function Get-Outcome([System.Management.Automation.ErrorRecord]$Err) {
    $msg = "$($Err.Exception.Message) $($Err.Exception.InnerException.Message)"
    if ($msg -match 'AuthorizationFailed|Forbidden|\b403\b|does not have authorization|not permitted|ForbiddenByRbac') { return 'Denied' }
    return 'Error'
}

function Invoke-Test {
    param([string]$Id, [string]$Name, [string]$Operation, [ValidateSet('Allowed', 'Denied')][string]$Expected,
          [scriptblock]$Action, [scriptblock]$Revert)
    if (-not $PSCmdlet.ShouldProcess($ResourceGroupName, "$Id $Name")) { return }
    $detail = ''
    try {
        & $Action | Out-Null
        $actual = 'Allowed'
    } catch {
        $actual = Get-Outcome $_
        $detail = ($_.Exception.Message -split "`n")[0]
    }
    if ($actual -eq 'Allowed' -and $Expected -eq 'Denied' -and $Revert) {
        try { & $Revert | Out-Null; $detail = 'UNEXPECTEDLY ALLOWED - change reverted' }
        catch { $detail = "UNEXPECTEDLY ALLOWED - revert failed: $($_.Exception.Message)" }
    }
    $verdict = if ($actual -eq $Expected) { 'PASS' } else { 'FAIL' }
    $results.Add([pscustomobject]@{
        TestId = $Id; Test = $Name; Operation = $Operation; Expected = $Expected; Actual = $actual; Verdict = $verdict
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('s')
        # Redact identifiers so the CSV is repo-safe
        Detail = ($detail -replace '[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}', '<GUID>' -replace '[^@\s''"]+@[^@\s''"]+', '<UPN>')
    })
    $color = if ($verdict -eq 'PASS') { 'Green' } else { 'Red' }
    Write-Host ("  {0}  {1,-44} expected {2,-7} got {3,-7} {4}" -f $Id, $Name, $Expected, $actual, $verdict) -ForegroundColor $color
    if ($detail) { Write-Host "        $($detail.Substring(0, [Math]::Min(160, $detail.Length)))" -ForegroundColor DarkGray }
}

if ($TestSet -eq 'KeyVault') {
    Invoke-Test -Id 'TC01' -Name 'Write a Key Vault secret version' -Operation 'Microsoft.KeyVault/vaults/secrets/setSecret/action' -Expected 'Allowed' -Action {
        $value = ConvertTo-SecureString ([guid]::NewGuid().ToString()) -AsPlainText -Force   # throwaway value, never printed
        Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name 'tc01-rotation-test' -SecretValue $value
    }
    Invoke-Test -Id 'TC02' -Name 'Delete the Key Vault' -Operation 'Microsoft.KeyVault/vaults/delete' -Expected 'Denied' -Action {
        Remove-AzKeyVault -VaultName $KeyVaultName -ResourceGroupName $ResourceGroupName -Force
    }
}
else {
    $nsgName = "nsg-tc06-$(Get-Date -Format 'HHmmss')"
    Invoke-Test -Id 'TC06' -Name 'Create a Network Security Group' -Operation 'Microsoft.Network/networkSecurityGroups/write' -Expected 'Allowed' -Action {
        New-AzNetworkSecurityGroup -Name $nsgName -ResourceGroupName $ResourceGroupName -Location $Location -Force
    }
    Invoke-Test -Id 'TC03' -Name 'Grant self Reader on the resource group' -Operation 'Microsoft.Authorization/roleAssignments/write' -Expected 'Denied' -Action {
        New-AzRoleAssignment -ObjectId $me.Id -RoleDefinitionName 'Reader' -Scope $rgScope
    } -Revert {
        Remove-AzRoleAssignment -ObjectId $me.Id -RoleDefinitionName 'Reader' -Scope $rgScope
    }
}

if ($results.Count) {
    $dir = Split-Path $EvidencePath
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $results | Export-Csv -Path $EvidencePath -NoTypeInformation
    $pass = ($results | Where-Object Verdict -eq 'PASS').Count
    Write-Host "`n$pass of $($results.Count) passed. Evidence: $EvidencePath" -ForegroundColor Cyan
    Write-Host "Capture: this terminal output + Azure portal > Monitor > Activity log (filter: Failed) for the denied operations." -ForegroundColor DarkGray
}
