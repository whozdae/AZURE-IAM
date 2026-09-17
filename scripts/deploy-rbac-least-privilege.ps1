#Requires -Version 5.1
#Requires -Modules Az.Accounts, Az.Resources

<#
.SYNOPSIS
    Deploys two least-privilege custom Azure RBAC roles and audits the subscription for high-risk role assignments.

.DESCRIPTION
    1. Connects to Azure (reuses an existing Az context if one is present).
    2. Creates two custom roles if they don't already exist:
         - Custom Key Vault Secrets Officer  (read + rotate secrets, cannot modify or delete vaults)
         - Custom Network Security Admin     (manage network resources, excludes ExpressRoute)
    3. Inventories every role assignment visible at the subscription scope.
    4. Flags Owner, Contributor, and User Access Administrator assignments as high risk.
    5. Exports the results to CSV.

    Supports -WhatIf: the audit still runs, but no roles are created.

.PARAMETER SubscriptionId
    Target subscription. If omitted, the current Az context's subscription is used.

.PARAMETER AssignableScope
    Scope the custom roles can be assigned at. Defaults to the whole subscription.
    Pass a resource group scope to lock them down further, e.g.
    /subscriptions/<id>/resourceGroups/RG-Data

.PARAMETER HighRiskRoles
    Role names that count as high risk in the audit.

.PARAMETER ReportPath
    Where to write the CSV. Defaults to ./output/AuditReport-IAM-<timestamp>.csv (git-ignored).

.EXAMPLE
    .\deploy-rbac-least-privilege.ps1 -SubscriptionId "00000000-0000-0000-0000-000000000000" -WhatIf

.EXAMPLE
    .\deploy-rbac-least-privilege.ps1 -AssignableScope "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/RG-Data"

.NOTES
    Required permissions: User Access Administrator or Owner on the target scope (to create role
    definitions) and Reader (to list role assignments).
    Rollback: Remove-AzRoleDefinition -Name "<role name>" -Force  (remove any assignments first).
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$SubscriptionId,

    [string]$AssignableScope,

    [string[]]$HighRiskRoles = @('Owner', 'Contributor', 'User Access Administrator'),

    [string]$ReportPath = (Join-Path $PSScriptRoot "..\output\AuditReport-IAM-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv")
)

$ErrorActionPreference = 'Stop'
# Hide Az "upcoming breaking change" banners for this session only
$env:SuppressAzurePowerShellBreakingChangeWarnings = 'true'

function New-LeastPrivilegeRole {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][string[]]$Actions,
        [string[]]$NotActions = @(),
        [string[]]$DataActions = @(),
        [Parameter(Mandatory)][string]$Scope
    )

    if (Get-AzRoleDefinition -Name $Name -ErrorAction SilentlyContinue) {
        Write-Host "    [EXISTS]  $Name" -ForegroundColor Gray
        return
    }

    if (-not $PSCmdlet.ShouldProcess($Scope, "Create custom role '$Name'")) { return }

    $perm = [Microsoft.Azure.Commands.Resources.Models.Authorization.PSPermission]::new()
    $perm.Actions        = [System.Collections.Generic.List[string]]$Actions
    $perm.NotActions     = [System.Collections.Generic.List[string]]$NotActions
    $perm.DataActions    = [System.Collections.Generic.List[string]]$DataActions
    $perm.NotDataActions = [System.Collections.Generic.List[string]]::new()

    $role = [Microsoft.Azure.Commands.Resources.Models.Authorization.PSRoleDefinition]::new()
    $role.Name             = $Name
    $role.Description      = $Description
    $role.IsCustom         = $true
    $role.Permissions      = [System.Collections.Generic.List[Microsoft.Azure.Commands.Resources.Models.Authorization.PSPermission]]::new()
    $role.Permissions.Add($perm)
    $role.AssignableScopes = [System.Collections.Generic.List[string]]@($Scope)

    New-AzRoleDefinition -Role $role | Out-Null
    Write-Host "    [CREATED] $Name" -ForegroundColor Green
}

Write-Host '==========================================================' -ForegroundColor Cyan
Write-Host ' Azure Least-Privilege IAM Deployment & Audit Script'        -ForegroundColor Cyan
Write-Host '==========================================================' -ForegroundColor Cyan

try {
    # 1. Authenticate
    $context = Get-AzContext
    if (-not $context) {
        Write-Host '[+] Authenticating to Azure...' -ForegroundColor Yellow
        Connect-AzAccount | Out-Null
        $context = Get-AzContext
    }

    if ($SubscriptionId) {
        $context = Set-AzContext -SubscriptionId $SubscriptionId
    }
    $SubscriptionId = $context.Subscription.Id
    Write-Host "[+] Subscription: $($context.Subscription.Name)" -ForegroundColor Green

    if (-not $AssignableScope) { $AssignableScope = "/subscriptions/$SubscriptionId" }

    # 2. Deploy custom roles
    Write-Host "`n[+] Deploying custom least-privilege roles (assignable at $AssignableScope)" -ForegroundColor Yellow

    New-LeastPrivilegeRole -Name 'Custom Key Vault Secrets Officer' `
        -Description 'Read and rotate Key Vault secrets without administrative override.' `
        -Actions @(
            'Microsoft.KeyVault/vaults/read',
            'Microsoft.KeyVault/vaults/secrets/read',
            'Microsoft.KeyVault/vaults/secrets/write',
            'Microsoft.Resources/subscriptions/resourceGroups/read'
        ) `
        -NotActions @(
            'Microsoft.KeyVault/vaults/write',
            'Microsoft.KeyVault/vaults/delete',
            'Microsoft.Authorization/*/write'
        ) `
        -DataActions @(
            'Microsoft.KeyVault/vaults/secrets/getSecret/action',
            'Microsoft.KeyVault/vaults/secrets/setSecret/action'
        ) `
        -Scope $AssignableScope

    New-LeastPrivilegeRole -Name 'Custom Network Security Admin' `
        -Description 'Manage Network Security Groups, VNets, and Firewalls.' `
        -Actions @(
            'Microsoft.Network/*',
            'Microsoft.Resources/subscriptions/resourceGroups/read'
        ) `
        -NotActions @(
            'Microsoft.Network/expressRouteCircuits/*',
            'Microsoft.Authorization/*/write'
        ) `
        -Scope $AssignableScope

    # 3. Audit role assignments
    Write-Host "`n[+] Auditing role assignments for high-risk roles..." -ForegroundColor Yellow
    $assignments = Get-AzRoleAssignment -Scope "/subscriptions/$SubscriptionId"

    $auditResults = foreach ($a in $assignments) {
        [PSCustomObject]@{
            DisplayName        = $a.DisplayName
            SignInName         = $a.SignInName
            ObjectType         = $a.ObjectType
            RoleDefinitionName = $a.RoleDefinitionName
            Scope              = $a.Scope
            HighRiskViolation  = $a.RoleDefinitionName -in $HighRiskRoles
        }
    }
    $violations = @($auditResults | Where-Object HighRiskViolation)

    # 4. Summary
    Write-Host "`n==========================================================" -ForegroundColor Red
    Write-Host ' Audit Findings Summary'                                      -ForegroundColor Red
    Write-Host '==========================================================' -ForegroundColor Red
    Write-Host " Total role assignments audited : $(@($auditResults).Count)"
    Write-Host " High-risk assignments          : $($violations.Count)" -ForegroundColor Red

    if ($violations) {
        Write-Host "`n[!] OVER-PRIVILEGED ASSIGNMENTS DETECTED:" -ForegroundColor Red
        $violations | Format-Table DisplayName, RoleDefinitionName, ObjectType, Scope -AutoSize
    }
    else {
        Write-Host "`n[OK] No high-risk assignments found." -ForegroundColor Green
    }

    # 5. Export (runs even under -WhatIf: it's a local, read-only report)
    $reportDir = Split-Path $ReportPath -Parent
    if (-not (Test-Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir -WhatIf:$false | Out-Null }
    $auditResults | Export-Csv -Path $ReportPath -NoTypeInformation -Force -WhatIf:$false
    Write-Host "`n[+] Report exported to: $ReportPath" -ForegroundColor Cyan
}
catch {
    Write-Error "Script failed: $($_.Exception.Message)"
    exit 1
}
