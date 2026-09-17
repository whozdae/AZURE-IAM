# Verification Plan: Proving the Custom Roles Work

Creating a custom role only proves that the definition exists. These tests prove it **enforces** least privilege.
Each test gets run against a dedicated test user, and the evidence gets saved to `/screenshots`.

**Status legend:** ✅ done · ⏳ planned

| ID | Test | Role under test | Expected result | Evidence to capture | Status |
| :-- | :-- | :-- | :-- | :-- | :-- |
| TC00 | Custom roles created by the script | Both | Roles visible in *Subscription → Access control (IAM) → Roles* | Script output + portal permissions view | ✅ |
| TC01 | Rotate a Key Vault secret (`Set-AzKeyVaultSecret`) | Custom Key Vault Secrets Officer | **Allowed** | Terminal output showing the new secret version | ⏳ |
| TC02 | Delete the Key Vault (`Remove-AzKeyVault`) | Custom Key Vault Secrets Officer | **Denied** with `AuthorizationFailed` | Terminal error + Activity Log entry | ⏳ |
| TC03 | Assign a role to self (`New-AzRoleAssignment`) | Custom Network Security Admin | **Denied** with `AuthorizationFailed` | Terminal error + Activity Log entry | ⏳ |
| TC04 | Audit flags high-risk assignments | Script audit | Owner / Contributor / UAA rows marked `True` | Audit summary output + sanitized CSV | ✅ |
| TC05 | KQL detection fires on a new role assignment | `queries/detect-rbac-role-assignment.kql` | Row returned for the TC01 test-user assignment | Log Analytics results pane | ⏳ |

## Setup for TC01 to TC03

```powershell
# Test user and an RG-scoped assignment (replace the placeholders)
$rg   = "RG-Data"
$upn  = "kv-tester@<tenant>.onmicrosoft.com"
New-AzRoleAssignment -SignInName $upn -RoleDefinitionName "Custom Key Vault Secrets Officer" -ResourceGroupName $rg

# Key Vault must use the Azure RBAC permission model for DataActions to apply
New-AzKeyVault -Name "kv-iamlab-<unique>" -ResourceGroupName $rg -Location "westus2" -EnableRbacAuthorization
```

Sign in as the test user in a private browser or a separate `Connect-AzAccount` session, then run each test.

## Cleanup / rollback

```powershell
Remove-AzRoleAssignment -SignInName $upn -RoleDefinitionName "Custom Key Vault Secrets Officer" -ResourceGroupName $rg
Remove-AzRoleDefinition -Name "Custom Key Vault Secrets Officer" -Force
Remove-AzRoleDefinition -Name "Custom Network Security Admin" -Force
```
