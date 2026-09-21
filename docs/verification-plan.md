# Verification Plan: Proving the Custom Roles Work

Creating a custom role only proves that the definition exists. These tests prove it **enforces** least privilege.
Each test gets run against a dedicated test user, and the evidence gets saved to `/screenshots`.

**Status legend:** ✅ done · ⏳ planned

| ID | Test | Role under test | Expected result | Evidence to capture | Status |
| :-- | :-- | :-- | :-- | :-- | :-- |
| TC00 | Custom roles created by the script | Both | Roles visible in *Subscription → Access control (IAM) → Roles* | Script output + portal permissions view | ✅ |
| TC01 | Rotate a Key Vault secret (`Set-AzKeyVaultSecret`) | Custom Key Vault Secrets Officer | **Allowed** | Terminal output showing the new secret version | ⏳ |
| TC02 | Delete the Key Vault (`Remove-AzKeyVault`) | Custom Key Vault Secrets Officer | **Denied** with `AuthorizationFailed` | Terminal error + Activity Log entry | ⏳ |
| TC03 | Grant self Reader on the RG (`New-AzRoleAssignment`) | Custom Network Security Admin | **Denied** with `AuthorizationFailed` | Terminal error + Activity Log entry | ⏳ |
| TC04 | Audit flags high-risk assignments | Script audit | Owner / Contributor / UAA rows marked `True` | Audit summary output + sanitized CSV | ✅ |
| TC06 | Create a Network Security Group (`New-AzNetworkSecurityGroup`) | Custom Network Security Admin | **Allowed** | Terminal output | ⏳ |
| TC05 | KQL detection fires on a new role assignment | `queries/detect-rbac-role-assignment.kql` | Row returned for the TC01 test-user assignment | Log Analytics results pane | ⏳ |

## How to run TC01 to TC03 and TC06

The tests are scripted so they're repeatable and the results land in `evidence/` as CSV.

```powershell
# 1. As the lab admin: resource group, RBAC-mode Key Vault, RG-scoped role assignments
.\scripts\setup-rbac-test-env.ps1 -KeyVaultTesterUpn <kv-tester-upn> -NetworkTesterUpn <net-tester-upn> -WhatIf
.\scripts\setup-rbac-test-env.ps1 -KeyVaultTesterUpn <kv-tester-upn> -NetworkTesterUpn <net-tester-upn>

# 2. Wait ~10 minutes for RBAC to propagate. Then, in a NEW window signed in as the Key Vault tester:
Connect-AzAccount
.\scripts\invoke-rbac-enforcement-tests.ps1 -TestSet KeyVault -KeyVaultName <vault-name>

# 3. New window, signed in as the Network tester:
Connect-AzAccount
.\scripts\invoke-rbac-enforcement-tests.ps1 -TestSet Network
```

The runner refuses to run as an account holding Owner, Contributor, or User Access Administrator, because a denial test run by an admin proves nothing. If a "Denied" test is unexpectedly allowed, it reverts the change and marks the test FAIL.

## Cleanup / rollback

```powershell
.\scripts\setup-rbac-test-env.ps1 -KeyVaultTesterUpn <kv-tester-upn> -NetworkTesterUpn <net-tester-upn> -Remove
# Only if retiring the roles entirely:
Remove-AzRoleDefinition -Name "Custom Key Vault Secrets Officer" -Force
Remove-AzRoleDefinition -Name "Custom Network Security Admin" -Force
```
