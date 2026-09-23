# Troubleshooting Log

Real problems hit while running the enforcement tests, traced to root cause in the sign-in logs.

## T01: Test user blocked from Azure PowerShell ("You don't have access to this")

| | |
| :-- | :-- |
| **Symptom** | Test user signs in successfully (password, then Temporary Access Pass), then gets *"Your sign-in was successful but you don't have permission to access this resource."* |
| **Where I looked** | Entra admin center > Users > test user > Sign-in logs > latest failure |
| **Error code** | `530035` "Access has been blocked by security defaults." |
| **Key fields** | Application: Microsoft Azure PowerShell · Resource: Azure Resource Manager · Original transfer method: **Device code flow** · Conditional Access tab: *Security Defaults* > Grant: **Block** |
| **Root cause** | The tenant runs **security defaults**, which block the device code flow outright. I used `Connect-AzAccount -UseDeviceAuthentication` to keep the test user's session separate from my admin session, and that flow is exactly what security defaults refuses. |
| **What it was not** | Not an RBAC problem (the role assignments were never evaluated) and not missing MFA (the Temporary Access Pass satisfies MFA, and the block persisted). |
| **Fix** | Sign in with the interactive browser flow instead: `Connect-AzAccount`, then "Use another account". Security defaults stays on. |
| **Lesson** | Authentication succeeded, then a tenant-wide policy blocked the *method* of sign-in. Read the sign-in log before changing anything: the "Original transfer method" field named the cause in one line. |

Reference: Microsoft Learn, *Security defaults in Microsoft Entra ID* ("authentication requests that use device code flow are blocked").

## T02: TC06 fails with "subscription is not registered to use namespace 'Microsoft.Network'"

| | |
| :-- | :-- |
| **Symptom** | TC06 (create a Network Security Group) returned `Error`, not `Denied`: *"The subscription is not registered to use namespace 'Microsoft.Network'."* TC03 in the same run passed. |
| **Root cause** | A resource provider must be registered on the subscription before its resource types can be used, and this subscription had never created a network resource. Registration is a subscription-level write, which the test user's custom role deliberately does not grant, so the test user can't self-heal it. |
| **Why it matters** | The failure is an environment gap, not a permission decision. Treating it as a denial would have been a false pass for least privilege. |
| **Fix** | Admin runs `Register-AzResourceProvider -ProviderNamespace Microsoft.Network`, waits for `Registered`, then the test user reruns TC06. `setup-rbac-test-env.ps1` now registers Microsoft.KeyVault and Microsoft.Network up front and waits for each. |
| **Lesson** | Separate "not allowed" from "not possible". My test runner classifies anything that isn't an authorization failure as `Error` instead of scoring it, which is what surfaced this. |
