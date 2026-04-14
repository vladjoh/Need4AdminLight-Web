# Permissions for Need4Admin Light (web)

Delegated permissions are defined in `Program.cs` (and on the home page / `ENTRA-APP-PERMISSIONS.md`).

**This build** only supports:

1. **Privileged users** — active Entra directory roles  
2. **Applications** — delegated and application (app role) API permissions  

**Seven Microsoft Graph delegated permissions (+ `openid`):**

| Permission | Why it is needed |
|------------|------------------|
| `openid` | Sign-in (OpenID Connect) |
| `User.Read` | Signed-in user |
| `User.Read.All` | Read user objects (UPN, account state) in the privileged-users report |
| `Directory.Read.All` | Directory roles and members, `groups/.../transitiveMembers`, `oauth2PermissionGrants` |
| `RoleManagement.Read.Directory` | `roleManagement/directory/roleAssignments`, `transitiveRoleAssignments` |
| `RoleAssignmentSchedule.Read.Directory` | PIM `roleAssignmentSchedules` / `roleAssignmentScheduleInstances` (active JIT roles) |
| `Application.Read.All` | List service principals and resolve app role assignments for the applications report |

Removed from this SKU (not requested in OAuth, not used in code paths): `Group.Read.All` (covered via `Directory.Read.All` for member reads), `UserAuthenticationMethod.Read.All`, `AuditLog.Read.All`.

Grant **admin consent** in Entra for the enterprise application in each tenant. After permission changes, users should **sign out and sign in** so tokens include the new scopes.
