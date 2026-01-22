# PIM Owner Sync - Feature Specification

## Problem Statement

GitHub Team license doesn't have native PIM (Privileged Identity Management) like Azure/Entra ID. We need a mechanism that enables:

- Temporary elevation of users to **GitHub Organization Owner**
- Activation via Entra ID PIM (existing mechanism)
- Fast synchronization (every 30 seconds)
- Safety mechanisms (break-glass account, whitelist)

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              ENTRA ID                                       │
│                                                                             │
│  ┌─────────────────────────────┐      ┌─────────────────────────────┐       │
│  │  github_pim_owners          │      │  Entra ID PIM               │       │
│  │  (security group)           │◄─────│  (user activates role)      │       │
│  ├─────────────────────────────┤      └─────────────────────────────┘       │
│  │ user1 (active PIM)          │                                            │
│  │ user2 (active PIM)          │                                            │
│  └─────────────────────────────┘                                            │
└────────────────────────────────────────┬────────────────────────────────────┘
                                         │
                                         │  sync.py --mode pim-owners
                                         │  (runs continuously, 30s interval)
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         GITHUB ORGANIZATION                                 │
│                                                                             │
│  OWNERS (role=admin):                  WHITELIST (never remove):            │
│  ┌─────────────────────────────┐       ┌─────────────────────────────┐      │
│  │ user1_gh (from PIM)         │       │ break-glass-admin           │      │
│  │ user2_gh (from PIM)         │       │ service-account             │      │
│  │ break-glass-admin           │       └─────────────────────────────┘      │
│  └─────────────────────────────┘                                            │
│                                                                             │
│  MEMBERS (role=member):                                                     │
│  ┌─────────────────────────────┐                                            │
│  │ user3_gh (regular member)   │                                            │
│  │ user4_gh (PIM expired)      │  ← demoted from owner to member            │
│  └─────────────────────────────┘                                            │
└─────────────────────────────────────────────────────────────────────────────┘
```

## User Workflow

1. User needs owner privileges on GitHub
2. Activates PIM role in Entra ID (e.g., "GitHub Owner")
3. PIM adds user to `github_pim_owners` group
4. Within 30 seconds, sync.py detects the change
5. User is promoted to GitHub Organization Owner
6. **User receives email notification about the promotion**
7. After PIM expires, user is removed from the group
8. Within 30 seconds, user is demoted back to member
9. **User receives email notification about the demotion**

## New CLI Arguments

```bash
# Existing full synchronization (unchanged)
python sync.py

# New mode: Fast PIM owner synchronization
python sync.py --mode pim-owners

# Continuous run with interval (for deployment)
python sync.py --mode pim-owners --continuous --interval 30
```

## New Environment Variables

```bash
# PIM Owner sync configuration
PIM_OWNERS_GROUP=github_pim_owners              # Entra ID group for PIM owners
PIM_OWNERS_WHITELIST=break-glass-admin,svc-github  # Never remove from owners
PIM_SYNC_INTERVAL=30                            # Default interval in seconds

# User notification (reuses existing ALERT_EMAIL_URL)
PIM_NOTIFY_USERS=true                           # Send email to users on role change
```

## Synchronization Logic

```python
def sync_pim_owners():
    # 1. Get members of Entra ID group github_pim_owners (includes email!)
    pim_members = get_entra_group_members(PIM_OWNERS_GROUP)
    # pim_members contains: {github_username, email, display_name}

    # 2. Get current GitHub owners
    current_owners = get_github_org_owners()

    # 3. Whitelist - never remove
    whitelist = set(PIM_OWNERS_WHITELIST.split(','))

    # 4. Target owner state = PIM members + whitelist
    pim_github_logins = {m['github_username'] for m in pim_members}
    target_owners = pim_github_logins | whitelist

    # 5. Promote new owners (change role member → admin)
    for member in pim_members:
        login = member['github_username']
        if login not in current_owners and is_org_member(login):
            set_org_membership(login, role='admin')
            notify_user(member['email'], 'promoted', member['display_name'])

    # 6. Demote owners no longer in PIM (except whitelist)
    for login in current_owners - pim_github_logins - whitelist:
        set_org_membership(login, role='member')
        # Reverse lookup: find Entra ID user by GitHub username (postalCode)
        user_info = lookup_entra_user_by_github_login(login)
        if user_info:
            notify_user(user_info['email'], 'demoted', user_info['display_name'])
```

## GitHub API

To change organization member role:

```
PUT /orgs/{org}/memberships/{username}
{
  "role": "admin"  // or "member"
}
```

To list organization owners:

```
GET /orgs/{org}/members?role=admin
```

**GitHub App permissions**: Existing `Organization: Members - Read and write` is sufficient.

> **Verified**: GitHub docs confirm these endpoints require "Members" organization permissions:
> - List members with role filter: Members (read)
> - Set membership role: Members (write)
>
> Source: [GitHub REST API - Organization Members](https://docs.github.com/en/rest/orgs/members)

## Entra ID Data

The existing `AzureADGroupMembers` class already fetches user details. We need to ensure we get the email:

```python
# Current select fields (sync.py:135)
select = ['id', 'displayName', 'postalCode']

# Need to add:
select = ['id', 'displayName', 'postalCode', 'mail', 'userPrincipalName']
```

User email will be available as `mail` or fallback to `userPrincipalName`.

## Entra ID Reverse Lookup

For demotions, we need to find the user's email by their GitHub username. This requires a new method in `AzureADGroupMembers`:

```python
async def get_user_by_github_login(self, github_login: str):
    """
    Find Entra ID user by GitHub username (stored in postalCode).

    :param github_login: GitHub username to search for
    :return: User details dict or None
    """
    if not self.client:
        await self.authenticate()

    query_params = UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
        filter=f"postalCode eq '{github_login}'",
        select=['id', 'displayName', 'mail', 'userPrincipalName', 'postalCode'],
        top=1,
    )
    request_configuration = UsersRequestBuilder.UsersRequestBuilderGetRequestConfiguration(
        query_parameters=query_params,
    )
    request_configuration.headers.add("ConsistencyLevel", "eventual")
    response = await self.client.users.get(request_configuration=request_configuration)

    if response and response.value:
        user = response.value[0]
        return {
            'id': user.id,
            'display_name': user.display_name,
            'email': user.mail or user.user_principal_name,
            'github_username': user.postal_code,
        }
    return None
```

**Note**: This requires `User.Read.All` permission on the Entra ID app (should already be configured for the existing sync).

**SECURITY**: Input must be sanitized before use in OData filter:

```python
def sanitize_odata_string(value: str) -> str:
    """Escape special characters for OData filter."""
    # Escape single quotes by doubling them
    return value.replace("'", "''")
```

## User Notification

When a user's owner status changes, send them an email:

**Promotion email:**
```
Subject: GitHub Owner Access Granted

Hi {display_name},

You have been granted Owner access to the GitHub organization {org_name}.

This access was activated through Entra ID PIM.

Remember: This access will be automatically revoked when your PIM session expires.
```

**Demotion email:**
```
Subject: GitHub Owner Access Revoked

Hi {display_name},

Your Owner access to the GitHub organization {org_name} has been revoked.

You are now a regular member of the organization.

If you need Owner access again, please activate it through Entra ID PIM.
```

## Deployment (Docker Compose)

Add a new service for PIM sync:

```yaml
services:
  # Existing full sync (runs periodically via cron or separate scheduler)
  sync:
    build: .
    env_file: .env
    command: python sync.py

  # New PIM owner sync (runs continuously)
  pim-sync:
    build: .
    env_file: .env
    command: python sync.py --mode pim-owners --continuous --interval 30
    restart: always
```

## Fail-safe Behavior

**IMPORTANT**: On any error reading data:
- DO NOT make any changes (do not remove owners)
- Log the error
- Send alert email
- Continue to next cycle

This ensures that temporary API issues don't accidentally revoke owner access.

## Security Requirements

### 1. Input Sanitization
All user-controlled input (GitHub usernames) must be sanitized before use in:
- OData filters (Entra ID queries)
- GitHub API calls
- Log messages (prevent log injection)

### 2. Minimum Owner Count
**CRITICAL**: Never reduce owner count below 1. Before any demotion:
```python
if len(current_owners) - len(owners_to_demote) < 1:
    raise SecurityError("Cannot demote: would leave org with 0 owners")
```

### 3. Empty PIM Group Protection
If PIM group returns 0 members, treat as **error** (not "demote all"):
```python
if len(pim_members) == 0:
    logging.error("PIM group returned 0 members - treating as API error")
    return  # Do nothing, continue to next cycle
```

### 4. Audit Logging
All owner changes must be logged with:
- Timestamp (ISO 8601)
- Action (promoted/demoted)
- GitHub username
- Entra ID user (if available)
- Trigger (PIM sync)

```python
logging.info(f"AUDIT: action=promoted user={login} entra_id={user_id} trigger=pim_sync")
```

### 5. Graceful Shutdown
Handle SIGTERM for clean Docker stop:
```python
import signal
shutdown_requested = False

def handle_sigterm(signum, frame):
    global shutdown_requested
    shutdown_requested = True
    logging.info("Shutdown requested, finishing current cycle...")

signal.signal(signal.SIGTERM, handle_sigterm)
```

### 6. Health Check Endpoint (Optional)
For Docker health checks, write last successful sync timestamp to file:
```python
# After successful sync cycle
with open('/tmp/healthcheck', 'w') as f:
    f.write(str(int(time.time())))
```

Docker healthcheck:
```yaml
healthcheck:
  test: ["CMD", "sh", "-c", "[ $(($(date +%s) - $(cat /tmp/healthcheck))) -lt 120 ]"]
  interval: 60s
  timeout: 5s
  retries: 3
```

## Risks and Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| Break-glass account compromised | Attacker has permanent owner access | Audit log, credential rotation, monitor usage |
| Entra ID API unavailable | Cannot verify PIM state | Fail-safe: don't remove owners on error |
| GitHub API unavailable | Changes don't apply | Retry logic, alerting |
| Sync process crashes | Owners remain active longer | Health check, auto-restart (Docker) |
| Email notification fails | User unaware of change | Log warning, don't block sync |
| **OData injection via GitHub username** | Query manipulation | Sanitize input, escape special chars |
| **Empty PIM group (API glitch)** | Mass demotion of all owners | Treat empty result as error, require explicit empty |
| **Fail-safe exploitation** | Attacker causes errors to prevent demotion | Rate limit errors, alert on repeated failures |
| **postalCode self-modification** | Privilege escalation | Verify Entra ID permissions, restrict postalCode write |
| **No minimum owner count** | Org left without owners | Enforce minimum 1 owner always remains |

## Test Scenarios

### Functional Tests
1. [ ] User activates PIM → becomes owner within 30s
2. [ ] User deactivates PIM → demoted to member within 30s
3. [ ] Break-glass account remains owner even without PIM
4. [ ] On Entra ID outage, no changes are made
5. [ ] On GitHub API failure, retry logic kicks in
6. [ ] User outside organization with active PIM is ignored
7. [ ] User receives email on promotion
8. [ ] User receives email on demotion (reverse lookup works)
9. [ ] Email failure doesn't block the sync process
10. [ ] Reverse lookup fails gracefully (demotion still happens, just no email)

### Security Tests
11. [ ] GitHub username with special chars (`'`, `"`, `\`) doesn't break queries
12. [ ] Empty PIM group triggers error, no demotions happen
13. [ ] Cannot demote last owner (minimum 1 owner enforced)
14. [ ] Audit log contains all required fields
15. [ ] SIGTERM causes graceful shutdown after current cycle
16. [ ] Health check file updated after each successful sync

## Implementation Steps

### Phase 1: Core Implementation
1. [ ] Approve this specification
2. [ ] Add `mail`/`userPrincipalName` to Entra ID group member query
3. [ ] Add `get_user_by_github_login()` method to `AzureADGroupMembers` (reverse lookup)
4. [ ] Add `sanitize_odata_string()` helper function
5. [ ] Add `list_owners()` method to `GitHubOrgManager`
6. [ ] Add `set_member_role()` method to `GitHubOrgManager`
7. [ ] Add `notify_user()` function for email notifications

### Phase 2: CLI & Sync Logic
8. [ ] Implement `--mode pim-owners` argument
9. [ ] Implement `--continuous` mode with `--interval`
10. [ ] Add empty PIM group protection
11. [ ] Add minimum owner count protection
12. [ ] Add new environment variables

### Phase 3: Security & Operations
13. [ ] Add structured audit logging for all owner changes
14. [ ] Add SIGTERM handler for graceful shutdown
15. [ ] Add health check file writing
16. [ ] Update docker-compose.yml with healthcheck

### Phase 4: Testing & Documentation
17. [ ] Test on staging organization (all functional tests)
18. [ ] Run security tests (input sanitization, edge cases)
19. [ ] Update README.md
20. [ ] Security review sign-off

> **IMPORTANT - postalCode Security Note**
>
> The security of this entire system depends on users NOT being able to modify their own `postalCode` attribute in Entra ID. If this restriction is ever relaxed, a malicious user could:
> 1. Set their postalCode to match an existing GitHub username
> 2. Get added to `github_pim_owners` group
> 3. Gain owner access to the GitHub organization
>
> **Recommendation**: Periodically audit Entra ID permissions to ensure `postalCode` write access remains restricted to admins only.
