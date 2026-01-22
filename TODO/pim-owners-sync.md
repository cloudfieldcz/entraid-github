# PIM Owner Sync - Feature Specification

## Problem Statement

GitHub Team license doesn't have native PIM (Privileged Identity Management) like Azure/Entra ID. We need a mechanism that enables:

- Temporary elevation of users to **GitHub Organization Owner**
- Activation via Entra ID PIM (existing mechanism)
- Fast synchronization (every 30 seconds)
- Safety mechanisms (break-glass account protection, stateful tracking)

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
│                           SYNC PROCESS                                      │
│  ┌─────────────────────────────┐                                            │
│  │  SQLite: promoted_owners    │  ← Tracks users WE promoted                │
│  ├─────────────────────────────┤                                            │
│  │ user1_gh (promoted by us)   │                                            │
│  │ user2_gh (promoted by us)   │                                            │
│  └─────────────────────────────┘                                            │
│                                                                             │
│  Logic: Only demote users in our DB that are no longer in PIM group         │
└────────────────────────────────────────┬────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         GITHUB ORGANIZATION                                 │
│                                                                             │
│  OWNERS (role=admin):                  NEVER TOUCHED (not in our DB):       │
│  ┌─────────────────────────────┐       ┌─────────────────────────────┐      │
│  │ user1_gh (from PIM)         │       │ break-glass-admin           │      │
│  │ user2_gh (from PIM)         │       │ service-account             │      │
│  │ break-glass-admin           │       │ manual-owner                │      │
│  │ service-account             │       └─────────────────────────────┘      │
│  └─────────────────────────────┘                                            │
│                                                                             │
│  MEMBERS (role=member):                                                     │
│  ┌─────────────────────────────┐                                            │
│  │ user3_gh (regular member)   │                                            │
│  │ user4_gh (PIM expired)      │  ← demoted because was in our DB           │
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
PIM_SYNC_INTERVAL=30                            # Default interval in seconds
PIM_STATE_FILE=/data/pim_state.db               # SQLite file for tracking promoted users

# User notification (reuses existing ALERT_EMAIL_URL)
PIM_NOTIFY_USERS=true                           # Send email to users on role change
```

> **Note**: `PIM_OWNERS_WHITELIST` is no longer needed - the stateful approach provides implicit protection for all users we didn't promote.

## Synchronization Logic

### Stateful Approach (Recommended)

Instead of comparing PIM group vs all GitHub owners, we track which users **we promoted**. This provides:
- **Implicit whitelist safety** - We never touch users we didn't promote (break-glass, service accounts)
- **No reverse lookup needed** - User info stored on promotion
- **Fewer API calls** - Only check users we're tracking
- **Config typo protection** - Misconfigured whitelist can't cause accidental demotions

```python
# SQLite schema
CREATE TABLE promoted_owners (
    github_login TEXT PRIMARY KEY,
    entra_id TEXT,
    email TEXT,
    display_name TEXT,
    promoted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

def sync_pim_owners():
    # 1. Get members of Entra ID group github_pim_owners
    pim_members = get_entra_group_members(PIM_OWNERS_GROUP)
    pim_logins = {m['github_username'] for m in pim_members}

    # 2. Get users WE have promoted (from local DB)
    our_promoted = get_promoted_owners_from_db()
    our_promoted_logins = {u['github_login'] for u in our_promoted}

    # 3. Promote: users in PIM but not yet promoted by us
    for member in pim_members:
        login = member['github_username']
        if login not in our_promoted_logins and is_org_member(login):
            set_org_membership(login, role='admin')
            save_to_db(login, member)  # Store for later demote
            notify_user(member['email'], 'promoted', member['display_name'])

    # 4. Demote: users WE promoted who are no longer in PIM
    to_demote = [u for u in our_promoted if u['github_login'] not in pim_logins]

    # Safety check: ensure we don't remove last owner
    if to_demote:
        current_owners = get_github_org_owners()
        if len(current_owners) - len(to_demote) < 1:
            raise SecurityError("Would leave org with 0 owners")

    for user in to_demote:
        set_org_membership(user['github_login'], role='member')
        remove_from_db(user['github_login'])
        notify_user(user['email'], 'demoted', user['display_name'])
```

### Key Principle

> **We only demote users that we promoted.**
>
> This means:
> - Break-glass accounts are never touched (we didn't promote them)
> - Service accounts are never touched (we didn't promote them)
> - Manual owner assignments are never touched
> - Whitelist config errors cannot cause accidental demotions

## GitHub API

To change organization member role:

```
PUT /orgs/{org}/memberships/{username}
{
  "role": "admin"  // or "member"
}
```

To list organization owners (used for minimum owner count check):

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

## State Storage (SQLite)

The sync process maintains a local SQLite database to track users it has promoted:

```python
import sqlite3

def init_db(db_path: str):
    conn = sqlite3.connect(db_path)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS promoted_owners (
            github_login TEXT PRIMARY KEY,
            entra_id TEXT,
            email TEXT,
            display_name TEXT,
            promoted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    return conn

def save_promoted_user(conn, github_login, entra_id, email, display_name):
    conn.execute('''
        INSERT OR REPLACE INTO promoted_owners
        (github_login, entra_id, email, display_name, promoted_at)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    ''', (github_login, entra_id, email, display_name))
    conn.commit()

def get_promoted_users(conn):
    cursor = conn.execute('SELECT * FROM promoted_owners')
    return [dict(zip(['github_login', 'entra_id', 'email', 'display_name', 'promoted_at'], row))
            for row in cursor.fetchall()]

def remove_promoted_user(conn, github_login):
    conn.execute('DELETE FROM promoted_owners WHERE github_login = ?', (github_login,))
    conn.commit()
```

### Recovery from DB Loss

If the SQLite file is lost/corrupted:
- **No automatic demotions occur** (we don't know who we promoted)
- All currently promoted users remain owners until manually resolved
- Alert is sent to admin
- Admin must either:
  1. Restore from backup
  2. Manually recreate the DB from current PIM group members
  3. Let users' PIM expire naturally (they stay owners until next promotion cycle re-adds them to DB)

```python
def handle_db_error():
    logging.critical("ALERT: PIM state database unavailable - no demotions will occur")
    send_alert_email("PIM state database error - manual intervention required")
    # Continue running but skip demote logic until DB is restored
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

Add a new service for PIM sync with persistent volume for SQLite:

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
    volumes:
      - pim-data:/data  # Persistent storage for SQLite state

volumes:
  pim-data:
    # Consider using named volume with backup strategy
```

> **Important**: The SQLite database must be persisted. Loss of this file means we lose track of who we promoted, which disables demote functionality until resolved.

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
**CRITICAL**: Never reduce owner count below 1. Before demoting, check GitHub:
```python
# Get current owner count from GitHub
current_owners = get_github_org_owners()  # GET /orgs/{org}/members?role=admin
owners_to_demote = [u for u in our_promoted if u['github_login'] not in pim_logins]

if len(current_owners) - len(owners_to_demote) < 1:
    logging.error("Cannot demote: would leave org with 0 owners")
    send_alert_email("PIM sync blocked - would remove last owner")
    return  # Skip demotions this cycle
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
| Entra ID API unavailable | Cannot verify PIM state | Fail-safe: don't demote on error |
| GitHub API unavailable | Changes don't apply | Retry logic, alerting |
| Sync process crashes | Owners remain active longer | Health check, auto-restart (Docker) |
| Email notification fails | User unaware of change | Log warning, don't block sync |
| **Empty PIM group (API glitch)** | Could demote all tracked users | Treat empty result as error |
| **SQLite DB lost/corrupted** | Cannot demote anyone | Alert admin, manual intervention, backups |
| **postalCode self-modification** | Privilege escalation | Verify Entra ID permissions, restrict postalCode write |

### Risks Eliminated by Stateful Approach

| Previous Risk | Why No Longer Applicable |
|---------------|--------------------------|
| Whitelist config typo | No whitelist needed - we only demote who we promoted |
| OData injection (reverse lookup) | No reverse lookup needed - user data stored on promote |
| Accidental break-glass demotion | Impossible - we never promoted them |
| Mass owner demotion | Can only demote users in our DB |

## Test Scenarios

### Functional Tests
1. [ ] User activates PIM → becomes owner within 30s, recorded in DB
2. [ ] User deactivates PIM → demoted to member within 30s, removed from DB
3. [ ] Break-glass account remains owner (never in our DB)
4. [ ] Manual owner assignment is not affected by sync
5. [ ] On Entra ID outage, no changes are made
6. [ ] On GitHub API failure, retry logic kicks in
7. [ ] User outside organization with active PIM is ignored
8. [ ] User receives email on promotion
9. [ ] User receives email on demotion
10. [ ] Email failure doesn't block the sync process

### Stateful Logic Tests
11. [ ] Promoted user is correctly stored in SQLite
12. [ ] Demoted user is correctly removed from SQLite
13. [ ] Restart preserves DB state (volume persistence)
14. [ ] DB corruption triggers alert, no demotions occur
15. [ ] DB recovery: manual re-seed from current PIM group works

### Security Tests
16. [ ] Empty PIM group triggers error, no demotions happen
17. [ ] Users not in our DB are never demoted (implicit whitelist)
18. [ ] Minimum owner count enforced (cannot demote last owner)
19. [ ] Audit log contains all required fields
20. [ ] SIGTERM causes graceful shutdown after current cycle
21. [ ] Health check file updated after each successful sync

## Implementation Steps

### Phase 1: Core Implementation
1. [ ] Approve this specification
2. [ ] Add `mail`/`userPrincipalName` to Entra ID group member query
3. [ ] Add SQLite state management (init, save, get, remove)
4. [ ] Add `list_owners()` method to `GitHubOrgManager` (for minimum owner check)
5. [ ] Add `set_member_role()` method to `GitHubOrgManager`
6. [ ] Add `notify_user()` function for email notifications

### Phase 2: CLI & Sync Logic
7. [ ] Implement `--mode pim-owners` argument
8. [ ] Implement `--continuous` mode with `--interval`
9. [ ] Implement stateful promote/demote logic
10. [ ] Add empty PIM group protection
11. [ ] Add minimum owner count protection
12. [ ] Add DB error handling (fail-safe on DB unavailable)
13. [ ] Add new environment variables

### Phase 3: Security & Operations
14. [ ] Add structured audit logging for all owner changes
15. [ ] Add SIGTERM handler for graceful shutdown
16. [ ] Add health check file writing
17. [ ] Update docker-compose.yml with healthcheck and volume

### Phase 4: Testing & Documentation
18. [ ] Test on staging organization (all functional tests)
19. [ ] Run security tests (DB loss scenario, edge cases)
20. [ ] Update README.md
21. [ ] Security review sign-off

> **IMPORTANT - postalCode Security Note**
>
> The security of this entire system depends on users NOT being able to modify their own `postalCode` attribute in Entra ID. If this restriction is ever relaxed, a malicious user could:
> 1. Set their postalCode to match an existing GitHub username
> 2. Get added to `github_pim_owners` group
> 3. Gain owner access to the GitHub organization
>
> **Recommendation**: Periodically audit Entra ID permissions to ensure `postalCode` write access remains restricted to admins only.
