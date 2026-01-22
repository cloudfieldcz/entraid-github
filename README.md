# github - Entra ID sync

## Idea behind

For GitHub Free plan or Team plan, you can't use SAML SSO. So you can't use Entra ID for authentication. This script will sync users from Entra ID to GitHub.

## How it works

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              ENTRA ID (Azure AD)                            │
│                                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐              │
│  │  github_all     │  │  github_devs    │  │  github_admins  │   ...        │
│  │  (dynamic)      │  │                 │  │                 │              │
│  ├─────────────────┤  ├─────────────────┤  ├─────────────────┤              │
│  │ user1           │  │ user1           │  │ user3           │              │
│  │ user2           │  │ user2           │  │                 │              │
│  │ user3           │  │                 │  │                 │              │
│  │ (postalCode=    │  │                 │  │                 │              │
│  │  github_login)  │  │                 │  │                 │              │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘              │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │
                                    │  sync.py
                                    │  (scheduled via cron/k8s job)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              GITHUB ORGANIZATION                            │
│                                                                             │
│  MEMBERS:                        TEAMS:                                     │
│  ┌─────────────────┐             ┌─────────────────┐  ┌─────────────────┐   │
│  │ github_login1   │             │  all            │  │  devs           │   │
│  │ github_login2   │             ├─────────────────┤  ├─────────────────┤   │
│  │ github_login3   │             │ github_login1   │  │ github_login1   │   │
│  └─────────────────┘             │ github_login2   │  │ github_login2   │   │
│                                  │ github_login3   │  └─────────────────┘   │
│  REPOSITORIES:                   └─────────────────┘                        │
│  ┌─────────────────┐                    │                                   │
│  │ repo1           │◄───────────────────┘ (pull permission)                 │
│  │ repo2           │◄───────────────────┘                                   │
│  │ repo3           │◄───────────────────┘                                   │
│  │ aida-secret     │  (ignored via READALL_IGNORE_PREFIXES)                 │
│  └─────────────────┘                                                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Sync Process

1. **User Sync**: Users in `github_all` group are synced to GitHub organization
   - Users in Entra ID but not in GitHub → invited
   - Users in GitHub but not in Entra ID → removed

2. **Team Sync**: Groups starting with `github_` are synced to GitHub teams
   - Group `github_devs` → Team `devs`
   - Group `github_admins` → Team `admins`
   - Teams are created if they don't exist

3. **Read-All Permissions**: Team specified in `READALL_TEAM` (default: `all`) gets `pull` permission on all repositories
   - Excludes archived repositories
   - Excludes repos matching `READALL_IGNORE_REPOS` or `READALL_IGNORE_PREFIXES`

### User Mapping

We use the `postalCode` property in Entra ID to store GitHub username. This is not ideal, but it's the only way to store custom information in Entra ID without additional licensing.

The `github_all` group should be a dynamic group with rule like:
```
(user.postalCode -ne null) and (user.accountEnabled -eq true)
```

## PIM Owner Sync (Privileged Identity Management)

GitHub Team license doesn't have native PIM like Azure/Entra ID. This feature enables temporary elevation of users to GitHub Organization Owner via Entra ID PIM.

### How PIM Sync Works

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

### User Workflow

1. User needs owner privileges on GitHub
2. Activates PIM role in Entra ID (e.g., "GitHub Owner")
3. PIM adds user to `github_pim_owners` group
4. Within 30 seconds, sync detects the change
5. User is promoted to GitHub Organization Owner
6. User receives email notification about the promotion
7. After PIM expires, user is removed from the group
8. Within 30 seconds, user is demoted back to member
9. User receives email notification about the demotion

### Stateful Approach - Safety by Design

Unlike traditional whitelisting, PIM sync uses a **stateful approach**:
- We track which users **we promoted** in a local SQLite database
- We **only demote users that we promoted**
- This provides implicit protection for:
  - Break-glass accounts (we never promoted them)
  - Service accounts (we never promoted them)
  - Manual owner assignments (we never promoted them)
- No whitelist configuration needed
- No risk of accidental mass demotion due to config errors

### Safety Mechanisms

1. **Minimum Owner Count**: Never reduces owner count below 1
2. **Empty PIM Group Protection**: By default, empty group is treated as error (configurable via `PIM_ALLOW_EMPTY_GROUP`)
3. **Fail-Safe on Errors**: API errors prevent any demotions
4. **Database Loss Protection**: If DB is lost, no demotions occur (alert sent)
5. **Audit Logging**: All owner changes logged with timestamp, user, and trigger

**Note on Empty Groups**: The stateful approach means break-glass accounts are always protected (they're never in our database). The empty group check protects against config errors and API issues. Set `PIM_ALLOW_EMPTY_GROUP=true` if you want to allow demoting all promoted users when the PIM group is legitimately empty.

**Extra Safety: Never-Demote Whitelist**: Use `PIM_NEVER_DEMOTE` to specify GitHub usernames that should never be demoted, even if they're in the database. This provides defense-in-depth for critical accounts like break-glass administrators. Example:
```bash
PIM_NEVER_DEMOTE=break-glass-admin,emergency-owner,svc-github-admin
```

### PIM Sync Commands

```bash
# Single run of PIM sync
python sync.py --mode pim-owners

# Continuous run with 30-second interval (default for deployment)
python sync.py --mode pim-owners --continuous --interval 30

# Custom interval (e.g., 60 seconds)
python sync.py --mode pim-owners --continuous --interval 60

# Regular full sync (unchanged)
python sync.py
```

### PIM Configuration

Add these environment variables to your `.env` file:

```bash
# PIM Owner sync configuration
PIM_OWNERS_GROUP=github_pim_owners              # Entra ID group for PIM owners
PIM_STATE_FILE=/data/pim_state.db               # SQLite file for tracking promoted users
PIM_NOTIFY_USERS=true                           # Send email to users on role change
PIM_ALLOW_EMPTY_GROUP=false                     # Allow empty PIM group (will demote all promoted users)
PIM_NEVER_DEMOTE=break-glass-admin,svc-account  # Comma-separated GitHub usernames to never demote
```

### Deployment with Docker Compose

Use the provided `docker-compose.yml`:

```bash
# Start PIM sync service (runs continuously)
docker-compose up -d pim-sync

# Run full sync once
docker-compose run --rm sync

# View PIM sync logs
docker-compose logs -f pim-sync

# Stop PIM sync
docker-compose down
```

The PIM sync service includes:
- Automatic restart on failure
- Health check monitoring (alerts if sync hasn't run in 2 minutes)
- Persistent volume for SQLite database
- Graceful shutdown handling (SIGTERM)

### IMPORTANT: postalCode Security

The security of this system depends on users **NOT** being able to modify their own `postalCode` attribute in Entra ID.

**Why this matters:**
- If a malicious user can modify their `postalCode` to match an existing GitHub username
- They could get added to `github_pim_owners` group
- And gain owner access to the organization

**Recommendation:** Periodically audit Entra ID permissions to ensure `postalCode` write access remains restricted to admins only.

## Known limitations

- Script cannot manipulate with GitHub seats, so you need to have enough seats for all users
- No support for GitHub Enterprise (only Free/Team plans)
- User mapping relies on `postalCode` field (not ideal but works)
- PIM sync requires SQLite database persistence (volume must be backed up)

## Configuration

### GitHub App Setup

This script uses a GitHub App for authentication instead of a personal access token (PAT). This provides better security with short-lived tokens (1 hour) and granular permissions.

#### Creating the GitHub App

1. Go to your organization: `https://github.com/organizations/YOUR_ORG/settings/apps`
2. Click "New GitHub App"
3. Configure the app:
   - **GitHub App name**: e.g., `entraid-sync`
   - **Homepage URL**: any valid URL
   - **Webhook**: uncheck "Active" (not needed)

4. Set **Repository permissions**:
   | Permission | Access |
   |------------|--------|
   | Administration | Read and write |
   | Metadata | Read-only |

5. Set **Organization permissions**:
   | Permission | Access |
   |------------|--------|
   | Members | Read and write |
   | Administration | Read and write |

   **Note on permissions:**
   - **Organization: Members** - invite/remove users, manage team memberships
   - **Organization: Administration** - create teams
   - **Repository: Administration** - set team permissions on repositories
   - **Repository: Metadata** - list repositories (required for repo operations)

6. Click "Create GitHub App"

7. Note the **App ID** from the app's settings page

8. Generate a **Private key**:
   - Scroll down to "Private keys" section
   - Click "Generate a private key"
   - Save the downloaded `.pem` file

9. Install the app on your organization:
   - Go to "Install App" in the left sidebar
   - Select your organization
   - Note the **Installation ID** from the URL: `https://github.com/organizations/YOUR_ORG/settings/installations/INSTALLATION_ID`

### Environment Variables

Create a `.env` file with the following content:

```bash
# GitHub App configuration
GITHUB_APP_ID=123456                    # App ID from GitHub App settings
GITHUB_APP_INSTALLATION_ID=987654       # Installation ID (from URL after installing the app)
GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
...your private key content...
-----END RSA PRIVATE KEY-----"
GITHUB_ORG=your_github_org              # Github organization name

# Entra ID configuration
AZURE_TENANT_ID=your_azure_tenant_id    # Entra ID tenant ID
AZURE_CLIENT_ID=your_azure_client_id    # Entra ID application client ID
AZURE_CLIENT_SECRET=your_azure_client_secret # Entra ID application secret

# Alerting configuration
ALERT_EMAIL_URL=your_alert_email_url    # URL for sending alerts
ALERT_EMAIL_RECIPIENT=your_alert_email_recipient # Email for sending alerts

# Read-all team permissions (optional)
READALL_TEAM=all                        # Team to grant read access (default: "all")
READALL_IGNORE_REPOS=secret-repo        # Comma-separated list of repos to skip
READALL_IGNORE_PREFIXES=secret-repo,another-private-repo # Comma-separated prefixes to skip (case-insensitive)
```

**Note**: For the private key in environment variables, you can either:
- Include the full PEM content with newlines (as shown above)
- Or use escaped newlines: `GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"`

## How to build

```bash
docker build -t YOUR_DOCKER_IMAGE_NAME .
```

## How to use

### Using Docker Compose (Recommended)

```bash
# Start PIM sync service (runs continuously in background)
docker-compose up -d pim-sync

# Run full sync once (can be scheduled via cron)
docker-compose run --rm sync

# View PIM sync logs
docker-compose logs -f pim-sync

# Stop all services
docker-compose down
```

### Using Docker directly

```bash
# Full sync (can be scheduled in cron)
docker run -it --rm -v $(pwd)/.env:/app/.env -w /app YOUR_DOCKER_IMAGE_NAME python sync.py

# PIM sync (single run)
docker run -it --rm -v $(pwd)/.env:/app/.env -v pim-data:/data -w /app YOUR_DOCKER_IMAGE_NAME python sync.py --mode pim-owners

# PIM sync (continuous)
docker run -it --rm -v $(pwd)/.env:/app/.env -v pim-data:/data -w /app YOUR_DOCKER_IMAGE_NAME python sync.py --mode pim-owners --continuous --interval 30
```
