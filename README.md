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

## Known limitations

- Script cannot manipulate with GitHub seats, so you need to have enough seats for all users
- No support for GitHub Enterprise (only Free/Team plans)
- User mapping relies on `postalCode` field (not ideal but works)

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
READALL_IGNORE_PREFIXES=aida-,internal- # Comma-separated prefixes to skip (case-insensitive)
```

**Note**: For the private key in environment variables, you can either:
- Include the full PEM content with newlines (as shown above)
- Or use escaped newlines: `GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"`

## How to build

```bash
docker build -t YOUR_DOCKER_IMAGE_NAME .
```

## How to use

```bash
# this command can be scheduled in cron
docker run -it --rm -v $(pwd)/.env:/app/.env -w /app YOUR_DOCKER_IMAGE_NAME python sync.py
```
