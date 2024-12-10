# GitHub - Entra ID Sync

## Overview

This script enables user synchronization from Entra ID (Azure AD) to GitHub for organizations using the **Free** or **Team** plans, which do not support SAML SSO.

Key features:
- Syncs users from Entra ID to GitHub based on specific group membership.
- Maps GitHub usernames to the `postalCode` attribute in Entra ID (a workaround due to attribute limitations).
- Dynamically manages team membership in GitHub using group names in Entra ID.

---

## Key Concepts

- **GitHub Username Mapping**:
  GitHub usernames are stored in the `postalCode` attribute of Entra ID. While not ideal, this is the only available attribute for this purpose.

- **Group-Based Synchronization**:
  - A special group in Entra ID, `github_all`, is used to sync all users to GitHub.
  - Additional groups with names starting with `github_` define GitHub teams.
    Example: A group `github_dev` in Entra ID creates a team `dev` in GitHub and syncs its members.
  - The group `github_all` is reserved for syncing all users.

- **Dynamic Membership**:
  The `github_all` group is dynamic, including all enabled Entra ID users with the `postalCode` attribute set.

---

## Known Limitations

1. **GitHub Seats**:
   The script does not handle GitHub license seat management. Ensure enough seats are available for all users.
   *Note*: GitHub does not provide an API to manage seats programmatically.

2. **Attribute Usage**:
   Storing GitHub usernames in the `postalCode` attribute is a limitation of Entra ID's available fields.

---

## Configuration

Create a `.env` file with the following content:

```bash
GITHUB_TOKEN=your_github_token          # GitHub token with admin rights
GITHUB_ORG=your_github_org              # GitHub organization name

AZURE_TENANT_ID=your_azure_tenant_id    # Entra ID tenant ID
AZURE_CLIENT_ID=your_azure_client_id    # Entra ID application client ID
AZURE_CLIENT_SECRET=your_azure_client_secret # Entra ID application secret

ALERT_EMAIL_URL=your_alert_email_url    # URL for sending email alerts
ALERT_EMAIL_RECIPIENT=your_alert_email_recipient # Email recipient for alerts
```

### Azure AD Configuration

1. **Application Registration**:
   - Register an application in Azure AD with the following permissions:
     - `User.Read` (Delegated)
     - `User.Read.All` (Application)
     - `Group.Read.All` (Application)
     - `GroupMember.Read.All` (Application)
   - Note the `client_id` and `client_secret`.

2. **Group Configuration**:
    - Create groups in Azure AD with names starting with `github_` for GitHub teams.
    - Create a group named `github_all` to sync all users. Best practice is to include all enabled users in this group - for example, by using a dynamic rule.

### GitHub Configuration

1. **Personal Access Token**:
   - Create a personal access token in GitHub with admin rights.
   - Note the token for the `.env` file.

2. **Organization Configuration**:
    - Create a GitHub organization for the users.
    - Ensure the organization has enough seats for all users.

### Email Alert Configuration

1. **REST API**:
   - Set up a REST API for sending email alerts.
   - Note the URL for the `.env` file.

2. **Email Recipient**:
    - Set the email recipient for alerts in the `.env` file.

---

## Building the Docker Image

Build the Docker image:

```bash
docker build -t YOUR_DOCKER_IMAGE_NAME .
```

---

## Usage

Run the script using Docker:

```bash
# Schedule this command in cron for periodic synchronization
docker run -it --rm -v $(pwd)/.env:/app/.env -w /app YOUR_DOCKER_IMAGE_NAME python sync.py
```

---

## Email Alert REST API

For email alerts, the script uses a REST API. Example POST request payload:

```json
{
  "recipient": "<LIST OF RECIPIENTS SEPARATED BY ;>",
  "subject": "Subject of the email",
  "body": "Body of the email"
}
```

### Example Setup:
- Azure Logic Apps with an HTTP trigger and Microsoft 365 Outlook connector for sending emails.
