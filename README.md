# github - Entra ID sync

## Idea behind

For github Free plan or Team plan, you can't use SAML SSO. So you can't use Entra ID for authentication. This script will sync users from Entra ID to Github.

We are using property `postalCode` in Entra ID to store github username. This is not ideal, but it's the only way how to store this information in Entra ID.

Also we are using special group in Entra ID to sync users to Github. The group name starting with `github_` is used for this purpose. All users in special group `github_all` will be synced to Github as users - in our case the group `github_all` is dynamic group, so all users in Entra ID with special property `postalCode` and with attribute `Enabled` will be synced to Github.
Rest of groups starting with `github_` are used for teams in Github. The group name `github_all` is reserved for all users. Script simply create teams in Github and add users to these teams (based on Entra ID membership), for team name we are using group name without `github_` prefix.

## Known limitations

Script cannot manipulate with Github seats, so you need to have enough seats in Github for all users. Unfortunately, there is no official API for this.

## Configuration

For configuration you need to create `.env` file with following content:

```bash
GITHUB_TOKEN=your_github_token # Github token with admin rights
GITHUB_ORG=your_github_org # Github organization name

AZURE_TENANT_ID=your_azure_tenant_id # Entra ID tenant ID
AZURE_CLIENT_ID=your_azure_client_id # Entra ID application client ID
AZURE_CLIENT_SECRET=your_azure_client_secret # Entra ID application secret

ALERT_EMAIL_URL=your_alert_email_url # URL for sending alerts
ALERT_EMAIL_RECIPIENT=your_alert_email_recipient # Email for sending alerts
```

## How to build

```bash
docker build -t YOUR_DOCKER_IMAGE_NAME .
```

## How to use

```bash
# this command can be scheduled in cron
docker run -it --rm -v $(pwd)/.env:/app/.env -w /app YOUR_DOCKER_IMAGE_NAME python sync.py
```
