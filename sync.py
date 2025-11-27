import requests
import asyncio
import os
import time
import jwt
from azure.identity.aio import ClientSecretCredential
from msgraph import GraphServiceClient
from msgraph.generated.groups.groups_request_builder import GroupsRequestBuilder
from dotenv import load_dotenv
import logging

# log format with timestamp 
LOGLEVEL = os.environ.get('LOGLEVEL', 'INFO').upper()
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=LOGLEVEL)

# Suppress logging for specific modules
logging.getLogger('azure.identity').setLevel(logging.WARNING)
logging.getLogger('msgraph').setLevel(logging.WARNING)
logging.getLogger('msgraph.generated.groups').setLevel(logging.WARNING)
# Suppress HTTP request/response logs
logging.getLogger('azure.core.pipeline.policies.http_logging_policy').setLevel(logging.WARNING)
logging.getLogger('azure.identity.aio').setLevel(logging.WARNING)

# Load environment variables from a .env file
load_dotenv()


def get_github_app_token(app_id: str, installation_id: str, private_key: str) -> str:
    """
    Generate an installation access token for a GitHub App.

    :param app_id: GitHub App ID
    :param installation_id: Installation ID of the App in the organization
    :param private_key: Private key (PEM format) for the GitHub App
    :return: Installation access token (valid for 1 hour)
    """
    # Create JWT for GitHub App authentication
    now = int(time.time())
    payload = {
        'iat': now - 60,  # Issued at (60s in past for clock skew)
        'exp': now + 540,  # Expires in 9 minutes (max 10 min)
        'iss': app_id
    }

    # Sign JWT with private key
    app_jwt = jwt.encode(payload, private_key, algorithm='RS256')

    # Exchange JWT for installation access token
    headers = {
        'Authorization': f'Bearer {app_jwt}',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28'
    }

    response = requests.post(
        f'https://api.github.com/app/installations/{installation_id}/access_tokens',
        headers=headers
    )

    if response.status_code == 201:
        token_data = response.json()
        logging.debug(f'GitHub App token obtained, expires at: {token_data.get("expires_at")}')
        return token_data['token']
    else:
        raise Exception(f'Error getting GitHub App token: {response.status_code} - {response.text}')

class AzureADGroupMembers:
    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        """
        Initialize the AzureADGroupMembers class with Azure AD credentials.

        :param tenant_id: Azure AD Tenant ID
        :param client_id: Azure AD Application (Client) ID
        :param client_secret: Azure AD Application Client Secret
        """
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.client = None

    async def authenticate(self):
        """
        Authenticates the service principal and initializes the GraphServiceClient.
        """
        credential = ClientSecretCredential(
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            client_secret=self.client_secret
        )
        self.client = GraphServiceClient(credential, scopes=['https://graph.microsoft.com/.default'])

    async def list_group_members_by_id(self, group_id: str):
        """
        Lists all effective members of the specified Azure AD group.

        :param group_id: The ID of the Azure AD group
        :return: A list of dictionaries containing member details
        """
        if not self.client:
            await self.authenticate()

        members = []
        query_params = GroupsRequestBuilder.GroupsRequestBuilderGetQueryParameters(
            select = ['id', 'displayName', 'postalCode'],
        )
        request_configuration = GroupsRequestBuilder.GroupsRequestBuilderGetRequestConfiguration(
            query_parameters = query_params,
        )
        request_configuration.headers.add("ConsistencyLevel", "eventual")
        result_page = await self.client.groups.by_group_id(group_id).transitive_members.get(
            request_configuration = request_configuration
        )

        while result_page:
            members.extend(result_page.value)
            # Check for the presence of @odata.nextLink in additional_data
            next_link = result_page.odata_next_link
            if next_link:
                # Fetch the next page of results
                result_page = await self.client.groups.by_group_id(group_id).transitive_members.with_url(next_link).get()
            else:
                # No more pages available
                break

        member_details = [
            {
                'id': member.id,
                'display_name': member.display_name,
                'type': member.odata_type,
                'github_username': member.postal_code,
            }
            for member in members
        ]

        return member_details

    async def get_group_members(self, group_name: str):
        """
        Gets the members of an Azure AD group by name.

        :param group_name: The name of the Azure AD group
        :return: A list of dictionaries containing member details
        """
        if not self.client:
            await self.authenticate()

        normalized_group_name = group_name.replace("'", "''")
        query_params = GroupsRequestBuilder.GroupsRequestBuilderGetQueryParameters(
    		filter = f"displayName eq '{group_name}'",
    		count = True,
    		top = 1,
    		orderby = ["displayName"],
        )
        request_configuration = GroupsRequestBuilder.GroupsRequestBuilderGetRequestConfiguration(
            query_parameters = query_params,
        )
        request_configuration.headers.add("ConsistencyLevel", "eventual")
        response = await self.client.groups.get(request_configuration = request_configuration)

        if response and response.value:
                group_id = response.value[0].id
                return await self.list_group_members_by_id(group_id)
        else:
            logging.debug(f"No group found with the name '{group_name}'")
            return None

    async def list_groups(self, group_name_prefix:str):
        """
        Gets the groups in Azure AD that match the specified prefix.

        :param group_name_prefix: The prefix of the group name
        :return: A list of dictionaries containing group details
        """
        if not self.client:
            await self.authenticate()

        groups = []
        normalized_group_name_prefix = group_name_prefix.replace("'", "''")
        query_params = GroupsRequestBuilder.GroupsRequestBuilderGetQueryParameters(
    		filter = f"startswith(displayName, '{group_name_prefix}')",
        )
        request_configuration = GroupsRequestBuilder.GroupsRequestBuilderGetRequestConfiguration(
            query_parameters = query_params,
        )
        request_configuration.headers.add("ConsistencyLevel", "eventual")
        result_page = await self.client.groups.get(request_configuration = request_configuration)

        while result_page:
            groups.extend(result_page.value)
            # Check for the presence of @odata.nextLink in additional_data
            next_link = result_page.odata_next_link
            if next_link:
                # Fetch the next page of results
                result_page = await self.client.groups.with_url(next_link).get()
            else:
                # No more pages available
                break

        group_details = [
            {
                'id': group.id,
                'display_name': group.display_name,
                'type': group.odata_type,
            }
            for group in groups
        ]

        return group_details

class GitHubOrgManager:
    def __init__(self, token, org_name):
        """
        Initialize the GitHubOrgManager with a personal access token and organization name.

        :param token: Personal Access Token with appropriate scopes.
        :param org_name: Name of the GitHub organization.
        """
        self.token = token
        self.org_name = org_name
        self.headers = {
            'Authorization': f'Bearer {self.token}',
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28'
        }
        self.base_url = f'https://api.github.com/orgs/{self.org_name}'

    def list_users_full(self):
        """
        List all active members in the organization, handling pagination.

        :return: List of usernames.
        """
        url = f'{self.base_url}/members'
        members = []
        page = 1
        per_page = 100  # Maximum allowed per page

        while True:
            params = {'per_page': per_page, 'page': page}
            response = requests.get(url, headers=self.headers, params=params)
            if response.status_code == 200:
                page_members = response.json()
                if not page_members:
                    break
                members.extend(page_members)
                page += 1
            else:
                raise Exception(f'Error listing users: {response.status_code} - {response.text}')

        return members

    def list_users(self):
        members = self.list_users_full()
        return [member['login'] for member in members]

    def invite_user(self, username):
        """
        Invite a user to the organization.

        :param username: GitHub username of the user to invite.
        """
        url = f'{self.base_url}/invitations'
        data = {'invitee_id': self.get_user_id(username)}
        response = requests.post(url, headers=self.headers, json=data)
        if response.status_code == 201:
            logging.debug(f'Invitation sent to {username}.')
        else:
            raise Exception(f'Error inviting user: {response.status_code} - {response.text}')

    def remove_user(self, username):
        """
        Remove a user from the organization.

        :param username: GitHub username of the user to remove.
        """
        url = f'{self.base_url}/members/{username}'
        response = requests.delete(url, headers=self.headers)
        if response.status_code == 204:
            logging.debug(f'{username} removed from the organization.')
        else:
            raise Exception(f'Error removing user: {response.status_code} - {response.text}')

    def list_teams(self):
        """
        List all teams in the organization.

        :return: List of team slugs.
        """
        url = f'{self.base_url}/teams'
        teams = []
        page = 1
        per_page = 100
        
        while True:
            params = {'per_page': per_page, 'page': page}
            response = requests.get(url, headers=self.headers, params=params)
            if response.status_code == 200:
                page_teams = response.json()
                if not page_teams:
                    break
                teams.extend(page_teams)
                page += 1
            else:
                raise Exception(f'Error listing teams: {response.status_code} - {response.text}')
        
        return [team['slug'] for team in teams]

    def create_team(self, team_name):
        """
        Create a new team in the organization.

        :param team_name: Name of the team.
        """
        url = f'{self.base_url}/teams'
        data = {'name': team_name}
        response = requests.post(url, headers=self.headers, json=data)
        if response.status_code == 201:
            logging.debug(f'Team {team_name} created.')
        else:
            raise Exception(f'Error creating team: {response.status_code} - {response.text}')

    def get_team_members(self, team_slug):
        """
        List all members of a team.

        :param team_slug: Slug of the team.
        :return: List of usernames.
        """
        url = f'{self.base_url}/teams/{team_slug}/members'
        members = []
        page = 1
        per_page = 100  # Maximum allowed per page

        while True:
            params = {'per_page': per_page, 'page': page}
            response = requests.get(url, headers=self.headers, params=params)
            if response.status_code == 200:
                page_members = response.json()
                if not page_members:
                    break
                members.extend(page_members)
                page += 1
            else:
                raise Exception(f'Error listing team members: {response.status_code} - {response.text}')

        return [member['login'] for member in members]

    def add_user_to_team(self, team_slug, username):
        """
        Add a user to a team.

        :param team_slug: Slug of the team.
        :param username: GitHub username of the user to add.
        """
        url = f'{self.base_url}/teams/{team_slug}/memberships/{username}'
        response = requests.put(url, headers=self.headers)
        if response.status_code == 200:
            logging.debug(f'{username} added to team {team_slug}.')
        else:
            raise Exception(f'Error adding user to team: {response.status_code} - {response.text}')

    def remove_user_from_team(self, team_slug, username):
        """
        Remove a user from a team.

        :param team_slug: Slug of the team.
        :param username: GitHub username of the user to remove.
        """
        url = f'{self.base_url}/teams/{team_slug}/memberships/{username}'
        response = requests.delete(url, headers=self.headers)
        if response.status_code == 204:
            logging.debug(f'{username} removed from team {team_slug}.')
        else:
            raise Exception(f'Error removing user from team: {response.status_code} - {response.text}')

    def get_pending_invitations(self):
        """
        Retrieve all pending invitations for the organization, handling pagination.

        :return: List of pending invitations.
        """
        url = f'{self.base_url}/invitations'
        invitations = []
        page = 1
        per_page = 100  # Maximum allowed per page

        while True:
            params = {'per_page': per_page, 'page': page}
            response = requests.get(url, headers=self.headers, params=params)
            if response.status_code == 200:
                page_invitations = response.json()
                if not page_invitations:
                    break
                invitations.extend(page_invitations)
                page += 1
            else:
                raise Exception(f'Error retrieving invitations: {response.status_code} - {response.text}')

        return invitations

    def get_seat_usage(self):
        """
        Approximate the number of seats in use by counting active members and pending invitations.

        :return: Dictionary with counts of active members, pending invitations, and total seats in use.
        """
        active_members = self.list_users()
        pending_invitations = self.get_pending_invitations()
        total_seats_in_use = len(active_members) + len(pending_invitations)

        return {
            'active_members_count': len(active_members),
            'pending_invitations_count': len(pending_invitations),
            'total_seats_in_use': total_seats_in_use
        }

    def get_billing_info(self):
        """
        Retrieve billing information for the organization, including total seats and used seats.

        :return: Dictionary with billing information.
        """
        url = f'{self.base_url}/billing'
        response = requests.get(url, headers=self.headers)
        if response.status_code == 200:
            billing_info = response.json()
            return {
                'total_seats': billing_info.get('total_seats', 0),
                'used_seats': billing_info.get('used_seats', 0),
                'billing_amount': billing_info.get('billing_amount', 0)
            }
        else:
            raise Exception(f'Error retrieving billing information: {response.status_code} - {response.text}')

    def get_copilot_seat_info(self):
        """
        Retrieve GitHub Copilot seat information.

        :return: Dictionary with total seats and seats in use.
        """
        url = f'{self.base_url}/copilot/billing'
        response = requests.get(url, headers=self.headers)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f'Error retrieving Copilot seat info: {response.status_code} - {response.text}')

    def assign_copilot_seat(self, username):
        """
        Assign a GitHub Copilot seat to a user.

        :param username: GitHub username of the user to assign.
        """
        url = f'{self.base_url}/copilot/billing/selected_users/{username}'
        response = requests.put(url, headers=self.headers)
        if response.status_code == 204:
            logging.debug(f'Copilot seat assigned to {username}.')
        else:
            raise Exception(f'Error assigning Copilot seat: {response.status_code} - {response.text}')

    def unassign_copilot_seat(self, username):
        """
        Unassign a GitHub Copilot seat from a user.

        :param username: GitHub username of the user to unassign.
        """
        url = f'{self.base_url}/copilot/billing/selected_users/{username}'
        response = requests.delete(url, headers=self.headers)
        if response.status_code == 204:
            logging.debug(f'Copilot seat unassigned from {username}.')
        else:
            raise Exception(f'Error unassigning Copilot seat: {response.status_code} - {response.text}')

    def get_user_id(self, username):
        """
        Retrieve the user ID for a given username.

        :param username: GitHub username.
        :return: User ID.
        """
        url = f'https://api.github.com/users/{username}'
        response = requests.get(url, headers=self.headers)
        if response.status_code == 200:
            user_info = response.json()
            return user_info['id']
        else:
            raise Exception(f'Error retrieving user ID: {response.status_code} - {response.text}')

    def get_organization(self):
        """
        Retrieve information about the organization.

        :return: Dictionary with organization information.
        """
        url = f'{self.base_url}'
        response = requests.get(url, headers=self.headers)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f'Error retrieving organization information: {response.status_code} - {response.text}')

    def list_repos(self):
        """
        List all non-archived repositories in the organization.

        :return: List of repository names.
        """
        url = f'{self.base_url}/repos'
        repos = []
        page = 1
        per_page = 100

        while True:
            params = {'per_page': per_page, 'page': page, 'type': 'all', 'sort': 'full_name', 'direction': 'asc'}
            response = requests.get(url, headers=self.headers, params=params)
            if response.status_code == 200:
                page_repos = response.json()
                if not page_repos:
                    break
                # Filter out archived repos
                repos.extend([repo['name'] for repo in page_repos if not repo.get('archived', False)])
                page += 1
            else:
                raise Exception(f'Error listing repos: {response.status_code} - {response.text}')

        return repos

    def set_team_repo_permission(self, team_slug, repo_name, permission='pull'):
        """
        Set team permission on a repository.

        :param team_slug: Slug of the team.
        :param repo_name: Name of the repository.
        :param permission: Permission level (pull, push, admin, maintain, triage).
        """
        url = f'{self.base_url}/teams/{team_slug}/repos/{self.org_name}/{repo_name}'
        data = {'permission': permission}
        response = requests.put(url, headers=self.headers, json=data)
        if response.status_code in [200, 204]:
            logging.debug(f'Team {team_slug} granted {permission} on {repo_name}.')
        else:
            raise Exception(f'Error setting team permission: {response.status_code} - {response.text}')

def remove_prefix(text, prefix):
    if text.startswith(prefix):
        return text[len(prefix):]
    return text


def should_skip_repo(repo_name: str, ignore_repos: list, ignore_prefixes: list) -> bool:
    """
    Check if a repository should be skipped based on ignore lists.

    :param repo_name: Name of the repository.
    :param ignore_repos: List of exact repo names to ignore.
    :param ignore_prefixes: List of prefixes to ignore (case-insensitive).
    :return: True if repo should be skipped.
    """
    # Check exact match
    if repo_name in ignore_repos:
        return True
    # Check prefixes (case-insensitive)
    repo_lower = repo_name.lower()
    for prefix in ignore_prefixes:
        if repo_lower.startswith(prefix.lower()):
            return True
    return False

async def sync():
    logging.info("SYNC")

    gh_prefix = 'github_'  # prefix for AAD groups
    gh_all_group = f'{gh_prefix}all'  # name of the group with all users
    
    error_log = []
    
    # Generate GitHub token from GitHub App
    github_token = get_github_app_token(
        app_id=os.getenv('GITHUB_APP_ID'),
        installation_id=os.getenv('GITHUB_APP_INSTALLATION_ID'),
        private_key=os.getenv('GITHUB_APP_PRIVATE_KEY')
    )
    gh = GitHubOrgManager(github_token, os.getenv('GITHUB_ORG'))
    aad = AzureADGroupMembers(
        tenant_id=os.getenv('AZURE_TENANT_ID'),
        client_id=os.getenv('AZURE_CLIENT_ID'),
        client_secret=os.getenv('AZURE_CLIENT_SECRET'),
    )

    gh_users = []
    try:
        gh_users = gh.list_users()
    except Exception as e:
        error_log.append(f'Error listing GitHub users: {e}')
    logging.info('GH users: %s', gh_users)    
    
    aad_users = []
    try:
        aad_users = await aad.get_group_members(gh_all_group)
    except Exception as e:
        error_log.append(f'Error listing AAD users: {e}')
    logging.info('AAD users: %s', aad_users)
    
    # gh users or aad users are empty, raise an error and skip the rest of the script
    if not gh_users or not aad_users:
        error_log.append('No users found in GitHub or Azure AD.')
        return error_log
        
    aad_gh_users = [user['github_username'] for user in aad_users]
    logging.info('AAD GH users: %s', aad_gh_users)

    gh_users_to_delete = [user for user in gh_users if user not in aad_gh_users]
    gh_users_to_add = [user for user in aad_gh_users if user not in gh_users]
    logging.info('GH users to remove: %s', gh_users_to_delete)
    
    # deleting users from github
    for user in gh_users_to_delete:
        try:
            gh.remove_user(user)
        except Exception as e:
            error_log.append(f'Error removing user {user} from GitHub: {e}')
            
    logging.info('GH users to add: %s', gh_users_to_add)
    # inviting users to github
    for user in gh_users_to_add:
        try:
            gh.invite_user(user)
        except Exception as e:
            error_log.append(f'Error inviting user {user} to GitHub: {e}')
    
    # teams
    try:
        gh_teams = gh.list_teams()
    except Exception as e:
        error_log.append(f'Error listing GitHub teams: {e}')
        return error_log
    logging.info('GH teams: %s', gh_teams)

    # process AAD groups
    try:
        aad_gh_groups = await aad.list_groups(gh_prefix)
    except Exception as e:
        error_log.append(f'Error listing AAD groups: {e}')
        return error_log
    logging.info('AAD GH groups: %s', aad_gh_groups)

    for tmp_group in aad_gh_groups:
        group_id = tmp_group['id']
        # aad group members
        try:
            aad_group_members = await aad.list_group_members_by_id(group_id)
            tmp_aad_gh_group_members = [user['github_username'] for user in aad_group_members]
            # filter out users that are not in aad_gh_users
            aad_gh_group_members = [user for user in tmp_aad_gh_group_members if user in aad_gh_users]
            logging.info(f'AAD GH group {tmp_group["display_name"]} members: %s', aad_gh_group_members)
            # gh team members
            gh_team_slug = remove_prefix(tmp_group["display_name"], gh_prefix)
            # check if team in gh_teams exists, if not, create it
            if gh_team_slug.lower() not in [team.lower() for team in gh_teams]:
                logging.info(f'GH team {gh_team_slug} does not exist, creating it...')
                gh.create_team(gh_team_slug)
            # get members of the team        
            gh_team_members = gh.get_team_members(gh_team_slug)
            logging.info(f'GH team {gh_team_slug} members: %s', gh_team_members)
            # users to add
            users_to_add = [user for user in aad_gh_group_members if user not in gh_team_members]
            logging.info(f'Users to add to GH team {gh_team_slug}: %s', users_to_add)
            # add users to team
            for user in users_to_add:
                try:
                    gh.add_user_to_team(gh_team_slug, user)
                except Exception as e:
                    error_log.append(f'Error adding user {user} to GH team {gh_team_slug}: {e}')
            # users to remove
            users_to_remove = [user for user in gh_team_members if user not in aad_gh_group_members]
            logging.info(f'Users to remove from GH team {gh_team_slug}: %s', users_to_remove)
            # remove users from team
            for user in users_to_remove:
                try:
                    gh.remove_user_from_team(gh_team_slug, user)
                except Exception as e:
                    error_log.append(f'Error removing user {user} from GH team {gh_team_slug}: {e}')
        except Exception as e:
            error_log.append(f'Error processing AAD group {tmp_group["display_name"]}: {e}')

    # Sync team "all" read permissions on all repos
    readall_team = os.getenv('READALL_TEAM', 'all')
    ignore_repos_str = os.getenv('READALL_IGNORE_REPOS', '')
    ignore_prefixes_str = os.getenv('READALL_IGNORE_PREFIXES', '')

    # Parse ignore lists (comma-separated)
    ignore_repos = [r.strip() for r in ignore_repos_str.split(',') if r.strip()]
    ignore_prefixes = [p.strip() for p in ignore_prefixes_str.split(',') if p.strip()]

    logging.info(f'Syncing read permissions for team "{readall_team}"')
    logging.info(f'Ignore repos: {ignore_repos}')
    logging.info(f'Ignore prefixes: {ignore_prefixes}')

    try:
        all_repos = gh.list_repos()
        logging.info(f'Found {len(all_repos)} non-archived repos')

        for repo in all_repos:
            if should_skip_repo(repo, ignore_repos, ignore_prefixes):
                logging.debug(f'Skipping repo {repo} (ignored)')
                continue
            try:
                gh.set_team_repo_permission(readall_team, repo, 'pull')
                logging.debug(f'Set pull permission for team {readall_team} on {repo}')
            except Exception as e:
                error_log.append(f'Error setting permission on repo {repo}: {e}')
    except Exception as e:
        error_log.append(f'Error syncing read permissions: {e}')

    return error_log


def send_email(errors):
    url = os.getenv('ALERT_EMAIL_URL')
    body = "<h3>Errors:</h3>"
    for err in errors:
        body += f"<p>{err}</p>"
    data = {
        "recipient": os.getenv('ALERT_EMAIL_RECIPIENT'),
        "subject": "GITHUB Sync errors",
        "body": body
    }
    logging.warning(f"Sending email with errors to {data['recipient']}")
    response = requests.post(url, json=data)

async def main():
    err_log = await sync()
    if err_log:
        logging.error('Errors:')
        for err in err_log:
            logging.error(err)
        send_email(err_log)
    else:
        logging.info('Sync completed successfully.')

asyncio.run(main())
