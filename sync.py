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


class GitHubAppTokenManager:
    """
    Manages GitHub App installation tokens with automatic refresh.
    Tokens are valid for 1 hour, but we refresh 5 minutes before expiry.
    """
    TOKEN_REFRESH_MARGIN = 300  # Refresh 5 minutes before expiry

    def __init__(self, app_id: str, installation_id: str, private_key: str):
        self.app_id = app_id
        self.installation_id = installation_id
        self.private_key = private_key
        self.token = None
        self.token_expires_at = 0

    def _fetch_token(self) -> tuple[str, int]:
        """
        Fetch a new installation access token from GitHub.

        :return: Tuple of (token, expires_at_timestamp)
        """
        # Create JWT for GitHub App authentication
        now = int(time.time())
        payload = {
            'iat': now - 60,  # Issued at (60s in past for clock skew)
            'exp': now + 540,  # Expires in 9 minutes (max 10 min)
            'iss': self.app_id
        }

        # Sign JWT with private key
        app_jwt = jwt.encode(payload, self.private_key, algorithm='RS256')

        # Exchange JWT for installation access token
        headers = {
            'Authorization': f'Bearer {app_jwt}',
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28'
        }

        response = requests.post(
            f'https://api.github.com/app/installations/{self.installation_id}/access_tokens',
            headers=headers
        )

        if response.status_code == 201:
            token_data = response.json()
            # Parse expires_at (ISO format: 2024-01-01T12:00:00Z)
            expires_at_str = token_data.get('expires_at', '')
            if expires_at_str:
                from datetime import datetime
                expires_at = int(datetime.fromisoformat(expires_at_str.replace('Z', '+00:00')).timestamp())
            else:
                # Fallback: assume 1 hour from now
                expires_at = now + 3600
            logging.debug(f'GitHub App token obtained, expires at: {expires_at_str}')
            return token_data['token'], expires_at
        else:
            raise Exception(f'Error getting GitHub App token: {response.status_code} - {response.text}')

    def get_token(self) -> str:
        """
        Get a valid token, refreshing if necessary.

        :return: Valid installation access token
        """
        now = int(time.time())
        if self.token is None or now >= (self.token_expires_at - self.TOKEN_REFRESH_MARGIN):
            logging.info('Refreshing GitHub App token...')
            self.token, self.token_expires_at = self._fetch_token()
        return self.token

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
            if member.odata_type == '#microsoft.graph.user'
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
    # Rate limiting configuration
    MAX_RETRIES = 5
    BASE_SLEEP = 2  # seconds
    PAUSE_MUTATION = 0.5  # pause between write operations
    SAFETY_MARGIN = 5  # if remaining <= margin, wait for reset

    def __init__(self, token_manager: GitHubAppTokenManager, org_name: str):
        """
        Initialize the GitHubOrgManager with a token manager and organization name.

        :param token_manager: GitHubAppTokenManager instance for automatic token refresh.
        :param org_name: Name of the GitHub organization.
        """
        self.token_manager = token_manager
        self.org_name = org_name
        self.base_url = f'https://api.github.com/orgs/{self.org_name}'

    def _get_headers(self):
        """Get headers with fresh token."""
        return {
            'Authorization': f'Bearer {self.token_manager.get_token()}',
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28'
        }

    def _handle_rate_limit(self, response):
        """
        Check rate limit headers and wait if necessary.
        """
        remaining = response.headers.get('X-RateLimit-Remaining')
        reset_time = response.headers.get('X-RateLimit-Reset')

        if remaining is not None and int(remaining) <= self.SAFETY_MARGIN:
            if reset_time:
                wait_time = int(reset_time) - int(time.time()) + 1
                if wait_time > 0:
                    logging.warning(f'Rate limit low (remaining={remaining}), waiting {wait_time}s until reset')
                    time.sleep(wait_time)

    def _request_with_retry(self, method, url, **kwargs):
        """
        Make HTTP request with retry logic for rate limits and server errors.

        :param method: HTTP method (get, post, put, delete)
        :param url: Request URL
        :param kwargs: Additional arguments for requests
        :return: Response object
        """
        for attempt in range(1, self.MAX_RETRIES + 1):
            # Get fresh headers (with potentially refreshed token) for each attempt
            response = getattr(requests, method)(url, headers=self._get_headers(), **kwargs)

            # Check rate limit headers proactively
            self._handle_rate_limit(response)

            # Success
            if response.status_code in [200, 201, 202, 204]:
                return response

            # Rate limit hit (GitHub uses both 403 and 429)
            if response.status_code in [403, 429]:
                retry_after = response.headers.get('Retry-After')
                remaining = response.headers.get('X-RateLimit-Remaining')
                reset_time = response.headers.get('X-RateLimit-Reset')

                # Secondary rate limit with Retry-After header
                if retry_after:
                    wait_time = int(retry_after)
                    logging.warning(f'Rate limit (HTTP {response.status_code}), Retry-After={wait_time}s, attempt {attempt}/{self.MAX_RETRIES}')
                    time.sleep(wait_time)
                    continue

                # Primary rate limit exhausted
                if remaining is not None and int(remaining) == 0 and reset_time:
                    wait_time = int(reset_time) - int(time.time()) + 1
                    if wait_time > 0:
                        logging.warning(f'Rate limit exhausted (HTTP {response.status_code}), waiting {wait_time}s until reset, attempt {attempt}/{self.MAX_RETRIES}')
                        time.sleep(wait_time)
                        continue

                # Secondary rate limit without headers - exponential backoff
                backoff = self.BASE_SLEEP * (2 ** (attempt - 1))
                logging.warning(f'Probable secondary rate limit (HTTP {response.status_code}), backoff {backoff}s, attempt {attempt}/{self.MAX_RETRIES}')
                time.sleep(backoff)
                continue

            # Server errors - exponential backoff
            if 500 <= response.status_code < 600:
                backoff = self.BASE_SLEEP * (2 ** (attempt - 1))
                logging.warning(f'Server error (HTTP {response.status_code}), backoff {backoff}s, attempt {attempt}/{self.MAX_RETRIES}')
                time.sleep(backoff)
                continue

            # 401 Unauthorized - token might have expired, force refresh and retry
            if response.status_code == 401:
                logging.warning(f'Unauthorized (HTTP 401), forcing token refresh, attempt {attempt}/{self.MAX_RETRIES}')
                # Force token refresh by resetting expiry
                self.token_manager.token_expires_at = 0
                time.sleep(self.BASE_SLEEP)
                continue

            # Other errors - don't retry
            break

        return response

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
            response = self._request_with_retry('get', url, params=params)
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
        response = self._request_with_retry('post', url, json=data)
        if response.status_code == 201:
            logging.debug(f'Invitation sent to {username}.')
        else:
            raise Exception(f'Error inviting user: {response.status_code} - {response.text}')
        time.sleep(self.PAUSE_MUTATION)  # Pause between mutations

    def remove_user(self, username):
        """
        Remove a user from the organization.

        :param username: GitHub username of the user to remove.
        """
        url = f'{self.base_url}/members/{username}'
        response = self._request_with_retry('delete', url)
        if response.status_code == 204:
            logging.debug(f'{username} removed from the organization.')
        else:
            raise Exception(f'Error removing user: {response.status_code} - {response.text}')
        time.sleep(self.PAUSE_MUTATION)  # Pause between mutations

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
            response = self._request_with_retry('get', url, params=params)
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
        response = self._request_with_retry('post', url, json=data)
        if response.status_code == 201:
            logging.debug(f'Team {team_name} created.')
        else:
            raise Exception(f'Error creating team: {response.status_code} - {response.text}')
        time.sleep(self.PAUSE_MUTATION)  # Pause between mutations

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
            response = self._request_with_retry('get', url, params=params)
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
        response = self._request_with_retry('put', url)
        if response.status_code == 200:
            logging.debug(f'{username} added to team {team_slug}.')
        else:
            raise Exception(f'Error adding user to team: {response.status_code} - {response.text}')
        time.sleep(self.PAUSE_MUTATION)  # Pause between mutations

    def remove_user_from_team(self, team_slug, username):
        """
        Remove a user from a team.

        :param team_slug: Slug of the team.
        :param username: GitHub username of the user to remove.
        """
        url = f'{self.base_url}/teams/{team_slug}/memberships/{username}'
        response = self._request_with_retry('delete', url)
        if response.status_code == 204:
            logging.debug(f'{username} removed from team {team_slug}.')
        else:
            raise Exception(f'Error removing user from team: {response.status_code} - {response.text}')
        time.sleep(self.PAUSE_MUTATION)  # Pause between mutations

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
            response = self._request_with_retry('get', url, params=params)
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
        response = self._request_with_retry('get', url)
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
        response = self._request_with_retry('get', url)
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
        response = self._request_with_retry('put', url)
        if response.status_code == 204:
            logging.debug(f'Copilot seat assigned to {username}.')
        else:
            raise Exception(f'Error assigning Copilot seat: {response.status_code} - {response.text}')
        time.sleep(self.PAUSE_MUTATION)  # Pause between mutations

    def unassign_copilot_seat(self, username):
        """
        Unassign a GitHub Copilot seat from a user.

        :param username: GitHub username of the user to unassign.
        """
        url = f'{self.base_url}/copilot/billing/selected_users/{username}'
        response = self._request_with_retry('delete', url)
        if response.status_code == 204:
            logging.debug(f'Copilot seat unassigned from {username}.')
        else:
            raise Exception(f'Error unassigning Copilot seat: {response.status_code} - {response.text}')
        time.sleep(self.PAUSE_MUTATION)  # Pause between mutations

    def get_user_id(self, username):
        """
        Retrieve the user ID for a given username.

        :param username: GitHub username.
        :return: User ID.
        """
        url = f'https://api.github.com/users/{username}'
        response = self._request_with_retry('get', url)
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
        response = self._request_with_retry('get', url)
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
            response = self._request_with_retry('get', url, params=params)
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
        response = self._request_with_retry('put', url, json=data)
        if response.status_code in [200, 204]:
            logging.debug(f'Team {team_slug} granted {permission} on {repo_name}.')
        else:
            raise Exception(f'Error setting team permission: {response.status_code} - {response.text}')
        time.sleep(self.PAUSE_MUTATION)  # Pause between mutations

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
    
    # Create token manager for automatic token refresh
    token_manager = GitHubAppTokenManager(
        app_id=os.getenv('GITHUB_APP_ID'),
        installation_id=os.getenv('GITHUB_APP_INSTALLATION_ID'),
        private_key=os.getenv('GITHUB_APP_PRIVATE_KEY')
    )
    gh = GitHubOrgManager(token_manager, os.getenv('GITHUB_ORG'))
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
                logging.info(f'Skipping repo {repo} (ignored)')
                continue
            try:
                gh.set_team_repo_permission(readall_team, repo, 'pull')
                logging.info(f'Set pull permission for team {readall_team} on {repo}')
            except Exception as e:
                error_log.append(f'Error setting permission on repo {repo}: {e}')
        logging.info('Read permissions synced successfully.')
    except Exception as e:
        error_log.append(f'Error syncing read permissions: {e}')

    logging.info('Sync completed with %d errors.', len(error_log))

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
