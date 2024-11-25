import requests
import asyncio
import os
import requests
from azure.identity.aio import ClientSecretCredential
from msgraph import GraphServiceClient
from msgraph.generated.groups.groups_request_builder import GroupsRequestBuilder
from dotenv import load_dotenv

# pip install azure-identity msgraph-core
# pip install msgraph-sdk azure-identity

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
            print(f"No group found with the name '{group_name}'")
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
            print(f'Invitation sent to {username}.')
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
            print(f'{username} removed from the organization.')
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
            print(f'Team {team_name} created.')
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
            print(f'{username} added to team {team_slug}.')
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
            print(f'{username} removed from team {team_slug}.')
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
            print(f'Copilot seat assigned to {username}.')
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
            print(f'Copilot seat unassigned from {username}.')
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

def remove_prefix(text, prefix):
    if text.startswith(prefix):
        return text[len(prefix):]
    return text

async def sync():
    print("SYNC")

    gh_prefix = 'github_'  # prefix for AAD groups
    gh_all_group = f'{gh_prefix}all'  # name of the group with all users

    # Load environment variables from a .env file
    load_dotenv()
    
    gh = GitHubOrgManager(os.getenv('GITHUB_TOKEN'), os.getenv('GITHUB_ORG'))
    aad = AzureADGroupMembers(
        tenant_id=os.getenv('AZURE_TENANT_ID'),
        client_id=os.getenv('AZURE_CLIENT_ID'),
        client_secret=os.getenv('AZURE_CLIENT_SECRET'),
    )

    gh_users = gh.list_users()
    aad_users = await aad.get_group_members(gh_all_group)
    aad_gh_users = [user['github_username'] for user in aad_users]
    print('GH users:', gh_users)
    print('AAD users:', aad_gh_users)

    gh_users_to_delete = [user for user in gh_users if user not in aad_gh_users]
    gh_users_to_add = [user for user in aad_gh_users if user not in gh_users]
    print('GH users to remove:', gh_users_to_delete)
    # deleting users from github
    for user in gh_users_to_delete:
        gh.remove_user(user)
    print('GH users to add:', gh_users_to_add)
    # inviting users to github
    for user in gh_users_to_add:
        gh.invite_user(user)
    
    # teams
    gh_teams = gh.list_teams()
    print('GH teams:', gh_teams)

    # process AAD groups
    aad_gh_groups = await aad.list_groups(gh_prefix)
    print('AAD GH groups:', aad_gh_groups)

    for tmp_group in aad_gh_groups:
        group_id = tmp_group['id']
        # aad group members
        aad_group_members = await aad.list_group_members_by_id(group_id)
        tmp_aad_gh_group_members = [user['github_username'] for user in aad_group_members]
        # filter out users that are not in aad_gh_users
        aad_gh_group_members = [user for user in tmp_aad_gh_group_members if user in aad_gh_users]
        print(f'AAD GH group {tmp_group["display_name"]} members:', aad_gh_group_members)
        # gh team members
        gh_team_slug = remove_prefix(tmp_group["display_name"], gh_prefix)
        # check if team in gh_teams exists, if not, create it
        if gh_team_slug.lower() not in [team.lower() for team in gh_teams]:
            print(f'GH team {gh_team_slug} does not exist, creating it...')
            gh.create_team(gh_team_slug)
        # get members of the team        
        gh_team_members = gh.get_team_members(gh_team_slug)
        print(f'GH team {gh_team_slug} members:', gh_team_members)
        # users to add
        users_to_add = [user for user in aad_gh_group_members if user not in gh_team_members]
        print(f'Users to add to GH team {gh_team_slug}:', users_to_add)
        # add users to team
        for user in users_to_add:
            gh.add_user_to_team(gh_team_slug, user)
        # users to remove
        users_to_remove = [user for user in gh_team_members if user not in aad_gh_group_members]
        print(f'Users to remove from GH team {gh_team_slug}:', users_to_remove)
        # remove users from team
        for user in users_to_remove:
            gh.remove_user_from_team(gh_team_slug, user)


asyncio.run(sync())
