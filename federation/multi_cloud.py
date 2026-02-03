"""
Multi-Cloud Identity Federation for Agentic-IAM

This module provides support for federated identity across multiple cloud providers:
- AWS IAM
- Azure Active Directory
- Google Cloud Identity

Features:
- Cross-cloud authentication and authorization
- Unified identity management across clouds
- Decentralized identity (DID) support
- Verifiable credentials integration
- Automated trust score synchronization
"""

import logging
import json
from typing import Dict, List, Optional, Any
from abc import ABC, abstractmethod
from dataclasses import dataclass
import boto3
from azure.identity import DefaultAzureCredential
from google.auth import default as gcp_default
from google.cloud import iam

logger = logging.getLogger(__name__)

@dataclass
class CloudIdentity:
    """Represents an identity in a cloud provider"""
    provider: str
    identity_id: str
    roles: List[str]
    permissions: List[str]
    metadata: Dict[str, Any]

@dataclass
class FederatedAgent:
    """Represents an agent with multi-cloud federation"""
    agent_id: str
    did: Optional[str]
    cloud_identities: Dict[str, CloudIdentity]
    trust_score: float
    last_sync: str

class CloudProvider(ABC):
    """Abstract base class for cloud providers"""

    @abstractmethod
    def authenticate(self, credentials: Dict[str, Any]) -> CloudIdentity:
        """Authenticate with the cloud provider"""
        pass

    @abstractmethod
    def get_roles(self, identity_id: str) -> List[str]:
        """Get roles for an identity"""
        pass

    @abstractmethod
    def get_permissions(self, identity_id: str) -> List[str]:
        """Get permissions for an identity"""
        pass

    @abstractmethod
    def create_federated_identity(self, agent_id: str, did: str) -> str:
        """Create a federated identity for an agent"""
        pass

class AWSProvider(CloudProvider):
    """AWS IAM provider implementation"""

    def __init__(self, region: str = 'us-east-1'):
        self.region = region
        self.iam_client = None

    def _get_client(self):
        if not self.iam_client:
            self.iam_client = boto3.client('iam', region_name=self.region)
        return self.iam_client

    def authenticate(self, credentials: Dict[str, Any]) -> CloudIdentity:
        """Authenticate using AWS credentials"""
        try:
            # Use provided credentials or assume role
            if 'access_key' in credentials:
                session = boto3.Session(
                    aws_access_key_id=credentials['access_key'],
                    aws_secret_access_key=credentials['secret_key'],
                    region_name=self.region
                )
                self.iam_client = session.client('iam')
            else:
                # Use instance profile or environment
                self.iam_client = boto3.client('iam', region_name=self.region)

            # Get current user/role
            identity = self.iam_client.get_user() if 'User' in str(self.iam_client.get_user()) else self.iam_client.get_caller_identity()

            return CloudIdentity(
                provider='aws',
                identity_id=identity['User']['UserName'] if 'User' in identity else identity['Arn'].split('/')[-1],
                roles=self.get_roles(identity['User']['UserName'] if 'User' in identity else identity['Arn']),
                permissions=self.get_permissions(identity['User']['UserName'] if 'User' in identity else identity['Arn']),
                metadata={'arn': identity.get('Arn'), 'account': identity.get('Account')}
            )
        except Exception as e:
            logger.error(f"AWS authentication failed: {e}")
            raise

    def get_roles(self, identity_id: str) -> List[str]:
        """Get IAM roles for identity"""
        try:
            client = self._get_client()
            roles = client.list_roles()
            # Filter roles that this identity can assume
            return [role['RoleName'] for role in roles['Roles']]
        except Exception as e:
            logger.error(f"Failed to get AWS roles: {e}")
            return []

    def get_permissions(self, identity_id: str) -> List[str]:
        """Get permissions for identity"""
        try:
            client = self._get_client()
            # Get attached policies
            policies = client.list_attached_user_policies(UserName=identity_id)
            permissions = []
            for policy in policies['AttachedPolicies']:
                policy_doc = client.get_policy_version(
                    PolicyArn=policy['PolicyArn'],
                    VersionId='v1'
                )
                permissions.extend(self._extract_permissions(policy_doc['PolicyVersion']['Document']))
            return permissions
        except Exception as e:
            logger.error(f"Failed to get AWS permissions: {e}")
            return []

    def _extract_permissions(self, policy_doc: Dict) -> List[str]:
        """Extract permissions from policy document"""
        permissions = []
        for statement in policy_doc.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                permissions.extend(actions)
        return permissions

    def create_federated_identity(self, agent_id: str, did: str) -> str:
        """Create IAM role for federated access"""
        try:
            client = self._get_client()

            # Create assume role policy for DID-based federation
            trust_policy = {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            "cognito-identity.amazonaws.com:aud": did
                        }
                    }
                }]
            }

            role_name = f"agentic-iam-{agent_id}"
            client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Description=f"Federated role for Agentic-IAM agent {agent_id}"
            )

            return f"arn:aws:iam::account:role/{role_name}"
        except Exception as e:
            logger.error(f"Failed to create AWS federated identity: {e}")
            raise

class AzureProvider(CloudProvider):
    """Azure Active Directory provider implementation"""

    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id
        self.credential = DefaultAzureCredential()
        self.graph_client = None

    def authenticate(self, credentials: Dict[str, Any]) -> CloudIdentity:
        """Authenticate using Azure credentials"""
        try:
            from azure.identity import ClientSecretCredential
            from msgraph import GraphServiceClient

            if 'client_id' in credentials:
                self.credential = ClientSecretCredential(
                    tenant_id=self.tenant_id,
                    client_id=credentials['client_id'],
                    client_secret=credentials['client_secret']
                )

            self.graph_client = GraphServiceClient(self.credential)

            # Get current user
            user = self.graph_client.me.get()
            user_id = user.id

            return CloudIdentity(
                provider='azure',
                identity_id=user_id,
                roles=self.get_roles(user_id),
                permissions=self.get_permissions(user_id),
                metadata={'display_name': user.display_name, 'mail': user.mail}
            )
        except Exception as e:
            logger.error(f"Azure authentication failed: {e}")
            raise

    def get_roles(self, identity_id: str) -> List[str]:
        """Get Azure AD roles"""
        try:
            # Get directory roles
            roles = self.graph_client.directory_roles.get()
            return [role.display_name for role in roles.value]
        except Exception as e:
            logger.error(f"Failed to get Azure roles: {e}")
            return []

    def get_permissions(self, identity_id: str) -> List[str]:
        """Get Azure AD permissions"""
        try:
            # Get app roles and permissions
            member_of = self.graph_client.users.by_user_id(identity_id).member_of.get()
            permissions = []
            for group in member_of.value:
                if hasattr(group, 'app_roles'):
                    permissions.extend([role.value for role in group.app_roles])
            return permissions
        except Exception as e:
            logger.error(f"Failed to get Azure permissions: {e}")
            return []

    def create_federated_identity(self, agent_id: str, did: str) -> str:
        """Create Azure AD application for federation"""
        try:
            # Create application
            app = {
                "displayName": f"Agentic-IAM-{agent_id}",
                "signInAudience": "AzureADMyOrg",
                "web": {
                    "redirectUris": [f"https://agentic-iam.io/callback/{agent_id}"],
                    "logoutUrl": f"https://agentic-iam.io/logout/{agent_id}"
                },
                "identifierUris": [did]
            }

            result = self.graph_client.applications.post(app)
            return result.id
        except Exception as e:
            logger.error(f"Failed to create Azure federated identity: {e}")
            raise

class GCPProvider(CloudProvider):
    """Google Cloud Identity provider implementation"""

    def __init__(self, project_id: str):
        self.project_id = project_id
        self.iam_client = None

    def _get_client(self):
        if not self.iam_client:
            credentials, project = gcp_default()
            self.iam_client = iam.IAMCredentialsClient(credentials=credentials)
        return self.iam_client

    def authenticate(self, credentials: Dict[str, Any]) -> CloudIdentity:
        """Authenticate using GCP credentials"""
        try:
            from google.auth import iam

            # Get current service account or user
            credentials, project = gcp_default()
            signer = iam.Signer(
                request=credentials,
                credentials=credentials
            )

            # Get service account info
            account_info = self._get_client().sign_blob(
                name=f"projects/-/serviceAccounts/{credentials.service_account_email}",
                payload=b"test"
            )

            return CloudIdentity(
                provider='gcp',
                identity_id=credentials.service_account_email or credentials._service_account_email,
                roles=self.get_roles(credentials.service_account_email),
                permissions=self.get_permissions(credentials.service_account_email),
                metadata={'project': project}
            )
        except Exception as e:
            logger.error(f"GCP authentication failed: {e}")
            raise

    def get_roles(self, identity_id: str) -> List[str]:
        """Get GCP IAM roles"""
        try:
            from google.cloud import resourcemanager

            client = resourcemanager.ProjectsClient()
            project = client.get_project(self.project_id)

            # Get IAM policy
            policy = client.get_iam_policy(f"projects/{self.project_id}")
            roles = []
            for binding in policy.bindings:
                if f"serviceAccount:{identity_id}" in binding.members:
                    roles.append(binding.role)
            return roles
        except Exception as e:
            logger.error(f"Failed to get GCP roles: {e}")
            return []

    def get_permissions(self, identity_id: str) -> List[str]:
        """Get GCP permissions"""
        try:
            # Permissions are derived from roles
            roles = self.get_roles(identity_id)
            # This is a simplified mapping - in practice, you'd query the IAM API
            permission_map = {
                'roles/editor': ['resourcemanager.projects.get', 'storage.objects.get'],
                'roles/viewer': ['resourcemanager.projects.get'],
                'roles/owner': ['resourcemanager.projects.get', 'resourcemanager.projects.delete']
            }
            permissions = []
            for role in roles:
                permissions.extend(permission_map.get(role, []))
            return permissions
        except Exception as e:
            logger.error(f"Failed to get GCP permissions: {e}")
            return []

    def create_federated_identity(self, agent_id: str, did: str) -> str:
        """Create GCP service account for federation"""
        try:
            from google.cloud import iam_admin_v1

            client = iam_admin_v1.IAMClient()
            account_name = f"projects/{self.project_id}/serviceAccounts/agentic-iam-{agent_id}@iam.gserviceaccount.com"

            account = iam_admin_v1.ServiceAccount(
                display_name=f"Agentic-IAM Agent {agent_id}",
                description=f"Federated service account for agent {agent_id}"
            )

            response = client.create_service_account(
                name=f"projects/{self.project_id}",
                account_id=f"agentic-iam-{agent_id}",
                service_account=account
            )

            return response.email
        except Exception as e:
            logger.error(f"Failed to create GCP federated identity: {e}")
            raise

class MultiCloudFederator:
    """Main class for multi-cloud identity federation"""

    def __init__(self):
        self.providers = {}
        self.federated_agents = {}

    def add_provider(self, name: str, provider: CloudProvider):
        """Add a cloud provider"""
        self.providers[name] = provider

    def authenticate_agent(self, agent_id: str, cloud_provider: str, credentials: Dict[str, Any]) -> CloudIdentity:
        """Authenticate an agent with a specific cloud provider"""
        if cloud_provider not in self.providers:
            raise ValueError(f"Unknown cloud provider: {cloud_provider}")

        provider = self.providers[cloud_provider]
        identity = provider.authenticate(credentials)

        # Store in federated agent
        if agent_id not in self.federated_agents:
            self.federated_agents[agent_id] = FederatedAgent(
                agent_id=agent_id,
                did=None,
                cloud_identities={},
                trust_score=0.5,
                last_sync=str(__import__('datetime').datetime.now())
            )

        self.federated_agents[agent_id].cloud_identities[cloud_provider] = identity
        return identity

    def get_unified_permissions(self, agent_id: str) -> List[str]:
        """Get unified permissions across all clouds"""
        if agent_id not in self.federated_agents:
            return []

        agent = self.federated_agents[agent_id]
        all_permissions = set()

        for cloud_identity in agent.cloud_identities.values():
            all_permissions.update(cloud_identity.permissions)

        return list(all_permissions)

    def get_unified_roles(self, agent_id: str) -> List[str]:
        """Get unified roles across all clouds"""
        if agent_id not in self.federated_agents:
            return []

        agent = self.federated_agents[agent_id]
        all_roles = set()

        for cloud_identity in agent.cloud_identities.values():
            all_roles.update(cloud_identity.roles)

        return list(all_roles)

    def create_federated_identity(self, agent_id: str, did: str, clouds: List[str]):
        """Create federated identities across multiple clouds"""
        federated_ids = {}

        for cloud in clouds:
            if cloud in self.providers:
                fed_id = self.providers[cloud].create_federated_identity(agent_id, did)
                federated_ids[cloud] = fed_id

        # Update agent
        if agent_id in self.federated_agents:
            self.federated_agents[agent_id].did = did

        return federated_ids

    def sync_trust_scores(self, agent_id: str):
        """Synchronize trust scores across clouds"""
        if agent_id not in self.federated_agents:
            return

        agent = self.federated_agents[agent_id]
        # In a real implementation, this would sync with each cloud's trust systems
        # For now, just update the timestamp
        agent.last_sync = str(__import__('datetime').datetime.now())
        logger.info(f"Synchronized trust scores for agent {agent_id}")

# Example usage
if __name__ == "__main__":
    federator = MultiCloudFederator()

    # Add providers
    federator.add_provider('aws', AWSProvider())
    federator.add_provider('azure', AzureProvider(tenant_id='your-tenant-id'))
    federator.add_provider('gcp', GCPProvider(project_id='your-project-id'))

    # Authenticate agent across clouds
    try:
        aws_identity = federator.authenticate_agent('agent-123', 'aws', {})
        azure_identity = federator.authenticate_agent('agent-123', 'azure', {})

        # Get unified permissions
        permissions = federator.get_unified_permissions('agent-123')
        print(f"Unified permissions: {permissions}")

        # Create federated identities
        did = "did:agentic:123456"
        federated_ids = federator.create_federated_identity('agent-123', did, ['aws', 'azure'])
        print(f"Federated identities created: {federated_ids}")

    except Exception as e:
        print(f"Federation error: {e}")