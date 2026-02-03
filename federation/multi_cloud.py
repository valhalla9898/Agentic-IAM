# Multi-Cloud Identity Federation

This module provides support for federated identity across multiple cloud providers.

## Supported Providers
- AWS IAM
- Azure Active Directory
- Google Cloud Identity

## Features
- Cross-cloud authentication
- Unified identity management
- Decentralized identity (DID) support
- Verifiable credentials integration

## Usage
```python
from federation.multi_cloud import MultiCloudFederator

federator = MultiCloudFederator()
federator.authenticate_agent(agent_id, cloud_provider='aws')
```