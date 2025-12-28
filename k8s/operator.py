"""
Minimal Kubernetes operator scaffold using Kopf.
This operator is a lightweight scaffold that can be extended to reconcile
Agent custom resources. To run locally for development:

pip install kopf kubernetes
kopf run k8s/operator.py

"""
import kopf
import logging

logger = logging.getLogger(__name__)

@kopf.on.startup()
def startup(logger, **kwargs):
    logger.info("Agentic-IAM operator starting up")

@kopf.on.create('agentic.example.com', 'v1', 'agents')
def on_agent_create(spec, name, namespace, **kwargs):
    logger.info(f"Agent CR created: {name} in {namespace} — spec={spec}")
    # Reconciliation logic would be implemented here (register agent, create secrets, etc.)
    return {'message': 'Agent processed'}

@kopf.on.delete('agentic.example.com', 'v1', 'agents')
def on_agent_delete(spec, name, namespace, **kwargs):
    logger.info(f"Agent CR deleted: {name} in {namespace}")
