from ariadne import QueryType, SubscriptionType, make_executable_schema, gql
from ariadne.asgi import GraphQL
import asyncio

# Basic GraphQL schema exposing agents and trust score
type_defs = gql("""
    type Agent {
        agent_id: String!
        status: String
        registration_date: String
        last_accessed: String
    }

    type TrustScore {
        overall_score: Float
        risk_level: String
        confidence: Float
    }

    type Query {
        agents: [Agent!]!
        agent(agent_id: String!): Agent
        trustScore(agent_id: String!): TrustScore
    }

    type Subscription {
        agentRegistered: Agent
    }
""")

query = QueryType()
subscription = SubscriptionType()

@query.field("agents")
def resolve_agents(_, info):
    iam = info.context.get("iam")
    if not iam:
        return []
    agents = iam.agent_registry.list_agents()
    result = []
    for a in agents:
        result.append({
            "agent_id": a.agent_id,
            "status": getattr(a.status, "value", "unknown"),
            "registration_date": getattr(a, "registration_date", None),
            "last_accessed": getattr(a, "last_accessed", None)
        })
    return result

@query.field("agent")
def resolve_agent(_, info, agent_id):
    iam = info.context.get("iam")
    if not iam:
        return None
    a = iam.agent_registry.get_agent(agent_id)
    if not a:
        return None
    return {
        "agent_id": a.agent_id,
        "status": getattr(a.status, "value", "unknown"),
        "registration_date": getattr(a, "registration_date", None),
        "last_accessed": getattr(a, "last_accessed", None)
    }

@query.field("trustScore")
def resolve_trust_score(_, info, agent_id):
    iam = info.context.get("iam")
    if not iam:
        return None
    # call async engine safely
    loop = asyncio.get_event_loop()
    try:
        score = loop.run_until_complete(iam.calculate_trust_score(agent_id))
    except Exception:
        score = None
    if not score:
        return None
    return {
        "overall_score": score.overall_score,
        "risk_level": getattr(score.risk_level, "value", "unknown"),
        "confidence": getattr(score, "confidence", 0.0)
    }

@subscription.source("agentRegistered")
async def agent_registered_generator(obj, info):
    # In a real implementation, this would listen to a pub/sub channel
    # For demo, just yield nothing or a mock
    yield {"agent_id": "demo-agent", "status": "active"}

@subscription.field("agentRegistered")
def agent_registered_resolver(agent, info):
    return agent

schema = make_executable_schema(type_defs, query, subscription)

# Create an ASGI GraphQL app factory that FastAPI can mount
def create_graphql_app(iam_instance=None):
    graphql = GraphQL(schema, context_value={"iam": iam_instance})
    return graphql
