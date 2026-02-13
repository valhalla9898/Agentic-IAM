"""
Test Data Generator for Agentic-IAM

Creates initial test agents and data for demonstration purposes.
"""

import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any


def generate_test_agents() -> List[Dict[str, Any]]:
    """Generate 10 test agents with different configurations"""
    
    agents = [
        {
            "agent_id": "agent_nlp_001",
            "name": "NLP Assistant",
            "type": "intelligent",
            "status": "active",
            "description": "Natural Language Processing Agent for text analysis",
            "capabilities": ["text_analysis", "sentiment_analysis", "entity_extraction"],
            "metadata": {
                "version": "1.0.0",
                "framework": "transformers",
                "model": "bert-base-uncased"
            }
        },
        {
            "agent_id": "agent_data_001",
            "name": "Data Processing Agent",
            "type": "processor",
            "status": "active",
            "description": "Handles data processing and transformation tasks",
            "capabilities": ["data_transform", "aggregation", "filtering"],
            "metadata": {
                "version": "2.1.0",
                "framework": "pandas",
                "max_records": "1000000"
            }
        },
        {
            "agent_id": "agent_monitoring_001",
            "name": "System Monitor",
            "type": "monitor",
            "status": "active",
            "description": "Monitors system health and performance metrics",
            "capabilities": ["health_check", "metrics", "alerts"],
            "metadata": {
                "version": "1.5.0",
                "check_interval": "60s",
                "alert_threshold": "80"
            }
        },
        {
            "agent_id": "agent_security_001",
            "name": "Security Analyzer",
            "type": "intelligent",
            "status": "active",
            "description": "Analyzes security threats and vulnerabilities",
            "capabilities": ["threat_detection", "vulnerability_scan", "anomaly_detection"],
            "metadata": {
                "version": "3.0.0",
                "detection_engine": "ml-based",
                "threat_db_version": "2024-02"
            }
        },
        {
            "agent_id": "agent_api_001",
            "name": "API Gateway Agent",
            "type": "standard",
            "status": "active",
            "description": "Manages API requests and routing",
            "capabilities": ["request_routing", "rate_limiting", "request_validation"],
            "metadata": {
                "version": "2.0.0",
                "protocols": ["http", "https", "grpc"],
                "max_requests": "10000/min"
            }
        },
        {
            "agent_id": "agent_ml_001",
            "name": "ML Model Server",
            "type": "intelligent",
            "status": "active",
            "description": "Serves machine learning models for inference",
            "capabilities": ["inference", "model_serving", "batch_prediction"],
            "metadata": {
                "version": "4.1.0",
                "framework": "tensorflow",
                "models_loaded": 5
            }
        },
        {
            "agent_id": "agent_logging_001",
            "name": "Logging Agent",
            "type": "monitor",
            "status": "active",
            "description": "Centralized logging and event tracking",
            "capabilities": ["log_aggregation", "filtering", "archival"],
            "metadata": {
                "version": "1.3.0",
                "storage": "elasticsearch",
                "retention_days": "90"
            }
        },
        {
            "agent_id": "agent_auth_001",
            "name": "Authentication Agent",
            "type": "processor",
            "status": "active",
            "description": "Handles authentication and credential management",
            "capabilities": ["auth_verify", "token_generation", "mfa"],
            "metadata": {
                "version": "2.5.0",
                "algorithms": ["jwt", "oauth2", "saml"],
                "token_ttl": "3600"
            }
        },
        {
            "agent_id": "agent_cache_001",
            "name": "Cache Manager",
            "type": "processor",
            "status": "active",
            "description": "Manages distributed caching and data synchronization",
            "capabilities": ["caching", "invalidation", "sync"],
            "metadata": {
                "version": "2.8.0",
                "backend": "redis",
                "max_size": "100GB"
            }
        },
        {
            "agent_id": "agent_report_001",
            "name": "Report Generator",
            "type": "intelligent",
            "status": "active",
            "description": "Generates comprehensive reports and analytics",
            "capabilities": ["report_generation", "analytics", "visualization"],
            "metadata": {
                "version": "3.2.0",
                "formats": ["pdf", "excel", "html"],
                "templates": 25
            }
        }
    ]
    
    return agents


def add_test_agents_to_db(db_instance):
    """Add test agents to database"""
    agents = generate_test_agents()
    added_count = 0
    
    for agent in agents:
        try:
            success = db_instance.add_agent(
                agent_id=agent['agent_id'],
                name=agent['name'],
                agent_type=agent['type'],
                metadata={
                    'description': agent['description'],
                    'capabilities': agent['capabilities'],
                    'metadata': agent['metadata'],
                    'created_at': datetime.utcnow().isoformat(),
                    'status': agent['status']
                }
            )
            if success:
                added_count += 1
                print(f"✅ Added agent: {agent['name']} ({agent['agent_id']})")
            else:
                print(f"⚠️ Agent already exists: {agent['agent_id']}")
        except Exception as e:
            print(f"❌ Error adding agent {agent['agent_id']}: {e}")
    
    return added_count


__all__ = ['generate_test_agents', 'add_test_agents_to_db']
