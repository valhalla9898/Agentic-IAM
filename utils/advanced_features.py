"""
Advanced Features Module for Agentic-IAM

Provides advanced features like agent analytics, health monitoring, and reporting.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import json
import logging

logger = logging.getLogger(__name__)


class AgentHealthMonitor:
    """Monitor agent health and performance metrics"""
    
    def __init__(self, db_instance):
        """Initialize health monitor"""
        self.db = db_instance
    
    def get_agent_health(self, agent_id: str) -> Dict[str, Any]:
        """Get health status for an agent"""
        try:
            agent = self.db.get_agent(agent_id)
            if not agent:
                return {"status": "unknown", "health_score": 0}
            
            # Get recent events for this agent
            events = self.db.get_events(agent_id=agent_id, limit=20)
            
            # Calculate health based on events
            total_events = len(events)
            successful_events = len([e for e in events if e.get('status') == 'success'])
            
            if total_events == 0:
                health_score = 100
            else:
                health_score = int((successful_events / total_events) * 100)
            
            # Get sessions
            sessions = self.db.get_agent_sessions(agent_id)
            active_sessions = len([s for s in sessions if s.get('status') == 'active'])
            
            return {
                "agent_id": agent_id,
                "agent_name": agent.get('name', 'Unknown'),
                "status": agent.get('status', 'unknown'),
                "health_score": health_score,
                "recent_events": total_events,
                "active_sessions": active_sessions,
                "last_activity": events[0].get('created_at') if events else "Never",
                "uptime_percentage": 99.5  # Placeholder
            }
        except Exception as e:
            logger.error(f"Error getting agent health: {e}")
            return {"status": "error", "health_score": 0}
    
    def get_system_health(self) -> Dict[str, Any]:
        """Get overall system health"""
        try:
            agents = self.db.list_agents()
            events = self.db.get_events(limit=100)
            users = self.db.list_users()
            
            if not agents:
                return {
                    "overall_health": 100,
                    "total_agents": 0,
                    "healthy_agents": 0,
                    "total_events": 0,
                    "system_uptime": "99.9%"
                }
            
            # Calculate health scores for all agents
            health_scores = []
            for agent in agents:
                health = self.get_agent_health(agent['id'])
                health_scores.append(health.get('health_score', 50))
            
            avg_health = sum(health_scores) / len(health_scores) if health_scores else 50
            
            return {
                "overall_health": int(avg_health),
                "total_agents": len(agents),
                "healthy_agents": len([h for h in health_scores if h >= 80]),
                "total_events": len(events),
                "total_users": len(users),
                "system_uptime": "99.95%",
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Error getting system health: {e}")
            return {"overall_health": 0, "error": str(e)}


class AgentAnalytics:
    """Analyze agent activity and generate insights"""
    
    def __init__(self, db_instance):
        """Initialize analytics engine"""
        self.db = db_instance
    
    def get_agent_activity_summary(self, agent_id: str, days: int = 7) -> Dict[str, Any]:
        """Get activity summary for an agent over the last N days"""
        try:
            events = self.db.get_events(agent_id=agent_id, limit=500)
            
            # Filter events from the last N days
            cutoff_date = (datetime.utcnow() - timedelta(days=days)).isoformat()
            recent_events = [e for e in events if e.get('created_at', '') >= cutoff_date]
            
            # Count events by type
            event_types = {}
            for event in recent_events:
                event_type = event.get('event_type', 'unknown')
                event_types[event_type] = event_types.get(event_type, 0) + 1
            
            # Count successful vs failed
            successful = len([e for e in recent_events if e.get('status') == 'success'])
            failed = len([e for e in recent_events if e.get('status') != 'success'])
            
            return {
                "agent_id": agent_id,
                "period_days": days,
                "total_events": len(recent_events),
                "successful_events": successful,
                "failed_events": failed,
                "success_rate": (successful / len(recent_events) * 100) if recent_events else 0,
                "event_types": event_types,
                "most_common_event": max(event_types.items(), key=lambda x: x[1])[0] if event_types else "none"
            }
        except Exception as e:
            logger.error(f"Error getting agent activity summary: {e}")
            return {"error": str(e)}
    
    def get_system_analytics(self) -> Dict[str, Any]:
        """Get system-wide analytics"""
        try:
            agents = self.db.list_agents()
            events = self.db.get_events(limit=1000)
            
            # Count events by type
            event_stats = {}
            for event in events:
                event_type = event.get('event_type', 'unknown')
                event_stats[event_type] = event_stats.get(event_type, 0) + 1
            
            # Success rate
            successful = len([e for e in events if e.get('status') == 'success'])
            total = len(events)
            success_rate = (successful / total * 100) if total > 0 else 0
            
            # Agent statistics
            active_agents = len([a for a in agents if a.get('status') == 'active'])
            
            return {
                "total_agents": len(agents),
                "active_agents": active_agents,
                "total_events": total,
                "success_rate": success_rate,
                "event_distribution": event_stats,
                "most_active_event": max(event_stats.items(), key=lambda x: x[1])[0] if event_stats else "none",
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Error getting system analytics: {e}")
            return {"error": str(e)}
    
    def get_agent_comparison(self, agent_ids: List[str]) -> Dict[str, Any]:
        """Compare multiple agents"""
        try:
            comparison_data = []
            
            for agent_id in agent_ids:
                agent = self.db.get_agent(agent_id)
                events = self.db.get_events(agent_id=agent_id, limit=100)
                
                successful = len([e for e in events if e.get('status') == 'success'])
                success_rate = (successful / len(events) * 100) if events else 0
                
                comparison_data.append({
                    "agent_id": agent_id,
                    "agent_name": agent.get('name', 'Unknown') if agent else 'Unknown',
                    "total_events": len(events),
                    "success_rate": success_rate,
                    "status": agent.get('status', 'unknown') if agent else 'unknown'
                })
            
            return {
                "comparison": comparison_data,
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Error comparing agents: {e}")
            return {"error": str(e)}


class ReportGenerator:
    """Generate comprehensive reports"""
    
    def __init__(self, db_instance):
        """Initialize report generator"""
        self.db = db_instance
        self.health_monitor = AgentHealthMonitor(db_instance)
        self.analytics = AgentAnalytics(db_instance)
    
    def generate_agent_report(self, agent_id: str) -> Dict[str, Any]:
        """Generate comprehensive report for an agent"""
        try:
            agent = self.db.get_agent(agent_id)
            health = self.health_monitor.get_agent_health(agent_id)
            activity = self.analytics.get_agent_activity_summary(agent_id)
            
            return {
                "report_type": "agent_detailed",
                "agent_id": agent_id,
                "agent_details": agent,
                "health_metrics": health,
                "activity_metrics": activity,
                "generated_at": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Error generating agent report: {e}")
            return {"error": str(e)}
    
    def generate_system_report(self) -> Dict[str, Any]:
        """Generate comprehensive system report"""
        try:
            health = self.health_monitor.get_system_health()
            analytics = self.analytics.get_system_analytics()
            agents = self.db.list_agents()
            users = self.db.list_users()
            
            return {
                "report_type": "system_comprehensive",
                "summary": {
                    "total_agents": len(agents),
                    "total_users": len(users),
                    "system_health": health.get('overall_health', 0),
                    "success_rate": analytics.get('success_rate', 0)
                },
                "health_metrics": health,
                "analytics": analytics,
                "generated_at": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Error generating system report: {e}")
            return {"error": str(e)}
    
    def generate_compliance_report(self) -> Dict[str, Any]:
        """Generate compliance and audit report"""
        try:
            events = self.db.get_events(limit=1000)
            users = self.db.list_users()
            
            # Audit trail
            audit_events = [e for e in events if e.get('event_type') in ['user_login', 'user_logout', 'agent_created', 'agent_deleted']]
            
            return {
                "report_type": "compliance_audit",
                "audit_trail": {
                    "total_events": len(events),
                    "significant_events": len(audit_events),
                    "user_actions": len([e for e in events if e.get('event_type').startswith('user_')])
                },
                "users_summary": {
                    "total_users": len(users),
                    "active_users": len([u for u in users if u.get('status') == 'active']),
                    "administrators": len([u for u in users if u.get('role') == 'admin'])
                },
                "generated_at": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Error generating compliance report: {e}")
            return {"error": str(e)}


__all__ = ['AgentHealthMonitor', 'AgentAnalytics', 'ReportGenerator']
