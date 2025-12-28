"""
Database Management Module for Agentic-IAM

Handles SQLite database operations for logging events and storing agent data.
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging

logger = logging.getLogger(__name__)

class Database:
    """SQLite database manager for Agentic-IAM"""
    
    def __init__(self, db_path: str = "data/agentic_iam.db"):
        """Initialize database connection"""
        self.db_path = db_path
        self._ensure_db_path()
        self.init_tables()
    
    def _ensure_db_path(self):
        """Ensure database directory exists"""
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)
    
    def get_connection(self):
        """Get database connection"""
        return sqlite3.connect(self.db_path)
    
    def init_tables(self):
        """Initialize database tables"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Agents table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS agents (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    type TEXT,
                    status TEXT DEFAULT 'active',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT
                )
            """)
            
            # Events/Audit log table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    agent_id TEXT,
                    action TEXT,
                    details TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'success',
                    FOREIGN KEY (agent_id) REFERENCES agents(id)
                )
            """)
            
            # Sessions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ended_at TIMESTAMP,
                    status TEXT DEFAULT 'active',
                    metadata TEXT,
                    FOREIGN KEY (agent_id) REFERENCES agents(id)
                )
            """)
            
            conn.commit()
            logger.info("Database tables initialized successfully")
    
    # Agent operations
    def add_agent(self, agent_id: str, name: str, agent_type: str = "standard", metadata: Dict = None) -> bool:
        """Add new agent to database"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO agents (id, name, type, metadata)
                    VALUES (?, ?, ?, ?)
                """, (agent_id, name, agent_type, json.dumps(metadata or {})))
                conn.commit()
                
                # Log event
                self.log_event("agent_created", agent_id, "create", f"Agent {name} created")
                logger.info(f"Agent {agent_id} added to database")
                return True
        except sqlite3.IntegrityError:
            logger.error(f"Agent {agent_id} already exists")
            return False
        except Exception as e:
            logger.error(f"Error adding agent: {e}")
            return False
    
    def get_agent(self, agent_id: str) -> Optional[Dict]:
        """Get agent details"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM agents WHERE id = ?", (agent_id,))
                row = cursor.fetchone()
                if row:
                    return {
                        'id': row[0],
                        'name': row[1],
                        'type': row[2],
                        'status': row[3],
                        'created_at': row[4],
                        'updated_at': row[5],
                        'metadata': json.loads(row[6]) if row[6] else {}
                    }
        except Exception as e:
            logger.error(f"Error getting agent: {e}")
        return None
    
    def list_agents(self) -> List[Dict]:
        """List all agents"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM agents ORDER BY created_at DESC")
                rows = cursor.fetchall()
                agents = []
                for row in rows:
                    agents.append({
                        'id': row[0],
                        'name': row[1],
                        'type': row[2],
                        'status': row[3],
                        'created_at': row[4],
                        'updated_at': row[5],
                        'metadata': json.loads(row[6]) if row[6] else {}
                    })
                return agents
        except Exception as e:
            logger.error(f"Error listing agents: {e}")
        return []
    
    def update_agent(self, agent_id: str, **kwargs) -> bool:
        """Update agent information"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                updates = []
                values = []
                
                for key, value in kwargs.items():
                    if key in ['name', 'type', 'status']:
                        updates.append(f"{key} = ?")
                        values.append(value)
                
                if not updates:
                    return False
                
                updates.append("updated_at = ?")
                values.append(datetime.now().isoformat())
                values.append(agent_id)
                
                query = f"UPDATE agents SET {', '.join(updates)} WHERE id = ?"
                cursor.execute(query, values)
                conn.commit()
                
                self.log_event("agent_updated", agent_id, "update", f"Agent {agent_id} updated")
                return True
        except Exception as e:
            logger.error(f"Error updating agent: {e}")
            return False
    
    # Event logging operations
    def log_event(self, event_type: str, agent_id: Optional[str] = None, 
                  action: Optional[str] = None, details: Optional[str] = None, 
                  status: str = "success") -> bool:
        """Log an event to database"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO events (event_type, agent_id, action, details, status)
                    VALUES (?, ?, ?, ?, ?)
                """, (event_type, agent_id, action, details, status))
                conn.commit()
                logger.info(f"Event logged: {event_type} for agent {agent_id}")
                return True
        except Exception as e:
            logger.error(f"Error logging event: {e}")
            return False
    
    def get_events(self, agent_id: Optional[str] = None, limit: int = 100) -> List[Dict]:
        """Get events from database"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                if agent_id:
                    cursor.execute("""
                        SELECT * FROM events 
                        WHERE agent_id = ? 
                        ORDER BY created_at DESC 
                        LIMIT ?
                    """, (agent_id, limit))
                else:
                    cursor.execute("""
                        SELECT * FROM events 
                        ORDER BY created_at DESC 
                        LIMIT ?
                    """, (limit,))
                
                rows = cursor.fetchall()
                events = []
                for row in rows:
                    events.append({
                        'id': row[0],
                        'event_type': row[1],
                        'agent_id': row[2],
                        'action': row[3],
                        'details': row[4],
                        'created_at': row[5],
                        'status': row[6]
                    })
                return events
        except Exception as e:
            logger.error(f"Error getting events: {e}")
        return []
    
    # Session operations
    def create_session(self, session_id: str, agent_id: str, metadata: Dict = None) -> bool:
        """Create a session for an agent"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO sessions (id, agent_id, metadata)
                    VALUES (?, ?, ?)
                """, (session_id, agent_id, json.dumps(metadata or {})))
                conn.commit()
                self.log_event("session_created", agent_id, "session_start", f"Session {session_id} started")
                return True
        except Exception as e:
            logger.error(f"Error creating session: {e}")
            return False
    
    def end_session(self, session_id: str) -> bool:
        """End a session"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE sessions 
                    SET status = 'ended', ended_at = ? 
                    WHERE id = ?
                """, (datetime.now().isoformat(), session_id))
                conn.commit()
                
                # Get agent_id for logging
                cursor.execute("SELECT agent_id FROM sessions WHERE id = ?", (session_id,))
                result = cursor.fetchone()
                if result:
                    self.log_event("session_ended", result[0], "session_end", f"Session {session_id} ended")
                
                return True
        except Exception as e:
            logger.error(f"Error ending session: {e}")
            return False
    
    def get_agent_sessions(self, agent_id: str) -> List[Dict]:
        """Get all sessions for an agent"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM sessions 
                    WHERE agent_id = ? 
                    ORDER BY started_at DESC
                """, (agent_id,))
                
                rows = cursor.fetchall()
                sessions = []
                for row in rows:
                    sessions.append({
                        'id': row[0],
                        'agent_id': row[1],
                        'started_at': row[2],
                        'ended_at': row[3],
                        'status': row[4],
                        'metadata': json.loads(row[5]) if row[5] else {}
                    })
                return sessions
        except Exception as e:
            logger.error(f"Error getting sessions: {e}")
        return []


# Global database instance
_db_instance = None

def get_database(db_path: str = "data/agentic_iam.db") -> Database:
    """Get or create global database instance"""
    global _db_instance
    if _db_instance is None:
        _db_instance = Database(db_path)
    return _db_instance
