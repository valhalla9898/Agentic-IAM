"""
Real-Time Dashboards with WebSocket Integration for Agentic-IAM

This module provides real-time dashboard updates using WebSocket connections
for live monitoring of agent activities, trust scores, and security events.

## Features
- Live agent status updates
- Trust score streaming
- Anomaly detection alerts
- Real-time audit log streaming
- WebSocket integration with Streamlit
- Connection pooling and management
"""

import asyncio
import json
import logging
import websockets
from typing import Dict, List, Set, Callable, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import threading
import time

logger = logging.getLogger(__name__)

@dataclass
class AgentStatus:
    """Real-time agent status"""
    agent_id: str
    status: str  # online, offline, suspicious
    trust_score: float
    last_seen: str
    location: Optional[str] = None
    current_action: Optional[str] = None

@dataclass
class SecurityAlert:
    """Real-time security alert"""
    alert_id: str
    severity: str  # low, medium, high, critical
    message: str
    agent_id: Optional[str]
    timestamp: str
    details: Dict[str, Any]

@dataclass
class AuditEvent:
    """Real-time audit event"""
    event_id: str
    event_type: str
    agent_id: str
    action: str
    timestamp: str
    details: Dict[str, Any]

class WebSocketDashboard:
    """
    WebSocket server for real-time dashboard updates
    """

    def __init__(self, host: str = "localhost", port: int = 8765):
        self.host = host
        self.port = port
        self.connected_clients: Set[websockets.WebSocketServerProtocol] = set()
        self.agent_statuses: Dict[str, AgentStatus] = {}
        self.alerts: List[SecurityAlert] = []
        self.audit_stream: List[AuditEvent] = []
        self.max_audit_events = 1000
        self.running = False
        self.server = None

    async def register_client(self, websocket: websockets.WebSocketServerProtocol):
        """Register a new client connection"""
        self.connected_clients.add(websocket)
        logger.info(f"Client connected. Total clients: {len(self.connected_clients)}")

        # Send initial data
        await self.send_initial_data(websocket)

    async def unregister_client(self, websocket: websockets.WebSocketServerProtocol):
        """Unregister a client connection"""
        self.connected_clients.remove(websocket)
        logger.info(f"Client disconnected. Total clients: {len(self.connected_clients)}")

    async def send_initial_data(self, websocket: websockets.WebSocketServerProtocol):
        """Send initial dashboard data to new client"""
        initial_data = {
            "type": "initial_data",
            "agent_statuses": [asdict(status) for status in self.agent_statuses.values()],
            "recent_alerts": [asdict(alert) for alert in self.alerts[-10:]],  # Last 10 alerts
            "recent_audit": [asdict(event) for event in self.audit_stream[-50:]]  # Last 50 events
        }

        try:
            await websocket.send(json.dumps(initial_data))
        except Exception as e:
            logger.error(f"Failed to send initial data: {e}")

    async def broadcast_update(self, update_type: str, data: Any):
        """Broadcast update to all connected clients"""
        if not self.connected_clients:
            return

        message = {
            "type": update_type,
            "data": data,
            "timestamp": datetime.now().isoformat()
        }

        # Remove disconnected clients
        disconnected = set()
        for client in self.connected_clients:
            try:
                await client.send(json.dumps(message))
            except websockets.exceptions.ConnectionClosed:
                disconnected.add(client)
            except Exception as e:
                logger.error(f"Failed to send update to client: {e}")
                disconnected.add(client)

        # Clean up disconnected clients
        self.connected_clients -= disconnected
        if disconnected:
            logger.info(f"Cleaned up {len(disconnected)} disconnected clients")

    def update_agent_status(self, agent_id: str, status: str, trust_score: float,
                          location: Optional[str] = None, current_action: Optional[str] = None):
        """Update agent status and broadcast"""
        agent_status = AgentStatus(
            agent_id=agent_id,
            status=status,
            trust_score=trust_score,
            last_seen=datetime.now().isoformat(),
            location=location,
            current_action=current_action
        )

        self.agent_statuses[agent_id] = agent_status

        # Broadcast update
        asyncio.create_task(self.broadcast_update("agent_status_update", asdict(agent_status)))

    def add_security_alert(self, severity: str, message: str, agent_id: Optional[str] = None,
                          details: Optional[Dict[str, Any]] = None):
        """Add security alert and broadcast"""
        alert = SecurityAlert(
            alert_id=f"alert_{int(time.time() * 1000)}",
            severity=severity,
            message=message,
            agent_id=agent_id,
            timestamp=datetime.now().isoformat(),
            details=details or {}
        )

        self.alerts.append(alert)

        # Keep only recent alerts
        if len(self.alerts) > 100:
            self.alerts = self.alerts[-100:]

        # Broadcast alert
        asyncio.create_task(self.broadcast_update("security_alert", asdict(alert)))

    def add_audit_event(self, event_type: str, agent_id: str, action: str,
                       details: Optional[Dict[str, Any]] = None):
        """Add audit event and broadcast"""
        event = AuditEvent(
            event_id=f"event_{int(time.time() * 1000)}",
            event_type=event_type,
            agent_id=agent_id,
            action=action,
            timestamp=datetime.now().isoformat(),
            details=details or {}
        )

        self.audit_stream.append(event)

        # Keep only recent events
        if len(self.audit_stream) > self.max_audit_events:
            self.audit_stream = self.audit_stream[-self.max_audit_events:]

        # Broadcast event
        asyncio.create_task(self.broadcast_update("audit_event", asdict(event)))

    async def websocket_handler(self, websocket: websockets.WebSocketServerProtocol, path: str):
        """Handle WebSocket connections"""
        await self.register_client(websocket)

        try:
            async for message in websocket:
                # Handle client messages if needed
                try:
                    data = json.loads(message)
                    logger.info(f"Received message from client: {data}")
                    # Process client requests here
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON received: {message}")
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            await self.unregister_client(websocket)

    async def start_server_async(self):
        """Start the WebSocket server asynchronously"""
        self.running = True
        logger.info(f"Starting WebSocket dashboard server on {self.host}:{self.port}")

        self.server = await websockets.serve(
            self.websocket_handler,
            self.host,
            self.port,
            ping_interval=30,
            ping_timeout=10
        )

        logger.info("WebSocket server started successfully")
        await self.server.wait_closed()

    def start_server(self):
        """Start the WebSocket server in a separate thread"""
        def run_async():
            asyncio.run(self.start_server_async())

        server_thread = threading.Thread(target=run_async, daemon=True)
        server_thread.start()
        logger.info("WebSocket server thread started")

    def stop_server(self):
        """Stop the WebSocket server"""
        self.running = False
        if self.server:
            self.server.close()
        logger.info("WebSocket server stopped")

class StreamlitWebSocketClient:
    """
    Client for connecting Streamlit dashboard to WebSocket server
    """

    def __init__(self, ws_url: str = "ws://localhost:8765"):
        self.ws_url = ws_url
        self.websocket = None
        self.connected = False
        self.data_callbacks: Dict[str, Callable] = {}

    def on_data_update(self, update_type: str):
        """Decorator to register callback for data updates"""
        def decorator(func: Callable):
            self.data_callbacks[update_type] = func
            return func
        return decorator

    async def connect_async(self):
        """Connect to WebSocket server asynchronously"""
        try:
            self.websocket = await websockets.connect(self.ws_url)
            self.connected = True
            logger.info("Connected to WebSocket dashboard server")

            # Start listening for messages
            asyncio.create_task(self.listen_for_updates())

        except Exception as e:
            logger.error(f"Failed to connect to WebSocket server: {e}")
            self.connected = False

    async def listen_for_updates(self):
        """Listen for real-time updates"""
        try:
            while self.connected and self.websocket:
                message = await self.websocket.recv()
                data = json.loads(message)

                update_type = data.get("type")
                if update_type in self.data_callbacks:
                    # Call the registered callback
                    self.data_callbacks[update_type](data.get("data", {}))
                else:
                    logger.debug(f"Received update type '{update_type}' with no callback")

        except websockets.exceptions.ConnectionClosed:
            logger.info("WebSocket connection closed")
            self.connected = False
        except Exception as e:
            logger.error(f"Error listening for updates: {e}")
            self.connected = False

    def connect(self):
        """Connect to WebSocket server in a separate thread"""
        def run_async():
            asyncio.run(self.connect_async())

        client_thread = threading.Thread(target=run_async, daemon=True)
        client_thread.start()

    def disconnect(self):
        """Disconnect from WebSocket server"""
        self.connected = False
        if self.websocket:
            asyncio.create_task(self.websocket.close())

# Example usage and integration with Streamlit
def create_sample_dashboard():
    """Create a sample dashboard instance with mock data"""
    dashboard = WebSocketDashboard()

    # Add some sample data
    dashboard.update_agent_status("agent-001", "online", 0.95, "us-east-1", "processing_data")
    dashboard.update_agent_status("agent-002", "suspicious", 0.45, "eu-west-1", "idle")
    dashboard.update_agent_status("agent-003", "offline", 0.80, "ap-southeast-1", None)

    dashboard.add_security_alert("high", "Anomaly detected in agent behavior", "agent-002",
                               {"anomaly_score": 0.87, "pattern": "unusual_api_calls"})

    dashboard.add_audit_event("authentication", "agent-001", "login_success",
                            {"ip": "192.168.1.100", "method": "jwt"})

    return dashboard

if __name__ == "__main__":
    # Start dashboard server
    dashboard = create_sample_dashboard()
    dashboard.start_server()

    # Keep running
    try:
        while True:
            time.sleep(1)
            # Simulate real-time updates
            import random
            if random.random() < 0.1:  # 10% chance every second
                agent_id = f"agent-{random.randint(1, 3):03d}"
                trust_score = random.uniform(0.3, 1.0)
                status = "online" if trust_score > 0.6 else "suspicious"
                dashboard.update_agent_status(agent_id, status, trust_score)

    except KeyboardInterrupt:
        dashboard.stop_server()
        print("Dashboard server stopped")