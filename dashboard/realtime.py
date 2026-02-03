# Real-Time Dashboards with WebSocket Integration

This module provides real-time dashboard updates using WebSocket connections.

## Features
- Live agent status updates
- Trust score streaming
- Anomaly alerts in real-time
- Integration with Streamlit via WebSocket

## Usage
```python
from dashboard.realtime import WebSocketDashboard

dashboard = WebSocketDashboard()
dashboard.start_server(port=8765)
```