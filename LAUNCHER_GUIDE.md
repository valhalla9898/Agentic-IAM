# 🚀 Agentic-IAM Launcher Guide

## Quick Start - EASIEST METHOD ✅

**Double-click the icon on your desktop: `Agentic-IAM`**

That's it! The application will:
- ✅ Start all Docker containers
- ✅ Check if services are healthy
- ✅ Open the dashboard in your browser
- ✅ Show connection details

---

## Alternative Launch Methods

### Method 1: Double-click LAUNCHER.bat (From Project Folder)
```
📁 Agentic-IAM-main
  └─ LAUNCHER.bat  ← Double-click this
```
- Opens a visible console window
- Shows detailed startup logs
- Good for troubleshooting

### Method 2: Double-click START.vbs (Silent Launch)
```
📁 Agentic-IAM-main
  └─ START.vbs  ← Double-click this
```
- Launches silently in background
- Opens dashboard automatically
- Cleaner user experience

### Method 3: Command Line (PowerShell)
```powershell
cd C:\Users\Lenovo\Desktop\Agentic-IAM-main
powershell -ExecutionPolicy Bypass -File LAUNCHER.ps1
```

### Method 4: Command Line (Batch)
```batch
cd C:\Users\Lenovo\Desktop\Agentic-IAM-main
LAUNCHER.bat
```

---

## What Happens When You Launch

1. **Docker Check** → Verifies Docker is installed and running
2. **Container Health** → Starts all Docker containers if not running
3. **Service Verification** → Checks if all services are responding
4. **Dashboard Opening** → Automatically opens browser to dashboard
5. **Status Display** → Shows connection details and helpful commands

---

## Access Points After Launch

| Service | URL | Port |
|---------|-----|------|
| **Dashboard** | http://localhost:8501 | 8501 |
| **API Server** | http://localhost:8000 | 8000 |
| **Monitoring** | http://localhost:9090 | 9090 |
| **Database** | localhost | 5432 |
| **Cache** | localhost | 6379 |

---

## Keyboard Shortcuts During Launch

- **Ctrl+C** → Stop the launcher (containers will keep running)
- **Ctrl+Break** → Force stop everything

---

## Troubleshooting

### "Docker not found"
- Install Docker Desktop from: https://www.docker.com/products/docker-desktop
- After installation, restart your computer

### "Port already in use"
- An old container is still running
- Run: `docker-compose down`
- Then try launching again

### "Connection refused"
- Services are still starting (can take 30 seconds)
- Wait a moment and refresh the browser
- Or check logs: `docker-compose logs -f agentic-iam-app`

### Dashboard won't open
- Check if port 8501 is blocked by a firewall
- Open manually: http://localhost:8501

---

## Useful Commands

### View Logs
```powershell
docker-compose logs -f agentic-iam-app
```

### Stop All Services
```powershell
docker-compose down
```

### Restart Services
```powershell
docker-compose restart
```

### Check Container Status
```powershell
docker ps
```

### View Memory Usage
```powershell
docker stats
```

---

## File Structure

```
📁 Agentic-IAM-main/
├─ 🎯 Agentic-IAM.lnk          ← Desktop Shortcut (RECOMMENDED)
├─ LAUNCHER.bat                 ← Batch file launcher
├─ LAUNCHER.ps1                 ← PowerShell launcher script
├─ START.vbs                    ← Silent VBScript launcher
├─ create-shortcut.ps1          ← Creates desktop shortcut
└─ [application files...]
```

---

## Security Notes

✅ The launcher does NOT require Administrator privileges
✅ All data is encrypted in transit
✅ Uses secure token generation for sessions
✅ Includes rate limiting and DDoS protection
✅ Production-ready security implementations

---

## Need Help?

1. Check the logs: `docker-compose logs -f`
2. Verify Docker is running: `docker ps`
3. Restart everything: `docker-compose restart`
4. Review README.md for detailed documentation
5. Check SECURITY.md for security features

---

**Last Updated:** February 14, 2026
**Version:** 2.0 (Production Ready)
