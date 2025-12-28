# Agentic-IAM Dashboard — How to Run

## Available methods

### 1️⃣ — Windows (easy)

Double-click the file:

```bash
run_dashboard.bat
```

### 2️⃣ — PowerShell / CMD

```powershell
cd C:\Users\Lenovo\Desktop\Agentic-IAM-main
streamlit run app.py
```

### 3️⃣ — Terminal (any OS)

```bash
streamlit run app.py
```

### 4️⃣ — Additional options

Run on a specific port:

```bash
streamlit run app.py --server.port 8501
```

Run with debug logging:

```bash
streamlit run app.py --logger.level=debug
```

Run without opening the browser automatically:

```bash
streamlit run app.py --server.headless true
```

## ✅ Prerequisites

Make sure Streamlit is installed:

```bash
pip install streamlit
```

## 📱 Dashboard address

After starting, the dashboard will open automatically in your browser at:

- **Local address:** `http://localhost:8501`

## 🛑 Stop the application

- Press `Ctrl + C` in the terminal
- Or close the browser window

---

## 🎯 Available features

- 👥 Agent Management
- 🔐 Session Management
- 📋 Audit Log
- ⚙️ Settings
- 📊 Home Dashboard
