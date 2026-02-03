# 🚀 Quick Commands Cheat Sheet

## First Time Setup with Virtual Environment

### Windows
```powershell
# Run automated setup (recommended)
setup_venv.bat

# OR manual setup
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

### Linux/Mac
```bash
# Run automated setup (recommended)
chmod +x setup_venv.sh
./setup_venv.sh

# OR manual setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

## Daily Usage

### Windows
```powershell
# Activate venv and run
run_with_venv.bat

# OR manually
venv\Scripts\activate
streamlit run app.py
```

### Linux/Mac
```bash
# Activate venv and run
chmod +x run_with_venv.sh
./run_with_venv.sh

# OR manually
source venv/bin/activate
streamlit run app.py
```

## Without Virtual Environment

```bash
# Simple start (Windows)
start_login.bat

# Simple start (any OS)
python run_gui.py

# Direct start (any OS)
streamlit run app.py
```

## Common Tasks

### Check if venv is active
```bash
# You should see (venv) in your prompt
# Example: (venv) C:\Projects\Agentic-IAM>
```

### Install new package
```bash
# Make sure venv is activated first
pip install package-name
```

### Update requirements file
```bash
pip freeze > requirements.txt
```

### Deactivate venv
```bash
deactivate
```

### Delete venv (clean reinstall)
```bash
# Windows
rmdir /s venv
setup_venv.bat

# Linux/Mac
rm -rf venv
./setup_venv.sh
```

## Troubleshooting

### PowerShell Execution Policy Error
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Python not found
```bash
# Try these alternatives
python --version
python3 --version
py --version
```

### Streamlit not found
```bash
# Activate venv first, then
pip install streamlit
```

### Port already in use
```bash
streamlit run app.py --server.port 8502
```

### Module import errors
```bash
# Reinstall requirements
pip install -r requirements.txt --force-reinstall
```

## Login Credentials

**Admin:**
- Username: `admin`
- Password: `admin123`

**User:**
- Username: `user`
- Password: `user123`

## Access URL

http://localhost:8501

## Stop Application

Press `Ctrl + C` in the terminal

## Need More Help?

- Virtual Environment Guide: [VENV_SETUP.md](VENV_SETUP.md)
- Full Documentation: [START_HERE.md](START_HERE.md)
- Login Guide: [LOGIN_GUIDE.md](LOGIN_GUIDE.md)
