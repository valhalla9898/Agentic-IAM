<h1 align="center" style="font-size: 72px; margin: 0;">DEVELOPED BY M/R</h1>

# 🎉 FIRST TIME SETUP - START HERE

## For: Riyad (or anyone opening this project for the first time)

---

## ⚡ Quick Start (30 seconds)

### Step 1: Double-click this file
```
RUN_ME_FIRST.bat
```

That's it! The script will:
- ✅ Create the Python environment
- ✅ Install all dependencies
- ✅ Create the desktop shortcut

---

## ✅ After Setup Complete

### Open the Application
Double-click the **Agentic-IAM** shortcut on your desktop.

### Login Credentials
- **Admin User:**
  - Username: `admin`
  - Password: `admin123`

- **Regular User:**
  - Username: `user`
  - Password: `user123`

⚠️ **Change these passwords after first login!**

---

## 📋 What You Get

✅ User Management System  
✅ Agent Registry & Management  
✅ Session Management  
✅ Audit Logs  
✅ Role-Based Access Control (Admin/User/Operator)  
✅ Security & Authentication  

---

## 🛠️ Troubleshooting

### If RUN_ME_FIRST.bat doesn't work:

**Manual Setup (Advanced):**

1. Open PowerShell
2. Navigate to the project folder:
   ```powershell
   cd "C:\Users\Lenovo\Desktop\Agentic-IAM-main (2)\Agentic-IAM-main"
   ```

3. Create virtual environment:
   ```powershell
   python -m venv .venv
   ```

4. Activate it:
   ```powershell
   .\.venv\Scripts\activate.bat
   ```

5. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```

6. Create shortcut:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\create-shortcut.ps1
   ```

7. Run the app:
   ```powershell
   python run_gui.py
   ```

---

## 📖 More Documentation

- **README.md** - Full project information
- **QUICK_START.md** - Quick reference
- **START_HERE.md** - Getting started guide

---

## 💡 Questions?

Check the documentation files or try the troubleshooting section above.

**Everything should work after RUN_ME_FIRST.bat** ✓
