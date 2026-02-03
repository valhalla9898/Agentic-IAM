# Quick Start - Project Launcher

This guide explains how to create a shortcut to run the project with one click.

## On Windows 10/11

### Quick method (recommended):

1. **Open File Explorer** and go to the project folder
   ```
   C:\Users\Lenovo\Desktop\Agentic-IAM-main
   ```

2. **Right-click on `start_project.bat`**

3. **Choose "Send to" > "Desktop (create shortcut)"**

4. **Click on the shortcut on the desktop to run the project** ✅

### Manual method (if the first method doesn't work):

1. **Right-click on the desktop**
2. **Choose "New" > "Shortcut"**
3. **In the location field, enter:**
   ```
   C:\Users\Lenovo\Desktop\Agentic-IAM-main\start_project.bat
   ```
4. **Press "Next"**
5. **Enter the name:** `Agentic-IAM`
6. **Press "Finish"**

### Optional: Change the icon

1. **Right-click on the shortcut**
2. **Choose "Properties"**
3. **Press "Change Icon..."**
4. **Search for VS Code icon:**
   ```
   C:\Users\Lenovo\AppData\Local\Programs\Microsoft VS Code\Code.exe
   ```

---

## On Linux/macOS

### Using Terminal:

```bash
# Make the script executable
chmod +x ~/Desktop/Agentic-IAM-main/start_project.sh

# Run it
~/Desktop/Agentic-IAM-main/start_project.sh
```

### Create Desktop Shortcut (Linux GNOME):

1. **Copy the `.desktop` file:**
   ```bash
   cp ~/Desktop/Agentic-IAM-main/agentic-iam.desktop ~/Desktop/
   ```

2. **Edit the path in the file:**
   ```bash
   nano ~/Desktop/agentic-iam.desktop
   ```
   
   Change this line:
   ```
   Exec=bash -c "cd /path/to/Agentic-IAM-main && ./start_project.sh"
   ```
   
   To:
   ```
   Exec=bash -c "cd ~/Desktop/Agentic-IAM-main && ./start_project.sh"
   ```

3. **Make it executable:**
   ```bash
   chmod +x ~/Desktop/agentic-iam.desktop
   ```

4. **Click on it to run the project** ✅

---

## What does the Launcher do?

When you press the shortcut:

✅ **Creates a virtual environment** (if not present)  
✅ **Installs required libraries**  
✅ **Opens VS Code** in the folder  
✅ **Runs API Server** on `http://localhost:8000`  
✅ **Runs Streamlit Dashboard** on `http://localhost:8501`  

### Available services after launch:

| Service | Link |
|---------|------|
| **API Server** | http://localhost:8000 |
| **API Documentation** | http://localhost:8000/docs |
| **Swagger UI** | http://localhost:8000/redoc |
| **Streamlit Dashboard** | http://localhost:8501 |
| **VS Code Editor** | Opens automatically |

---

## Troubleshooting

### If the project doesn't open:

1. **Ensure Python 3.9+ is installed:**
   ```bash
   python --version
   ```

2. **Ensure pip is installed:**
   ```bash
   pip --version
   ```

3. **Try running the script manually:**
   
   **Windows:**
   ```cmd
   cd C:\Users\Lenovo\Desktop\Agentic-IAM-main
   start_project.bat
   ```
   
   **Linux/macOS:**
   ```bash
   cd ~/Desktop/Agentic-IAM-main
   ./start_project.sh
   ```

4. **If there's an installation error:**
   ```bash
   pip install --upgrade -e .
   ```

---

## Shutdown

To stop all services:

1. **Close PowerShell/Command Prompt windows**
2. **Or press Ctrl+C in each window**

---

## Notes

- The launcher will open **3 new windows** (VS Code + API + Dashboard)
- Ensure no services are running on ports `8000` and `8501`
- The first time may take longer (to install libraries)
