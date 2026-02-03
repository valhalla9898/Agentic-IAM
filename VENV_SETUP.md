# Running Agentic-IAM in a Virtual Environment

## Quick Setup (Recommended)

### Windows

1. **Create and activate virtual environment:**
   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application:**
   ```bash
   streamlit run app.py
   ```

### Linux/Mac

1. **Create and activate virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application:**
   ```bash
   streamlit run app.py
   ```

## Automated Setup (Easy Way)

I've created automated scripts for you:

### Windows
```bash
setup_venv.bat
```

This will:
- ✅ Create virtual environment
- ✅ Activate it
- ✅ Install all dependencies
- ✅ Start the application

### Linux/Mac
```bash
chmod +x setup_venv.sh
./setup_venv.sh
```

## Step-by-Step Guide

### 1. Create Virtual Environment

**Windows PowerShell:**
```powershell
python -m venv venv
```

**Windows Command Prompt:**
```cmd
python -m venv venv
```

**Linux/Mac:**
```bash
python3 -m venv venv
```

This creates a folder called `venv` with Python and pip isolated from your system.

### 2. Activate Virtual Environment

**Windows PowerShell:**
```powershell
.\venv\Scripts\Activate.ps1
```

If you get an execution policy error, run:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Windows Command Prompt:**
```cmd
venv\Scripts\activate.bat
```

**Linux/Mac:**
```bash
source venv/bin/activate
```

You'll see `(venv)` in your terminal prompt when activated.

### 3. Install Dependencies

With virtual environment activated:

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Run the Application

**Option 1 - Using Streamlit:**
```bash
streamlit run app.py
```

**Option 2 - Using launcher:**
```bash
python run_gui.py
```

### 5. Access the Application

Open your browser to: **http://localhost:8501**

Login with:
- Admin: `admin` / `admin123`
- User: `user` / `user123`

## Deactivate Virtual Environment

When you're done:
```bash
deactivate
```

## Troubleshooting

### "python not found"
**Solution:** Use `python3` instead of `python` or `py` instead of `python`

### "pip not found"
**Solution:** 
```bash
python -m pip install --upgrade pip
```

### PowerShell execution policy error
**Solution:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Module not found errors
**Solution:**
```bash
pip install -r requirements.txt --force-reinstall
```

### Streamlit not found
**Solution:**
```bash
pip install streamlit
```

### Port already in use
**Solution:**
```bash
streamlit run app.py --server.port 8502
```

## Virtual Environment Benefits

✅ **Isolated dependencies** - Won't conflict with other Python projects  
✅ **Clean installation** - Only install what you need  
✅ **Version control** - Specific package versions guaranteed  
✅ **Easy cleanup** - Just delete the `venv` folder  
✅ **Reproducible** - Same environment on any machine  

## Checking Your Setup

After activation, verify installation:

```bash
# Check Python version
python --version

# Check pip version
pip --version

# Check installed packages
pip list

# Check Streamlit
streamlit --version
```

## Daily Usage

### Starting Work
```bash
# Navigate to project folder
cd g:\Agentic-IAM-main\Agentic-IAM-main

# Activate venv
venv\Scripts\activate    # Windows
source venv/bin/activate # Linux/Mac

# Run application
streamlit run app.py
```

### Stopping Work
```bash
# Stop Streamlit (Ctrl+C)
# Deactivate venv
deactivate
```

## Requirements File

The `requirements.txt` includes:
- streamlit
- pandas
- plotly
- asyncio
- cryptography
- And all other dependencies

## Updating Dependencies

To update all packages:
```bash
pip install --upgrade -r requirements.txt
```

To update specific package:
```bash
pip install --upgrade streamlit
```

## Alternative: Using Conda

If you prefer Conda:

```bash
# Create environment
conda create -n agentic-iam python=3.10

# Activate
conda activate agentic-iam

# Install dependencies
pip install -r requirements.txt

# Run
streamlit run app.py

# Deactivate
conda deactivate
```

## IDE Setup

### VS Code
1. Open Command Palette (Ctrl+Shift+P)
2. Type "Python: Select Interpreter"
3. Choose `./venv/Scripts/python.exe`

### PyCharm
1. File → Settings → Project → Python Interpreter
2. Click gear icon → Add
3. Select "Existing environment"
4. Choose `venv/Scripts/python.exe`

## Docker Alternative

If you prefer Docker, use:
```bash
docker-compose up
```

See `docker-compose.yml` for configuration.

---

**Need Help?** Check [START_HERE.md](START_HERE.md) for more information.
