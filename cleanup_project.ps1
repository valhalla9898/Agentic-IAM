# Remove unnecessary files from Agentic-IAM project

# Cleanup tools (5 files)
Remove-Item -Force cleanup.py
Remove-Item -Force cleanup_arabic.py
Remove-Item -Force clean_markdown.py
Remove-Item -Force final_cleanup.py
Remove-Item -Force find_arabic_chars.py

# Conversion tools (3 files)
Remove-Item -Force convert_to_word.py
Remove-Item -Force convert_to_word_full.py
Remove-Item -Force create_full_docx.py

# Reports and summaries (10 files)
Remove-Item -Force COMPLETION_SUMMARY.py
Remove-Item -Force COMPREHENSIVE_REPORT.md
Remove-Item -Force FINAL_DELIVERY_SUMMARY.md
Remove-Item -Force V2_DELIVERY_SUMMARY.md
Remove-Item -Force FIXES_SUMMARY.md
Remove-Item -Force IMPLEMENTATION_SUMMARY.md
Remove-Item -Force PROJECT_REPORT.md
Remove-Item -Force TECHNICAL_REPORT.md
Remove-Item -Force PROJECT_COMPLETION_STATUS.md
Remove-Item -Force STATUS.txt

# Old guides (10 files)
Remove-Item -Force README_old.md
Remove-Item -Force QUICK_START.md
Remove-Item -Force QUICK_COMMANDS.md
Remove-Item -Force QUICK_LAUNCHER.md
Remove-Item -Force HOW_TO_RUN_GUI.md
Remove-Item -Force HOW_TO_USE.md
Remove-Item -Force LAUNCHER_GUIDE.md
Remove-Item -Force LOGIN_GUIDE.md
Remove-Item -Force LOGIN_README.md
Remove-Item -Force START_HERE.md

# Launcher files (8 files)
Remove-Item -Force LAUNCHER.bat
Remove-Item -Force LAUNCHER.ps1
Remove-Item -Force Open-Agentic-IAM.bat
Remove-Item -Force OPEN.bat
Remove-Item -Force START.vbs
Remove-Item -Force ask_ai.bat
Remove-Item -Force ask_ai.ps1
Remove-Item -Force start_login.bat

# Setup scripts (8 files)
Remove-Item -Force setup_venv.bat
Remove-Item -Force setup_venv.sh
Remove-Item -Force start_project.bat
Remove-Item -Force start_project.ps1
Remove-Item -Force start_project.sh
Remove-Item -Force run_dashboard.bat
Remove-Item -Force run_dashboard.sh
Remove-Item -Force run_with_venv.bat

# Old tests (3 files)
Remove-Item -Force test_login.py
Remove-Item -Force test_setup.py
Remove-Item -Force conftest.py
Remove-Item -Force test_single.txt

# Result reports (3 files)
Remove-Item -Force pytest_results.txt
Remove-Item -Force security_report.json
Remove-Item -Force bandit_report.json

# Other files (5 files)
Remove-Item -Force ARCHITECTURE_DIAGRAM.md
Remove-Item -Force agentic-iam.desktop
Remove-Item -Force streamlit_err.log
Remove-Item -Force streamlit_out.log
Remove-Item -Force .ai_index.json

# Other documentation (5 files)
Remove-Item -Force VENV_SETUP.md
Remove-Item -Force VISUAL_GUIDE.md
Remove-Item -Force RUNBOOK.md
Remove-Item -Force SECURITY_TESTING.md
Remove-Item -Force SECURITY.md

# Unused directories (12 folders)
Remove-Item -Recurse -Force federation/
Remove-Item -Recurse -Force encryption/
Remove-Item -Recurse -Force audit/
Remove-Item -Recurse -Force intelligence/
Remove-Item -Recurse -Force mobile/
Remove-Item -Recurse -Force monitoring/
Remove-Item -Recurse -Force nginx/
Remove-Item -Recurse -Force secrets/
Remove-Item -Recurse -Force scripts/
Remove-Item -Recurse -Force utils/
Remove-Item -Recurse -Force logs/ -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force k8s/

# Word files (2 files)
Remove-Item -Force TECHNICAL_REPORT.docx -ErrorAction SilentlyContinue
Remove-Item -Force TECHNICAL_REPORT_FULL.docx -ErrorAction SilentlyContinue
Remove-Item -Force THESIS_FINAL_CORRECTED.docx -ErrorAction SilentlyContinue

Write-Host "Cleanup completed successfully!" -ForegroundColor Green
Write-Host "All unnecessary files have been removed" -ForegroundColor Green
