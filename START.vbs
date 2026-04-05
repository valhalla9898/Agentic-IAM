' Agentic-IAM One-Click Silent Launcher
' This VBScript runs the launcher without displaying a console window
' Double-click this to silently start the application

Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")

' Get the directory where this script is located
scriptPath = objFSO.GetParentFolderName(WScript.ScriptFullName)

' Path to the local launcher batch file (uses local venv, no Docker required)
launcherPath = scriptPath & "\start_login.bat"

' Check if launcher exists
if objFSO.FileExists(launcherPath) then
    ' Run the launcher visible (1 = normal window) so user can see progress
    objShell.Run """" & launcherPath & """", 1, False
else
    ' If launcher doesn't exist, show error
    objShell.Popup "Error: start_login.bat not found in " & scriptPath, 0, "Agentic-IAM Launcher Error", 16
end if
