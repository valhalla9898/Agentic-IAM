' Agentic-IAM One-Click Silent Launcher
' This VBScript runs the launcher without displaying a console window
' Double-click this to silently start the application

Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")

' Get the directory where this script is located
scriptPath = objFSO.GetParentFolderName(WScript.ScriptFullName)

' Path to the launcher batch file
launcherPath = scriptPath & "\LAUNCHER.bat"

' Check if launcher exists
if objFSO.FileExists(launcherPath) then
    ' Run the launcher hidden (0 = hidden, True = wait for completion)
    objShell.Run launcherPath, 0, True
else
    ' If launcher doesn't exist, show error
    objShell.Popup "Error: LAUNCHER.bat not found in " & scriptPath, 0, "Agentic-IAM Launcher Error", 16
end if
