' Create Desktop Shortcut for Agentic-IAM
' This VBScript creates an icon on the desktop

Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")

' Get desktop path
strDesktop = objShell.SpecialFolders("Desktop")

' Get current directory (where this script runs)
strProjectPath = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)

' Create shortcut
Set objLink = objShell.CreateShortcut(strDesktop & "\Agentic-IAM.lnk")
objLink.TargetPath = strProjectPath & "\LAUNCHER.bat"
objLink.WorkingDirectory = strProjectPath
objLink.Description = "Agentic-IAM - Enterprise IAM for AI Agents"
objLink.WindowStyle = 1
objLink.Save

WScript.Echo "✅ Success! Agentic-IAM shortcut created on desktop." & vbCrLf & "Double-click to launch!"
