$desktop = [Environment]::GetFolderPath("Desktop")
$shortcutPath = Join-Path $desktop "CyberAtlas SOC.lnk"
$electronExe = "C:\Users\cheta\Desktop\Cyber Twin\Frontend\node_modules\electron\dist\electron.exe"
$appPath = "C:\Users\cheta\Desktop\Cyber Twin\Frontend"
$icoPath = "C:\Users\cheta\Desktop\Cyber Twin\cyberatlas.ico"

$wscript = New-Object -ComObject WScript.Shell
$shortcut = $wscript.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $electronExe
$shortcut.Arguments = "electron\main.cjs"
$shortcut.WorkingDirectory = $appPath
$shortcut.WindowStyle = 1
$shortcut.Description = "CyberAtlas Autonomous Enterprise SOC Platform"
$shortcut.IconLocation = "$icoPath,0"
$shortcut.Save()

Write-Host "SUCCESS: Shortcut updated to launch completely silent (NO Command Prompt) at $shortcutPath"
