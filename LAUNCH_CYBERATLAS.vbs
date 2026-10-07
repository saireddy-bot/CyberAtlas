Set WshShell = CreateObject("WScript.Shell")
WshShell.CurrentDirectory = "C:\Users\cheta\Desktop\Cyber Twin\Frontend"
WshShell.Run """C:\Users\cheta\Desktop\Cyber Twin\Frontend\node_modules\electron\dist\electron.exe"" electron\main.cjs", 0, False
