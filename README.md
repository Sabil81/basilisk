To enable port forwarding on Windows run this in CMD:
"reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /t REG_DWORD /v IPEnableRouter /d 1 /f"
(without quotes)
