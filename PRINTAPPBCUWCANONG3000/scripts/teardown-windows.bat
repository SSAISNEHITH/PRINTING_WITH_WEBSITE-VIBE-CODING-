@echo off
:: ============================================================================
::  teardown-windows.bat
::  Removes ALL firewall rules added by setup-hotspot-windows.bat
::  and stops the hosted network.
::  Run as Administrator.
:: ============================================================================

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Must run as Administrator.
    pause & exit /b 1
)

echo Stopping hotspot...
netsh wlan stop hostednetwork

echo Removing captive portal firewall rules...
for %%R in (
    "CaptivePortal-BlockClientToClient-IN"
    "CaptivePortal-BlockClientToClient-FWD"
    "CaptivePortal-AllowPortal"
    "CaptivePortal-BlockWAN-OUT"
    "CaptivePortal-AllowDNS"
    "CaptivePortal-BlockSMB"
    "CaptivePortal-BlockNetBIOS"
) do (
    netsh advfirewall firewall delete rule name=%%R >nul 2>&1
)

echo Removing per-client block rules (pattern: BlockCaptiveClient-*)...
:: Remove any per-client rules added dynamically by NetworkSecurityManager
for /f "tokens=*" %%A in ('netsh advfirewall firewall show rule name="BlockCaptiveClient-*" ^| findstr /i "Rule Name"') do (
    set "LINE=%%A"
    set "RULE=!LINE:Rule Name:                          =!"
    if not "!RULE!"=="" (
        netsh advfirewall firewall delete rule name="!RULE!" >nul 2>&1
        echo   Removed: !RULE!
    )
)

echo Killing Java print server process...
taskkill /f /im java.exe >nul 2>&1

echo.
echo [OK] Teardown complete.
pause
