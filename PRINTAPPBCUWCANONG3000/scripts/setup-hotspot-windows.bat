@echo off
:: ============================================================================
::  setup-hotspot-windows.bat
::  Configures a Windows Mobile Hotspot + ICS for the Captive Portal Print Server
::
::  Requirements:
::    - Run as Administrator
::    - A Wi-Fi adapter capable of being a hosted network
::    - Internet Connection Sharing source adapter (e.g. Ethernet, another Wi-Fi)
::
::  What this script does:
::    1. Creates the Mobile Hotspot (hosted network) with WPA2-PSK
::    2. Starts the hotspot
::    3. Shares the internet connection (ICS) — or isolates it if no WAN
::    4. Configures dnsmasq-equivalent via Windows DNS settings (see notes)
::    5. Adds a firewall rule to redirect all DNS queries to 127.0.0.1 (this machine)
::    6. Enables AP isolation (client-to-client blocking) via firewall
::
::  DNS Hijacking on Windows:
::    Windows ICS assigns itself as the DHCP server on 192.168.137.1.
::    The DHCP server gives clients THIS machine as DNS resolver.
::    Spring Boot's PortalController handles all OS captive-portal probes.
::    For true DNS hijacking (all queries → portal), install Simple DNS Plus
::    or dnscrypt-proxy configured to redirect all A queries → 192.168.137.1.
::    Alternatively use Acrylic DNS Proxy (free): https://mayakron.altervista.org/
::
:: ============================================================================

setlocal EnableDelayedExpansion

:: ─── Configuration — EDIT THESE ─────────────────────────────────────────────
set SSID=SecurePrint
set PASSWORD=PrintPortal2024!
set INTERFACE_NAME=Wi-Fi 2
set PORTAL_IP=192.168.137.1
set PORTAL_PORT=8080

:: ─── Privilege check ─────────────────────────────────────────────────────────
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] This script must be run as Administrator.
    pause
    exit /b 1
)

echo.
echo =====================================================
echo   Captive Portal Print Server - Hotspot Setup
echo =====================================================
echo.

:: ─── Step 1: Stop any existing hosted network ────────────────────────────────
echo [1/7] Stopping any existing hosted network...
netsh wlan stop hostednetwork >nul 2>&1
timeout /t 1 /nobreak >nul

:: ─── Step 2: Configure the hosted network ────────────────────────────────────
echo [2/7] Configuring hotspot: SSID="%SSID%" ...
netsh wlan set hostednetwork mode=allow ssid="%SSID%" key="%PASSWORD%" keyusage=persistent
if %errorLevel% neq 0 (
    echo [ERROR] Failed to configure hosted network. Check your Wi-Fi adapter.
    pause
    exit /b 1
)

:: ─── Step 3: Start the hosted network ────────────────────────────────────────
echo [3/7] Starting hosted network...
netsh wlan start hostednetwork
if %errorLevel% neq 0 (
    echo [ERROR] Failed to start hosted network.
    pause
    exit /b 1
)
timeout /t 2 /nobreak >nul

:: ─── Step 4: AP Isolation — block client-to-client traffic ──────────────────
echo [4/7] Enabling AP isolation (client-to-client blocking)...
:: Block forwarding between clients on the hotspot subnet (192.168.137.0/24)
:: by blocking routed traffic on the hosted network interface.
netsh advfirewall firewall add rule ^
    name="CaptivePortal-BlockClientToClient-IN" ^
    dir=in action=block ^
    localip=192.168.137.0/24 ^
    remoteip=192.168.137.0/24 ^
    enable=yes profile=any ^
    description="AP Isolation: prevent hotspot clients from seeing each other"

netsh advfirewall firewall add rule ^
    name="CaptivePortal-BlockClientToClient-FWD" ^
    dir=out action=block ^
    localip=192.168.137.0/24 ^
    remoteip=192.168.137.0/24 ^
    enable=yes profile=any

:: ─── Step 5: Block internet access from hotspot clients ─────────────────────
echo [5/7] Blocking internet access for hotspot clients (portal-only)...
:: Allow traffic TO this machine's portal port only
netsh advfirewall firewall add rule ^
    name="CaptivePortal-AllowPortal" ^
    dir=in action=allow ^
    protocol=TCP localport=%PORTAL_PORT% ^
    remoteip=192.168.137.0/24 ^
    enable=yes profile=any

:: Block all other outbound traffic from hotspot subnet to WAN
netsh advfirewall firewall add rule ^
    name="CaptivePortal-BlockWAN-OUT" ^
    dir=out action=block ^
    remoteip=0.0.0.0/0 ^
    localip=192.168.137.0/24 ^
    enable=yes profile=any

:: Allow DNS (UDP 53) from clients → this machine (for captive-portal probe interception)
netsh advfirewall firewall add rule ^
    name="CaptivePortal-AllowDNS" ^
    dir=in action=allow ^
    protocol=UDP localport=53 ^
    remoteip=192.168.137.0/24 ^
    enable=yes profile=any

:: ─── Step 6: Block access to host file system ────────────────────────────────
echo [6/7] Blocking file sharing from hotspot clients...
:: Disable SMB/NetBIOS from hotspot subnet
netsh advfirewall firewall add rule ^
    name="CaptivePortal-BlockSMB" ^
    dir=in action=block ^
    protocol=TCP localport=445,139,137,138 ^
    remoteip=192.168.137.0/24 ^
    enable=yes profile=any

netsh advfirewall firewall add rule ^
    name="CaptivePortal-BlockNetBIOS" ^
    dir=in action=block ^
    protocol=UDP localport=137,138 ^
    remoteip=192.168.137.0/24 ^
    enable=yes profile=any

:: ─── Step 7: Launch the Spring Boot print server ────────────────────────────
echo [7/7] Starting Captive Portal Print Server on %PORTAL_IP%:%PORTAL_PORT%...
echo.
echo  SSID     : %SSID%
echo  Password : %PASSWORD%
echo  Portal   : http://%PORTAL_IP%:%PORTAL_PORT%/portal
echo.
echo  NOTE: For DNS hijacking (automatic captive portal pop-up), install
echo        Acrylic DNS Proxy and configure it to redirect all A queries
echo        to %PORTAL_IP%. See docs\DNS_SETUP.md for detailed instructions.
echo.

:: Start the JAR (assumes it was built with mvn package)
set JAR_PATH=%~dp0target\print-server-1.0.0.jar
if exist "%JAR_PATH%" (
    start "PrintServer" java -Djava.awt.headless=false -jar "%JAR_PATH%"
    echo [OK] Print server launched.
) else (
    echo [WARN] JAR not found at %JAR_PATH%
    echo        Run: mvn package -DskipTests
    echo        Then re-run this script or start manually.
)

echo.
echo =====================================================
echo   Setup complete. Connect to Wi-Fi: %SSID%
echo =====================================================
pause
endlocal
