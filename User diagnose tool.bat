@echo off
rem ȡ�ù���ԱȨ��
tasklist /fi "IMAGENAME eq 360tray.exe" |findstr /i 360tray.exe >nul 2>nul
if %ERRORLEVEL% equ 0 (
	msg %username% "    ���˳�360��ȫ��ʿ���������й����б���" 2>nul >nul
	exit
) else (
	echo. >nul >nul
)

tasklist /fi "IMAGENAME eq QQPCSoftMgr.exe" |findstr /i QQPCSoftMgr.exe >nul 2>nul
if %ERRORLEVEL% equ 0 (
	msg %username% "    ���˳���ѶQQ���Թܼң��������й����б���" 2>nul >nul
	exit
) else (
	echo. >nul >nul
)

netstat -nbo >nul 2>nul
if %errorLevel% == 0 (
	echo. >nul 2>nul
) else (
	echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs" 
	echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
		if exist "%temp%\getadmin.vbs" (
			"%temp%\getadmin.vbs"
			del /f /q "%temp%\getadmin.vbs" >nul 2>nul
			exit
		) else (
			echo. >nul 2>nul
		)
)

title Leigod User version v1.0.0  (dengze@nn.com)
mode con cols=105 lines=61
setlocal enabledelayedexpansion
chcp 936 2>nul >nul
rem ��ȡϵͳ�汾��Ϣ
ver /? >nul 2>nul
if !ERRORLEVEL! equ 0 (
	for /f "tokens=4 " %%i in ('ver') do  (
		for /f "tokens=1 delims=." %%a in ('echo %%i 2^>nul') do set systemver=%%a
	)
) else (
	set systemver=9
)

set ipv4ipv6=^\^<[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*\^> [0-9][a-f]*: [a-f][0-9]*:

rem ������ȫ/����/����/ģ����/�����������
set SecuritySoftwareProcess=Avast adguard 2345 V2RayN V3Medic V3LSvc Ldshelper LenovoNerveCenter wsctrl LenovoPcManagerService McUICnt kxetray rstray HipsDaemon HipsTray HipsMain ADSafe kavsvc Norton Mcafee avguard SecurityHealthSystray KWatch ZhuDongFangYu 360tray 360safe QQPCMgr QQPCTray QQPCRTP BullGuardCore GlassWire avira k7gw panda avg QHActiveDefense QHWatchDog symantec mbam HitmanPro emsi BdAgent iobit zoner sophos WO17 gdata zonealarm trend fsagent antimalwareservice webroot spyshelter Lavservice killer 8021x NetPeeker NetLimiter SSTap SSTap-mod GameFirst_V Shadowsocks SSTap SuService drclient C+WClient NetScaning Clmsn BarClientView ProcessSafe iNode GOGO�ϻ� RzxClient CoobarClt nvvsvc NXPRUN LdBoxHeadless LdVBoxHeadless MEmuHeadless NoxVMHandle AndroidEmulator ddemuhandle LDSGameMaster
rem ��Ϸ���̺ڰ�����/�ڴ��СKB
set GameProcessBlack=http https 127.0.0.1 msedge.exe QQLive.exe 8080 8081 8181 xbox LeagueClient.exe domain MsMpEng.exe
set GameProcessWhite=Legends.exe FreeStyle.exe KartRider.exe freestyle2.exe
set MemorySize=1280000
set MemorySizeStart=963200
for /f "tokens=1*" %%i in ('tzutil.exe /g') do set TimeZone=%%i %%j

rem for /f "tokens=2" %%i in ('dism/online /get-intl ^|findstr /r "��װ������"') do set SystemLanguages=%%i
for /f "tokens=3" %%i in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Nls\Language" /v InstallLanguage 2^>nul') do set Languages=%%i
if defined Languages (
	if !Languages!==0804 set SystemLanguages=����
	if !Languages!==0404 set SystemLanguages=TraditionalChinese
	if !Languages!==0409 set SystemLanguages=English
	if !Languages!==0011 set SystemLanguages=Japanese
	if !Languages!==0012 set SystemLanguages=Korean
	if !Languages!==0007 set SystemLanguages=German
	if !Languages!==040C set SystemLanguages=French
) else (
	echo. >nul 2>nul
)

if defined date (
	set year=%date:~0,4%
	set month=%date:~5,2%
	set day=%date:~8,2%
	set week=%date:~11,6%
	set hour=%time:~0,2%
) else (
	echo. >nul 2>nul
)

rem ��ȡ�ҵ��ĵ�·��
for /f "tokens=3,4*" %%i in ('reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v Personal 2^>nul ^|findstr "Personal"') do set MyDocuments=%%i %%j %%k
if defined MyDocuments (
	set MyDocuments=!MyDocuments:~0,-2!
) else (
	echo. >nul 2>nul
)

rem ����ʱ�����־��¼�ļ��Ƿ���
for /f "tokens=1" %%i in ('dir /tc "%temp%\xygamedate.txt" 2^>nul ^|findstr xygamedate') do (
	if %%i equ %year%/%month%/%day% (
		echo. >nul 2>nul
	) else (
		del /f /q "%temp%\xygamedate.txt" >nul 2>nul
	)
)

rem ���ϵͳ��������
wmic /? >nul 2>nul
if %ERRORLEVEL% equ 0 (
	echo. >nul 2>nul
) else (
	call:systempath %%SystemRoot%%\System32\Wbem
)

netsh winsock show >nul 2>nul
if %ERRORLEVEL% equ 0 (
	echo. >nul 2>nul
) else (
	call:systempath %%SystemRoot%%\System32
)

rem ����û�temp����Ŀ¼��������
echo %temp% |findstr "Local\Temp" >nul 2>nul
if %ERRORLEVEL% equ 0 (
	echo. >nul 2>nul
) else (
	reg add "HKEY_CURRENT_USER\Environment" /v Temp /t REG_EXPAND_SZ /d "%USERPROFILE%\AppData\Local\Temp" /f >nul 2>nul
	set Temp=%USERPROFILE%\AppData\Local\Temp
	msg %username% "���޸��û����������������´򿪼�鹤��" 2>nul >nul
)

rem ��ȡ����ʹ�����������
set NNN=0
for /f "tokens=1 delims=," %%i in ('Getmac /v /nh /fo csv ^|findstr /r "Device ��ȱ" ^|findstr /r /v "Switch Bluetooth Direct Xbox VMware VirtualBox ZeroTier WSL Loopback û��Ӳ��"') do (
	set /a NNN+=1
	set NetworkName!NNN!=%%i
)
rem �ж�����ӿ����ȼ�
if %NNN% equ 2 (
for /f %%i in ('netsh int ipv4 show interfaces ^|findstr /c:%NetworkName1%') do set NetworkName1ID=%%i
for /f %%i in ('netsh int ipv4 show interfaces ^|findstr /c:%NetworkName2%') do set NetworkName2ID=%%i
	if !NetworkName1ID! LSS !NetworkName2ID! (
	echo. >nul 2>nul
	) else (
	set NetworkName1=%NetworkName2%
	)
) else (
echo. >nul 2>nul
)

:menu

rem ��������drvinst����


for /f "tokens=4" %%i in ('POWERCFG /LIST ^|findstr /v "Active" ^|findstr "*"') do set powerState=%%i
set powerState=!powerState:(=! 2>nul
set powerState=!powerState:)=! 2>nul

rem Win10��Ϸģʽ
if "%systemver%"=="10" (
for /f "tokens=3" %%i in ('reg query "HKEY_CURRENT_USER\Software\Microsoft\GameBar" /v AutoGameModeEnabled 2^>nul') do set GameBar=%%i
if defined GameBar (
if !GameBar!==0x0 set GameBar=��Ϸģʽ:��
if !GameBar!==0x1 set GameBar=��Ϸģʽ:��
) else (
set "GameBar=��Ϸģʽ:��"
) 
) else (
echo. >nul
)
cls
echo ϵͳʱ��:%time:~0,8%  ʱ��:%TimeZone%  ��װ����:%Languages%%SystemLanguages%  ��Դģʽ:%powerState% %GameBar%

echo 1�����ٻ������           2������DNS             3����������                       4����ģʽ���޸�
echo 5������                   6��WinMTR              7��http/httsץ��(��SYN)           8���������ģʽ
echo 9��SpeedTest����          10�������Ϸ����       11���ͻ��˰���/�޷���¼/û����Ϸ  12���Ŵ������޸�

set /p pointer=��ѡ����Ŀ:
if %pointer% equ 1 goto modespeed
if %pointer% equ 2 goto SDns
if %pointer% equ 3 goto renetwork
if %pointer% equ 4 goto modetwo
if %pointer% equ 5 goto screenshot
if %pointer% equ 6 goto WinMTR
if %pointer% equ 7 goto NetworkTrafficView
if %pointer% equ 8 goto power
if %pointer% equ 9 goto SpeedTest
if %pointer% equ 10 goto GameTemp
if %pointer% equ 11 goto repair
if %pointer% equ 12 goto magnifyingglass



echo.
echo �������,�밴���������ѡ��˵�. . .
echo.
pause >nul
goto menu


:modespeed
call:SystemVer
call:securitysoft 2
call:toolkit
call:dnsserver 3������DNS������:
call:dnsEventLog
call:NICinterface 4
call:Hardware
call:IPv6State 6
call:IEproxy 7
call:SystemFirewall 8
call:hostsusb 9

echo.
echo 11������DNS��������(Ԥ�ƺ�ʱ5s-10s):
ipconfig /flushdns >nul 2>nul
rem ��Ŀ9
call:nslookvalue www.playbattlegrounds.com lol.qq.com jx3.xoyo.com www.escapefromtarkov.com store.steampowered.com wot.kongzhong.com www.rockstargames.com xyq.163.com wow.blizzard.cn 
set /a sum1=sum
rem ��Ŀ9
call:nslookvalue  api1.nn.com api2.nn.com api3.nn.com www.ringofelysiumonline.com  game.163.com update.nn.com jiasu.nn.com
set /a sum2=sum

set /a sumall=sum1+sum2
set /a sumavg=sumall*100/36
echo     �ɹ���:%sumavg%%%
call:systemtime 12
call:IPAddress 13����Ӫ��: http://myip.ipip.net/

echo.
pause
goto menu


:SystemVer
ping -n 1 /f -l 1372 www.baidu.com |findstr DF >nul
if "%errorlevel%"=="0" (
set mtu=����:�ϲ��豸MTUС��1400
) else (
set mtu=MTU��1400,
)
for /f "tokens=3" %%i in ('netsh int ip show interfaces ^|findstr /r "\<connected" ^|findstr /r "��̫�� ��������"') do set mtuvalue=%%i
for /f "tokens=3" %%i in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /V ReleaseId 2^>nul') do set systemVersion=%%i
for /f "delims=." %%i in ('wmic datafile where name^="C:\\Program Files\\Internet Explorer\\IEXPLORE.EXE" get Version 2^>nul ^|findstr /i /c:"."') do set IEVersion=%%i

for /f "tokens=1,*" %%i in ('ver') do echo %%i %%j %systemVersion% �����:%COMPUTERNAME% IE�汾:%IEVersion% %mtu%%mtuvalue%
goto:eof

:securitysoft
echo %1����ȫ/����/����/ģ����/�������:&& for /f "tokens=1,10 delims=," %%i in ('tasklist /v /fo csv ^|findstr /I "%SecuritySoftwareProcess%"') do echo    %%i ����:%%j

echo.
goto:eof

:toolkit
rem ���psping��curl��iconv��LiveTcpUdpWatch.exe��7za.exe��blat.exe��mtee����
IF EXIST C:\Windows\System32\curl.exe (
echo. >nul 2>nul
) else (
del /f /q C:\Windows\System32\psping.exe >nul 2>nul
)

IF EXIST %temp%\LiveTcpUdpWatch.exe (
echo. >nul 2>nul
) else (
del /f /q C:\Windows\System32\psping.exe >nul 2>nul
)

IF EXIST %temp%\iconv.exe (
echo. >nul 2>nul
) else (
del /f /q C:\Windows\System32\psping.exe >nul 2>nul
)

IF EXIST C:\Windows\System32\7za.exe (
echo. >nul 2>nul
) else (
del /f /q C:\Windows\System32\psping.exe >nul 2>nul
)

IF EXIST %temp%\mtee.exe (
echo. >nul 2>nul
) else (
del /f /q C:\Windows\System32\psping.exe >nul 2>nul
)

IF EXIST %temp%\blat\blat.exe (
echo. >nul 2>nul
) else (
del /f /q C:\Windows\System32\psping.exe >nul 2>nul
)

IF EXIST C:\Windows\System32\psping.exe (
echo. >nul 2>nul
) else (
if EXIST C:\Windows\System32\curl.exe (
curl.exe -s -o %temp%\softwarepic.cab https://img.sobot.com/console/9444/kb/file/4ecd9283bb8b4c339b9bf371b3ac23f4.cab >nul 2>nul
) else (
rem ��ȡcurl����
call:downloadfile https://img.sobot.com/console/9444/kb/file/90fd46d3bc9242c78df1865bca621da5.cab %temp%\curl.cab curl %temp%\curl.cab
expand.exe -F:* %temp%\curl.cab c:\windows\system32\curl.exe >nul 2>nul
call:downloadcurlvbs
curl.exe -s -o %temp%\softwarepic.cab https://img.sobot.com/console/9444/kb/file/4ecd9283bb8b4c339b9bf371b3ac23f4.cab >nul 2>nul
del /f /q %temp%\curl.cab >nul 2>nul
)

rem ��֤�ļ�softwarepic.cab��С������
call:downloadfileRetrycurl %temp%\softwarepic.cab 1000000 https://img.sobot.com/console/9444/kb/file/4ecd9283bb8b4c339b9bf371b3ac23f4.cab
call:downloadfileRetry %temp%\softwarepic.cab 1000000 https://img.sobot.com/console/9444/kb/file/4ecd9283bb8b4c339b9bf371b3ac23f4.cab softwarepic

expand.exe -F:* %temp%\softwarepic.cab %temp%\ >nul 2>nul
copy /Y %temp%\psping.exe C:\Windows\System32\psping.exe >nul 2>nul
copy /Y %temp%\curl.exe C:\Windows\System32\curl.exe >nul 2>nul
copy /Y %temp%\7za.exe C:\Windows\System32\7za.exe >nul 2>nul
reg add "HKEY_CURRENT_USER\Software\Sysinternals\PsPing" /v EulaAccepted /t reg_dword /d 00000001 /f >nul 2>nul
mkdir %temp%\blat\ >nul 2>nul
move /y %temp%\blat.exe %temp%\blat\ >nul 2>nul
move /y %temp%\blat.dll %temp%\blat\ >nul 2>nul
del /f /q %temp%\curl.exe %temp%\psping.exe %temp%\softwarepic.cab %temp%\7za.exe >nul 2>nul
)
goto:eof

:NICinterface
echo %1������:&& for /f "tokens=1,2,4 delims=," %%i in ('Getmac /v /nh /fo csv') do (
set Networkstatus=%%k
echo    %%i %%j  !Networkstatus:~1,7!
) 
rem ����WIFI��Ϣ
set WF=0
for /f "tokens=2 delims=:" %%i in ('netsh wlan show Interfaces') do (
for /f "tokens=1" %%a in ('echo %%i') do (
set /a WF+=1
set wifi!WF!=%%a
)
)
netsh wlan show Interfaces |findstr /R "\<SSID" >nul
if "%errorlevel%"=="0" (
echo    WiFi:%wifi7%   ״̬:%wifi6%   �ŵ�:%wifi14%   �ź�:%wifi17%   �ٶ�:%wifi16%Mbps
for /f "tokens=2,4 delims=," %%i in ('DRIVERQUERY /fo csv ^|findstr "Wireless" ^|findstr "[0-9]/[0-9]/[0-9]"') do echo    %%i ��������%%j
) else (
echo >nul 2>nul 
)
echo.
goto:eof

:Hardware
echo 7���豸Ӧ����Ϣ:
for /f "tokens=*" %%i in ('wmic cpu get name ^|findstr /i "intel AMD"') do echo    CPU:%%i
for /f %%i in ('wmic os get TotalVisibleMemorySize ^|findstr [0-9]') do set /a RAM=%%i/1024
for /f %%i in ('wmic os get SizeStoredInPagingFiles ^|findstr [0-9]') do set /a VirtualRAM=%%i/1024
echo    �ڴ�:%RAM% MB����ǰ���������ڴ�:%VirtualRAM% MB
for /f "tokens=2 delims==" %%i in ('wmic path Win32_VideoController get AdapterRAM^,Name /value ^|findstr Name') do set VName=%%i
echo    �Կ�:%VName%
for /f "tokens=1,2" %%i in ('wmic DesktopMonitor Get ScreenWidth^,ScreenHeight ^|findstr /i "\<[0-9]"') do echo    �ֱ���:%%j*%%i
rem dxdiag /t %temp%\info.txt
rem Ӧ�ó��������Ϣ
if "%systemver%"=="10" (
for /f "tokens=1,2,4* skip=3" %%i in ('powershell Get-EventLog -LogName Application -EntryType Error -Newest 2 -After %year%-%month%-%day% -Source 'Application Error' 2^>nul ^^^| Select-Object TimeGenerated^,Message 2^>nul') do echo    %%i %%j ����:%%k %%l
) else (
echo. >nul 2>nul
)
echo.
goto:eof

:dnsserver
for /f "tokens=1-2" %%i in ('wmic nicConfig where "IPEnabled='True'" get DNSServerSearchOrder ^|findstr "{"') do set  dnsserverip=%%i %%j
set dnsserverip=%dnsserverip:"=%
set dnsserverip=%dnsserverip:{=%
set dnsserverip=%dnsserverip:}=%
echo %1 %dnsserverip%
goto:eof

:dnsEventLog 
if "%systemver%"=="10" (
for /f "tokens=1,2,4,6* skip=3" %%i in ('powershell Get-EventLog -LogName System -EntryType Warning -Newest 3 -After %year%-%month%-%day% -Source 'Microsoft-Windows-DNS-Client' 2^>nul ^^^| Select-Object TimeGenerated^,Message 2^>nul') do echo    %%i %%j %%k��Ӧ����:%%l %%m
) else (
echo. >nul 2>nul
)
echo.
goto:eof


:hostsusb
rem hosts�ļ�����޸�ʱ��
IF EXIST C:\Windows\System32\drivers\etc\hosts (
cd C:\Windows\System32\drivers\etc >nul 2>nul
for /f "tokens=*" %%i in ('forfiles /M hosts /C "cmd /c echo @fdate @ftime" 2^>nul') do set filetime=%%i
rem ͳ��hosts��ע������
for /f %%i in ('type c:\Windows\System32\drivers\etc\hosts 2^>nul ^|findstr /v /b "\<#" ^|findstr "." ^|find /c /v ""') do set hostsnumber=%%i
rem #UHE������
for /f %%i in ('type C:\Windows\system32\drivers\etc\hosts 2^>nul ^|findstr /v /b "\<#" ^|find /c "#UHE_"') do set hostsnumberUHE=%%i
rem ͳ��127.0.0��
for /f %%i in ('type C:\Windows\system32\drivers\etc\hosts 2^>nul ^|findstr /v /b "\<#" ^|find /c "127.0.0"') do set hostsnumber127=%%i
rem ͳ��155.89��
for /f %%i in ('type C:\Windows\system32\drivers\etc\hosts 2^>nul ^|findstr /v /b "\<#" ^|find /c "155.89"') do set hostsnumber155=%%i
echo %1��hosts�޸�:!filetime!;��Ч����!hostsnumber!^(��^);UHE:!hostsnumberUHE!^(��^);127��ͷ:!hostsnumber127!^(��^);155��ͷ:!hostsnumber155!^(��^)
) else (
echo %1��hosts�ļ�:������
)
goto:eof

:IPv6State
wmic nicConfig where "IPEnabled='True'" get IPAddress |find ":" |findstr /i "[0-9][a-f]*: [a-f][0-9]*:" >nul
if "%errorlevel%"=="0" (
echo %1��IPv6Э��:������(������IPv4����^)
rem ˫ջЭ��ʱipv4����:netsh interface ipv6 show prefixpolicies
for /f "tokens=1,2,3" %%i in ('netsh interface ipv6 show prefixpolicies ^|findstr [0-9]') do netsh interface ipv6 set prefixpolicy %%k %%i %%j >nul 2>nul
netsh interface ipv6 set prefixpolicy ::ffff:0:0/96 100 4 >nul 2>nul
) else (
echo %1��IPv6Э��:�ѹر�
)
goto:eof

:IEproxy
rem ��ȡ����������Ϣ
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v AutoConfigURL 2>nul >nul
if %ERRORLEVEL%==0 (
for /f "tokens=3" %%i in ('reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v AutoConfigURL 2^>nul') do set AutoConfigURL=%%i
) else (
set AutoConfigURL=��
)
for /f "tokens=3" %%i in ('reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable 2^>nul') do set ProxyEnable=%%i
if DEFINED ProxyEnable (
if %ProxyEnable%==0x0 set ProxyEnable=��
if %ProxyEnable%==0x1 set ProxyEnable=��
) else (
echo. >nul 2>nul
)

for /f "tokens=3" %%i in ('reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer 2^>nul') do set ProxyServer=%%i
rem ��ȡ�������10���ַ���
echo %1����������:AutoConfigURL:%AutoConfigURL:~0,20%������״̬:%ProxyEnable%����ַ/�˿�:%ProxyServer%
set AutoConfigURL=<nul

rem ע��������ȫ����Ȩ��
rem echo HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings [1 7 17] > %temp%\IEqx
rem regini %temp%\IEqx 2>nul

if "%systemver%"=="10" ( 
rem �����Զ��������
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" /v DefaultConnectionSettings /t REG_BINARY /d 4600000000 /f >nul 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" /v SavedLegacySettings /t REG_BINARY /d 4600000000 /f >nul 2>nul
) else (
echo. >nul
)
rem �����Զ�����URL
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v AutoConfigURL /f >nul 2>nul

rem �ֶ���������
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f >nul 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /d "" /f >nul 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyOverride /t REG_SZ /d "" /f >nul 2>nul

rem �������ü��
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v AutoConfigURL 2>nul >nul
if %ERRORLEVEL%==0 (
echo    �ָ�Ĭ��:����ʧ��
) else (
echo    �ָ�Ĭ��:�����ɹ�
)
goto:eof

:SystemFirewall
netsh advfirewall set allprofiles state off >nul 2>nul
echo %1��Windowsϵͳ����ǽ:�ѹر�
goto:eof

:nslookvalue
ping -n 1 -w 10 %1 |findstr "["  >nul
if "%errorlevel%"=="0" (set a1=1) else (set a1=0)

ping -n 1 -w 10 %2 |findstr "["  >nul
if "%errorlevel%"=="0" (set a2=1) else (set a2=0)

ping -n 1 -w 10 %3 |findstr "["  >nul
if "%errorlevel%"=="0" (set a3=1) else (set a3=0)

ping -n 1 -w 10 %4 |findstr "["  >nul
if "%errorlevel%"=="0" (set a4=1) else (set a4=0)

ping -n 1 -w 10 %5 |findstr "["  >nul
if "%errorlevel%"=="0" (set a5=1) else (set a5=0)

ping -n 1 -w 10 %6 |findstr "["  >nul
if "%errorlevel%"=="0" (set a6=1) else (set a6=0)

ping -n 1 -w 10 %7 |findstr "["  >nul
if "%errorlevel%"=="0" (set a7=1) else (set a7=0)

ping -n 1 -w 10 %8 |findstr "["  >nul
if "%errorlevel%"=="0" (set a8=1) else (set a8=0)

ping -n 1 -w 10 %9 |findstr "["  >nul
if "%errorlevel%"=="0" (set a9=1) else (set a9=0)

set /a sum=a1+a2+a3+a4+a5+a6+a7+a8+a9
goto:eof

:systemtime
if "%systemver%"=="10" (
rem for /f "tokens=1,2 " %%i in ('powershell Invoke-RestMethod http://quan.suning.com/getSysTime.do -TimeoutSec 15 2^>nul ^|findstr ":"') do echo %1������ϵͳʱ��:%date:~0,10% %time:~0,8%  ���߱���ʱ��:%%i %%j
for /f "tokens=3-6" %%i in ('powershell Invoke-RestMethod http://time.tianqi.com -TimeoutSec 15 2^>nul ^|findstr "GMT"') do echo %1������ϵͳʱ��:%date:~0,10% %time:~0,8%  ���߱���ʱ��:%%k/%%j/%%i %%l
goto SystemtimeExit
) else (
goto Win7time
)

:IPAddress
if "%systemver%"=="10" (
for /f "tokens=2*" %%i in ('powershell Invoke-RestMethod %2 -TimeoutSec 15 2^>nul') do echo %1 %%i %%j
goto:Win10ExIP
) else (
goto:Win7ExIP
)

:Win10ExIP
goto:eof

:Win7ExIP
set "URL=%2"
(echo Set objDOM = WScript.GetObject("%URL%"^)
echo Do Until objDOM.ReadyState = "complete"
echo WScript.Sleep 100
echo Loop
echo WScript.Echo objDOM.DocumentElement.OuterText
)>%temp%\download.vbs
for /f "delims=" %%i in ('cscript //nologo //e:vbscript %temp%\download.vbs 2^>nul') do echo %1 %%i
echo.

:SystemtimeExit
goto:eof

:SDns
echo.
echo 0���������˵�
echo 1����ѡ:223.5.5.5    ����:8.8.8.8
echo 2����ѡ:114.114.114.114       ����:8.8.8.8
echo 3����ѡ:114.114.114.114 ����:223.5.5.5  ���Ƽ���

echo.
set /p dns=��ѡ��:
if %dns% equ 0 goto dnsip0
if %dns% equ 1 goto dnsip1
if %dns% equ 2 goto dnsip2
if %dns% equ 3 goto dnsip3
:dnsip0
goto menu
:dnsip1
call:dnssetting 223.5.5.5 8.8.8.8
pause
goto menu
:dnsip2
call:dnssetting 114.114.114.114 8.8.8.8
pause
goto menu
:dnsip3
call:dnssetting 114.114.114.114 223.5.5.5
nslookup whether.114dns.com 114.114.114.114 2>nul |findstr 127.0.0 >nul
If %ERRORLEVEL% equ 0 (
echo    ����:ISP�ٳ���114DNS
echo.
) else (
echo. >nul 2>nul
)
pause
goto menu

:dnssetting
netsh interface ip set dnsservers %NetworkName1% static %1 >nul 2>nul
netsh interface ip add dnsservers %NetworkName1% %2 >nul 2>nul
echo.
call:dnsserver 1��DNS�����óɹ�:
ipconfig /flushdns >nul 2>nul
echo 2��DNS������ˢ��
echo.
goto:eof


:power
if "%systemver%"=="10" (
goto powerLabeWin10
) else (
goto powerLabeWin7
)
:powerLabeWin10
POWERCFG /LIST |findstr "׿Խ����"
if "%errorlevel%"=="1" (
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
echo.
) else (
echo. >nul 2>nul
)
for /f "tokens=3" %%i in ('POWERCFG /LIST ^|findstr "׿Խ����"') do set powerGUID=%%i
Powercfg -s %powerGUID%
echo.
goto powerLabelExit
:powerLabeWin7
for /f "tokens=3" %%i in ('POWERCFG /LIST ^|findstr "������"') do set powerGUID=%%i
Powercfg -s %powerGUID%
echo.
echo ��Դ����:������(���óɹ�)
echo.

:powerLabelExit
pause
goto menu


:screenshot
echo.
call:nircmdprc
echo 3������...
ping -n 3 127.1 >nul 2>nul
echo ��ͼ��λ������: %userprofile%\desktop\leigod_NN\
rem %1(start /min cmd.exe /c %0 :&exit)
echo.
pause
goto menu

:WinMTR
echo.
reg delete "HKCU\Software\WinMTR\config" /f >nul 2>nul
reg add "HKCU\Software\WinMTR\LRU" /v Host1 /t REG_SZ /d "114.114.114.114" /f >nul 2>nul
reg add "HKCU\Software\WinMTR\LRU" /v NrLRU /t REG_DWORD /d "1" /f >nul 2>nul
echo 1����ʼ׼����...
call:toolkit
if EXIST %temp%\WinMTR\WinMTR.exe (
echo. >nul 2>nul
) else (
curl.exe -L -# -o "%temp%\WinMTR.cab" https://img.sobot.com/console/9444/kb/file/3ad34ed7878547619b7e5d8707698412.cab
)

rem ��֤�ļ���С������
call:downloadfileRetrycurl %temp%\WinMTR.cab 5000000 https://img.sobot.com/console/9444/kb/file/3ad34ed7878547619b7e5d8707698412.cab
call:downloadfileRetry %temp%\WinMTR.cab 5000000 https://img.sobot.com/console/9444/kb/file/3ad34ed7878547619b7e5d8707698412.cab WinMTR

mkdir %temp%\WinMTR >nul 2>nul
expand.exe -F:* %temp%\WinMTR.cab %temp%\WinMTR >nul 2>nul
IF EXIST %temp%\WinMTR\WinMTR.exe (
cd %temp%\WinMTR
start "" WinMTR.exe
echo 2��WinMTR������...
) else (
echo 2����������ʧ�������³��ԣ�
)
del /f /q %temp%\WinMTR.cab >nul 2>nul
echo.
pause
cd C:\Windows\system32 >nul 2>nul
goto menu

:NetworkTrafficView
echo.
echo 1����ʼ׼����...
call:downloadfile https://img.sobot.com/console/9444/kb/file/0f9c0c1d01e941fb8b623c75ce9108f2.cab %temp%\NetworkTrafficView.cab NetworkTrafficView %temp%\NetworkTrafficView\NetworkTrafficView.exe
mkdir %temp%\NetworkTrafficView >nul 2>nul
expand.exe -F:* %temp%\NetworkTrafficView.cab %temp%\NetworkTrafficView >nul 2>nul
IF EXIST %temp%\NetworkTrafficView\NetworkTrafficView.exe (
start "" %temp%\NetworkTrafficView\NetworkTrafficView.exe
echo 2������������...
) else (
echo 2����������ʧ�������³��ԣ�
)
del /f /q %temp%\NetworkTrafficView.cab >nul 2>nul
echo.
pause
goto menu

:downloadfile
rem ����1���ص�ַ ����2����·�� ��������3�������� ����4ִ���ļ�·��
if EXIST %4 (
goto downloadfileExit
) else (
goto downloadfileStart
)
:downloadfileStart
if "%systemver%"=="10" (
powershell /? >nul 2>nul
if !errorlevel! equ 0 (
powershell Invoke-WebRequest -TimeoutSec 15 %1 -OutFile %2 >nul 2>nul
) else (
start /min bitsadmin.exe /setpriority %3 foreground
bitsadmin.exe /rawreturn /transfer "%3" %1 %2 >nul 2>nul
)
) else (
start /min bitsadmin.exe /setpriority %3 foreground
bitsadmin.exe /rawreturn /transfer "%3" %1 %2 >nul 2>nul
)

:systemtimereset
net stop w32time 2>nul >nul
w32tm /unregister 2>nul >nul
w32tm /register 2>nul >nul
net start w32time 2>nul >nul
w32tm /resync 2>nul >nul
goto:eof

:modetwo
taskkill /f /IM leigod.exe
sc stop lgdcatcher
sc delete lgdcatcher
echo �밴�������ʼ��װ����
pause
start tools/LeiGodSetup_guanwang_nn.exe

:SpeedTest
echo.
rem CHCP 65001 2>nul >nul
rem echo Start TestSpeed,Please wait...
call:toolkit
echo 1����ʼ׼����...
curl.exe -# -o %temp%\speedtest.cab https://img.sobot.com/console/9444/kb/file/d6a44b73f5214c4ab3c68ee2c50442d6.cab
expand.exe %temp%\speedtest.cab %temp%\speedtest.exe >nul 2>nul
IF EXIST %temp%\speedtest.exe (
echo 2������SpeedTest���٣����Ե�...
echo YES|%temp%\speedtest.exe
) else (
echo 2��SpeedTest����ʧ�������³��ԣ�
)
del /f /q %temp%\speedtest.cab >nul 2>nul
echo.
pause
rem chcp 936 2>nul >nul
goto menu

:GameTemp
echo.
echo 0���������˵�
echo 1������Originƽ̨����
echo 2������R��ƽ̨����



echo.
set /p SwGameID=��ѡ��:
if %SwGameID% equ 0 goto SwGameID0
if %SwGameID% equ 1 goto SwGameID1
if %SwGameID% equ 2 goto SwGameID2

:SwGameID0
echo.
goto menu
:SwGameID1
echo.
echo ��ʼ����Originƽ̨����...
ipconfig /flushdns >nul 2>nul
del /f /s /q "%appdata%\Origin\" 
del /f /s /q "%ProgramData%\Origin\"
del /f /s /q "%localappdata%\Origin\Origin\" 
echo ִ����ɣ�
echo.
pause
goto menu
:SwGameID2
echo.
echo ��ʼ����R��ƽ̨����...
ipconfig /flushdns >nul 2>nul
echo "%MyDocuments%" |findstr ""C:\Users"" >nul
if %errorlevel% equ 0 (
del /f /s /q "%USERPROFILE%\Documents\Rockstar Games\Social Club" "%localappdata%\Rockstar Games\Social Club\"
) else (
del /f /s /q "%MyDocuments%\Rockstar Games\Social Club" "%localappdata%\Rockstar Games\Social Club\"
del /f /s /q "%USERPROFILE%\Documents\Rockstar Games\Social Club" "%localappdata%\Rockstar Games\Social Club\"
)
del /f/ s /q "%ProgramData%\Rockstar Games"
echo ִ����ɣ�
echo.
pause
goto menu

:repair
echo.
rem ������ȫ����Ȩ��
echo y| cacls.exe C:\Windows\System32\drivers\etc\hosts /t /p Everyone:F
copy /y C:\Windows\system32\drivers\etc\hosts_bak C:\Windows\system32\drivers\etc\hosts
del /f /q "C:\Windows\System32\drivers\etc\hosts" >nul 2>nul
call:dnssetting 114.114.114.114 223.5.5.5
ipconfig /flushdns >nul 2>nul
echo ִ�гɹ���
echo.
pause
goto menu

:magnifyingglass
echo.
echo ����"D:\Program Files\LeiGod_Acc"
set /p magnifyingglass=�������������װ����·��:
if exist %magnifyingglass%\leigod.exe  ( set lass=0 ) else set lass=1
if %lass% equ 0 (
taskkill /f /IM leigod.exe
del %magnifyingglass%\net_test.exe
del %magnifyingglass%\searchgamepath.exe
start %magnifyingglass%\leigod.exe
echo.
pause
goto menu
) else (
echo ·��������� ����������
echo.
pause
goto menu
)

:nircmdprc
call:downloadfile https://img.sobot.com/console/9444/kb/file/916924176a054efeb0691fc4fe2d0b6f.png %temp%\nircmd.exe nircmd %temp%\nircmd.exe
mkdir "%userprofile%\desktop\leigod_NN\" >nul 2>nul
%temp%\nircmd.exe cmdwait 100 savescreenshot "%userprofile%\desktop\leigod_NN\~$currdate.yyyy_MM_dd$-~$currtime.HH_mm_ss$.png"
taskkill /F /IM nircmd.exe >nul 2>nul
goto:eof

:downloadfileExit
goto:eof

:renetwork
netsh winsock reset
ipconfig/flushdns
echo ��������ɹ���
echo.
pause
goto:eof