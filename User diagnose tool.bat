@echo off
rem 取得管理员权限
tasklist /fi "IMAGENAME eq 360tray.exe" |findstr /i 360tray.exe >nul 2>nul
if %ERRORLEVEL% equ 0 (
	msg %username% "    请退出360安全卫士，避免运行过程中报错！" 2>nul >nul
	exit
) else (
	echo. >nul >nul
)

tasklist /fi "IMAGENAME eq QQPCSoftMgr.exe" |findstr /i QQPCSoftMgr.exe >nul 2>nul
if %ERRORLEVEL% equ 0 (
	msg %username% "    请退出腾讯QQ电脑管家，避免运行过程中报错！" 2>nul >nul
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
rem 获取系统版本信息
ver /? >nul 2>nul
if !ERRORLEVEL! equ 0 (
	for /f "tokens=4 " %%i in ('ver') do  (
		for /f "tokens=1 delims=." %%a in ('echo %%i 2^>nul') do set systemver=%%a
	)
) else (
	set systemver=9
)

set ipv4ipv6=^\^<[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*\^> [0-9][a-f]*: [a-f][0-9]*:

rem 声明安全/拨号/代理/模拟器/限速软件变量
set SecuritySoftwareProcess=Avast adguard 2345 V2RayN V3Medic V3LSvc Ldshelper LenovoNerveCenter wsctrl LenovoPcManagerService McUICnt kxetray rstray HipsDaemon HipsTray HipsMain ADSafe kavsvc Norton Mcafee avguard SecurityHealthSystray KWatch ZhuDongFangYu 360tray 360safe QQPCMgr QQPCTray QQPCRTP BullGuardCore GlassWire avira k7gw panda avg QHActiveDefense QHWatchDog symantec mbam HitmanPro emsi BdAgent iobit zoner sophos WO17 gdata zonealarm trend fsagent antimalwareservice webroot spyshelter Lavservice killer 8021x NetPeeker NetLimiter SSTap SSTap-mod GameFirst_V Shadowsocks SSTap SuService drclient C+WClient NetScaning Clmsn BarClientView ProcessSafe iNode GOGO上机 RzxClient CoobarClt nvvsvc NXPRUN LdBoxHeadless LdVBoxHeadless MEmuHeadless NoxVMHandle AndroidEmulator ddemuhandle LDSGameMaster
rem 游戏进程黑白名单/内存大小KB
set GameProcessBlack=http https 127.0.0.1 msedge.exe QQLive.exe 8080 8081 8181 xbox LeagueClient.exe domain MsMpEng.exe
set GameProcessWhite=Legends.exe FreeStyle.exe KartRider.exe freestyle2.exe
set MemorySize=1280000
set MemorySizeStart=963200
for /f "tokens=1*" %%i in ('tzutil.exe /g') do set TimeZone=%%i %%j

rem for /f "tokens=2" %%i in ('dism/online /get-intl ^|findstr /r "安装的语言"') do set SystemLanguages=%%i
for /f "tokens=3" %%i in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Nls\Language" /v InstallLanguage 2^>nul') do set Languages=%%i
if defined Languages (
	if !Languages!==0804 set SystemLanguages=中文
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

rem 获取我的文档路径
for /f "tokens=3,4*" %%i in ('reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v Personal 2^>nul ^|findstr "Personal"') do set MyDocuments=%%i %%j %%k
if defined MyDocuments (
	set MyDocuments=!MyDocuments:~0,-2!
) else (
	echo. >nul 2>nul
)

rem 启动时检查日志记录文件是否当天
for /f "tokens=1" %%i in ('dir /tc "%temp%\xygamedate.txt" 2^>nul ^|findstr xygamedate') do (
	if %%i equ %year%/%month%/%day% (
		echo. >nul 2>nul
	) else (
		del /f /q "%temp%\xygamedate.txt" >nul 2>nul
	)
)

rem 检查系统环境变量
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

rem 检查用户temp缓存目录环境变量
echo %temp% |findstr "Local\Temp" >nul 2>nul
if %ERRORLEVEL% equ 0 (
	echo. >nul 2>nul
) else (
	reg add "HKEY_CURRENT_USER\Environment" /v Temp /t REG_EXPAND_SZ /d "%USERPROFILE%\AppData\Local\Temp" /f >nul 2>nul
	set Temp=%USERPROFILE%\AppData\Local\Temp
	msg %username% "已修复用户环境变量，请重新打开检查工具" 2>nul >nul
)

rem 获取正在使用网络的名称
set NNN=0
for /f "tokens=1 delims=," %%i in ('Getmac /v /nh /fo csv ^|findstr /r "Device 暂缺" ^|findstr /r /v "Switch Bluetooth Direct Xbox VMware VirtualBox ZeroTier WSL Loopback 没有硬件"') do (
	set /a NNN+=1
	set NetworkName!NNN!=%%i
)
rem 判断网络接口优先级
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

rem 虚拟网卡drvinst变量


for /f "tokens=4" %%i in ('POWERCFG /LIST ^|findstr /v "Active" ^|findstr "*"') do set powerState=%%i
set powerState=!powerState:(=! 2>nul
set powerState=!powerState:)=! 2>nul

rem Win10游戏模式
if "%systemver%"=="10" (
for /f "tokens=3" %%i in ('reg query "HKEY_CURRENT_USER\Software\Microsoft\GameBar" /v AutoGameModeEnabled 2^>nul') do set GameBar=%%i
if defined GameBar (
if !GameBar!==0x0 set GameBar=游戏模式:关
if !GameBar!==0x1 set GameBar=游戏模式:开
) else (
set "GameBar=游戏模式:开"
) 
) else (
echo. >nul
)
cls
echo 系统时间:%time:~0,8%  时区:%TimeZone%  安装语言:%Languages%%SystemLanguages%  电源模式:%powerState% %GameBar%

echo 1、加速环境诊断           2、设置DNS             3、网络重置                       4、跳模式二修复
echo 5、截屏                   6、WinMTR              7、http/htts抓包(类SYN)           8、最佳性能模式
echo 9、SpeedTest测速          10、清除游戏缓存       11、客户端白屏/无法登录/没有游戏  12、放大镜问题修复

set /p pointer=请选择项目:
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
echo 输入错误,请按任意键返回选择菜单. . .
echo.
pause >nul
goto menu


:modespeed
call:SystemVer
call:securitysoft 2
call:toolkit
call:dnsserver 3、本地DNS服务器:
call:dnsEventLog
call:NICinterface 4
call:Hardware
call:IPv6State 6
call:IEproxy 7
call:SystemFirewall 8
call:hostsusb 9

echo.
echo 11、本地DNS解析测试(预计耗时5s-10s):
ipconfig /flushdns >nul 2>nul
rem 项目9
call:nslookvalue www.playbattlegrounds.com lol.qq.com jx3.xoyo.com www.escapefromtarkov.com store.steampowered.com wot.kongzhong.com www.rockstargames.com xyq.163.com wow.blizzard.cn 
set /a sum1=sum
rem 项目9
call:nslookvalue  api1.nn.com api2.nn.com api3.nn.com www.ringofelysiumonline.com  game.163.com update.nn.com jiasu.nn.com
set /a sum2=sum

set /a sumall=sum1+sum2
set /a sumavg=sumall*100/36
echo     成功率:%sumavg%%%
call:systemtime 12
call:IPAddress 13、运营商: http://myip.ipip.net/

echo.
pause
goto menu


:SystemVer
ping -n 1 /f -l 1372 www.baidu.com |findstr DF >nul
if "%errorlevel%"=="0" (
set mtu=警告:上层设备MTU小于1400
) else (
set mtu=MTU≥1400,
)
for /f "tokens=3" %%i in ('netsh int ip show interfaces ^|findstr /r "\<connected" ^|findstr /r "以太网 本地连接"') do set mtuvalue=%%i
for /f "tokens=3" %%i in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /V ReleaseId 2^>nul') do set systemVersion=%%i
for /f "delims=." %%i in ('wmic datafile where name^="C:\\Program Files\\Internet Explorer\\IEXPLORE.EXE" get Version 2^>nul ^|findstr /i /c:"."') do set IEVersion=%%i

for /f "tokens=1,*" %%i in ('ver') do echo %%i %%j %systemVersion% 计算机:%COMPUTERNAME% IE版本:%IEVersion% %mtu%%mtuvalue%
goto:eof

:securitysoft
echo %1、安全/拨号/代理/模拟器/限速软件:&& for /f "tokens=1,10 delims=," %%i in ('tasklist /v /fo csv ^|findstr /I "%SecuritySoftwareProcess%"') do echo    %%i 名称:%%j

echo.
goto:eof

:toolkit
rem 添加psping、curl、iconv、LiveTcpUdpWatch.exe、7za.exe、blat.exe、mtee功能
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
rem 获取curl工具
call:downloadfile https://img.sobot.com/console/9444/kb/file/90fd46d3bc9242c78df1865bca621da5.cab %temp%\curl.cab curl %temp%\curl.cab
expand.exe -F:* %temp%\curl.cab c:\windows\system32\curl.exe >nul 2>nul
call:downloadcurlvbs
curl.exe -s -o %temp%\softwarepic.cab https://img.sobot.com/console/9444/kb/file/4ecd9283bb8b4c339b9bf371b3ac23f4.cab >nul 2>nul
del /f /q %temp%\curl.cab >nul 2>nul
)

rem 验证文件softwarepic.cab大小并重试
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
echo %1、网卡:&& for /f "tokens=1,2,4 delims=," %%i in ('Getmac /v /nh /fo csv') do (
set Networkstatus=%%k
echo    %%i %%j  !Networkstatus:~1,7!
) 
rem 无线WIFI信息
set WF=0
for /f "tokens=2 delims=:" %%i in ('netsh wlan show Interfaces') do (
for /f "tokens=1" %%a in ('echo %%i') do (
set /a WF+=1
set wifi!WF!=%%a
)
)
netsh wlan show Interfaces |findstr /R "\<SSID" >nul
if "%errorlevel%"=="0" (
echo    WiFi:%wifi7%   状态:%wifi6%   信道:%wifi14%   信号:%wifi17%   速度:%wifi16%Mbps
for /f "tokens=2,4 delims=," %%i in ('DRIVERQUERY /fo csv ^|findstr "Wireless" ^|findstr "[0-9]/[0-9]/[0-9]"') do echo    %%i 驱动日期%%j
) else (
echo >nul 2>nul 
)
echo.
goto:eof

:Hardware
echo 7、设备应用信息:
for /f "tokens=*" %%i in ('wmic cpu get name ^|findstr /i "intel AMD"') do echo    CPU:%%i
for /f %%i in ('wmic os get TotalVisibleMemorySize ^|findstr [0-9]') do set /a RAM=%%i/1024
for /f %%i in ('wmic os get SizeStoredInPagingFiles ^|findstr [0-9]') do set /a VirtualRAM=%%i/1024
echo    内存:%RAM% MB；当前分配虚拟内存:%VirtualRAM% MB
for /f "tokens=2 delims==" %%i in ('wmic path Win32_VideoController get AdapterRAM^,Name /value ^|findstr Name') do set VName=%%i
echo    显卡:%VName%
for /f "tokens=1,2" %%i in ('wmic DesktopMonitor Get ScreenWidth^,ScreenHeight ^|findstr /i "\<[0-9]"') do echo    分辨率:%%j*%%i
rem dxdiag /t %temp%\info.txt
rem 应用程序错误信息
if "%systemver%"=="10" (
for /f "tokens=1,2,4* skip=3" %%i in ('powershell Get-EventLog -LogName Application -EntryType Error -Newest 2 -After %year%-%month%-%day% -Source 'Application Error' 2^>nul ^^^| Select-Object TimeGenerated^,Message 2^>nul') do echo    %%i %%j 错误:%%k %%l
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
for /f "tokens=1,2,4,6* skip=3" %%i in ('powershell Get-EventLog -LogName System -EntryType Warning -Newest 3 -After %year%-%month%-%day% -Source 'Microsoft-Windows-DNS-Client' 2^>nul ^^^| Select-Object TimeGenerated^,Message 2^>nul') do echo    %%i %%j %%k响应域名:%%l %%m
) else (
echo. >nul 2>nul
)
echo.
goto:eof


:hostsusb
rem hosts文件最后修改时间
IF EXIST C:\Windows\System32\drivers\etc\hosts (
cd C:\Windows\System32\drivers\etc >nul 2>nul
for /f "tokens=*" %%i in ('forfiles /M hosts /C "cmd /c echo @fdate @ftime" 2^>nul') do set filetime=%%i
rem 统计hosts非注释行数
for /f %%i in ('type c:\Windows\System32\drivers\etc\hosts 2^>nul ^|findstr /v /b "\<#" ^|findstr "." ^|find /c /v ""') do set hostsnumber=%%i
rem #UHE工具行
for /f %%i in ('type C:\Windows\system32\drivers\etc\hosts 2^>nul ^|findstr /v /b "\<#" ^|find /c "#UHE_"') do set hostsnumberUHE=%%i
rem 统计127.0.0行
for /f %%i in ('type C:\Windows\system32\drivers\etc\hosts 2^>nul ^|findstr /v /b "\<#" ^|find /c "127.0.0"') do set hostsnumber127=%%i
rem 统计155.89行
for /f %%i in ('type C:\Windows\system32\drivers\etc\hosts 2^>nul ^|findstr /v /b "\<#" ^|find /c "155.89"') do set hostsnumber155=%%i
echo %1、hosts修改:!filetime!;有效解析!hostsnumber!^(行^);UHE:!hostsnumberUHE!^(行^);127开头:!hostsnumber127!^(行^);155开头:!hostsnumber155!^(行^)
) else (
echo %1、hosts文件:不存在
)
goto:eof

:IPv6State
wmic nicConfig where "IPEnabled='True'" get IPAddress |find ":" |findstr /i "[0-9][a-f]*: [a-f][0-9]*:" >nul
if "%errorlevel%"=="0" (
echo %1、IPv6协议:开启中(已设置IPv4优先^)
rem 双栈协议时ipv4优先:netsh interface ipv6 show prefixpolicies
for /f "tokens=1,2,3" %%i in ('netsh interface ipv6 show prefixpolicies ^|findstr [0-9]') do netsh interface ipv6 set prefixpolicy %%k %%i %%j >nul 2>nul
netsh interface ipv6 set prefixpolicy ::ffff:0:0/96 100 4 >nul 2>nul
) else (
echo %1、IPv6协议:已关闭
)
goto:eof

:IEproxy
rem 读取代理配置信息
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v AutoConfigURL 2>nul >nul
if %ERRORLEVEL%==0 (
for /f "tokens=3" %%i in ('reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v AutoConfigURL 2^>nul') do set AutoConfigURL=%%i
) else (
set AutoConfigURL=无
)
for /f "tokens=3" %%i in ('reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable 2^>nul') do set ProxyEnable=%%i
if DEFINED ProxyEnable (
if %ProxyEnable%==0x0 set ProxyEnable=关
if %ProxyEnable%==0x1 set ProxyEnable=开
) else (
echo. >nul 2>nul
)

for /f "tokens=3" %%i in ('reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer 2^>nul') do set ProxyServer=%%i
rem 截取变量最后10个字符串
echo %1、代理配置:AutoConfigURL:%AutoConfigURL:~0,20%，代理状态:%ProxyEnable%，地址/端口:%ProxyServer%
set AutoConfigURL=<nul

rem 注册表该项完全访问权限
rem echo HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings [1 7 17] > %temp%\IEqx
rem regini %temp%\IEqx 2>nul

if "%systemver%"=="10" ( 
rem 禁用自动检测设置
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" /v DefaultConnectionSettings /t REG_BINARY /d 4600000000 /f >nul 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" /v SavedLegacySettings /t REG_BINARY /d 4600000000 /f >nul 2>nul
) else (
echo. >nul
)
rem 禁用自动配置URL
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v AutoConfigURL /f >nul 2>nul

rem 手动代理设置
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f >nul 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /d "" /f >nul 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyOverride /t REG_SZ /d "" /f >nul 2>nul

rem 代理配置检查
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v AutoConfigURL 2>nul >nul
if %ERRORLEVEL%==0 (
echo    恢复默认:操作失败
) else (
echo    恢复默认:操作成功
)
goto:eof

:SystemFirewall
netsh advfirewall set allprofiles state off >nul 2>nul
echo %1、Windows系统防火墙:已关闭
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
rem for /f "tokens=1,2 " %%i in ('powershell Invoke-RestMethod http://quan.suning.com/getSysTime.do -TimeoutSec 15 2^>nul ^|findstr ":"') do echo %1、本地系统时间:%date:~0,10% %time:~0,8%  在线北京时间:%%i %%j
for /f "tokens=3-6" %%i in ('powershell Invoke-RestMethod http://time.tianqi.com -TimeoutSec 15 2^>nul ^|findstr "GMT"') do echo %1、本地系统时间:%date:~0,10% %time:~0,8%  在线北京时间:%%k/%%j/%%i %%l
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
echo 0、返回主菜单
echo 1、首选:223.5.5.5    备用:8.8.8.8
echo 2、首选:114.114.114.114       备用:8.8.8.8
echo 3、首选:114.114.114.114 备用:223.5.5.5  （推荐）

echo.
set /p dns=请选择:
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
echo    警告:ISP劫持了114DNS
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
call:dnsserver 1、DNS已设置成功:
ipconfig /flushdns >nul 2>nul
echo 2、DNS缓存已刷新
echo.
goto:eof


:power
if "%systemver%"=="10" (
goto powerLabeWin10
) else (
goto powerLabeWin7
)
:powerLabeWin10
POWERCFG /LIST |findstr "卓越性能"
if "%errorlevel%"=="1" (
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
echo.
) else (
echo. >nul 2>nul
)
for /f "tokens=3" %%i in ('POWERCFG /LIST ^|findstr "卓越性能"') do set powerGUID=%%i
Powercfg -s %powerGUID%
echo.
goto powerLabelExit
:powerLabeWin7
for /f "tokens=3" %%i in ('POWERCFG /LIST ^|findstr "高性能"') do set powerGUID=%%i
Powercfg -s %powerGUID%
echo.
echo 电源管理:高性能(设置成功)
echo.

:powerLabelExit
pause
goto menu


:screenshot
echo.
call:nircmdprc
echo 3秒后截屏...
ping -n 3 127.1 >nul 2>nul
echo 截图存位置桌面: %userprofile%\desktop\leigod_NN\
rem %1(start /min cmd.exe /c %0 :&exit)
echo.
pause
goto menu

:WinMTR
echo.
reg delete "HKCU\Software\WinMTR\config" /f >nul 2>nul
reg add "HKCU\Software\WinMTR\LRU" /v Host1 /t REG_SZ /d "114.114.114.114" /f >nul 2>nul
reg add "HKCU\Software\WinMTR\LRU" /v NrLRU /t REG_DWORD /d "1" /f >nul 2>nul
echo 1、开始准备中...
call:toolkit
if EXIST %temp%\WinMTR\WinMTR.exe (
echo. >nul 2>nul
) else (
curl.exe -L -# -o "%temp%\WinMTR.cab" https://img.sobot.com/console/9444/kb/file/3ad34ed7878547619b7e5d8707698412.cab
)

rem 验证文件大小并重试
call:downloadfileRetrycurl %temp%\WinMTR.cab 5000000 https://img.sobot.com/console/9444/kb/file/3ad34ed7878547619b7e5d8707698412.cab
call:downloadfileRetry %temp%\WinMTR.cab 5000000 https://img.sobot.com/console/9444/kb/file/3ad34ed7878547619b7e5d8707698412.cab WinMTR

mkdir %temp%\WinMTR >nul 2>nul
expand.exe -F:* %temp%\WinMTR.cab %temp%\WinMTR >nul 2>nul
IF EXIST %temp%\WinMTR\WinMTR.exe (
cd %temp%\WinMTR
start "" WinMTR.exe
echo 2、WinMTR运行中...
) else (
echo 2、程序下载失败请重新尝试！
)
del /f /q %temp%\WinMTR.cab >nul 2>nul
echo.
pause
cd C:\Windows\system32 >nul 2>nul
goto menu

:NetworkTrafficView
echo.
echo 1、开始准备中...
call:downloadfile https://img.sobot.com/console/9444/kb/file/0f9c0c1d01e941fb8b623c75ce9108f2.cab %temp%\NetworkTrafficView.cab NetworkTrafficView %temp%\NetworkTrafficView\NetworkTrafficView.exe
mkdir %temp%\NetworkTrafficView >nul 2>nul
expand.exe -F:* %temp%\NetworkTrafficView.cab %temp%\NetworkTrafficView >nul 2>nul
IF EXIST %temp%\NetworkTrafficView\NetworkTrafficView.exe (
start "" %temp%\NetworkTrafficView\NetworkTrafficView.exe
echo 2、程序运行中...
) else (
echo 2、程序下载失败请重新尝试！
)
del /f /q %temp%\NetworkTrafficView.cab >nul 2>nul
echo.
pause
goto menu

:downloadfile
rem 参数1下载地址 参数2保存路径 参数下载3任务名称 参数4执行文件路径
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
echo 请按任意键开始安装补丁
pause
start tools/LeiGodSetup_guanwang_nn.exe

:SpeedTest
echo.
rem CHCP 65001 2>nul >nul
rem echo Start TestSpeed,Please wait...
call:toolkit
echo 1、开始准备中...
curl.exe -# -o %temp%\speedtest.cab https://img.sobot.com/console/9444/kb/file/d6a44b73f5214c4ab3c68ee2c50442d6.cab
expand.exe %temp%\speedtest.cab %temp%\speedtest.exe >nul 2>nul
IF EXIST %temp%\speedtest.exe (
echo 2、启动SpeedTest测速，请稍等...
echo YES|%temp%\speedtest.exe
) else (
echo 2、SpeedTest下载失败请重新尝试！
)
del /f /q %temp%\speedtest.cab >nul 2>nul
echo.
pause
rem chcp 936 2>nul >nul
goto menu

:GameTemp
echo.
echo 0、返回主菜单
echo 1、清理Origin平台缓存
echo 2、清理R星平台缓存



echo.
set /p SwGameID=请选择:
if %SwGameID% equ 0 goto SwGameID0
if %SwGameID% equ 1 goto SwGameID1
if %SwGameID% equ 2 goto SwGameID2

:SwGameID0
echo.
goto menu
:SwGameID1
echo.
echo 开始清理Origin平台缓存...
ipconfig /flushdns >nul 2>nul
del /f /s /q "%appdata%\Origin\" 
del /f /s /q "%ProgramData%\Origin\"
del /f /s /q "%localappdata%\Origin\Origin\" 
echo 执行完成！
echo.
pause
goto menu
:SwGameID2
echo.
echo 开始清理R星平台缓存...
ipconfig /flushdns >nul 2>nul
echo "%MyDocuments%" |findstr ""C:\Users"" >nul
if %errorlevel% equ 0 (
del /f /s /q "%USERPROFILE%\Documents\Rockstar Games\Social Club" "%localappdata%\Rockstar Games\Social Club\"
) else (
del /f /s /q "%MyDocuments%\Rockstar Games\Social Club" "%localappdata%\Rockstar Games\Social Club\"
del /f /s /q "%USERPROFILE%\Documents\Rockstar Games\Social Club" "%localappdata%\Rockstar Games\Social Club\"
)
del /f/ s /q "%ProgramData%\Rockstar Games"
echo 执行完成！
echo.
pause
goto menu

:repair
echo.
rem 赋予完全控制权限
echo y| cacls.exe C:\Windows\System32\drivers\etc\hosts /t /p Everyone:F
copy /y C:\Windows\system32\drivers\etc\hosts_bak C:\Windows\system32\drivers\etc\hosts
del /f /q "C:\Windows\System32\drivers\etc\hosts" >nul 2>nul
call:dnssetting 114.114.114.114 223.5.5.5
ipconfig /flushdns >nul 2>nul
echo 执行成功！
echo.
pause
goto menu

:magnifyingglass
echo.
echo 例如"D:\Program Files\LeiGod_Acc"
set /p magnifyingglass=请输入加速器安装完整路径:
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
echo 路径输入错误 请重新输入
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
echo 重置网络成功！
echo.
pause
goto:eof