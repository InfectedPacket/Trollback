@echo off
CLS
SETLOCAL ENABLEEXTENSIONS
SET log=scan_results.log
SET words=throwback,INJECTION,cdx-dev,rundll32.exe,venom,index.php
echo        :\     /;               _
echo       ;  \___/  ;             ; ;		-=[Infected Packet]=-
echo      ,:-"'   `"-:.            / ;		-=[Trollback 1.2b ]=-
echo _   /,---.   ,---.\   _     _; /
echo _:^>((  ^|  ) (  ^|  ))^<:_ ,-""_,"	-=[               ]=-
echo     \`````   `````/""""",-""
echo      '-.._ v _..-'      )			-=[ T: @cyberrecce    ]=-
echo        / ___   ____,..  \			-=[ G: /infectedpacket]=-
echo       / /   ^| ^|   ^| ( \. \
echo      / /    ^| ^|    ^| ^|  \ \
echo      `"     `"     `"    `"
echo *-=-=-=-=-=-=-=-=-=-=-=-=-=-=-* 
echo [+] Scanning : C:\Windows\
echo		  : C:\Program Files (x86)\
echo		  : C:\Program Files\
echo		  : %APPDATA%
echo [*] Keywords : %words%
echo [*] Log	  : %log%
echo *-=-=-=-=-=-=-=-=-=-=-=-=-=-=-*  
echo.

:choice
set /P c=Launch scanning operation[Y/N]?
if /I "%c%" EQU "Y" goto :launch
if /I "%c%" EQU "N" goto :abort
goto :choice


:launch

echo [*] Scanning Windows folder...
C:\Python27\python.exe trollback.py -f c:\windows\ %words% -vv >> %log%

echo [*] Scanning Program Files (x86)
C:\Python27\python.exe trollback.py -f "c:\Program Files (x86)\" %words% -vv >> %log%

echo [*] Scanning Program Files
C:\Python27\python.exe trollback.py -f "c:\Program Files" %words% -vv >> %log%

echo [*] Scanning for JAR files in %APPDATA%
for /f "delims=" %%a in ('dir %APPDATA%\*.jar /s /B') do set _TMP=%%a
IF {%_TMP%}=={} (
	echo [+] No Java archives found in %APPDATA%. >> %log%
) ELSE (
	echo [!] Java archives located in %APPDATA%. >> %log%
	dir %APPDATA\*.jar /s /B >> %log%
)

echo [+] Completed. Results saved to %log%.
:abort
echo [!] Terminating scan.

