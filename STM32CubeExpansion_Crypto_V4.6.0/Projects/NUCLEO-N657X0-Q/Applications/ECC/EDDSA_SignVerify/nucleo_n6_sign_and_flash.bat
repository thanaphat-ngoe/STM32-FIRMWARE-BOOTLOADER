@ECHO OFF
:: Enable delayed expansion
setlocal EnableDelayedExpansion

call ../../../env.bat

:: Flash address
set bootaddress=0x70000000
set appliaddress=0x70100000

:: Flash sector size is 64KB
:: 64K * 24 = 1536K
set last_sector=24

:: CubeProgrammer connection
set connect_reset="-c port=SWD ap=1"

set flash_log=flash_programming.log
if exist %flash_log% del /f /q %flash_log%

set FSBL_BIN="%~dp0\Binary\Template_FSBL_XIP_FSBL.bin"
set FSBL_TRUSTED_BIN="%~dp0\Binary\FSBL-trusted.bin"

set PRJ_BIN="%~dp0\Binary\Appli.bin"
set PRJ_TRUSTED_BIN="%~dp0\Binary\Project-trusted.bin"

if exist %FSBL_TRUSTED_BIN% del /f /q %FSBL_TRUSTED_BIN%
if exist %PRJ_TRUSTED_BIN% del /f /q %PRJ_TRUSTED_BIN%

if not exist %FSBL_BIN% (
echo Error file %FSBL_BIN% not found!
echo
pause >nul
exit 1
)

if not exist %PRJ_BIN% (
echo Error file %PRJ_BIN% not found!
echo
pause >nul
exit 1
)

"%stm32signingtoolcli%" -bin %FSBL_BIN% -nk -of 0x80000000 -t fsbl -o %FSBL_TRUSTED_BIN% -hv 2.3 -dump %FSBL_TRUSTED_BIN%

"%stm32signingtoolcli%" -bin %PRJ_BIN% -nk -of 0x80000000 -t fsbl -o %PRJ_TRUSTED_BIN% -hv 2.3 -dump %PRJ_TRUSTED_BIN%

goto:MAIN
:error

echo "       Error when trying to %action%" >> %flash_log% 2>>&1
echo "       flash Programming aborted" >> %flash_log% 2>>&1
echo Error when trying to %action%
echo Flash Programming aborted
echo See %flash_log% for details. Then try again.
echo
pause >nul
exit 1

:MAIN
:: ============================================================ Download images ============================================================
echo.
echo ============================================================
echo.
echo     * Boot mode should be set to development mode
echo         (BOOT1 switch position at 1-3)
echo         Press any key to continue...
echo.
pause >nul

set "action=Reset the target"
echo %action%
"%stm32programmercli%" %connect_reset% >> %flash_log% 2>>&1
if %errorlevel% neq 0 (
  call error
)
echo Reset done

set "action=Erase flash sectors"
echo %action%
"%stm32programmercli%" %connect_reset% -el "%stm32ExtLoaderFlash%" -e [0 %last_sector%] >> %flash_log% 2>>&1
if %errorlevel% neq 0 (
  goto error
)
echo Flash sectors erased

set "action=Write %FSBL_TRUSTED_BIN%"
echo %action%
"%stm32programmercli%" %connect_reset% -el "%stm32ExtLoaderFlash%" -d "%FSBL_TRUSTED_BIN%" %bootaddress% -v >> %flash_log% 2>>&1
if %errorlevel% neq 0 (
  goto error
)
echo %FSBL_TRUSTED_BIN% Written

set "action=Write %PRJ_TRUSTED_BIN%"
echo %action%
"%stm32programmercli%" %connect_reset% -el "%stm32ExtLoaderFlash%" -d "%PRJ_TRUSTED_BIN%" %appliaddress% -v >> %flash_log% 2>>&1
if %errorlevel% neq 0 (
  goto error
)
echo %PRJ_TRUSTED_BIN% Written

echo Programming success

echo.
echo ============================================================
echo.
echo     * Boot mode should be set to flash mode
echo         (BOOT1 switch position at 1-2 and BOOT0 switch position at 1-2)
echo         Press any key to continue...
echo.
pause >nul

echo =====
echo ===== The board is correctly configured.
echo ===== Connect UART console (115200 baudrate) and press Reset to start application.
echo =====

exit 0
