@ECHO OFF

:: ==============================================================================
::                                    General
:: ==============================================================================
:: Configure tools installation path
set stm32tool_path=C:\Program Files\STMicroelectronics\STM32Cube\STM32CubeProgrammer\bin

set stm32programmercli=%stm32tool_path%\STM32_Programmer_CLI.exe
set stm32tpccli=%stm32tool_path%\STM32TrustedPackageCreator_CLI.exe
set stm32keygencli=%stm32tool_path%\STM32_KeyGen_CLI.exe
set stm32signingtoolcli=%stm32tool_path%\STM32_SigningTool_CLI.exe
set stm32ExtLoaderFlash=%stm32tool_path%\ExternalLoader\MX66UW1G45G_STM32N6570-DK.stldr
set stm32ExtOTPInterace=%stm32tool_path%\ExternalLoader\OTP_FUSES_STM32N6xx.stldr
set imgtool=%stm32tool_path%\Utilities\Windows\imgtool.exe
