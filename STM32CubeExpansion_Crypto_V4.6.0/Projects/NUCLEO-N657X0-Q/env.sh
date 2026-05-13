#!/bin/bash -

#==============================================================================
#                                    General
#==============================================================================
# Configure tools installation path
WIN_CUBE_PROGRAMMER_PATH="C:\Program Files\STMicroelectronics\STM32Cube\STM32CubeProgrammer\bin"

POSIX_CUBE_PROGRAMMER_PATH=$(echo ${WIN_CUBE_PROGRAMMER_PATH} | tr '\\' '/')
POSIX_CUBE_PROGRAMMER_PATH=$(echo "$POSIX_CUBE_PROGRAMMER_PATH" | sed 's/ /\\ /g')


stm32programmercli_path=${POSIX_CUBE_PROGRAMMER_PATH}

stm32programmercli="$stm32programmercli_path/STM32_Programmer_CLI.exe"
stm32tpccli="$stm32programmercli_path/STM32TrustedPackageCreator_CLI.exe"
stm32keygencli="$stm32programmercli_path/STM32_KeyGen_CLI.exe"
stm32signingtoolcli="$stm32programmercli_path/STM32_SigningTool_CLI.exe"
stm32ExtLoaderFlash="$stm32programmercli_path/ExternalLoader/MX66UW1G45G_STM32N6570-DK.stldr"
stm32ExtOTPInterace="$stm32programmercli_path/ExternalLoader/OTP_FUSES_STM32N6xx.stldr"
imgtool="$stm32programmercli_path/Utilities/Windows/imgtool.exe"

