#!/bin/bash

source ../../../env.sh

# Flash address
bootaddress=0x70000000
appliaddress=0x70100000

# Flash sector size is 64KB
# 64K * 24 = 1536K
last_sector=24

# CubeProgrammer connection
connect_reset="-c port=SWD ap=1"

flash_log=flash_programming.log

FSBL_BIN="${PWD}/Binary/Template_FSBL_XIP_FSBL.bin"
FSBL_TRUSTED_BIN="${PWD}/Binary/FSBL-trusted.bin"

PRJ_BIN="${PWD}/Binary/Appli.bin"
PRJ_TRUSTED_BIN="${PWD}/Binary/Project-trusted.bin"

rm -rf ${FSBL_TRUSTED_BIN}
rm -rf ${PRJ_TRUSTED_BIN}

eval "${stm32signingtoolcli}" -bin ${FSBL_BIN} -nk -of 0x80000000 -t fsbl -o ${FSBL_TRUSTED_BIN} -hv 2.3 -dump ${FSBL_TRUSTED_BIN}

eval "${stm32signingtoolcli}" -bin ${PRJ_BIN} -nk -of 0x80000000 -t fsbl -o ${PRJ_TRUSTED_BIN} -hv 2.3 -dump ${PRJ_TRUSTED_BIN}

error()
{
  echo "       Error when trying to $action" >> "$flash_log"
  echo "       flash Programming aborted" >> "$flash_log"
  echo "Error when trying to $action"
  echo "Flash Programming aborted"
  echo "See $flash_log for details. Then try again."
  echo
  exit 1
}

# ============================================================ Download images ============================================================
echo ""
echo "============================================================"
echo ""
echo "    * Boot mode should be set to development mode"
echo "        (BOOT1 switch position at 1-3)"
echo "        Press any key to continue..."
echo
read -p "" -n1 -s

action="Reset the target"
echo $action
eval "${stm32programmercli}" $connect_reset > "$flash_log"
if [ $? -ne 0 ]; then
	error
fi
echo "Reset done"

action="Erase flash sectors"
echo $action
eval "$stm32programmercli" $connect_reset -el "$stm32ExtLoaderFlash" -e [0 $last_sector] >> "$flash_log"
if [ $? -ne 0 ]; then
	error
fi
echo "Flash sectors erased"

action="Write $FSBL_TRUSTED_BIN"
echo $action
eval "$stm32programmercli" $connect_reset -el "$stm32ExtLoaderFlash" -d "$FSBL_TRUSTED_BIN" $bootaddress -v >> "$flash_log"
if [ $? -ne 0 ]; then
	error
fi
echo "$FSBL_TRUSTED_BIN Written"

action="Write $PRJ_TRUSTED_BIN"
echo $action
eval "$stm32programmercli" $connect_reset -el "$stm32ExtLoaderFlash" -d "$PRJ_TRUSTED_BIN" $appliaddress -v >> "$flash_log"
if [ $? -ne 0 ]; then
	error
fi
echo "$PRJ_TRUSTED_BIN Written"

echo "Programming success"

echo ""
echo "============================================================"
echo ""
echo "    * Boot mode should be set to flash mode"
echo "        (BOOT1 switch position at 1-2 and BOOT0 switch position at 1-2)"
echo "        Press any key to continue..."
echo
read -p "" -n1 -s

echo "====="
echo "===== The board is correctly configured."
echo "===== Connect UART console (115200 baudrate) and press Reset to start application."
echo "====="

exit 0
