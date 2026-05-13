/**
  @page SM2_SignVerify ECC example

  @verbatim
  ******************************************************************************
  * @file    Applications/ECC/SM2_SignVerify/readme.txt
  * @author  MCD Application Team
  * @brief   Description of the SM2_SignVerify example.
  ******************************************************************************
  *
  * Copyright (c) 2023 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file in
  * the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
   @endverbatim

@par Example Description
This example describes how to use the STM32 Cryptographic Library to sign and verify
a message using the SM2 algorithm.

This example demonstrates how to use the predefined curves parameters to perform
ECC operation in a single call method: the configuration of the algorithm, and the operation
is done in one single API call.

This example is schedule as follow:
Preliminary - Generate digest of the known message
a - The signature of the known message digest using a known random, so that generated
    signature can be compared to the known signature
b - The verification of the know message digest with the known signature
c - The signature of the known message digest using a true random
d - The verification of the know message digest with this newly generated signature

In case of successful operations:
- the red led will be turned on
- the global variable glob_status will be set to PASSED
In case of failure:
- the red led will be toggled each 250 milliseconds in an infinity loop.
- the global variable glob_status will be set to FAILED

@note NIST vectors examples for ECDSA are taken from:
"SM2 Digital Signature Algorithm / draft-shen-sm2-ecdsa-02"
Available at:
 https://tools.ietf.org/html/draft-shen-sm2-ecdsa-02

@par Keywords

Cryptography, authentication, SM2, Cryptographic

@par Directory contents

  - ECC/SM2_SignVerify/Inc/stm32h7rsxx_nucleo_conf.h     BSP configuration file
  - ECC/SM2_SignVerify/Inc/stm32h7rsxx_hal_conf.h    HAL configuration file
  - ECC/SM2_SignVerify/Inc/stm32h7rsxx_it.h          Interrupt handlers header file
  - ECC/SM2_SignVerify/Inc/main.h                        Header for main.c module
  - ECC/SM2_SignVerify/Src/stm32h7rsxx_it.c          Interrupt handlers
  - ECC/SM2_SignVerify/Src/stm32h7rsxx_hal_msp.c     HAL MSP module
  - ECC/SM2_SignVerify/Src/main.c                        Main program
  - ECC/SM2_SignVerify/Src/system_stm32h7rsxx.c      STM32H7RSxx system source file
  - ECC/SM2_SignVerify/Src/cmox_low_level.c              CMOX low level services implementation

@par Hardware and Software environment

  - This example runs on STM32H7RSxx devices.

  - This example has been tested with NUCLEO-H7S3L8 board and can be
    easily tailored to any other supported device and development board.

@par How to use it ?

In order to make the program work, you must do the following :
EWARM and MDK-ARM:

 - Open your preferred toolchain
 - Rebuild all files from sub-project Appli and load your images into memories: This sub-project will first load Boot_XIP.hex in internal Flash, than load Appli part in External memory available on NUCLEO-H7S3L8 board.
 - Run the example

CubeIDE:

 - Compile the example/application; the elf file is required to configure the debug profile (the "active configuration" must be "debug", else only assembly debug is available)
 - Open the menu [Run]->[Debug configuration] and double click on [STM32 C/C++ Application] (it creates a default debug configuration for the current project selected)
 - In [Debugger] tab, section "External loaders" add the external loader corresponding to your Board/Memory as described below:
 - In "External loaders" section, click on [Add]
 - Select the loader among the available list (MX25UW25645G_NUCLEO-H7S3L8.stldr or MX66UW1G45G_STM32H7S78-DK.stldr)
 - Option "Enabled" checked and Option "Initialize" unchecked
 - In "Misc" section, uncheck the option "Verify flash download"
 - In [Startup] tab, section "Load Image and Symbols":
    - Click on [Add]
    - If your project contains a boot project:
        - click on "Project" and then select the boot project.
        - click on Build configuration and select "Use active".
        - then select the following options:
           - "Perform build" checked.
           - "Download" checked.
           - "Load symbols" unchecked.
    - If your project doesn't contain a boot project:
        - click on [File System] and select the Boot HEX file corresponding to your board
          - Boot_XIP.hex can be found in folder [Binary] on each Template_XIP project
          - You may need to force the capability to select a .hex file by typing " * " + pressing the "Enter" key in the file name dialog

        - then select the following options:
          - "Download" checked.
          - "Load symbols" unchecked.
          - Click Ok
        - Back in the in the [Startup] tab, move down the boot project for it to be in second position
    - Our debug configuration is ready to be used.

 * <h3><center>&copy; COPYRIGHT STMicroelectronics</center></h3>
 */
