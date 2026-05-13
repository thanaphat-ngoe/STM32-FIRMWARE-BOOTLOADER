/**
  @page RandomGeneration DRBG example

  @verbatim
  ******************************************************************************
  * @file    Applications/DRBG/RandomGeneration/readme.txt
  * @author  MCD Application Team
  * @brief   Description of the RandomGeneration example.
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
This example describes how to use the STM32 Cryptographic Library to generate random numbers
using the DRBG module.

This example demonstrates the generation of random numbers based on known input entropy, nonce and personalization.
So that produced random can be compared to known random.

In case of successful operations:
- the red led will be turned on
- the global variable glob_status will be set to PASSED
In case of failure:
- the red led will be toggled each 250 milliseconds in an infinity loop.
- the global variable glob_status will be set to FAILED

@note NIST vectors examples for DRGB are taken from:
"Test Vectors"
Available at:
 https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/random-number-generators

@par Keywords

Cryptography, random, DRBG, Cryptographic

@par Directory contents

  - DRBG/RandomGeneration/Inc/stm32h7rsxx_nucleo_conf.h     BSP configuration file
  - DRBG/RandomGeneration/Inc/stm32h7rsxx_hal_conf.h    HAL configuration file
  - DRBG/RandomGeneration/Inc/stm32h7rsxx_it.h          Interrupt handlers header file
  - DRBG/RandomGeneration/Inc/main.h                        Header for main.c module
  - DRBG/RandomGeneration/Src/stm32h7rsxx_it.c          Interrupt handlers
  - DRBG/RandomGeneration/Src/stm32h7rsxx_hal_msp.c     HAL MSP module
  - DRBG/RandomGeneration/Src/main.c                        Main program
  - DRBG/RandomGeneration/Src/system_stm32h7rsxx.c      STM32H7RSxx system source file
  - DRBG/RandomGeneration/Src/cmox_low_level.c              CMOX low level services implementation

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
