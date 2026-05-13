/**
  @page RandomGeneration DRBG example

  @verbatim
  ******************************************************************************
  * @file    Applications/DRBG/RandomGeneration/readme.txt
  * @author  MCD Application Team
  * @brief   Description of the RandomGeneration example.
  ******************************************************************************
  *
  * Copyright (c) 2018 STMicroelectronics.
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
- the yellow led will be turned on
- the global variable glob_status will be set to PASSED
In case of failure:
- the yellow led will be toggled each 250 milliseconds in an infinity loop.
- the global variable glob_status will be set to FAILED

@note NIST vectors examples for DRGB are taken from:
"Test Vectors"
Available at:
 https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/random-number-generators

@par Keywords

Cryptography, random, DRBG, Cryptographic

@par Directory contents

  - DRBG/RandomGeneration/Inc/stm32h7xx_hal_conf.h    HAL configuration file
  - DRBG/RandomGeneration/Inc/stm32h7xx_it.h          Interrupt handlers header file
  - DRBG/RandomGeneration/Inc/main.h                        Header for main.c module
  - DRBG/RandomGeneration/Src/stm32h7xx_it.c          Interrupt handlers
  - DRBG/RandomGeneration/Src/stm32h7xx_hal_msp.c     HAL MSP module
  - DRBG/RandomGeneration/Src/main.c                        Main program
  - DRBG/RandomGeneration/Src/system_stm32h7xx.c      STM32H7xx system source file
  - DRBG/RandomGeneration/Src/cmox_low_level.c              CMOX low level services implementation

@par Hardware and Software environment

  - This example runs on STM32H7xx devices.

  - This example has been tested with STM32H753ZI-Nucleo board and can be
    easily tailored to any other supported device and development board.

@par How to use it ?

In order to make the program work, you must do the following :
 - Open your preferred toolchain
 - Rebuild all files and load your image into target memory
 - Run the example

 * <h3><center>&copy; COPYRIGHT STMicroelectronics</center></h3>
 */
