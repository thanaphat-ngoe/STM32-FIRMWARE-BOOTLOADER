/**
  @page SHA2_Digest Hash example

  @verbatim
  ******************************************************************************
  * @file    Applications/Hash/SHA2_Digest/readme.txt
  * @author  MCD Application Team
  * @brief   Description of the SHA2_Digest example.
  ******************************************************************************
  *
  * Copyright (c) 2020 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file in
  * the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
   @endverbatim

@par Example Description
This example describes how to use the STM32 Cryptographic Library to hash a message
using the SHA256 algorithm.

This example demonstrates two ways of using the cryptographic services:
1 - The single call method: algorithm configuration and execution is done via a single API cal.
2 - The multiple calls method: algorithm configuration and execution is done in several API calls,
allowing in particular a piecemeal injection of data to process.

For each method, there is on example provided:
a - A hashing of a known message, followed by the verification of the generated digest

In case of successful operations:
- the red led will be turned on
- the global variable glob_status will be set to PASSED
In case of failure:
- the red led will be toggled each 250 milliseconds in an infinity loop.
- the global variable glob_status will be set to FAILED

@note NIST vectors examples for SHA2 are taken from:
"SHA Test Vectors for Hashing Byte-Oriented Messages"
Available at:
 https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing

@par Keywords

Cryptography, digest, SHA256, Cryptographic

@par Directory contents

  - Hash/SHA2_Digest/Inc/stm32l5xx_nucleo_conf.h     BSP configuration file
  - Hash/SHA2_Digest/Inc/stm32l5xx_hal_conf.h    HAL configuration file
  - Hash/SHA2_Digest/Inc/stm32l5xx_it.h          Interrupt handlers header file
  - Hash/SHA2_Digest/Inc/main.h                        Header for main.c module
  - Hash/SHA2_Digest/Src/stm32l5xx_it.c          Interrupt handlers
  - Hash/SHA2_Digest/Src/stm32l5xx_hal_msp.c     HAL MSP module
  - Hash/SHA2_Digest/Src/main.c                        Main program
  - Hash/SHA2_Digest/Src/system_stm32l5xx.c      STM32L5xx system source file
  - Hash/SHA2_Digest/Src/cmox_low_level.c              CMOX low level services implementation

@par Hardware and Software environment

  - This example runs on STM32L5xx devices.

  - This example has been tested with NUCLEO-L552ZE-Q board and can be
    easily tailored to any other supported device and development board.

@par How to use it ?

In order to make the program work, you must do the following :
 - Open your preferred toolchain
 - Rebuild all files and load your image into target memory
 - Run the example

 * <h3><center>&copy; COPYRIGHT STMicroelectronics</center></h3>
 */
