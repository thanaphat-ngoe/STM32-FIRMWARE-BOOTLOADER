/**
  @page HMAC_SHA2_AuthenticateVerify MAC example

  @verbatim
  ******************************************************************************
  * @file    Applications/MAC/HMAC_SHA2_AuthenticateVerify/readme.txt
  * @author  MCD Application Team
  * @brief   Description of the HMAC_SHA2_AuthenticateVerify example.
  ******************************************************************************
  *
  * Copyright (c) 2021 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file in
  * the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
   @endverbatim

@par Example Description
This example describes how to use the STM32 Cryptographic Library to generate and verify
a message authentication code (MAC) of a plaintext using the HMAC-SHA256 algorithm.

This example demonstrates two ways of using the cryptographic services:
1 - The single call method: algorithm configuration and execution is done via a single API call.
2 - The multiple calls method: algorithm configuration and execution is done in several API calls,
allowing in particular a piecemeal injection of data to process.

For each method, there are two examples provided:
a - A generation of the MAC of a known message, followed by the verification of it.
b - A verification of the message using the given authentication tag

In case of successful operations:
- the red led will be turned on
- the global variable glob_status will be set to PASSED
In case of failure:
- the red led will be toggled each 250 milliseconds in an infinity loop.
- the global variable glob_status will be set to FAILED

@note NIST vectors examples for HMAC are taken from:
"Test Vectors"
Available at:
 https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/message-authentication

@par Keywords

Cryptography, authentication, HMAC, SHA256, Cryptographic

@par Directory contents

  - MAC/HMAC_SHA2_AuthenticateVerify/Inc/stm32u5xx_nucleo_conf.h     BSP configuration file
  - MAC/HMAC_SHA2_AuthenticateVerify/Inc/stm32u5xx_hal_conf.h    HAL configuration file
  - MAC/HMAC_SHA2_AuthenticateVerify/Inc/stm32u5xx_it.h          Interrupt handlers header file
  - MAC/HMAC_SHA2_AuthenticateVerify/Inc/main.h                        Header for main.c module
  - MAC/HMAC_SHA2_AuthenticateVerify/Src/stm32u5xx_it.c          Interrupt handlers
  - MAC/HMAC_SHA2_AuthenticateVerify/Src/stm32u5xx_hal_msp.c     HAL MSP module
  - MAC/HMAC_SHA2_AuthenticateVerify/Src/main.c                        Main program
  - MAC/HMAC_SHA2_AuthenticateVerify/Src/system_stm32u5xx.c      STM32U5xx system source file
  - MAC/HMAC_SHA2_AuthenticateVerify/Src/cmox_low_level.c              CMOX low level services implementation

@par Hardware and Software environment

  - This example runs on STM32U5xx devices.

  - This example has been tested with NUCLEO-U575ZI-Q board and can be
    easily tailored to any other supported device and development board.

@par How to use it ?

In order to make the program work, you must do the following :
 - Open your preferred toolchain
 - Rebuild all files and load your image into target memory
 - Run the example

 * <h3><center>&copy; COPYRIGHT STMicroelectronics</center></h3>
 */
