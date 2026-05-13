/**
  @page EDDSA_SignVerify ECC example

  @verbatim
  ******************************************************************************
  * @file    Applications/ECC/EDDSA_SignVerify/readme.txt
  * @author  MCD Application Team
  * @brief   Description of the EDDSA_SignVerify example.
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
This example describes how to use the STM32 Cryptographic Library to sign and verify
a message using the EdDSA algorithm over Ed25519 curve.

This example demonstrates how to use the predefined curves parameters to perform
ECC operation in a single call method: the configuration of the algorithm, and the operation
is done in one single API call.

This example is schedule as follow:
a - The signature of the known message, so that generated signature can be compared
    to the known signature
b - The verification of the know message with the known signature

In case of successful operations:
- the green led will be turned on
- the global variable glob_status will be set to PASSED
In case of failure:
- the green led will be toggled each 250 milliseconds in an infinity loop.
- the global variable glob_status will be set to FAILED

@note Vectors examples for EdDSA are taken from:
"Edwards-Curve Digital Signature Algorithm (EdDSA)"
Available at:
 https://tools.ietf.org/html/rfc8032

@par Keywords

Cryptography, authentication, EdDSA, Cryptographic

@par Directory contents

  - ECC/EDDSA_SignVerify/Inc/stm32l4xx_hal_conf.h    HAL configuration file
  - ECC/EDDSA_SignVerify/Inc/stm32l4xx_it.h          Interrupt handlers header file
  - ECC/EDDSA_SignVerify/Inc/main.h                        Header for main.c module
  - ECC/EDDSA_SignVerify/Src/stm32l4xx_it.c          Interrupt handlers
  - ECC/EDDSA_SignVerify/Src/stm32l4xx_hal_msp.c     HAL MSP module
  - ECC/EDDSA_SignVerify/Src/main.c                        Main program
  - ECC/EDDSA_SignVerify/Src/system_stm32l4xx.c      STM32L4xx system source file
  - ECC/EDDSA_SignVerify/Src/cmox_low_level.c              CMOX low level services implementation

@par Hardware and Software environment

  - This example runs on STM32L4xx devices.

  - This example has been tested with STM32L476RG-Nucleo Rev C board and can be
    easily tailored to any other supported device and development board.

@par How to use it ?

In order to make the program work, you must do the following :
 - Open your preferred toolchain
 - Rebuild all files and load your image into target memory
 - Run the example

 * <h3><center>&copy; COPYRIGHT STMicroelectronics</center></h3>
 */
