/**
  @page ECDSA_SignVerify ECC example

  @verbatim
  ******************************************************************************
  * @file    Applications/ECC/ECDSA_SignVerify/readme.txt
  * @author  MCD Application Team
  * @brief   Description of the ECDSA_SignVerify example.
  ******************************************************************************
  *
  * Copyright (c) 2019 STMicroelectronics.
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
a message using the ECDSA algorithm over SECP256R1 curve.

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
- the green led will be turned on
- the global variable glob_status will be set to PASSED
In case of failure:
- the green led will be toggled each 250 milliseconds in an infinity loop.
- the global variable glob_status will be set to FAILED

@note NIST vectors examples for ECDSA are taken from:
"ECDSA Test vectors / FIPS 186-4"
Available at:
 https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures

@par Keywords

Cryptography, authentication, ECDSA, Cryptographic

@par Directory contents

  - ECC/ECDSA_SignVerify/Inc/stm32g4xx_nucleo_conf.h     BSP configuration file
  - ECC/ECDSA_SignVerify/Inc/stm32g4xx_hal_conf.h    HAL configuration file
  - ECC/ECDSA_SignVerify/Inc/stm32g4xx_it.h          Interrupt handlers header file
  - ECC/ECDSA_SignVerify/Inc/main.h                        Header for main.c module
  - ECC/ECDSA_SignVerify/Src/stm32g4xx_it.c          Interrupt handlers
  - ECC/ECDSA_SignVerify/Src/stm32g4xx_hal_msp.c     HAL MSP module
  - ECC/ECDSA_SignVerify/Src/main.c                        Main program
  - ECC/ECDSA_SignVerify/Src/system_stm32g4xx.c      STM32G4xx system source file
  - ECC/ECDSA_SignVerify/Src/cmox_low_level.c              CMOX low level services implementation

@par Hardware and Software environment

  - This example runs on STM32G4xx devices.

  - This example has been tested with NUCLEO-G474RE RevC board and can be
    easily tailored to any other supported device and development board.

@par How to use it ?

In order to make the program work, you must do the following :
 - Open your preferred toolchain
 - Rebuild all files and load your image into target memory
 - Run the example

 * <h3><center>&copy; COPYRIGHT STMicroelectronics</center></h3>
 */
