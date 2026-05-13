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

  - ECC/SM2_SignVerify/Inc/stm32wbaxx_nucleo_conf.h     BSP configuration file
  - ECC/SM2_SignVerify/Inc/stm32wbaxx_hal_conf.h    HAL configuration file
  - ECC/SM2_SignVerify/Inc/stm32wbaxx_it.h          Interrupt handlers header file
  - ECC/SM2_SignVerify/Inc/main.h                        Header for main.c module
  - ECC/SM2_SignVerify/Src/stm32wbaxx_it.c          Interrupt handlers
  - ECC/SM2_SignVerify/Src/stm32wbaxx_hal_msp.c     HAL MSP module
  - ECC/SM2_SignVerify/Src/main.c                        Main program
  - ECC/SM2_SignVerify/Src/system_stm32wbaxx.c      STM32WBAxx system source file
  - ECC/SM2_SignVerify/Src/cmox_low_level.c              CMOX low level services implementation

@par Hardware and Software environment

  - This example runs on STM32WBAxx devices.

  - This example has been tested with NUCLEO-WBA52CG board and can be
    easily tailored to any other supported device and development board.

@par How to use it ?

In order to make the program work, you must do the following :
 - Open your preferred toolchain
 - Rebuild all files and load your image into target memory
 - Run the example

 * <h3><center>&copy; COPYRIGHT STMicroelectronics</center></h3>
 */
