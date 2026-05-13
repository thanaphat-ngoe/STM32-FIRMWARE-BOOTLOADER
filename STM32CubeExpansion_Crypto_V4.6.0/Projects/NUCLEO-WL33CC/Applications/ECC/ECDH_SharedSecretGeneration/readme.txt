/**
  @page ECDH_SharedSecretGeneration ECC example

  @verbatim
  ******************************************************************************
  * @file    Applications/ECC/ECDH_SharedSecretGeneration/readme.txt
  * @author  MCD Application Team
  * @brief   Description of the ECDH_SharedSecretGeneration example.
  ******************************************************************************
  *
  * Copyright (c) 2024 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file in
  * the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
   @endverbatim

@par Example Description
This example describes how to use the STM32 Cryptographic Library to establish
a shared secret using the ECDH algorithm over SECP256R1 curve.

This example demonstrates how to use the predefined curves parameters to perform
ECC operation in a single call method: the configuration of the algorithm, and the operation
is done in one single API call.

This example is schedule as follow:
a - Using known remote public key and known local private, establish the shared secret
b - Shared secret is composed of 2 coordinates X & Y. Compare the generated secret X coordinate with the expected one

In case of successful operations:
- the red led will be turned on
- the global variable glob_status will be set to PASSED
In case of failure:
- the red led will be toggled each 250 milliseconds in an infinity loop.
- the global variable glob_status will be set to FAILED

@note NIST vectors examples for ECDH are taken from:
"SP 800-56A / ECCCDH Primitive Test Vectors"
Available at:
 https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/Component-Testing

@par Keywords

Cryptography, ECDH shared secret, Cryptographic

@par Directory contents

  - ECC/ECDH_SharedSecretGeneration/Inc/stm32wl3x_nucleo_conf.h     BSP configuration file
  - ECC/ECDH_SharedSecretGeneration/Inc/stm32wl3x_hal_conf.h    HAL configuration file
  - ECC/ECDH_SharedSecretGeneration/Inc/stm32wl3x_it.h          Interrupt handlers header file
  - ECC/ECDH_SharedSecretGeneration/Inc/main.h                        Header for main.c module
  - ECC/ECDH_SharedSecretGeneration/Src/stm32wl3x_it.c          Interrupt handlers
  - ECC/ECDH_SharedSecretGeneration/Src/stm32wl3x_hal_msp.c     HAL MSP module
  - ECC/ECDH_SharedSecretGeneration/Src/main.c                        Main program
  - ECC/ECDH_SharedSecretGeneration/Src/system_stm32wl3x.c      STM32WL3x system source file
  - ECC/ECDH_SharedSecretGeneration/Src/cmox_low_level.c              CMOX low level services implementation

@par Hardware and Software environment

  - This example runs on STM32WL3x devices.

  - This example has been tested with NUCLEO-WL33CC board and can be
    easily tailored to any other supported device and development board.

@par How to use it ?

In order to make the program work, you must do the following :
 - Open your preferred toolchain
 - Rebuild all files and load your image into target memory
 - Run the example

 * <h3><center>&copy; COPYRIGHT STMicroelectronics</center></h3>
 */
