/**
  @page PKCS1v1.5_SignVerify RSA example

  @verbatim
  ******************************************************************************
  * @file    Applications/RSA/PKCS1v1.5_SignVerify/readme.txt
  * @author  MCD Application Team
  * @brief   Description of the PKCS1v1.5_SignVerify example.
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
This example describes how to use the STM32 Cryptographic Library to sign and verify
a message using the RSA PKCS#1 v1.5 compliant algorithm.

This example demonstrates how to use the library services to perform RSA operation
in a single call method: the configuration of the algorithm, and the operation
is done in one single API call.

This example is schedule as follow:
Preliminary - Generate digest of the known message
a - The signature of the known message digest using the regular private key representation (modulus + exponent),
    so that generated signature can be compared to the known signature
b - The signature of the known message digest using the chinese remainder theorem (CRT) private key representation,
    so that generated signature can be compared to the known signature
c - The verification of the message digest with the known signature

In case of successful operations:
- the red led will be turned on
- the global variable glob_status will be set to PASSED
In case of failure:
- the red led will be toggled each 250 milliseconds in an infinity loop.
- the global variable glob_status will be set to FAILED

@note This example uses the specific cmox_rsa_setKeyCRTwithFACM that allows to be protected
against the Bellcore attack. For more details on this attack, see https://eprint.iacr.org/2012/553.pdf

@note Vectors examples for RSA are taken from:
"pyca cryptography / pkcs1v15sign-vectors.txt"
Available at:
 https://github.com/pyca/cryptography/tree/master/vectors/cryptography_vectors/asymmetric/RSA

@par Keywords

Cryptography, authentication, RSA, PKCS1_V1.5, Cryptographic

@par Directory contents

  - RSA/PKCS1v1.5_SignVerify/Inc/stm32wlxx_nucleo_conf.h     BSP configuration file
  - RSA/PKCS1v1.5_SignVerify/Inc/stm32wlxx_hal_conf.h    HAL configuration file
  - RSA/PKCS1v1.5_SignVerify/Inc/stm32wlxx_it.h          Interrupt handlers header file
  - RSA/PKCS1v1.5_SignVerify/Inc/main.h                        Header for main.c module
  - RSA/PKCS1v1.5_SignVerify/Src/stm32wlxx_it.c          Interrupt handlers
  - RSA/PKCS1v1.5_SignVerify/Src/stm32wlxx_hal_msp.c     HAL MSP module
  - RSA/PKCS1v1.5_SignVerify/Src/main.c                        Main program
  - RSA/PKCS1v1.5_SignVerify/Src/system_stm32wlxx.c      STM32WLxx system source file
  - RSA/PKCS1v1.5_SignVerify/Src/cmox_low_level.c              CMOX low level services implementation

@par Hardware and Software environment

  - This example runs on STM32WLxx devices.

  - This example has been tested with NUCLEO-WL55JC RevC board and can be
    easily tailored to any other supported device and development board.

@par How to use it ?

In order to make the program work, you must do the following :
 - Open your preferred toolchain
 - Rebuild all files and load your image into target memory
 - Run the example

 * <h3><center>&copy; COPYRIGHT STMicroelectronics</center></h3>
 */
