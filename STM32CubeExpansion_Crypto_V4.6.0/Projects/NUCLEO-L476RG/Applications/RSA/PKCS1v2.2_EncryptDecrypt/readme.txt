/**
  @page PKCS1v2.2_EncryptDecrypt RSA example

  @verbatim
  ******************************************************************************
  * @file    Applications/RSA/PKCS1v2.2_EncryptDecrypt/readme.txt
  * @author  MCD Application Team
  * @brief   Description of the PKCS1v2.2_EncryptDecrypt example.
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
This example describes how to use the STM32 Cryptographic Library to encrypt and decrypt
a message using the RSA PKCS#1 v2.2 compliant algorithm.

This example demonstrates how to use the library services to perform RSA operation
in a single call method: the configuration of the algorithm, and the operation
is done in one single API call.

This example is schedule as follow:
Preliminary - Generate digest of the known message
a - The decryption of the known message using the regular private key representation (modulus + exponent),
    so that generated clear message can be compared to the known message
b - The decryption of the known message digest using the chinese remainder theorem (CRT) private key representation,
    so that generated clear message can be compared to the known message
c - The encryption of a known message, so that generated clear message can be compared to the known encrypted text

In case of successful operations:
- the green led will be turned on
- the global variable glob_status will be set to PASSED
In case of failure:
- the green led will be toggled each 250 milliseconds in an infinity loop.
- the global variable glob_status will be set to FAILED

@note Vectors examples for RSA are taken from:
"pyca cryptography / pkcs-1v2-1d2-vec/oaep-vect.txt"
Available at:
 https://github.com/pyca/cryptography/tree/master/vectors/cryptography_vectors/asymmetric/RSA

@par Keywords

Cryptography, cipher, decipher, RSA, PKCS1_V2.2, Cryptographic

@par Directory contents

  - RSA/PKCS1v2.2_EncryptDecrypt/Inc/stm32l4xx_hal_conf.h    HAL configuration file
  - RSA/PKCS1v2.2_EncryptDecrypt/Inc/stm32l4xx_it.h          Interrupt handlers header file
  - RSA/PKCS1v2.2_EncryptDecrypt/Inc/main.h                        Header for main.c module
  - RSA/PKCS1v2.2_EncryptDecrypt/Src/stm32l4xx_it.c          Interrupt handlers
  - RSA/PKCS1v2.2_EncryptDecrypt/Src/stm32l4xx_hal_msp.c     HAL MSP module
  - RSA/PKCS1v2.2_EncryptDecrypt/Src/main.c                        Main program
  - RSA/PKCS1v2.2_EncryptDecrypt/Src/system_stm32l4xx.c      STM32L4xx system source file
  - RSA/PKCS1v2.2_EncryptDecrypt/Src/cmox_low_level.c              CMOX low level services implementation

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
