/**
  @page SM4_CTR_EncryptDecrypt Cipher example

  @verbatim
  ******************************************************************************
  * @file    Applications/Cipher/SM4_CTR_EncryptDecrypt/readme.txt
  * @author  MCD Application Team
  * @brief   Description of the SM4_CTR_EncryptDecrypt example.
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
This example describes how to use the STM32 Cryptographic Library to perform encryption
and decryption using the SM4 CTR algorithm.

This example demonstrates two ways of using the cryptographic services:
1 - The single call method: algorithm configuration and execution is done via a single API call.
2 - The multiple calls method: algorithm configuration and execution is done in several API calls,
allowing in particular a piecemeal injection of data to process.

For each method, there are two examples provided:
a - An encryption of a known plaintext, followed by the verification of the generated ciphertext
b - An decryption of a known ciphertext, followed by the verification of the generated plaintext

In case of successful operations:
- the red led will be turned on
- the global variable glob_status will be set to PASSED
In case of failure:
- the red led will be toggled each 250 milliseconds in an infinity loop.
- the global variable glob_status will be set to FAILED

@note Vectors examples for SM4 CTR are taken from:
"The SM4 Blockcipher Algorithm And Its Modes Of Operations - draft-ribose-cfrg-sm4-10"
Available at:
 https://tools.ietf.org/html/draft-ribose-cfrg-sm4-10

@par Keywords

Cryptography, cipher, decipher, SM4, SM4CTR, Cryptographic

@par Directory contents

  - Cipher/SM4_CTR_EncryptDecrypt/Inc/stm32l5xx_nucleo_conf.h     BSP configuration file
  - Cipher/SM4_CTR_EncryptDecrypt/Inc/stm32l5xx_hal_conf.h    HAL configuration file
  - Cipher/SM4_CTR_EncryptDecrypt/Inc/stm32l5xx_it.h          Interrupt handlers header file
  - Cipher/SM4_CTR_EncryptDecrypt/Inc/main.h                        Header for main.c module
  - Cipher/SM4_CTR_EncryptDecrypt/Src/stm32l5xx_it.c          Interrupt handlers
  - Cipher/SM4_CTR_EncryptDecrypt/Src/stm32l5xx_hal_msp.c     HAL MSP module
  - Cipher/SM4_CTR_EncryptDecrypt/Src/main.c                        Main program
  - Cipher/SM4_CTR_EncryptDecrypt/Src/system_stm32l5xx.c      STM32L5xx system source file
  - Cipher/SM4_CTR_EncryptDecrypt/Src/cmox_low_level.c              CMOX low level services implementation

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
