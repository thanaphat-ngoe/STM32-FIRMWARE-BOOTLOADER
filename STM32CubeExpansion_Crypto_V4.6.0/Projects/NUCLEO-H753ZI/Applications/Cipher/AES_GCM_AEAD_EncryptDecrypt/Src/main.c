/**
  ******************************************************************************
  * @file    Cipher/AES_GCM_AEAD_EncryptDecrypt/Src/main.c
  * @author  MCD Application Team
  * @brief   This example provides a short description of how to use the
  *          STM32 Cryptographic Library
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2021 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file in
  * the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */

/* Includes ------------------------------------------------------------------*/
#include <string.h>
#include "main.h"
#include "cmox_crypto.h"

/* Global variables ----------------------------------------------------------*/
/* GCM context handle */
cmox_gcm_handle_t Gcm_Ctx;

__IO TestStatus glob_status = FAILED;
/* Private typedef -----------------------------------------------------------*/
/* Private defines -----------------------------------------------------------*/
#define CHUNK_SIZE  48u   /* Chunk size (in bytes) when data to encrypt or decrypt are processed by chunk */
/* Private macros ------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
/** Extract from NIST Special Publication 800-38D
  * gcmEncryptExtIV256.rsp
[Keylen = 128]
[IVlen = 96]
[PTlen = 408]
[AADlen = 384]
[Taglen = 128]

Count = 0
Key = 463b412911767d57a0b33969e674ffe7845d313b88c6fe312f3d724be68e1fca
IV = 611ce6f9a6880750de7da6cb
PT = e7d1dcf668e2876861940e012fe52a98dacbd78ab63c08842cc9801ea581682ad54af0c34d0d7f6f59e8ee0bf4900e0fd85042
AAD = 0a682fbc6192e1b47a5e0868787ffdafe5a50cead3575849990cdd2ea9b3597749403efb4a56684f0c6bde352d4aeec5
CT = 8886e196010cb3849d9c1a182abe1eeab0a5f3ca423c3669a4a8703c0f146e8e956fb122e0d721b869d2b6fcd4216d7d4d3758
Tag = 2469cecd70fd98fec9264f71df1aee9a
  */
const uint8_t Key[] =
{
  0x46, 0x3b, 0x41, 0x29, 0x11, 0x76, 0x7d, 0x57, 0xa0, 0xb3, 0x39, 0x69, 0xe6, 0x74, 0xff, 0xe7,
  0x84, 0x5d, 0x31, 0x3b, 0x88, 0xc6, 0xfe, 0x31, 0x2f, 0x3d, 0x72, 0x4b, 0xe6, 0x8e, 0x1f, 0xca
};
const uint8_t IV[] =
{
  0x61, 0x1c, 0xe6, 0xf9, 0xa6, 0x88, 0x07, 0x50, 0xde, 0x7d, 0xa6, 0xcb
};
const uint8_t Plaintext[] =
{
  0xe7, 0xd1, 0xdc, 0xf6, 0x68, 0xe2, 0x87, 0x68, 0x61, 0x94, 0x0e, 0x01, 0x2f, 0xe5, 0x2a, 0x98,
  0xda, 0xcb, 0xd7, 0x8a, 0xb6, 0x3c, 0x08, 0x84, 0x2c, 0xc9, 0x80, 0x1e, 0xa5, 0x81, 0x68, 0x2a,
  0xd5, 0x4a, 0xf0, 0xc3, 0x4d, 0x0d, 0x7f, 0x6f, 0x59, 0xe8, 0xee, 0x0b, 0xf4, 0x90, 0x0e, 0x0f,
  0xd8, 0x50, 0x42
};
const uint8_t AddData[] =
{
  0x0a, 0x68, 0x2f, 0xbc, 0x61, 0x92, 0xe1, 0xb4, 0x7a, 0x5e, 0x08, 0x68, 0x78, 0x7f, 0xfd, 0xaf,
  0xe5, 0xa5, 0x0c, 0xea, 0xd3, 0x57, 0x58, 0x49, 0x99, 0x0c, 0xdd, 0x2e, 0xa9, 0xb3, 0x59, 0x77,
  0x49, 0x40, 0x3e, 0xfb, 0x4a, 0x56, 0x68, 0x4f, 0x0c, 0x6b, 0xde, 0x35, 0x2d, 0x4a, 0xee, 0xc5
};
const uint8_t Expected_Ciphertext[] =
{
  0x88, 0x86, 0xe1, 0x96, 0x01, 0x0c, 0xb3, 0x84, 0x9d, 0x9c, 0x1a, 0x18, 0x2a, 0xbe, 0x1e, 0xea,
  0xb0, 0xa5, 0xf3, 0xca, 0x42, 0x3c, 0x36, 0x69, 0xa4, 0xa8, 0x70, 0x3c, 0x0f, 0x14, 0x6e, 0x8e,
  0x95, 0x6f, 0xb1, 0x22, 0xe0, 0xd7, 0x21, 0xb8, 0x69, 0xd2, 0xb6, 0xfc, 0xd4, 0x21, 0x6d, 0x7d,
  0x4d, 0x37, 0x58,
};
const uint8_t Expected_Tag[] =
{
  0x24, 0x69, 0xce, 0xcd, 0x70, 0xfd, 0x98, 0xfe, 0xc9, 0x26, 0x4f, 0x71, 0xdf, 0x1a, 0xee, 0x9a
};

/* Computed data buffer */
uint8_t Computed_Ciphertext[sizeof(Expected_Ciphertext) + sizeof(Expected_Tag)];
uint8_t Computed_Plaintext[sizeof(Plaintext)];

/* Private function prototypes -----------------------------------------------*/
static void SystemClock_Config(void);
static void CPU_CACHE_Enable(void);
static void Error_Handler(void);

/* Functions Definition ------------------------------------------------------*/

/**
  * @brief  Main program
  * @param  None
  * @retval None
  */
int main(void)
{
  cmox_cipher_retval_t retval;
  size_t computed_size;
  /* General cipher context */
  cmox_cipher_handle_t *cipher_ctx;
  /* Index for piecemeal processing */
  uint32_t index;
  /* Fault check verification variable */
  uint32_t fault_check = CMOX_CIPHER_AUTH_FAIL;

  
  /* Enable the CPU Cache */
  CPU_CACHE_Enable();
  /* STM32H7xx HAL library initialization:
       - Systick timer is configured by default as source of time base, but user 
         can eventually implement his proper time base source (a general purpose 
         timer for example or other time source), keeping in mind that Time base 
         duration should be kept 1ms since PPP_TIMEOUT_VALUEs are defined and 
         handled in milliseconds basis.
       - Set NVIC Group Priority to 4
       - Low Level Initialization
     */
  HAL_Init();

  /* Configure the System clock */
  SystemClock_Config();


  cmox_init_arg_t init_target = {CMOX_INIT_TARGET_AUTO, NULL};

  /* Configure LED2 */
  BSP_LED_Init(LED2);

  /* Initialize cryptographic library */
  if (cmox_initialize(&init_target) != CMOX_INIT_SUCCESS)
  {
    Error_Handler();
  }

  /* --------------------------------------------------------------------------
   * SINGLE CALL USAGE
   * --------------------------------------------------------------------------
   */
  /* Compute directly the ciphertext and tag passing all the needed parameters */
  /* Note: CMOX_AES_GCM_ENC_ALGO refer to the default AES implementation
   * selected in cmox_default_config.h. To use a specific implementation, user can
   * directly choose:
   * - CMOX_AESSMALL_GCMSMALL_ENC_ALGO to select the AES small and GCM small implementations
   * - CMOX_AESSMALL_GCMFAST_ENC_ALGO to select the AES small and GCM fast implementations
   * - CMOX_AESFAST_GCMSMALL_ENC_ALGO to select the AES fast and GCM small implementations
   * - CMOX_AESFAST_GCMFAST_ENC_ALGO to select the AES fast and GCM fast implementations
   */
  retval = cmox_aead_encrypt(CMOX_AES_GCM_ENC_ALGO,                  /* Use AES GCM algorithm */
                             Plaintext, sizeof(Plaintext),           /* Plaintext to encrypt */
                             sizeof(Expected_Tag),                   /* Authentication tag size */
                             Key, sizeof(Key),                       /* AES key to use */
                             IV, sizeof(IV),                         /* Initialization vector */
                             AddData, sizeof(AddData),               /* Additional authenticated data */
                             Computed_Ciphertext, &computed_size);   /* Data buffer to receive generated ciphertext
                                                                        and authentication tag */

  /* Verify API returned value */
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    Error_Handler();
  }

  /* Verify generated data size is the expected one */
  if (computed_size != (sizeof(Expected_Ciphertext) + sizeof(Expected_Tag)))
  {
    Error_Handler();
  }

  /* Verify generated data are the expected ones */
  if (memcmp(Expected_Ciphertext, Computed_Ciphertext, sizeof(Expected_Ciphertext)) != 0)
  {
    Error_Handler();
  }

  /* Verify generated authentication tag is the expected one */
  if (memcmp(Expected_Tag, &Computed_Ciphertext[sizeof(Expected_Ciphertext)], sizeof(Expected_Tag)) != 0)
  {
    Error_Handler();
  }

  /* Decrypt and verify directly ciphertext and tag passing all the needed parameters */
  /* Note: CMOX_AES_GCM_DEC_ALGO refer to the default AES implementation
   * selected in cmox_default_config.h. To use a specific implementation, user can
   * directly choose:
   * - CMOX_AESSMALL_GCMSMALL_DEC_ALGO to select the AES small and GCM small implementations
   * - CMOX_AESSMALL_GCMFAST_DEC_ALGO to select the AES small and GCM fast implementations
   * - CMOX_AESFAST_GCMSMALL_DEC_ALGO to select the AES fast and GCM small implementations
   * - CMOX_AESFAST_GCMFAST_DEC_ALGO to select the AES fast and GCM fast implementations
   */
  retval = cmox_aead_decrypt(CMOX_AES_GCM_DEC_ALGO,                  /* Use AES GCM algorithm */
                             Computed_Ciphertext, computed_size,     /* Ciphertext + tag to decrypt and verify */
                             sizeof(Expected_Tag),                   /* Authentication tag size */
                             Key, sizeof(Key),                       /* AES key to use */
                             IV, sizeof(IV),                         /* Initialization vector */
                             AddData, sizeof(AddData),               /* Additional authenticated data */
                             Computed_Plaintext, &computed_size);    /* Data buffer to receive generated plaintext */

  /* Verify API returned value */
  if (retval != CMOX_CIPHER_AUTH_SUCCESS)
  {
    Error_Handler();
  }

  /* Verify generated data size is the expected one */
  if (computed_size != sizeof(Plaintext))
  {
    Error_Handler();
  }

  /* Verify generated data are the expected ones */
  if (memcmp(Plaintext, Computed_Plaintext, computed_size) != 0)
  {
    Error_Handler();
  }

  /* --------------------------------------------------------------------------
   * MULTIPLE CALLS USAGE
   * --------------------------------------------------------------------------
   */

  /* Construct a cipher context that is configured to perform AES GCM encryption operations */
  /* Note: CMOX_AES_GCM_ENC refer to the default AES implementation
   * selected in cmox_default_config.h. To use a specific implementation, user can
   * directly choose:
   * - CMOX_AESSMALL_GCMSMALL_ENC to select the AES small and GCM small implementations
   * - CMOX_AESSMALL_GCMFAST_ENC to select the AES small and GCM fast implementations
   * - CMOX_AESFAST_GCMSMALL_ENC to select the AES fast and GCM small implementations
   * - CMOX_AESFAST_GCMFAST_ENC to select the AES fast and GCM fast implementations
   */
  cipher_ctx = cmox_gcm_construct(&Gcm_Ctx, CMOX_AES_GCM_ENC);
  if (cipher_ctx == NULL)
  {
    Error_Handler();
  }

  /* Initialize the cipher context */
  retval = cmox_cipher_init(cipher_ctx);
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    Error_Handler();
  }

  /* Setup of the authentication tag length into the context */
  retval = cmox_cipher_setTagLen(cipher_ctx, sizeof(Expected_Tag));  /* Authentication tag size */
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    Error_Handler();
  }

  /* Setup of the encryption key into the context */
  retval = cmox_cipher_setKey(cipher_ctx, Key, sizeof(Key));  /* AES key to use */
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    Error_Handler();
  }

  /* Setup of the Initialization Vector (IV) into the context */
  retval = cmox_cipher_setIV(cipher_ctx, IV, sizeof(IV));     /* Initialization vector */
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    Error_Handler();
  }

  /* Inject the additional authenticated data */
  retval = cmox_cipher_appendAD(cipher_ctx, AddData, sizeof(AddData));  /* Additional authenticated data */
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    Error_Handler();
  }

  /* Encrypt the plaintext in multiple steps by appending chunks of CHUNK_SIZE bytes */
  for (index = 0; index < (sizeof(Plaintext) - CHUNK_SIZE); index += CHUNK_SIZE)
  {
    retval = cmox_cipher_append(cipher_ctx,
                                &Plaintext[index], CHUNK_SIZE,    /* Chunk of plaintext to authenticate and encrypt */
                                Computed_Ciphertext, &computed_size);   /* Data buffer to receive generated chunk
                                                                           of ciphertext */

    /* Verify API returned value */
    if (retval != CMOX_CIPHER_SUCCESS)
    {
      Error_Handler();
    }

    /* Verify generated data size is the expected one */
    if (computed_size != CHUNK_SIZE)
    {
      Error_Handler();
    }

    /* Verify generated data are the expected ones */
    if (memcmp(&Expected_Ciphertext[index], Computed_Ciphertext, computed_size) != 0)
    {
      Error_Handler();
    }
  }
  /* Process with encryption of the last part if needed */
  if (index < sizeof(Plaintext))
  {
    retval = cmox_cipher_append(cipher_ctx,
                                &Plaintext[index], sizeof(Plaintext) - index,   /* Last part of plaintext to encrypt */
                                Computed_Ciphertext, &computed_size);   /* Data buffer to receive generated last part
                                                                           of ciphertext */

    /* Verify API returned value */
    if (retval != CMOX_CIPHER_SUCCESS)
    {
      Error_Handler();
    }

    /* Verify generated data size is the expected one */
    if (computed_size != (sizeof(Plaintext) - index))
    {
      Error_Handler();
    }

    /* Verify generated data are the expected ones */
    if (memcmp(&Expected_Ciphertext[index], Computed_Ciphertext, computed_size) != 0)
    {
      Error_Handler();
    }
  }
  /* Generate the authentication tag */
  retval = cmox_cipher_generateTag(cipher_ctx,
                                   Computed_Ciphertext, &computed_size);  /* Data buffer to receive
                                                                             the authentication tag */

  /* Verify API returned value */
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    Error_Handler();
  }

  /* Verify generated authentication tag size is the expected one */
  if (computed_size != sizeof(Expected_Tag))
  {
    Error_Handler();
  }

  /* Verify generated authentication tag is the expected one */
  if (memcmp(Expected_Tag, Computed_Ciphertext, computed_size) != 0)
  {
    Error_Handler();
  }

  /* Cleanup the context */
  retval = cmox_cipher_cleanup(cipher_ctx);
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    Error_Handler();
  }

  /* Construct a cipher context that is configured to perform AES GCM decryption operations */
  /* Note: CMOX_AES_GCM_DEC refer to the default AES implementation
   * selected in cmox_default_config.h. To use a specific implementation, user can
   * directly choose:
   * - CMOX_AESSMALL_GCMSMALL_DEC to select the AES small and GCM small implementations
   * - CMOX_AESSMALL_GCMFAST_DEC to select the AES small and GCM fast implementations
   * - CMOX_AESFAST_GCMSMALL_DEC to select the AES fast and GCM small implementations
   * - CMOX_AESFAST_GCMFAST_DEC to select the AES fast and GCM fast implementations
   */
  cipher_ctx = cmox_gcm_construct(&Gcm_Ctx, CMOX_AES_GCM_DEC);
  if (cipher_ctx == NULL)
  {
    Error_Handler();
  }

  /* Initialize the cipher context */
  retval = cmox_cipher_init(cipher_ctx);
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    Error_Handler();
  }

  /* Setup of the authentication tag length into the context */
  retval = cmox_cipher_setTagLen(cipher_ctx, sizeof(Expected_Tag));  /* Authentication tag size */
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    Error_Handler();
  }

  /* Setup of the decryption key into the context */
  retval = cmox_cipher_setKey(cipher_ctx, Key, sizeof(Key));  /* AES key to use */
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    Error_Handler();
  }

  /* Setup of the Initialization Vector (IV) into the context */
  retval = cmox_cipher_setIV(cipher_ctx, IV, sizeof(IV));     /* Initialization vector */
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    Error_Handler();
  }

  /* Inject the additional authenticated data */
  retval = cmox_cipher_appendAD(cipher_ctx, AddData, sizeof(AddData));  /* Additional authenticated data */
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    Error_Handler();
  }

  /* Decrypt the plaintext in multiple steps by appending chunks of CHUNK_SIZE bytes */
  for (index = 0; index < (sizeof(Expected_Ciphertext) - CHUNK_SIZE); index += CHUNK_SIZE)
  {
    retval = cmox_cipher_append(cipher_ctx,
                                &Expected_Ciphertext[index], CHUNK_SIZE, /* Chunk of ciphertext to decrypt and verify */
                                Computed_Plaintext, &computed_size);     /* Data buffer to receive generated
                                                                            chunk of plaintext */

    /* Verify API returned value */
    if (retval != CMOX_CIPHER_SUCCESS)
    {
      Error_Handler();
    }

    /* Verify generated data size is the expected one */
    if (computed_size != CHUNK_SIZE)
    {
      Error_Handler();
    }

    /* Verify generated data are the expected ones */
    if (memcmp(&Plaintext[index], Computed_Plaintext, computed_size) != 0)
    {
      Error_Handler();
    }
  }
  /* Process with encryption of the last part if needed */
  if (index < sizeof(Expected_Ciphertext))
  {
    retval = cmox_cipher_append(cipher_ctx,
                                &Expected_Ciphertext[index], sizeof(Expected_Ciphertext) - index, /* Last part of
                                                                                ciphertext to decrypt and verify */
                                Computed_Plaintext, &computed_size); /* Data buffer to receive generated last part
                                                                        of plaintext */

    /* Verify API returned value */
    if (retval != CMOX_CIPHER_SUCCESS)
    {
      Error_Handler();
    }

    /* Verify generated data size is the expected one */
    if (computed_size != (sizeof(Expected_Ciphertext) - index))
    {
      Error_Handler();
    }

    /* Verify generated data are the expected ones */
    if (memcmp(&Plaintext[index], Computed_Plaintext, computed_size) != 0)
    {
      Error_Handler();
    }
  }

  /* Verify the authentication tag */
  retval = cmox_cipher_verifyTag(cipher_ctx,
                                 Expected_Tag,      /* Authentication tag used for verification */
                                 &fault_check);     /* Fault check variable:
                                                       to ensure no fault injection occurs during this API call */

  /* Verify API returned value */
  if (retval != CMOX_CIPHER_AUTH_SUCCESS)
  {
    Error_Handler();
  }
  /* Verify Fault check variable value */
  if (fault_check != CMOX_CIPHER_AUTH_SUCCESS)
  {
    Error_Handler();
  }

  /* Cleanup the handle */
  retval = cmox_cipher_cleanup(cipher_ctx);
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    Error_Handler();
  }


  /* No more need of cryptographic services, finalize cryptographic library */
  if (cmox_finalize(NULL) != CMOX_INIT_SUCCESS)
  {
    Error_Handler();
  }

  /* Turn on LED2 in an infinite loop in case of AES GCM operations are successful */
  BSP_LED_On(LED2);
  glob_status = PASSED;
  while (1)
  {}
}

/**
  * @brief  System Clock Configuration
  *         The system Clock is configured as follow : 
  *            System Clock source            = PLL (HSE BYPASS)
  *            SYSCLK(Hz)                     = 400000000 (CPU Clock)
  *            HCLK(Hz)                       = 200000000 (AXI and AHBs Clock)
  *            AHB Prescaler                  = 2
  *            D1 APB3 Prescaler              = 2 (APB3 Clock  100MHz)
  *            D2 APB1 Prescaler              = 2 (APB1 Clock  100MHz)
  *            D2 APB2 Prescaler              = 2 (APB2 Clock  100MHz)
  *            D3 APB4 Prescaler              = 2 (APB4 Clock  100MHz)
  *            HSE Frequency(Hz)              = 8000000
  *            PLL_M                          = 4
  *            PLL_N                          = 400
  *            PLL_P                          = 2
  *            PLL_Q                          = 4
  *            PLL_R                          = 2
  *            VDD(V)                         = 3.3
  *            Flash Latency(WS)              = 4
  * @param  None
  * @retval None
  */
static void SystemClock_Config(void)
{
  RCC_ClkInitTypeDef RCC_ClkInitStruct;
  RCC_OscInitTypeDef RCC_OscInitStruct;
  HAL_StatusTypeDef ret = HAL_OK;
  
  /*!< Supply configuration update enable */
  HAL_PWREx_ConfigSupply(PWR_LDO_SUPPLY);

  /* The voltage scaling allows optimizing the power consumption when the device is
     clocked below the maximum system frequency, to update the voltage scaling value
     regarding system frequency refer to product datasheet.  */
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

  while(!__HAL_PWR_GET_FLAG(PWR_FLAG_VOSRDY)) {}
  
  /* Enable HSE Oscillator and activate PLL with HSE as source */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_BYPASS;
  RCC_OscInitStruct.HSIState = RCC_HSI_OFF;
  RCC_OscInitStruct.CSIState = RCC_CSI_OFF;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;

  RCC_OscInitStruct.PLL.PLLM = 4;
  RCC_OscInitStruct.PLL.PLLN = 400;
  RCC_OscInitStruct.PLL.PLLFRACN = 0;
  RCC_OscInitStruct.PLL.PLLP = 2;
  RCC_OscInitStruct.PLL.PLLR = 2;
  RCC_OscInitStruct.PLL.PLLQ = 4;

  RCC_OscInitStruct.PLL.PLLVCOSEL = RCC_PLL1VCOWIDE;
  RCC_OscInitStruct.PLL.PLLRGE = RCC_PLL1VCIRANGE_2;
  ret = HAL_RCC_OscConfig(&RCC_OscInitStruct);
  if(ret != HAL_OK)
  {
    Error_Handler();
  }
  
/* Select PLL as system clock source and configure  bus clocks dividers */
  RCC_ClkInitStruct.ClockType = (RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_D1PCLK1 | RCC_CLOCKTYPE_PCLK1 | \
                                 RCC_CLOCKTYPE_PCLK2  | RCC_CLOCKTYPE_D3PCLK1);

  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.SYSCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_HCLK_DIV2;
  RCC_ClkInitStruct.APB3CLKDivider = RCC_APB3_DIV2;  
  RCC_ClkInitStruct.APB1CLKDivider = RCC_APB1_DIV2; 
  RCC_ClkInitStruct.APB2CLKDivider = RCC_APB2_DIV2; 
  RCC_ClkInitStruct.APB4CLKDivider = RCC_APB4_DIV2; 
  ret = HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_4);
  if(ret != HAL_OK)
  {
    Error_Handler();
  }

/*
  Note : The activation of the I/O Compensation Cell is recommended with communication  interfaces
          (GPIO, SPI, FMC, QSPI ...)  when  operating at  high frequencies(please refer to product datasheet)       
          The I/O Compensation Cell activation  procedure requires :
        - The activation of the CSI clock
        - The activation of the SYSCFG clock
        - Enabling the I/O Compensation Cell : setting bit[0] of register SYSCFG_CCCSR
  
          To do this please uncomment the following code 
*/
 
  /*  
  __HAL_RCC_CSI_ENABLE() ;
  
  __HAL_RCC_SYSCFG_CLK_ENABLE() ;
  
  HAL_EnableCompensationCell();
  */ 
	
}


/**
  * @brief  CPU L1-Cache enable.
  * @param  None
  * @retval None
  */
static void CPU_CACHE_Enable(void)
{
  /* Enable I-Cache */
  SCB_EnableICache();

  /* Enable D-Cache */
  SCB_EnableDCache();
}

/**
  * @brief  This function is executed in case of error occurrence
  * @param  None
  * @retval None
  */
static void Error_Handler(void)
{
  /* User may add here some code to deal with this error */
  /* Toggle LED2 @2Hz to notify error condition */
  while (1)
  {
    BSP_LED_Toggle(LED2);
    HAL_Delay(250);
  }
}

#ifdef USE_FULL_ASSERT

/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */

  /* Infinite loop */
  while (1)
  {}
}
#endif /* USE_FULL_ASSERT */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
