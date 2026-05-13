/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2025 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include <string.h>
#include "main.h"
#include "cmox_crypto.h"

/* Global variables ----------------------------------------------------------*/
/* CTR context handle */
cmox_ctr_handle_t Ctr_Ctx;
BSEC_HandleTypeDef hbsec;
__IO TestStatus glob_status = FAILED;

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */

/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
#define CHUNK_SIZE  48u   /* Chunk size (in bytes) when data to encrypt or decrypt are processed by chunk */
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/

/* USER CODE BEGIN PV */
/** Extract from IETF draft-ribose-cfrg-sm4-10
  * A.2.5.  SM4-CTR Examples
  * A.2.5.1.  Example 1
   Plaintext:

   AA AA AA AA AA AA AA AA BB BB BB BB BB BB BB BB
   CC CC CC CC CC CC CC CC DD DD DD DD DD DD DD DD
   EE EE EE EE EE EE EE EE FF FF FF FF FF FF FF FF
   AA AA AA AA AA AA AA AA BB BB BB BB BB BB BB BB

   Encryption Key:

   01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10

   IV:

   00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F

   Ciphertext:

   AC 32 36 CB 97 0C C2 07 91 36 4C 39 5A 13 42 D1
   A3 CB C1 87 8C 6F 30 CD 07 4C CE 38 5C DD 70 C7
   F2 34 BC 0E 24 C1 19 80 FD 12 86 31 0C E3 7B 92
   6E 02 FC D0 FA A0 BA F3 8B 29 33 85 1D 82 45 14
  */
const uint8_t Key[] =
{
  0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
};
const uint8_t IV[] =
{
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};
const uint8_t Plaintext[] =
{
  0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
  0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
  0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB
};
const uint8_t Expected_Ciphertext[] =
{
  0xAC, 0x32, 0x36, 0xCB, 0x97, 0x0C, 0xC2, 0x07, 0x91, 0x36, 0x4C, 0x39, 0x5A, 0x13, 0x42, 0xD1,
  0xA3, 0xCB, 0xC1, 0x87, 0x8C, 0x6F, 0x30, 0xCD, 0x07, 0x4C, 0xCE, 0x38, 0x5C, 0xDD, 0x70, 0xC7,
  0xF2, 0x34, 0xBC, 0x0E, 0x24, 0xC1, 0x19, 0x80, 0xFD, 0x12, 0x86, 0x31, 0x0C, 0xE3, 0x7B, 0x92,
  0x6E, 0x02, 0xFC, 0xD0, 0xFA, 0xA0, 0xBA, 0xF3, 0x8B, 0x29, 0x33, 0x85, 0x1D, 0x82, 0x45, 0x14
};

/* Computed data buffer */
uint8_t Computed_Ciphertext[sizeof(Expected_Ciphertext)];
uint8_t Computed_Plaintext[sizeof(Plaintext)];
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
static void MPU_Config(void);
/* USER CODE BEGIN PFP */
void Error_Handler(void);

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{
  cmox_cipher_retval_t retval;
  size_t computed_size;
  /* General cipher context */
  cmox_cipher_handle_t *cipher_ctx;
  /* Index for piecemeal processing */
  uint32_t index;

  /* USER CODE BEGIN 1 */
  /* System clock already configured, simply SystemCoreClock init */
  SystemCoreClockUpdate();
  /* USER CODE END 1 */

  /* MPU Configuration--------------------------------------------------------*/
  MPU_Config();

  /* Enable the CPU Cache */

  /* Enable I-Cache---------------------------------------------------------*/
  SCB_EnableICache();

  /* Enable D-Cache---------------------------------------------------------*/
  SCB_EnableDCache();

  /* MCU Configuration--------------------------------------------------------*/
  HAL_Init();

  /* USER CODE BEGIN Init */
  /* Initialize LED1 */
  BSP_LED_Init(LED_GREEN);
  /* USER CODE END Init */

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  /* USER CODE BEGIN 2 */
  cmox_init_arg_t init_target = {CMOX_INIT_TARGET_AUTO, NULL};

  /* Configure LED2 */
  BSP_LED_Init(LED2);
  
  /* Debug opening in boot from Flash mode */
  hbsec.Instance = BSEC; 
  BSEC_DebugCfgTypeDef config_debug; 
  config_debug.HDPL_Open_Dbg = HAL_BSEC_OPEN_DBG_LEVEL_0; 
  config_debug.NonSec_Dbg_Auth = HAL_BSEC_NONSEC_DBG_AUTH; 
  config_debug.Sec_Dbg_Auth = HAL_BSEC_SEC_DBG_AUTH; 
  if(HAL_BSEC_ConfigDebug(&hbsec, &config_debug) != HAL_OK) 
  { 
    Error_Handler(); 
  } 
  if(HAL_BSEC_UnlockDebug(&hbsec) != HAL_OK) 
  { 
    Error_Handler(); 
  }

  /* Initialize cryptographic library */
  if (cmox_initialize(&init_target) != CMOX_INIT_SUCCESS)
  {
    Error_Handler();
  }

  /* --------------------------------------------------------------------------
   * SINGLE CALL USAGE
   * --------------------------------------------------------------------------
   */

  /* Compute directly the ciphertext passing all the needed parameters */
  retval = cmox_cipher_encrypt(CMOX_SM4_CTR_ENC_ALGO,                  /* Use SM4 CTR algorithm */
                               Plaintext, sizeof(Plaintext),           /* Plaintext to encrypt */
                               Key, sizeof(Key),                       /* AES key to use */
                               IV, sizeof(IV),                         /* Initialization vector */
                               Computed_Ciphertext, &computed_size);   /* Data buffer to receive generated ciphertext */

  /* Verify API returned value */
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    Error_Handler();
  }

  /* Verify generated data size is the expected one */
  if (computed_size != sizeof(Expected_Ciphertext))
  {
    Error_Handler();
  }

  /* Verify generated data are the expected ones */
  if (memcmp(Expected_Ciphertext, Computed_Ciphertext, computed_size) != 0)
  {
    Error_Handler();
  }

  /* Compute directly the plaintext passing all the needed parameters */
  retval = cmox_cipher_decrypt(CMOX_SM4_CTR_DEC_ALGO,                 /* Use SM4 CTR algorithm */
                               Expected_Ciphertext, sizeof(Expected_Ciphertext), /* Ciphertext to decrypt */
                               Key, sizeof(Key),                      /* AES key to use */
                               IV, sizeof(IV),                        /* Initialization vector */
                               Computed_Plaintext, &computed_size);   /* Data buffer to receive generated plaintext */

  /* Verify API returned value */
  if (retval != CMOX_CIPHER_SUCCESS)
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

  /* Construct a cipher context that is configured to perform SM4 CTR encryption operations */
  cipher_ctx = cmox_ctr_construct(&Ctr_Ctx, CMOX_SM4_CTR_ENC);
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

  /* Encrypt the plaintext in multiple steps by appending chunks of CHUNK_SIZE bytes */
  for (index = 0; index < (sizeof(Plaintext) - CHUNK_SIZE); index += CHUNK_SIZE)
  {
    retval = cmox_cipher_append(cipher_ctx,
                                &Plaintext[index], CHUNK_SIZE,        /* Chunk of plaintext to encrypt */
                                Computed_Ciphertext, &computed_size); /* Data buffer to receive generated
                                                                         chunk of ciphertext */

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
                                &Plaintext[index], sizeof(Plaintext) - index, /* Last part of plaintext to encrypt */
                                Computed_Ciphertext, &computed_size);         /* Data buffer to receive generated
                                                                                 last part of ciphertext */

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

  /* Cleanup the context */
  retval = cmox_cipher_cleanup(cipher_ctx);
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    Error_Handler();
  }

  /* Construct a cipher context that is configured to perform SM4 CTR decryption operations */
  cipher_ctx = cmox_ctr_construct(&Ctr_Ctx, CMOX_SM4_CTR_DEC);
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

  /* Decrypt the plaintext in multiple steps by appending chunks of CHUNK_SIZE bytes */
  for (index = 0; index < (sizeof(Expected_Ciphertext) - CHUNK_SIZE); index += CHUNK_SIZE)
  {
    retval = cmox_cipher_append(cipher_ctx,
                                &Expected_Ciphertext[index], CHUNK_SIZE,  /* Chunk of ciphertext to decrypt */
                                Computed_Plaintext, &computed_size);      /* Data buffer to receive generated
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
                                                                                         ciphertext to decrypt */
                                Computed_Plaintext, &computed_size);  /* Data buffer to receive generated last part
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

  /* Turn on LED2 in an infinite loop in case of AES CBC operations are successful */
  BSP_LED_On(LED2);
  glob_status = PASSED;
  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
  {
    /* Toggle LED1 every 250ms */
    BSP_LED_Toggle(LED_GREEN);
    HAL_Delay(250);
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
  }
  /* USER CODE END 3 */
}

/* USER CODE BEGIN 4 */

/* USER CODE END 4 */

 /* MPU Configuration */

void MPU_Config(void)
{
  MPU_Region_InitTypeDef MPU_InitStruct = {0};
  MPU_Attributes_InitTypeDef MPU_AttributesInit = {0};
  uint32_t primask_bit = __get_PRIMASK();
  __disable_irq();

  /* Disables the MPU */
  HAL_MPU_Disable();

  /** Initializes and configures the Region 0 and the memory to be protected
  */
  MPU_InitStruct.Enable = MPU_REGION_ENABLE;
  MPU_InitStruct.Number = MPU_REGION_NUMBER0;
  MPU_InitStruct.BaseAddress = __NON_CACHEABLE_SECTION_BEGIN;
  MPU_InitStruct.LimitAddress = __NON_CACHEABLE_SECTION_END;
  MPU_InitStruct.AttributesIndex = MPU_ATTRIBUTES_NUMBER0;
  MPU_InitStruct.AccessPermission = MPU_REGION_ALL_RW;
  MPU_InitStruct.DisableExec = MPU_INSTRUCTION_ACCESS_ENABLE;
  MPU_InitStruct.DisablePrivExec = MPU_PRIV_INSTRUCTION_ACCESS_ENABLE;
  MPU_InitStruct.IsShareable = MPU_ACCESS_NOT_SHAREABLE;

  HAL_MPU_ConfigRegion(&MPU_InitStruct);

  /** Initializes and configures the Attribute 0 and the memory to be protected
  */
  MPU_AttributesInit.Number = MPU_ATTRIBUTES_NUMBER0;
  MPU_AttributesInit.Attributes = INNER_OUTER(MPU_NOT_CACHEABLE);

  HAL_MPU_ConfigMemoryAttributes(&MPU_AttributesInit);
  /* Enables the MPU */
  HAL_MPU_Enable(MPU_HFNMI_PRIVDEF);

  /* Exit critical section to lock the system and avoid any issue around MPU mechanism */
  __set_PRIMASK(primask_bit);

}

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  /* Toggle LED2 @2Hz to notify error condition */
  while (1)
  {
    BSP_LED_Toggle(LED2);
    HAL_Delay(250);
  }
  /* USER CODE END Error_Handler_Debug */
}
#ifdef USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
