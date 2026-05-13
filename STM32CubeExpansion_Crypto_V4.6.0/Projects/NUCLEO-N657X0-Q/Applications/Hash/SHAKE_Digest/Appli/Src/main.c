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
/* SHA3 context handle is used for SHAKE */
cmox_sha3_handle_t sha3_ctx;
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
#define CHUNK_SIZE  48u   /* Chunk size (in bytes) when data to hash are processed by chunk */
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/

/* USER CODE BEGIN PV */
/** Extract from SHAKE128LongMsg.rsp
  *

Len = 2696
Msg = a6fe00064257aa318b621c5eb311d32bb8004c2fa1a969d205d71762cc5d2e633907992629d1b69d9557ff6d5e8deb4
54ab00f6e497c89a4fea09e257a6fa2074bd818ceb5981b3e3faefd6e720f2d1edd9c5e4a5c51e5009abf636ed5bca53fe159
c8287014a1bd904f5c8a7501625f79ac81eb618f478ce21cae6664acffb30572f059e1ad0fc2912264e8f1ca52af26c8bf78e
09d75f3dd9fc734afa8770abe0bd78c90cc2ff448105fb16dd2c5b7edd8611a62e537db9331f5023e16d6ec150cc6e706d7c7
fcbfff930c7281831fd5c4aff86ece57ed0db882f59a5fe403105d0592ca38a081fed84922873f538ee774f13b8cc09bd0521
db4374aec69f4bae6dcb66455822c0b84c91a3474ffac2ad06f0a4423cd2c6a49d4f0d6242d6a1890937b5d9835a5f0ea5b1d
01884d22a6c1718e1f60b3ab5e232947c76ef70b344171083c688093b5f1475377e3069863
Output = 3109d9472ca436e805c6b3db2251a9bc

  */
const uint8_t Message[] =
{
  0xa6, 0xfe, 0x00, 0x06, 0x42, 0x57, 0xaa, 0x31, 0x8b, 0x62, 0x1c, 0x5e, 0xb3, 0x11, 0xd3, 0x2b,
  0xb8, 0x00, 0x4c, 0x2f, 0xa1, 0xa9, 0x69, 0xd2, 0x05, 0xd7, 0x17, 0x62, 0xcc, 0x5d, 0x2e, 0x63,
  0x39, 0x07, 0x99, 0x26, 0x29, 0xd1, 0xb6, 0x9d, 0x95, 0x57, 0xff, 0x6d, 0x5e, 0x8d, 0xeb, 0x45,
  0x4a, 0xb0, 0x0f, 0x6e, 0x49, 0x7c, 0x89, 0xa4, 0xfe, 0xa0, 0x9e, 0x25, 0x7a, 0x6f, 0xa2, 0x07,
  0x4b, 0xd8, 0x18, 0xce, 0xb5, 0x98, 0x1b, 0x3e, 0x3f, 0xae, 0xfd, 0x6e, 0x72, 0x0f, 0x2d, 0x1e,
  0xdd, 0x9c, 0x5e, 0x4a, 0x5c, 0x51, 0xe5, 0x00, 0x9a, 0xbf, 0x63, 0x6e, 0xd5, 0xbc, 0xa5, 0x3f,
  0xe1, 0x59, 0xc8, 0x28, 0x70, 0x14, 0xa1, 0xbd, 0x90, 0x4f, 0x5c, 0x8a, 0x75, 0x01, 0x62, 0x5f,
  0x79, 0xac, 0x81, 0xeb, 0x61, 0x8f, 0x47, 0x8c, 0xe2, 0x1c, 0xae, 0x66, 0x64, 0xac, 0xff, 0xb3,
  0x05, 0x72, 0xf0, 0x59, 0xe1, 0xad, 0x0f, 0xc2, 0x91, 0x22, 0x64, 0xe8, 0xf1, 0xca, 0x52, 0xaf,
  0x26, 0xc8, 0xbf, 0x78, 0xe0, 0x9d, 0x75, 0xf3, 0xdd, 0x9f, 0xc7, 0x34, 0xaf, 0xa8, 0x77, 0x0a,
  0xbe, 0x0b, 0xd7, 0x8c, 0x90, 0xcc, 0x2f, 0xf4, 0x48, 0x10, 0x5f, 0xb1, 0x6d, 0xd2, 0xc5, 0xb7,
  0xed, 0xd8, 0x61, 0x1a, 0x62, 0xe5, 0x37, 0xdb, 0x93, 0x31, 0xf5, 0x02, 0x3e, 0x16, 0xd6, 0xec,
  0x15, 0x0c, 0xc6, 0xe7, 0x06, 0xd7, 0xc7, 0xfc, 0xbf, 0xff, 0x93, 0x0c, 0x72, 0x81, 0x83, 0x1f,
  0xd5, 0xc4, 0xaf, 0xf8, 0x6e, 0xce, 0x57, 0xed, 0x0d, 0xb8, 0x82, 0xf5, 0x9a, 0x5f, 0xe4, 0x03,
  0x10, 0x5d, 0x05, 0x92, 0xca, 0x38, 0xa0, 0x81, 0xfe, 0xd8, 0x49, 0x22, 0x87, 0x3f, 0x53, 0x8e,
  0xe7, 0x74, 0xf1, 0x3b, 0x8c, 0xc0, 0x9b, 0xd0, 0x52, 0x1d, 0xb4, 0x37, 0x4a, 0xec, 0x69, 0xf4,
  0xba, 0xe6, 0xdc, 0xb6, 0x64, 0x55, 0x82, 0x2c, 0x0b, 0x84, 0xc9, 0x1a, 0x34, 0x74, 0xff, 0xac,
  0x2a, 0xd0, 0x6f, 0x0a, 0x44, 0x23, 0xcd, 0x2c, 0x6a, 0x49, 0xd4, 0xf0, 0xd6, 0x24, 0x2d, 0x6a,
  0x18, 0x90, 0x93, 0x7b, 0x5d, 0x98, 0x35, 0xa5, 0xf0, 0xea, 0x5b, 0x1d, 0x01, 0x88, 0x4d, 0x22,
  0xa6, 0xc1, 0x71, 0x8e, 0x1f, 0x60, 0xb3, 0xab, 0x5e, 0x23, 0x29, 0x47, 0xc7, 0x6e, 0xf7, 0x0b,
  0x34, 0x41, 0x71, 0x08, 0x3c, 0x68, 0x80, 0x93, 0xb5, 0xf1, 0x47, 0x53, 0x77, 0xe3, 0x06, 0x98,
  0x63
};
const uint8_t Expected_Hash[] =
{
  0x31, 0x09, 0xd9, 0x47, 0x2c, 0xa4, 0x36, 0xe8, 0x05, 0xc6, 0xb3, 0xdb, 0x22, 0x51, 0xa9, 0xbc
};

/* Computed data buffer */
uint8_t computed_hash[sizeof(Expected_Hash)];
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
  cmox_hash_retval_t retval;
  size_t computed_size;
  /* General hash context */
  cmox_hash_handle_t *hash_ctx;
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
  retval = cmox_hash_compute(CMOX_SHAKE128_ALGO,       /* Use SHAKE-128 algorithm */
                             Message, sizeof(Message), /* Message to digest */
                             computed_hash,            /* Data buffer to receive digest data */
                             sizeof(Expected_Hash),    /* Expected digest size */
                             &computed_size);          /* Size of computed digest */

  /* Verify API returned value */
  if (retval != CMOX_HASH_SUCCESS)
  {
    Error_Handler();
  }

  /* Verify generated data size is the expected one */
  if (computed_size != sizeof(Expected_Hash))
  {
    Error_Handler();
  }

  /* Verify generated data are the expected ones */
  if (memcmp(Expected_Hash, computed_hash, computed_size) != 0)
  {
    Error_Handler();
  }

  /* --------------------------------------------------------------------------
   * MULTIPLE CALLS USAGE
   * --------------------------------------------------------------------------
   */

  /* Construct a hash context that is configured to perform SHAKE-128 digest operations */
  hash_ctx = cmox_shake128_construct(&sha3_ctx);
  if (hash_ctx == NULL)
  {
    Error_Handler();
  }

  /* Initialize the hash context */
  retval = cmox_hash_init(hash_ctx);
  if (retval != CMOX_HASH_SUCCESS)
  {
    Error_Handler();
  }

  /* Set the desired size for the digest to compute: note that in the case
     where the size of the digest is the default for the algorithm, it is
     possible to skip this call. */
  retval = cmox_hash_setTagLen(hash_ctx, sizeof(Expected_Hash));
  if (retval != CMOX_HASH_SUCCESS)
  {
    Error_Handler();
  }

  /* Append the message to be hashed by chunks of CHUNK_SIZE Bytes */
  for (index = 0; index < (sizeof(Message) - CHUNK_SIZE); index += CHUNK_SIZE)
  {
    retval = cmox_hash_append(hash_ctx, &Message[index], CHUNK_SIZE); /* Chunk of data to digest */

    /* Verify API returned value */
    if (retval != CMOX_HASH_SUCCESS)
    {
      Error_Handler();
    }
  }
  /* Append the last part of the message if needed */
  if (index < sizeof(Message))
  {
    retval = cmox_hash_append(hash_ctx, &Message[index], sizeof(Message) - index); /* Last part of data to digest */

    /* Verify API returned value */
    if (retval != CMOX_HASH_SUCCESS)
    {
      Error_Handler();
    }
  }

  /* Generate the digest data */
  retval = cmox_hash_generateTag(hash_ctx, computed_hash, &computed_size);

  /* Verify API returned value */
  if (retval != CMOX_HASH_SUCCESS)
  {
    Error_Handler();
  }

  /* Verify generated data size is the expected one */
  if (computed_size != sizeof(Expected_Hash))
  {
    Error_Handler();
  }

  /* Verify generated data are the expected ones */
  if (memcmp(Expected_Hash, computed_hash, computed_size) != 0)
  {
    Error_Handler();
  }

  /* Cleanup the context */
  retval = cmox_hash_cleanup(hash_ctx);
  if (retval != CMOX_HASH_SUCCESS)
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
