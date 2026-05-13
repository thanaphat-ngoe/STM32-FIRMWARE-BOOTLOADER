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
/* DRBG context handle */
cmox_ctr_drbg_handle_t Drbg_Ctx;
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

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/

/* USER CODE BEGIN PV */
/** Extract from CTR_DRBG.rsp
  * [AES-256 use df]
[PredictionResistance = False]
[EntropyInputLen = 256]
[NonceLen = 128]
[PersonalizationStringLen = 256]
[AdditionalInputLen = 0]
[ReturnedBitsLen = 512]

COUNT = 0
EntropyInput = 4cfb218673346d9d50c922e49b0dfcd090adf04f5c3ba47327dfcd6fa63a785c
Nonce = 016962a7fd2787a24bf6be47ef3783f1
PersonalizationString = 88eeb8e0e83bf3294bdacd6099ebe4bf55ecd9113f71e5ebcb4575f3d6a68a6b
EntropyInputReseed = b7ec46072363834a1b0133f2c23891db4f11a68651f23e3a8b1fdc03b192c7e7
AdditionalInputReseed =
AdditionalInput =
AdditionalInput =
ReturnedBits = a55180a190bef3adaf28f6b795e9f1f3d6dfa1b27dd0467b0c75f5fa931e971475b27
cae03a29654e2f40966ea33643040d1400fe677873af8097c1fe9f00298

  */
const uint8_t Entropy[] =
{
  0x4c, 0xfb, 0x21, 0x86, 0x73, 0x34, 0x6d, 0x9d, 0x50, 0xc9, 0x22, 0xe4, 0x9b, 0x0d, 0xfc, 0xd0,
  0x90, 0xad, 0xf0, 0x4f, 0x5c, 0x3b, 0xa4, 0x73, 0x27, 0xdf, 0xcd, 0x6f, 0xa6, 0x3a, 0x78, 0x5c
};
const uint8_t Nonce[] =
{
  0x01, 0x69, 0x62, 0xa7, 0xfd, 0x27, 0x87, 0xa2, 0x4b, 0xf6, 0xbe, 0x47, 0xef, 0x37, 0x83, 0xf1
};
const uint8_t Personalization[] =
{
  0x88, 0xee, 0xb8, 0xe0, 0xe8, 0x3b, 0xf3, 0x29, 0x4b, 0xda, 0xcd, 0x60, 0x99, 0xeb, 0xe4, 0xbf,
  0x55, 0xec, 0xd9, 0x11, 0x3f, 0x71, 0xe5, 0xeb, 0xcb, 0x45, 0x75, 0xf3, 0xd6, 0xa6, 0x8a, 0x6b
};
const uint8_t EntropyInputReseed[] =
{
  0xb7, 0xec, 0x46, 0x07, 0x23, 0x63, 0x83, 0x4a, 0x1b, 0x01, 0x33, 0xf2, 0xc2, 0x38, 0x91, 0xdb,
  0x4f, 0x11, 0xa6, 0x86, 0x51, 0xf2, 0x3e, 0x3a, 0x8b, 0x1f, 0xdc, 0x03, 0xb1, 0x92, 0xc7, 0xe7
};
const uint8_t Known_Random[] =
{
  0xa5, 0x51, 0x80, 0xa1, 0x90, 0xbe, 0xf3, 0xad, 0xaf, 0x28, 0xf6, 0xb7, 0x95, 0xe9, 0xf1, 0xf3,
  0xd6, 0xdf, 0xa1, 0xb2, 0x7d, 0xd0, 0x46, 0x7b, 0x0c, 0x75, 0xf5, 0xfa, 0x93, 0x1e, 0x97, 0x14,
  0x75, 0xb2, 0x7c, 0xae, 0x03, 0xa2, 0x96, 0x54, 0xe2, 0xf4, 0x09, 0x66, 0xea, 0x33, 0x64, 0x30,
  0x40, 0xd1, 0x40, 0x0f, 0xe6, 0x77, 0x87, 0x3a, 0xf8, 0x09, 0x7c, 0x1f, 0xe9, 0xf0, 0x02, 0x98
};

/* Computed data buffer */
uint8_t Computed_Random[sizeof(Known_Random)];
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
  cmox_drbg_retval_t retval;
  /* General DRBG context */
  cmox_drbg_handle_t *drgb_ctx;

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
   * KNOWN RANDOM PRODUCTION
   * --------------------------------------------------------------------------
   */

  /* Construct a drbg context that is configured to perform ctrDRBG with AES256 operations */
  drgb_ctx = cmox_ctr_drbg_construct(&Drbg_Ctx, CMOX_CTR_DRBG_AES256);
  if (drgb_ctx == NULL)
  {
    Error_Handler();
  }

  /* Initialize the DRBG context with entropy, nonce and personalization string parameters */
  retval = cmox_drbg_init(drgb_ctx,                                     /* DRBG context */
                          Entropy, sizeof(Entropy),                     /* Entropy data */
                          Personalization, sizeof(Personalization),     /* Personalization string */
                          Nonce, sizeof(Nonce));                        /* Nonce data */
  if (retval != CMOX_DRBG_SUCCESS)
  {
    Error_Handler();
  }

  /* Reseed the DRBG with reseed parameters */
  retval = cmox_drbg_reseed(drgb_ctx,                                           /* DRBG context */
                            EntropyInputReseed, sizeof(EntropyInputReseed),     /* Entropy reseed data */
                            NULL, 0);                                           /* No additional reseed data */
  if (retval != CMOX_DRBG_SUCCESS)
  {
    Error_Handler();
  }

  /* Generate 1st random data */
  retval = cmox_drbg_generate(drgb_ctx,                                    /* DRBG context */
                              NULL, 0,                                     /* No additional data */
                              Computed_Random, sizeof(Computed_Random));   /* Data buffer to receive generated random */

  /* Verify API returned value */
  if (retval != CMOX_DRBG_SUCCESS)
  {
    Error_Handler();
  }

  /* Generate 2nd random data */
  retval = cmox_drbg_generate(drgb_ctx,                                    /* DRBG context */
                              NULL, 0,                                     /* No additional data */
                              Computed_Random, sizeof(Computed_Random));   /* Data buffer to receive generated random */

  /* Verify API returned value */
  if (retval != CMOX_DRBG_SUCCESS)
  {
    Error_Handler();
  }

  /* Verify generated data are the expected ones */
  if (memcmp(Computed_Random, Known_Random, sizeof(Known_Random)) != 0)
  {
    Error_Handler();
  }

  /* Cleanup the context */
  retval = cmox_drbg_cleanup(drgb_ctx);
  if (retval != CMOX_DRBG_SUCCESS)
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
