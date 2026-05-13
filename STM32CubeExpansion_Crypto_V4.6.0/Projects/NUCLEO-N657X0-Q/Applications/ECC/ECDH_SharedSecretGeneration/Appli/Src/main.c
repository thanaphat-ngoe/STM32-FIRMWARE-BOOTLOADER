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
/* ECC context */
cmox_ecc_handle_t Ecc_Ctx;
/* ECC working buffer */
uint8_t Working_Buffer[2000];
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
/** Extract from KAS_ECC_CDH_PrimitiveTest.txt
  * [P-256]

COUNT = 0
QCAVSx = 700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287
QCAVSy = db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac
dIUT = 7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534
QIUTx = ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230
QIUTy = 28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141
ZIUT = 46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b

  */
const uint8_t Private_Key[] =
{
  0x7d, 0x7d, 0xc5, 0xf7, 0x1e, 0xb2, 0x9d, 0xda, 0xf8, 0x0d, 0x62, 0x14, 0x63, 0x2e, 0xea, 0xe0,
  0x3d, 0x90, 0x58, 0xaf, 0x1f, 0xb6, 0xd2, 0x2e, 0xd8, 0x0b, 0xad, 0xb6, 0x2b, 0xc1, 0xa5, 0x34
};
const uint8_t Remote_Public_Key[] =
{
  0x70, 0x0c, 0x48, 0xf7, 0x7f, 0x56, 0x58, 0x4c, 0x5c, 0xc6, 0x32, 0xca, 0x65, 0x64, 0x0d, 0xb9,
  0x1b, 0x6b, 0xac, 0xce, 0x3a, 0x4d, 0xf6, 0xb4, 0x2c, 0xe7, 0xcc, 0x83, 0x88, 0x33, 0xd2, 0x87,
  0xdb, 0x71, 0xe5, 0x09, 0xe3, 0xfd, 0x9b, 0x06, 0x0d, 0xdb, 0x20, 0xba, 0x5c, 0x51, 0xdc, 0xc5,
  0x94, 0x8d, 0x46, 0xfb, 0xf6, 0x40, 0xdf, 0xe0, 0x44, 0x17, 0x82, 0xca, 0xb8, 0x5f, 0xa4, 0xac
};
const uint8_t Expected_SecretX[] =
{
  0x46, 0xfc, 0x62, 0x10, 0x64, 0x20, 0xff, 0x01, 0x2e, 0x54, 0xa4, 0x34, 0xfb, 0xdd, 0x2d, 0x25,
  0xcc, 0xc5, 0x85, 0x20, 0x60, 0x56, 0x1e, 0x68, 0x04, 0x0d, 0xd7, 0x77, 0x89, 0x97, 0xbd, 0x7b
};

/* Computed data buffer */
uint8_t Computed_Secret[CMOX_ECC_SECP256R1_SECRET_LEN];
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
  cmox_ecc_retval_t retval;
  size_t computed_size;

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

  /* Construct a ECC context, specifying mathematics implementation and working buffer for later processing */
  /* Note: CMOX_ECC256_MATH_FUNCS refer to the default mathematics implementation
   * selected in cmox_default_config.h. To use a specific implementation, user can
   * directly choose:
   * - CMOX_MATH_FUNCS_SMALL to select the mathematics small implementation
   * - CMOX_MATH_FUNCS_FAST to select the mathematics fast implementation
   * - CMOX_MATH_FUNCS_SUPERFAST256 to select the mathematics fast implementation optimized for 256 bits computation
   */
  cmox_ecc_construct(&Ecc_Ctx, CMOX_ECC256_MATH_FUNCS, Working_Buffer, sizeof(Working_Buffer));

  /* Compute directly the shared secret passing all the needed parameters */
  /* Note: CMOX_ECC_CURVE_SECP256R1 refer to the default SECP256R1 definition
   * selected in cmox_default_config.h. To use a specific definition, user can
   * directly choose:
   * - CMOX_ECC_SECP256R1_LOWMEM to select the low RAM usage definition (slower computing)
   * - CMOX_ECC_SECP256R1_HIGHMEM to select the high RAM usage definition (faster computing)
   */
  retval = cmox_ecdh(&Ecc_Ctx,                                         /* ECC context */
                     CMOX_ECC_CURVE_SECP256R1,                         /* SECP256R1 ECC curve selected */
                     Private_Key, sizeof(Private_Key),                 /* Local Private key */
                     Remote_Public_Key, sizeof(Remote_Public_Key),     /* Remote Public key */
                     Computed_Secret, &computed_size);                 /* Data buffer to receive shared secret */

  /* Verify API returned value */
  if (retval != CMOX_ECC_SUCCESS)
  {
    Error_Handler();
  }

  /* Verify generated data size is the expected one */
  if (computed_size != sizeof(Computed_Secret))
  {
    Error_Handler();
  }

  /* Verify generated data are the expected ones */
  if (memcmp(Computed_Secret, Expected_SecretX, sizeof(Expected_SecretX)) != 0)
  {
    Error_Handler();
  }

  /* Cleanup context */
  cmox_ecc_cleanup(&Ecc_Ctx);

  /* No more need of cryptographic services, finalize cryptographic library */
  if (cmox_finalize(NULL) != CMOX_INIT_SUCCESS)
  {
    Error_Handler();
  }

  /* Turn on LED2 in an infinite loop in case of ECC ECDH operations are successful */
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
