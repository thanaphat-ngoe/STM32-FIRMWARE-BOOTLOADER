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
/* Random data buffer */
uint32_t Computed_Random[8];
/* RNG peripheral handle */
RNG_HandleTypeDef hrng;

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
/** Extract from SigGen.txt
  * [P-256,SHA-224]

Msg = ff624d0ba02c7b6370c1622eec3fa2186ea681d1659e0a845448e777b75a8e77a77bb26e5733179d58ef9bc8a4e8b69
71aef2539f77ab0963a3415bbd6258339bd1bf55de65db520c63f5b8eab3d55debd05e9494212170f5d65b3286b8b668705b1
e2b2b5568610617abb51d2dd0cb450ef59df4b907da90cfa7b268de8c4c2
d = 708309a7449e156b0db70e5b52e606c7e094ed676ce8953bf6c14757c826f590
Qx = 29578c7ab6ce0d11493c95d5ea05d299d536801ca9cbd50e9924e43b733b83ab
Qy = 08c8049879c6278b2273348474158515accaa38344106ef96803c5a05adc4800
k = 58f741771620bdc428e91a32d86d230873e9140336fcfb1e122892ee1d501bdc
R = 4a19274429e40522234b8785dc25fc524f179dcc95ff09b3c9770fc71f54ca0d
S = 58982b79a65b7320f5b92d13bdaecdd1259e760f0f718ba933fd098f6f75d4b7

  */
const uint8_t Message[] =
{
  0xff, 0x62, 0x4d, 0x0b, 0xa0, 0x2c, 0x7b, 0x63, 0x70, 0xc1, 0x62, 0x2e, 0xec, 0x3f, 0xa2, 0x18,
  0x6e, 0xa6, 0x81, 0xd1, 0x65, 0x9e, 0x0a, 0x84, 0x54, 0x48, 0xe7, 0x77, 0xb7, 0x5a, 0x8e, 0x77,
  0xa7, 0x7b, 0xb2, 0x6e, 0x57, 0x33, 0x17, 0x9d, 0x58, 0xef, 0x9b, 0xc8, 0xa4, 0xe8, 0xb6, 0x97,
  0x1a, 0xef, 0x25, 0x39, 0xf7, 0x7a, 0xb0, 0x96, 0x3a, 0x34, 0x15, 0xbb, 0xd6, 0x25, 0x83, 0x39,
  0xbd, 0x1b, 0xf5, 0x5d, 0xe6, 0x5d, 0xb5, 0x20, 0xc6, 0x3f, 0x5b, 0x8e, 0xab, 0x3d, 0x55, 0xde,
  0xbd, 0x05, 0xe9, 0x49, 0x42, 0x12, 0x17, 0x0f, 0x5d, 0x65, 0xb3, 0x28, 0x6b, 0x8b, 0x66, 0x87,
  0x05, 0xb1, 0xe2, 0xb2, 0xb5, 0x56, 0x86, 0x10, 0x61, 0x7a, 0xbb, 0x51, 0xd2, 0xdd, 0x0c, 0xb4,
  0x50, 0xef, 0x59, 0xdf, 0x4b, 0x90, 0x7d, 0xa9, 0x0c, 0xfa, 0x7b, 0x26, 0x8d, 0xe8, 0xc4, 0xc2
};
const uint8_t Private_Key[] =
{
  0x70, 0x83, 0x09, 0xa7, 0x44, 0x9e, 0x15, 0x6b, 0x0d, 0xb7, 0x0e, 0x5b, 0x52, 0xe6, 0x06, 0xc7,
  0xe0, 0x94, 0xed, 0x67, 0x6c, 0xe8, 0x95, 0x3b, 0xf6, 0xc1, 0x47, 0x57, 0xc8, 0x26, 0xf5, 0x90
};
const uint8_t Public_Key[] =
{
  0x29, 0x57, 0x8c, 0x7a, 0xb6, 0xce, 0x0d, 0x11, 0x49, 0x3c, 0x95, 0xd5, 0xea, 0x05, 0xd2, 0x99,
  0xd5, 0x36, 0x80, 0x1c, 0xa9, 0xcb, 0xd5, 0x0e, 0x99, 0x24, 0xe4, 0x3b, 0x73, 0x3b, 0x83, 0xab,
  0x08, 0xc8, 0x04, 0x98, 0x79, 0xc6, 0x27, 0x8b, 0x22, 0x73, 0x34, 0x84, 0x74, 0x15, 0x85, 0x15,
  0xac, 0xca, 0xa3, 0x83, 0x44, 0x10, 0x6e, 0xf9, 0x68, 0x03, 0xc5, 0xa0, 0x5a, 0xdc, 0x48, 0x00
};
const uint8_t Known_Random[] = /* = k - 1 */
{
  0x58, 0xf7, 0x41, 0x77, 0x16, 0x20, 0xbd, 0xc4, 0x28, 0xe9, 0x1a, 0x32, 0xd8, 0x6d, 0x23, 0x08,
  0x73, 0xe9, 0x14, 0x03, 0x36, 0xfc, 0xfb, 0x1e, 0x12, 0x28, 0x92, 0xee, 0x1d, 0x50, 0x1b, 0xdb
};
const uint8_t Known_Signature[] =
{
  0x4a, 0x19, 0x27, 0x44, 0x29, 0xe4, 0x05, 0x22, 0x23, 0x4b, 0x87, 0x85, 0xdc, 0x25, 0xfc, 0x52,
  0x4f, 0x17, 0x9d, 0xcc, 0x95, 0xff, 0x09, 0xb3, 0xc9, 0x77, 0x0f, 0xc7, 0x1f, 0x54, 0xca, 0x0d,
  0x58, 0x98, 0x2b, 0x79, 0xa6, 0x5b, 0x73, 0x20, 0xf5, 0xb9, 0x2d, 0x13, 0xbd, 0xae, 0xcd, 0xd1,
  0x25, 0x9e, 0x76, 0x0f, 0x0f, 0x71, 0x8b, 0xa9, 0x33, 0xfd, 0x09, 0x8f, 0x6f, 0x75, 0xd4, 0xb7
};

/* Computed data buffer */
uint8_t Computed_Hash[CMOX_SHA224_SIZE];
uint8_t Computed_Signature[CMOX_ECC_SECP256R1_SIG_LEN];
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
  cmox_hash_retval_t hretval;
  cmox_ecc_retval_t retval;
  size_t computed_size;
  /* Fault check verification variable */
  uint32_t fault_check = CMOX_ECC_AUTH_FAIL;
  RNG_ConfigTypeDef rng_conf;

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

  /* Compute directly the digest passing all the needed parameters */
  hretval = cmox_hash_compute(CMOX_SHA224_ALGO,         /* Use SHA224 algorithm */
                              Message, sizeof(Message), /* Message to digest */
                              Computed_Hash,            /* Data buffer to receive digest data */
                              CMOX_SHA224_SIZE,         /* Expected digest size */
                              &computed_size);          /* Size of computed digest */

  /* Verify API returned value */
  if (hretval != CMOX_HASH_SUCCESS)
  {
    Error_Handler();
  }

  /* Verify generated data size is the expected one */
  if (computed_size != CMOX_SHA224_SIZE)
  {
    Error_Handler();
  }

  /* --------------------------------------------------------------------------
   * KNOWN RANDOM USAGE
   * --------------------------------------------------------------------------
   */

  /* Construct a ECC context, specifying mathematics implementation and working buffer for later processing */
  /* Note: CMOX_ECC256_MATH_FUNCS refer to the default mathematics implementation
   * selected in cmox_default_config.h. To use a specific implementation, user can
   * directly choose:
   * - CMOX_MATH_FUNCS_SMALL to select the mathematics small implementation
   * - CMOX_MATH_FUNCS_FAST to select the mathematics fast implementation
   * - CMOX_MATH_FUNCS_SUPERFAST256 to select the mathematics fast implementation optimized for 256 bits computation
   */
  cmox_ecc_construct(&Ecc_Ctx, CMOX_ECC256_MATH_FUNCS, Working_Buffer, sizeof(Working_Buffer));

  /* Compute directly the signature passing all the needed parameters */
  /* Note: CMOX_ECC_CURVE_SECP256R1 refer to the default SECP256R1 definition
   * selected in cmox_default_config.h. To use a specific definition, user can
   * directly choose:
   * - CMOX_ECC_SECP256R1_LOWMEM to select the low RAM usage definition (slower computing)
   * - CMOX_ECC_SECP256R1_HIGHMEM to select the high RAM usage definition (faster computing)
   */
  retval = cmox_ecdsa_sign(&Ecc_Ctx,                                 /* ECC context */
                           CMOX_ECC_CURVE_SECP256R1,                 /* SECP256R1 ECC curve selected */
                           Known_Random, sizeof(Known_Random),       /* Random data buffer */
                           Private_Key, sizeof(Private_Key),         /* Private key for signature */
                           Computed_Hash, CMOX_SHA224_SIZE,          /* Digest to sign */
                           Computed_Signature, &computed_size);      /* Data buffer to receive signature */

  /* Verify API returned value */
  if (retval != CMOX_ECC_SUCCESS)
  {
    Error_Handler();
  }

  /* Verify generated data size is the expected one */
  if (computed_size != sizeof(Known_Signature))
  {
    Error_Handler();
  }

  /* Verify generated data are the expected ones */
  if (memcmp(Computed_Signature, Known_Signature, computed_size) != 0)
  {
    Error_Handler();
  }

  /* Cleanup context */
  cmox_ecc_cleanup(&Ecc_Ctx);

  /* Construct a ECC context, specifying mathematics implementation and working buffer for later processing */
  /* Note: CMOX_ECC256_MATH_FUNCS refer to the default mathematics implementation
   * selected in cmox_default_config.h. To use a specific implementation, user can
   * directly choose:
   * - CMOX_MATH_FUNCS_SMALL to select the mathematics small implementation
   * - CMOX_MATH_FUNCS_FAST to select the mathematics fast implementation
   * - CMOX_MATH_FUNCS_SUPERFAST256 to select the mathematics fast implementation optimized for 256 bits computation
   */
  cmox_ecc_construct(&Ecc_Ctx, CMOX_ECC256_MATH_FUNCS, Working_Buffer, sizeof(Working_Buffer));

  /* Verify directly the signature passing all the needed parameters */
  /* Note: CMOX_ECC_CURVE_SECP256R1 refer to the default SECP256R1 definition
   * selected in cmox_default_config.h. To use a specific definition, user can
   * directly choose:
   * - CMOX_ECC_SECP256R1_LOWMEM to select the low RAM usage definition (slower computing)
   * - CMOX_ECC_SECP256R1_HIGHMEM to select the high RAM usage definition (faster computing)
   */
  retval = cmox_ecdsa_verify(&Ecc_Ctx,                                  /* ECC context */
                             CMOX_ECC_CURVE_SECP256R1,                  /* SECP256R1 ECC curve selected */
                             Public_Key, sizeof(Public_Key),            /* Public key for verification */
                             Computed_Hash, CMOX_SHA224_SIZE,           /* Digest to verify */
                             Known_Signature, sizeof(Known_Signature),  /* Data buffer to receive signature */
                             &fault_check);                             /* Fault check variable:
                                                            to ensure no fault injection occurs during this API call */

  /* Verify API returned value */
  if (retval != CMOX_ECC_AUTH_SUCCESS)
  {
    Error_Handler();
  }
  /* Verify Fault check variable value */
  if (fault_check != CMOX_ECC_AUTH_SUCCESS)
  {
    Error_Handler();
  }

  /* Cleanup context */
  cmox_ecc_cleanup(&Ecc_Ctx);

  /* --------------------------------------------------------------------------
   * TRUE RANDOM USAGE
   * --------------------------------------------------------------------------
   */

  /* Configure RNG peripheral */
  hrng.Instance = RNG;
  hrng.Init.ClockErrorDetection = RNG_CED_ENABLE;
  if (HAL_RNG_Init(&hrng) != HAL_OK)
  {
    Error_Handler();
  }
  /* Set configuration for better security */
  rng_conf.Config1 = 0x0FUL;
  rng_conf.Config2 = 0UL;
  rng_conf.Config3 = 0x0DUL;
  rng_conf.ClockDivider = RNG_CLKDIV_BY_1;
  rng_conf.NistCompliance = RNG_NIST_COMPLIANT;
  rng_conf.AutoReset = RNG_ARDIS_ENABLE;
  rng_conf.HealthTest = 0x0000AAC7UL;
  if (HAL_RNGEx_SetConfig(&hrng, &rng_conf) != HAL_OK)
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

  /* Note: The random value must satisfy some arithmetic constraints versus the selected curve and points
   * to minimize the statictical vulnerability.
   * In case this is not satisfied, cmox_ecdsa_sign returns CMOX_ECC_ERR_WRONG_RANDOM: new random has to be
   * generated and API call again.
   */
  do
  {
    /* Generate random numbers */
    for (uint32_t i = 0; i < sizeof(Computed_Random) / sizeof(uint32_t); i++)
    {
      if (HAL_RNG_GenerateRandomNumber(&hrng, &Computed_Random[i]) != HAL_OK)
      {
        /* Random number generation error */
        Error_Handler();
      }
    }

    /* Compute directly the signature passing all the needed parameters */
    /* Note: CMOX_ECC_CURVE_SECP256R1 refer to the default SECP256R1 definition
     * selected in cmox_default_config.h. To use a specific definition, user can
     * directly choose:
     * - CMOX_ECC_SECP256R1_LOWMEM to select the low RAM usage definition (slower computing)
     * - CMOX_ECC_SECP256R1_HIGHMEM to select the high RAM usage definition (faster computing)
     */
    retval = cmox_ecdsa_sign(&Ecc_Ctx,                                            /* ECC context */
                             CMOX_ECC_CURVE_SECP256R1,                            /* SECP256R1 ECC curve selected */
                             (uint8_t *)Computed_Random, sizeof(Computed_Random), /* Random data buffer */
                             Private_Key, sizeof(Private_Key),                    /* Private key for signature */
                             Computed_Hash, CMOX_SHA224_SIZE,                     /* Digest to sign */
                             Computed_Signature, &computed_size);                 /* Data buffer to receive signature */

  } while (retval == CMOX_ECC_ERR_WRONG_RANDOM);

  /* Verify API returned value */
  if (retval != CMOX_ECC_SUCCESS)
  {
    Error_Handler();
  }

  /* Verify generated data size is the expected one */
  if (computed_size != sizeof(Known_Signature))
  {
    Error_Handler();
  }

  /* Cleanup context */
  cmox_ecc_cleanup(&Ecc_Ctx);

  /* Construct a ECC context, specifying mathematics implementation and working buffer for later processing */
  /* Note: CMOX_ECC256_MATH_FUNCS refer to the default mathematics implementation
   * selected in cmox_default_config.h. To use a specific implementation, user can
   * directly choose:
   * - CMOX_MATH_FUNCS_SMALL to select the mathematics small implementation
   * - CMOX_MATH_FUNCS_FAST to select the mathematics fast implementation
   * - CMOX_MATH_FUNCS_SUPERFAST256 to select the mathematics fast implementation optimized for 256 bits computation
   */
  cmox_ecc_construct(&Ecc_Ctx, CMOX_ECC256_MATH_FUNCS, Working_Buffer, sizeof(Working_Buffer));

  /* Verify directly the signature passing all the needed parameters */
  /* Note: CMOX_ECC_CURVE_SECP256R1 refer to the default SECP256R1 definition
   * selected in cmox_default_config.h. To use a specific definition, user can
   * directly choose:
   * - CMOX_ECC_SECP256R1_LOWMEM to select the low RAM usage definition (slower computing)
   * - CMOX_ECC_SECP256R1_HIGHMEM to select the high RAM usage definition (faster computing)
   */
  retval = cmox_ecdsa_verify(&Ecc_Ctx,                                        /* ECC context */
                             CMOX_ECC_CURVE_SECP256R1,                        /* SECP256R1 ECC curve selected */
                             Public_Key, sizeof(Public_Key),                  /* Public key for verification */
                             Computed_Hash, CMOX_SHA224_SIZE,                 /* Digest to verify */
                             Computed_Signature, sizeof(Computed_Signature),  /* Data buffer to receive signature */
                             &fault_check);                                   /* Fault check variable:
                                                            to ensure no fault injection occurs during this API call */

  /* Verify API returned value */
  if (retval != CMOX_ECC_AUTH_SUCCESS)
  {
    Error_Handler();
  }
  /* Verify Fault check variable value */
  if (fault_check != CMOX_ECC_AUTH_SUCCESS)
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

  /* Turn on LED2 in an infinite loop in case of ECC ECDSA operations are successful */
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
