/**
  ******************************************************************************
  * @file    ECC/ECDSA_SignVerify/Src/main.c
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
/* ECC context */
cmox_ecc_handle_t Ecc_Ctx;
/* ECC working buffer */
uint8_t Working_Buffer[2000];

/* Random data buffer */
uint32_t Computed_Random[8];
/* RNG peripheral handle */
RNG_HandleTypeDef hrng;

__IO TestStatus glob_status = FAILED;

/* Private typedef -----------------------------------------------------------*/
/* Private defines -----------------------------------------------------------*/
/* Private macros ------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
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
  cmox_hash_retval_t hretval;
  cmox_ecc_retval_t retval;
  size_t computed_size;
  /* Fault check verification variable */
  uint32_t fault_check = CMOX_ECC_AUTH_FAIL;

  
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
