/**
  ******************************************************************************
  * @file    Hash/SHA3_Digest/Src/main.c
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
/* SHA3 context handle */
cmox_sha3_handle_t sha3_ctx;

__IO TestStatus glob_status = FAILED;

/* Private typedef -----------------------------------------------------------*/
/* Private defines -----------------------------------------------------------*/
#define CHUNK_SIZE  48u   /* Chunk size (in bytes) when data to hash are processed by chunk */
/* Private macros ------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
/** Extract from SHA3_512LongMsg.rsp
  *
Len = 2328
Msg = 22e1df25c30d6e7806cae35cd4317e5f94db028741a76838bfb7d5576fbccab001749a95897122c8d51bb49cfef854
563e2b27d9013b28833f161d520856ca4b61c2641c4e184800300aede3518617c7be3a4e6655588f181e9641f8df7a6a42ea
d423003a8c4ae6be9d767af5623078bb116074638505c10540299219b0155f45b1c18a74548e4328de37a911140531deb643
4c534af2449c1abe67e18030681a61240225f87ede15d519b7ce2500bccf33e1364e2fbe6a8a2fe6c15d73242610ed36b074
0080812e8902ee531c88e0359020797cbdd1fb78848ae6b5105961d05cdddb8af5fef21b02db94c9810464b8d3ea5f047b94
bf0d23931f12df37e102b603cd8e5f5ffa83488df257ddde110106262e0ef16d7ef213e7b49c69276d4d048f
MD = a6375ff04af0a18fb4c8175f671181b4cf79653a3d70847c6d99694b3f5d41601f1dbef809675c63cac4ec83153b1c7
8131a7b61024ce36244f320ab8740cb7e

  */
const uint8_t Message[] =
{
  0x22, 0xe1, 0xdf, 0x25, 0xc3, 0x0d, 0x6e, 0x78, 0x06, 0xca, 0xe3, 0x5c, 0xd4, 0x31, 0x7e, 0x5f,
  0x94, 0xdb, 0x02, 0x87, 0x41, 0xa7, 0x68, 0x38, 0xbf, 0xb7, 0xd5, 0x57, 0x6f, 0xbc, 0xca, 0xb0,
  0x01, 0x74, 0x9a, 0x95, 0x89, 0x71, 0x22, 0xc8, 0xd5, 0x1b, 0xb4, 0x9c, 0xfe, 0xf8, 0x54, 0x56,
  0x3e, 0x2b, 0x27, 0xd9, 0x01, 0x3b, 0x28, 0x83, 0x3f, 0x16, 0x1d, 0x52, 0x08, 0x56, 0xca, 0x4b,
  0x61, 0xc2, 0x64, 0x1c, 0x4e, 0x18, 0x48, 0x00, 0x30, 0x0a, 0xed, 0xe3, 0x51, 0x86, 0x17, 0xc7,
  0xbe, 0x3a, 0x4e, 0x66, 0x55, 0x58, 0x8f, 0x18, 0x1e, 0x96, 0x41, 0xf8, 0xdf, 0x7a, 0x6a, 0x42,
  0xea, 0xd4, 0x23, 0x00, 0x3a, 0x8c, 0x4a, 0xe6, 0xbe, 0x9d, 0x76, 0x7a, 0xf5, 0x62, 0x30, 0x78,
  0xbb, 0x11, 0x60, 0x74, 0x63, 0x85, 0x05, 0xc1, 0x05, 0x40, 0x29, 0x92, 0x19, 0xb0, 0x15, 0x5f,
  0x45, 0xb1, 0xc1, 0x8a, 0x74, 0x54, 0x8e, 0x43, 0x28, 0xde, 0x37, 0xa9, 0x11, 0x14, 0x05, 0x31,
  0xde, 0xb6, 0x43, 0x4c, 0x53, 0x4a, 0xf2, 0x44, 0x9c, 0x1a, 0xbe, 0x67, 0xe1, 0x80, 0x30, 0x68,
  0x1a, 0x61, 0x24, 0x02, 0x25, 0xf8, 0x7e, 0xde, 0x15, 0xd5, 0x19, 0xb7, 0xce, 0x25, 0x00, 0xbc,
  0xcf, 0x33, 0xe1, 0x36, 0x4e, 0x2f, 0xbe, 0x6a, 0x8a, 0x2f, 0xe6, 0xc1, 0x5d, 0x73, 0x24, 0x26,
  0x10, 0xed, 0x36, 0xb0, 0x74, 0x00, 0x80, 0x81, 0x2e, 0x89, 0x02, 0xee, 0x53, 0x1c, 0x88, 0xe0,
  0x35, 0x90, 0x20, 0x79, 0x7c, 0xbd, 0xd1, 0xfb, 0x78, 0x84, 0x8a, 0xe6, 0xb5, 0x10, 0x59, 0x61,
  0xd0, 0x5c, 0xdd, 0xdb, 0x8a, 0xf5, 0xfe, 0xf2, 0x1b, 0x02, 0xdb, 0x94, 0xc9, 0x81, 0x04, 0x64,
  0xb8, 0xd3, 0xea, 0x5f, 0x04, 0x7b, 0x94, 0xbf, 0x0d, 0x23, 0x93, 0x1f, 0x12, 0xdf, 0x37, 0xe1,
  0x02, 0xb6, 0x03, 0xcd, 0x8e, 0x5f, 0x5f, 0xfa, 0x83, 0x48, 0x8d, 0xf2, 0x57, 0xdd, 0xde, 0x11,
  0x01, 0x06, 0x26, 0x2e, 0x0e, 0xf1, 0x6d, 0x7e, 0xf2, 0x13, 0xe7, 0xb4, 0x9c, 0x69, 0x27, 0x6d,
  0x4d, 0x04, 0x8f
};
const uint8_t Expected_Hash[] =
{
  0xa6, 0x37, 0x5f, 0xf0, 0x4a, 0xf0, 0xa1, 0x8f, 0xb4, 0xc8, 0x17, 0x5f, 0x67, 0x11, 0x81, 0xb4,
  0xcf, 0x79, 0x65, 0x3a, 0x3d, 0x70, 0x84, 0x7c, 0x6d, 0x99, 0x69, 0x4b, 0x3f, 0x5d, 0x41, 0x60,
  0x1f, 0x1d, 0xbe, 0xf8, 0x09, 0x67, 0x5c, 0x63, 0xca, 0xc4, 0xec, 0x83, 0x15, 0x3b, 0x1c, 0x78,
  0x13, 0x1a, 0x7b, 0x61, 0x02, 0x4c, 0xe3, 0x62, 0x44, 0xf3, 0x20, 0xab, 0x87, 0x40, 0xcb, 0x7e
};

/* Computed data buffer */
uint8_t computed_hash[CMOX_SHA3_512_SIZE];

/* Private function prototypes -----------------------------------------------*/
static void SystemClock_Config(void);
static void Error_Handler(void);
/* Functions Definition ------------------------------------------------------*/

/**
  * @brief  Main program
  * @param  None
  * @retval None
  */
int main(void)
{
  cmox_hash_retval_t retval;
  size_t computed_size;
  /* General hash context */
  cmox_hash_handle_t *hash_ctx;
  /* Index for piecemeal processing */
  uint32_t index;

  /* STM32WBxx HAL library initialization:
       - Configure the Flash prefetch
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
  /* Configure the System clock */
  SystemClock_Config();


  cmox_init_arg_t init_target = {CMOX_INIT_TARGET_AUTO, NULL};

  /* Configure LED3 */
  BSP_LED_Init(LED3);

  /* Initialize cryptographic library */
  if (cmox_initialize(&init_target) != CMOX_INIT_SUCCESS)
  {
    Error_Handler();
  }

  /* --------------------------------------------------------------------------
   * SINGLE CALL USAGE
   * --------------------------------------------------------------------------
   */
  /* Compute directly the digest passing all the needed parameters */
  retval = cmox_hash_compute(CMOX_SHA3_512_ALGO,       /* Use SHA3-512 algorithm */
                             Message, sizeof(Message), /* Message to digest */
                             computed_hash,            /* Data buffer to receive digest data */
                             CMOX_SHA3_512_SIZE,       /* Expected digest size */
                             &computed_size);          /* Size of computed digest */

  /* Verify API returned value */
  if (retval != CMOX_HASH_SUCCESS)
  {
    Error_Handler();
  }

  /* Verify generated data size is the expected one */
  if (computed_size != CMOX_SHA3_512_SIZE)
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

  /* Construct a hash context that is configured to perform SHA3-512 digest operations */
  hash_ctx = cmox_sha3_512_construct(&sha3_ctx);
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
  retval = cmox_hash_setTagLen(hash_ctx, CMOX_SHA3_512_SIZE);
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
  if (computed_size != CMOX_SHA3_512_SIZE)
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

  /* Turn on LED3 in an infinite loop in case of AES CBC operations are successful */
  BSP_LED_On(LED3);
  glob_status = PASSED;
  while (1)
  {}
}

/**
  * @brief  System Clock Configuration
  *         The system Clock is configured as follow :
  *            System Clock source            = PLL (MSI)
  *            SYSCLK(Hz)                     = 64000000
  *            HCLK(Hz)                       = 64000000
  *            HCLK1 Prescaler                = 1
  *            HCKL2 Prescaler                = 2
  *            HCKLS Prescaler                = 1
  *            APB1 Prescaler                 = 1
  *            APB2 Prescaler                 = 1
  *            MSI Frequency(Hz)              = 4000000
  *            PLL_M                          = 1
  *            PLL_N                          = 32
  *            PLL_P                          = 5
  *            PLL_Q                          = 4
  *            PLL_R                          = 2
  *            Flash Latency(WS)              = 3
  */
void SystemClock_Config(void)
{
  RCC_ClkInitTypeDef RCC_ClkInitStruct ={0};
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};

  /* Activate PLL with HSI as source */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_MSI;
  RCC_OscInitStruct.MSIState = RCC_MSI_ON;
  RCC_OscInitStruct.MSIClockRange = RCC_MSIRANGE_6;
  RCC_OscInitStruct.MSICalibrationValue = RCC_MSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_MSI;
  RCC_OscInitStruct.PLL.PLLM = RCC_PLLM_DIV1;
  RCC_OscInitStruct.PLL.PLLN = 32;
  RCC_OscInitStruct.PLL.PLLR = RCC_PLLR_DIV2;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV5;
  RCC_OscInitStruct.PLL.PLLQ = RCC_PLLQ_DIV4;
  if(HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    /* Initialization Error */
    while (1);
  }

  /* Select PLL as system clock source and configure the HCLK, PCLK1 and PCLK2
     clocks dividers */
  RCC_ClkInitStruct.ClockType = (RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2 | RCC_CLOCKTYPE_HCLK2 | RCC_CLOCKTYPE_HCLK4);
  RCC_ClkInitStruct.SYSCLKSource   = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider  = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;
  RCC_ClkInitStruct.AHBCLK2Divider = RCC_SYSCLK_DIV2;
  RCC_ClkInitStruct.AHBCLK4Divider = RCC_SYSCLK_DIV1;
  if(HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_3) != HAL_OK)
  {
    /* Initialization Error */
    while (1);
  }
}


/**
  * @brief  This function is executed in case of error occurrence
  * @param  None
  * @retval None
  */
static void Error_Handler(void)
{
  /* User may add here some code to deal with this error */
  /* Toggle LED3 @2Hz to notify error condition */
  while (1)
  {
    BSP_LED_Toggle(LED3);
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
