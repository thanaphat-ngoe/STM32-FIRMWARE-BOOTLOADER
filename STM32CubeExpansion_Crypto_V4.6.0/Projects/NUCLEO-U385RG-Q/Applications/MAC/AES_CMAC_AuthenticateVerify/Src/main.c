/**
  ******************************************************************************
  * @file    MAC/AES_CMAC_AuthenticateVerify/Src/main.c
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
/* CMAC context handle */
cmox_cmac_handle_t Cmac_Ctx;

__IO TestStatus glob_status = FAILED;

/* Private typedef -----------------------------------------------------------*/
/* Private defines -----------------------------------------------------------*/
#define CHUNK_SIZE  48u   /* Chunk size (in bytes) when data to mac are processed by chunk */
/* Private macros ------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
/** Extract from NIST Special Publication 800-38A
  * Example #4

Key is
 2B7E1516 28AED2A6 ABF71588 09CF4F3C
Mlen=64

PT is
6BC1BEE2 2E409F96 E93D7E11 7393172A
AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51
30C81C46 A35CE411 E5FBC119 1A0A52EF
F69F2445 DF4F9B17 AD2B417B E66C3710

...

Tag is
51F0BEBF 7E3B9D92 FC497417 79363CFE
  */
const uint8_t Key[] =
{
  0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
};
const uint8_t Message[] =
{
  0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
  0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
  0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
  0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
};
const uint8_t Expected_Tag[] =
{
  0x51, 0xF0, 0xBE, 0xBF, 0x7E, 0x3B, 0x9D, 0x92, 0xFC, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3C, 0xFE
};

/* Computed data buffer */
uint8_t Computed_Tag[sizeof(Expected_Tag)];

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
  cmox_mac_retval_t retval;
  size_t computed_size;
  /* General mac context */
  cmox_mac_handle_t *mac_ctx;
  /* Index for piecemeal processing */
  uint32_t index;
  /* Fault check verification variable */
  uint32_t fault_check = CMOX_MAC_AUTH_FAIL;

  /* STM32U3xx HAL library initialization:
       - Configure the Flash prefetch
       - Configure the Systick to generate an interrupt each 1 msec
       - Set NVIC Group Priority to 4
       - Low Level Initialization
     */
  HAL_Init();

  /* Configure the System clock */
  SystemClock_Config();


  /* Enable instruction cache (default 2-ways set associative cache) */
  if (HAL_ICACHE_Enable() != HAL_OK)
  {
    Error_Handler();
  }

  cmox_init_arg_t init_target = {CMOX_INIT_TARGET_AUTO, NULL};

  /* Configure LD2 */
  BSP_LED_Init(LD2);

  /* Initialize cryptographic library */
  if (cmox_initialize(&init_target) != CMOX_INIT_SUCCESS)
  {
    Error_Handler();
  }

  /* --------------------------------------------------------------------------
   * SINGLE CALL USAGE
   * --------------------------------------------------------------------------
   */

  /* Compute directly the authentication tag passing all the needed parameters */
  /* Note: CMOX_CMAC_AES_ALGO refer to the default AES implementation
   * selected in cmox_default_config.h. To use a specific implementation, user can
   * directly choose:
   * - CMOX_CMAC_AESFAST_ALGO to select the AES fast implementation
   * - CMOX_CMAC_AESSMALL_ALGO to select the AES small implementation
   */
  retval = cmox_mac_compute(CMOX_CMAC_AES_ALGO,        /* Use AES CMAC algorithm */
                            Message, sizeof(Message),  /* Message to authenticate */
                            Key, sizeof(Key),          /* AES key to use */
                            NULL, 0,                   /* Custom data */
                            Computed_Tag,              /* Data buffer to receive generated authnetication tag */
                            sizeof(Expected_Tag),      /* Expected authentication tag size */
                            &computed_size);           /* Generated tag size */

  /* Verify API returned value */
  if (retval != CMOX_MAC_SUCCESS)
  {
    Error_Handler();
  }

  /* Verify generated data size is the expected one */
  if (computed_size != sizeof(Expected_Tag))
  {
    Error_Handler();
  }

  /* Verify generated data are the expected ones */
  if (memcmp(Expected_Tag, Computed_Tag, computed_size) != 0)
  {
    Error_Handler();
  }

  /* Verify directly the message passing all the needed parameters */
  /* Note: CMOX_CMAC_AES_ALGO refer to the default AES implementation
   * selected in cmox_default_config.h. To use a specific implementation, user can
   * directly choose:
   * - CMOX_CMAC_AESFAST_ALGO to select the AES fast implementation
   * - CMOX_CMAC_AESSMALL_ALGO to select the AES small implementation
   */
  retval = cmox_mac_verify(CMOX_CMAC_AES_ALGO,        /* Use AES CMAC algorithm */
                           Message, sizeof(Message),  /* Message to authenticate */
                           Key, sizeof(Key),          /* AES key to use */
                           NULL, 0,                   /* Custom data */
                           Expected_Tag,              /* Authentication tag */
                           sizeof(Expected_Tag));     /* tag size */

  /* Verify API returned value */
  if (retval != CMOX_MAC_AUTH_SUCCESS)
  {
    Error_Handler();
  }

  /* --------------------------------------------------------------------------
   * MULTIPLE CALLS USAGE
   * --------------------------------------------------------------------------
   */

  /* Construct a MAC context that is configured to perform AES CMAC authentication operations */
  /* Note: CMOX_CMAC_AES refer to the default AES implementation
   * selected in cmox_default_config.h. To use a specific implementation, user can
   * directly choose:
   * - CMOX_CMAC_AESFAST to select the AES fast implementation
   * - CMOX_CMAC_AESSMALL to select the AES small implementation
   */
  mac_ctx = cmox_cmac_construct(&Cmac_Ctx, CMOX_CMAC_AES);
  if (mac_ctx == NULL)
  {
    Error_Handler();
  }

  /* Initialize the MAC context */
  retval = cmox_mac_init(mac_ctx);
  if (retval != CMOX_MAC_SUCCESS)
  {
    Error_Handler();
  }

  /* Set the desired size for the authentication tag to compute: note that in the case
     where the size of the tag is the default for the algorithm, it is
     possible to skip this call. */
  retval = cmox_mac_setTagLen(mac_ctx, sizeof(Expected_Tag));
  if (retval != CMOX_MAC_SUCCESS)
  {
    Error_Handler();
  }

  /* Setup of the authentication key into the context */
  retval = cmox_mac_setKey(mac_ctx, Key, sizeof(Key));  /* AES key to use */
  if (retval != CMOX_MAC_SUCCESS)
  {
    Error_Handler();
  }

  /* Append the message to be authenticated by chunks of CHUNK_SIZE Bytes */
  for (index = 0; index < (sizeof(Message) - CHUNK_SIZE); index += CHUNK_SIZE)
  {
    retval = cmox_mac_append(mac_ctx, &Message[index], CHUNK_SIZE); /* Chunk of data to authenticate */

    /* Verify API returned value */
    if (retval != CMOX_MAC_SUCCESS)
    {
      Error_Handler();
    }
  }
  /* Append the last part of the message if needed */
  if (index < sizeof(Message))
  {
    retval = cmox_mac_append(mac_ctx, &Message[index], sizeof(Message) - index); /* Last part of data to authenticate */

    /* Verify API returned value */
    if (retval != CMOX_MAC_SUCCESS)
    {
      Error_Handler();
    }
  }

  /* Generate the authentication tag */
  retval = cmox_mac_generateTag(mac_ctx, Computed_Tag, &computed_size);

  /* Verify API returned value */
  if (retval != CMOX_MAC_SUCCESS)
  {
    Error_Handler();
  }

  /* Verify generated data size is the expected one */
  if (computed_size != sizeof(Expected_Tag))
  {
    Error_Handler();
  }

  /* Verify generated data are the expected ones */
  if (memcmp(Expected_Tag, Computed_Tag, computed_size) != 0)
  {
    Error_Handler();
  }

  /* Cleanup the context */
  retval = cmox_mac_cleanup(mac_ctx);
  if (retval != CMOX_MAC_SUCCESS)
  {
    Error_Handler();
  }

  /* Construct a MAC context that is configured to perform AES CMAC authentication operations */
  /* Note: CMOX_CMAC_AES refer to the default AES implementation
   * selected in cmox_default_config.h. To use a specific implementation, user can
   * directly choose:
   * - CMOX_CMAC_AESFAST to select the AES fast implementation
   * - CMOX_CMAC_AESSMALL to select the AES small implementation
   */
  mac_ctx = cmox_cmac_construct(&Cmac_Ctx, CMOX_CMAC_AES);
  if (mac_ctx == NULL)
  {
    Error_Handler();
  }

  /* Initialize the MAC context */
  retval = cmox_mac_init(mac_ctx);
  if (retval != CMOX_MAC_SUCCESS)
  {
    Error_Handler();
  }

  /* Set the desired size for the authentication tag to compute: note that in the case
     where the size of the tag is the default for the algorithm, it is
     possible to skip this call. */
  retval = cmox_mac_setTagLen(mac_ctx, sizeof(Expected_Tag));
  if (retval != CMOX_MAC_SUCCESS)
  {
    Error_Handler();
  }

  /* Setup of the authentication key into the context */
  retval = cmox_mac_setKey(mac_ctx, Key, sizeof(Key));  /* AES key to use */
  if (retval != CMOX_MAC_SUCCESS)
  {
    Error_Handler();
  }

  /* Append the message to be authenticated by chunks of CHUNK_SIZE Bytes */
  for (index = 0; index < (sizeof(Message) - CHUNK_SIZE); index += CHUNK_SIZE)
  {
    retval = cmox_mac_append(mac_ctx, &Message[index], CHUNK_SIZE); /* Chunk of data to authenticate */

    /* Verify API returned value */
    if (retval != CMOX_MAC_SUCCESS)
    {
      Error_Handler();
    }
  }
  /* Append the last part of the message if needed */
  if (index < sizeof(Message))
  {
    retval = cmox_mac_append(mac_ctx, &Message[index], sizeof(Message) - index); /* Last part of data to authenticate */

    /* Verify API returned value */
    if (retval != CMOX_MAC_SUCCESS)
    {
      Error_Handler();
    }
  }

  /* Verify the authentication tag */
  retval = cmox_mac_verifyTag(mac_ctx,
                              Expected_Tag,   /* Authentication tag used for verification */
                              &fault_check);  /* Fault check variable:
                                              to ensure no fault injection occurs during this API call */

  /* Verify API returned value */
  if (retval != CMOX_MAC_AUTH_SUCCESS)
  {
    Error_Handler();
  }
  /* Verify Fault check variable value */
  if (fault_check != CMOX_MAC_AUTH_SUCCESS)
  {
    Error_Handler();
  }

  /* Cleanup the context */
  retval = cmox_mac_cleanup(mac_ctx);
  if (retval != CMOX_MAC_SUCCESS)
  {
    Error_Handler();
  }

  /* No more need of cryptographic services, finalize cryptographic library */
  if (cmox_finalize(NULL) != CMOX_INIT_SUCCESS)
  {
    Error_Handler();
  }

  /* Turn on LD2 in an infinite loop in case of AES CMAC operations are successful */
  BSP_LED_On(LD2);
  glob_status = PASSED;
  while (1)
  {}
}

/**
  * @brief  System Clock Configuration
  *         The system Clock is configured as follow :
  *            System Clock source            = MSIS
  *            SYSCLK(Hz)                     = 96000000
  *            HCLK(Hz)                       = 96000000
  *            AHB Prescaler                  = 1
  *            APB1 Prescaler                 = 1
  *            APB2 Prescaler                 = 1
  *            APB3 Prescaler                 = 1
  *            Flash Latency(WS)              = 2
  * @param  None
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Enable Epod Booster
  */
  if (HAL_RCCEx_EpodBoosterClkConfig(RCC_EPODBOOSTER_SOURCE_MSIS, RCC_EPODBOOSTER_DIV1) != HAL_OK)
  {
    Error_Handler();
  }

  if (HAL_PWREx_EnableEpodBooster() != HAL_OK)
  {
    Error_Handler();
  }

  /** Configure the main internal regulator output voltage
  */
  if (HAL_PWREx_ControlVoltageScaling(PWR_REGULATOR_VOLTAGE_SCALE1) != HAL_OK)
  {
    Error_Handler();
  }

  /** Set Flash latency before increasing MSIS
  */
  __HAL_FLASH_SET_LATENCY(FLASH_LATENCY_2);

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_MSIS;
  RCC_OscInitStruct.MSISState = RCC_MSI_ON;
  RCC_OscInitStruct.MSISSource = RCC_MSI_RC0;
  RCC_OscInitStruct.MSISDiv = RCC_MSI_DIV1;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2
                              |RCC_CLOCKTYPE_PCLK3;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_MSIS;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;
  RCC_ClkInitStruct.APB3CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_2) != HAL_OK)
  {
    Error_Handler();
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
  /* Toggle LD2 @2Hz to notify error condition */
  while (1)
  {
    BSP_LED_Toggle(LD2);
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
