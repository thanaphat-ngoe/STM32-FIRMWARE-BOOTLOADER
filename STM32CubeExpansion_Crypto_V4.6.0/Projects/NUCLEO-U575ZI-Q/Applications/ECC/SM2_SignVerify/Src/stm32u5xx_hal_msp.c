/**
  ******************************************************************************
  * @file    ECC/SM2_SignVerify/Src/stm32u5xx_hal_msp.c
  * @author  MCD Application Team
  * @brief   This file contains HAL MSP module
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
#include "main.h"

/* Global variables ----------------------------------------------------------*/


/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
/* Private function prototypes -----------------------------------------------*/
/* Private functions ---------------------------------------------------------*/

/**
  * @brief  Initialize the Global MSP.
  * @retval None
  */
void HAL_MspInit(void)
{
  __HAL_RCC_SYSCFG_CLK_ENABLE();
  __HAL_RCC_PWR_CLK_ENABLE();

  /** Disable the internal Pull-Up in Dead Battery pins of UCPD peripheral
  */
  HAL_PWREx_DisableUCPDDeadBattery();
}

/**
  * @brief RNG MSP Initialization
  * This function configures the hardware resources used in this example
  * @param hrng: RNG handle pointer
  * @retval None
  */
void HAL_RNG_MspInit(RNG_HandleTypeDef *hrng)
{
  if (hrng->Instance == RNG)
  {
    /** Initializes the peripherals clock
      */
    RCC_PeriphCLKInitTypeDef PeriphClkInit = {0};
    RCC_OscInitTypeDef RCC_OscInitStruct = {0};
    RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI48;
    RCC_OscInitStruct.HSI48State = RCC_HSI48_ON;
    if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
    {
      /* Initialization Error */
      while (1);
    }
    PeriphClkInit.PeriphClockSelection = RCC_PERIPHCLK_RNG;
    PeriphClkInit.RngClockSelection = RCC_RNGCLKSOURCE_HSI48;
    if (HAL_RCCEx_PeriphCLKConfig(&PeriphClkInit) != HAL_OK)
    {
      while (1);
    }
    /* Peripheral clock enable */
    __HAL_RCC_RNG_CLK_ENABLE();
  }
}

/**
  * @brief RNG MSP De-Initialization
  * This function freeze the hardware resources used in this example
  * @param hrng: RNG handle pointer
  * @retval None
  */
void HAL_RNG_MspDeInit(RNG_HandleTypeDef *hrng)
{
  if (hrng->Instance == RNG)
  {
    /* Peripheral clock disable */
    __HAL_RCC_RNG_CLK_DISABLE();
    /* Enable RNG reset state */
    __HAL_RCC_RNG_FORCE_RESET();
    /* Release RNG from reset state */
    __HAL_RCC_RNG_RELEASE_RESET();
  }
}


/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
