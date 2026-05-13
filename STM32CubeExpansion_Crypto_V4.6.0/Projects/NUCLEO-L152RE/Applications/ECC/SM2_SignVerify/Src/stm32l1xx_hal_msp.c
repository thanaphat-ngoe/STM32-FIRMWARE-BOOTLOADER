/**
  ******************************************************************************
  * @file    ECC/SM2_SignVerify/Src/stm32l1xx_hal_msp.c
  * @author  MCD Application Team
  * @brief   This file contains HAL MSP module
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2016 STMicroelectronics.
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
#include "entropy.h"

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
}


/**
  * @brief TIM MSP Initialization
  * This function configures the hardware resources used in this example
  * @param htim: TIM handle pointer
  * @retval None
  */
void HAL_TIM_Base_MspInit(TIM_HandleTypeDef *htim)
{
  if (htim->Instance == TIM10)
  {
    __HAL_RCC_TIM10_CLK_ENABLE();
  }
  
}

/**
  * @brief TIM MSP De-Initialization
  * This function freeze the hardware resources used in this example
  * @param htim: TIM handle pointer
  * @retval None
  */
void HAL_TIM_Base_MspDeInit(TIM_HandleTypeDef *htim)
{
  if (htim->Instance == TIM10)
  {
    __HAL_RCC_TIM10_CLK_DISABLE();
  }
  
}

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
