/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.h
  * @brief          : Header for main.c file.
  *                   This file contains the common defines of the application.
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2026 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef __MAIN_H
#define __MAIN_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#include "stm32l0xx_hal.h"
#include "stdbool.h"
/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */

/* USER CODE END Includes */

/* Exported types ------------------------------------------------------------*/
/* USER CODE BEGIN ET */
typedef void (*pFunction)(void);

typedef struct VectorTable_TypeDef {
    /* ARM Cortex-M Core Exceptions */
    uint32_t  Initial_SP;                     /* 0x00 Initial Stack Pointer value (_estack) */
    pFunction Reset_Handler;                  /* 0x04 Reset Handler */
    pFunction NMI_Handler;                    /* 0x08 Non Maskable Interrupt */
    pFunction HardFault_Handler;              /* 0x0C Hard Fault Interrupt */
    uint32_t  Reserved1[7];                   /* 0x10 - 0x28 Reserved */
    pFunction SVC_Handler;                    /* 0x2C SV Call Interrupt */
    uint32_t  Reserved2[2];                   /* 0x30 - 0x34 Reserved */
    pFunction PendSV_Handler;                 /* 0x38 Pend SV Interrupt */
    pFunction SysTick_Handler;                /* 0x3C System Tick Interrupt */

    /* STM32 Specific External Interrupts */
    pFunction WWDG_IRQHandler;                /* Window WatchDog */
    pFunction PVD_IRQHandler;                 /* PVD through EXTI Line detection */
    pFunction RTC_IRQHandler;                 /* RTC through the EXTI line */
    pFunction FLASH_IRQHandler;               /* FLASH */
    pFunction RCC_CRS_IRQHandler;             /* RCC and CRS */
    pFunction EXTI0_1_IRQHandler;             /* EXTI Line 0 and 1 */
    pFunction EXTI2_3_IRQHandler;             /* EXTI Line 2 and 3 */
    pFunction EXTI4_15_IRQHandler;            /* EXTI Line 4 to 15 */
    pFunction TSC_IRQHandler;                 /* TSC */
    pFunction DMA1_Channel1_IRQHandler;       /* DMA1 Channel 1 */
    pFunction DMA1_Channel2_3_IRQHandler;     /* DMA1 Channel 2 and Channel 3 */
    pFunction DMA1_Channel4_5_6_7_IRQHandler; /* DMA1 Channel 4, Channel 5, Channel 6 and Channel 7 */
    pFunction ADC1_COMP_IRQHandler;           /* ADC1, COMP1 and COMP2 */
    pFunction LPTIM1_IRQHandler;              /* LPTIM1 */
    uint32_t  Reserved3;                      /* Reserved */
    pFunction TIM2_IRQHandler;                /* TIM2 */
    uint32_t  Reserved4;                      /* Reserved */
    pFunction TIM6_DAC_IRQHandler;            /* TIM6 and DAC */
    uint32_t  Reserved5[2];                   /* Reserved */
    pFunction TIM21_IRQHandler;               /* TIM21 */
    uint32_t  Reserved6;                      /* Reserved */
    pFunction TIM22_IRQHandler;               /* TIM22 */
    pFunction I2C1_IRQHandler;                /* I2C1 */
    pFunction I2C2_IRQHandler;                /* I2C2 */
    pFunction SPI1_IRQHandler;                /* SPI1 */
    pFunction SPI2_IRQHandler;                /* SPI2 */
    pFunction USART1_IRQHandler;              /* USART1 */
    pFunction USART2_IRQHandler;              /* USART2 */
    pFunction RNG_LPUART1_IRQHandler;         /* RNG and LPUART1 */
    pFunction LCD_IRQHandler;                 /* LCD */
    pFunction USB_IRQHandler;                 /* USB */
} VectorTable_TypeDef;
/* USER CODE END ET */

/* Exported constants --------------------------------------------------------*/
/* USER CODE BEGIN EC */

/* USER CODE END EC */

/* Exported macro ------------------------------------------------------------*/
/* USER CODE BEGIN EM */

/* USER CODE END EM */

/* Exported functions prototypes ---------------------------------------------*/
void Error_Handler(void);

/* USER CODE BEGIN EFP */

/* USER CODE END EFP */

/* Private defines -----------------------------------------------------------*/
#define B1_Pin GPIO_PIN_13
#define B1_GPIO_Port GPIOC
#define USART_TX_Pin GPIO_PIN_2
#define USART_TX_GPIO_Port GPIOA
#define USART_RX_Pin GPIO_PIN_3
#define USART_RX_GPIO_Port GPIOA
#define LD2_Pin GPIO_PIN_5
#define LD2_GPIO_Port GPIOA
#define TMS_Pin GPIO_PIN_13
#define TMS_GPIO_Port GPIOA
#define TCK_Pin GPIO_PIN_14
#define TCK_GPIO_Port GPIOA

/* USER CODE BEGIN Private defines */

/* USER CODE END Private defines */

#ifdef __cplusplus
}
#endif

#endif /* __MAIN_H */
