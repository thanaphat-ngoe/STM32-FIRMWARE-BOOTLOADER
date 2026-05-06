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
**/
/* USER CODE END Header */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef __MAIN_H
#define __MAIN_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#include "stm32l0xx_hal.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
/* USER CODE END Includes */

/* Exported types ------------------------------------------------------------*/
/* USER CODE BEGIN ET */
typedef void (*isr_handler_t)(void);

// MEMORY LAYOUT OF THE STM32L053xx VECTOR TABLE
typedef struct {
    void *initial_sp;                             // 0x00: Initial Stack Pointer
    isr_handler_t Reset_Handler;                  // 0x04: Reset Handler
    isr_handler_t NMI_Handler;                    // 0x08: NMI Handler
    isr_handler_t HardFault_Handler;              // 0x0C: Hard Fault Handler
    uint32_t reserved1[7];                        // 0x10 - 0x28: Reserved
    isr_handler_t SVC_Handler;                    // 0x2C: SVCall Handler
    uint32_t reserved2[2];                        // 0x30 - 0x34: Reserved
    isr_handler_t PendSV_Handler;                 // 0x38: PendSV Handler
    isr_handler_t SysTick_Handler;                // 0x3C: SysTick Handler
    
    // --- PERIPHERAL INTERRUPTS ---
    isr_handler_t WWDG_IRQHandler;                // Window WatchDog
    isr_handler_t PVD_IRQHandler;                 // PVD through EXTI Line detection
    isr_handler_t RTC_IRQHandler;                 // RTC through the EXTI line
    isr_handler_t FLASH_IRQHandler;               // FLASH
    isr_handler_t RCC_CRS_IRQHandler;             // RCC and CRS
    isr_handler_t EXTI0_1_IRQHandler;             // EXTI Line 0 and 1
    isr_handler_t EXTI2_3_IRQHandler;             // EXTI Line 2 and 3
    isr_handler_t EXTI4_15_IRQHandler;            // EXTI Line 4 to 15
    isr_handler_t TSC_IRQHandler;                 // TSC
    isr_handler_t DMA1_Channel1_IRQHandler;       // DMA1 Channel 1
    isr_handler_t DMA1_Channel2_3_IRQHandler;     // DMA1 Channel 2 and 3
    isr_handler_t DMA1_Channel4_5_6_7_IRQHandler; // DMA1 Channel 4, 5, 6 and 7
    isr_handler_t ADC1_COMP_IRQHandler;           // ADC1, COMP1 and COMP2
    isr_handler_t LPTIM1_IRQHandler;              // LPTIM1
    uint32_t reserved3[1];                        // Reserved
    isr_handler_t TIM2_IRQHandler;                // TIM2
    uint32_t reserved4[1];                        // Reserved
    isr_handler_t TIM6_DAC_IRQHandler;            // TIM6 and DAC
    uint32_t reserved5[2];                        // Reserved
    isr_handler_t TIM21_IRQHandler;               // TIM21
    uint32_t reserved6[1];                        // Reserved
    isr_handler_t TIM22_IRQHandler;               // TIM22
    isr_handler_t I2C1_IRQHandler;                // I2C1
    isr_handler_t I2C2_IRQHandler;                // I2C2
    isr_handler_t SPI1_IRQHandler;                // SPI1
    isr_handler_t SPI2_IRQHandler;                // SPI2
    isr_handler_t USART1_IRQHandler;              // USART1
    isr_handler_t USART2_IRQHandler;              // USART2
    isr_handler_t RNG_LPUART1_IRQHandler;         // RNG and LPUART1
    isr_handler_t LCD_IRQHandler;                 // LCD
    isr_handler_t USB_IRQHandler;                 // USB
} VectorTable_t;
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
