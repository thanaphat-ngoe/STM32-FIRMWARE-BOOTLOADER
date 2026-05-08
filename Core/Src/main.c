/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
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
/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "stm32l0xx_hal.h"
#include "stm32l0xx_hal_flash_ex.h"
#include "stm32l0xx_hal_uart.h"
#include "transport-layer.h"
#include "ring-buffer.h"
#include "crc8.h"
/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */

/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */
typedef struct FirmwareHeader_TypeDef {
	uint32_t MagicNumber;
	uint32_t DeviceID;
	uint32_t Version;
	uint32_t Size;
	uint32_t Flags;
	uint32_t EntryPointAddress;
	uint32_t CRC32;
	uint32_t Signature_R[8];
	uint32_t Signature_S[8];
	uint32_t Reserved[41];
} FirmwareHeader_TypeDef;

typedef struct TIMER_TypeDef {
    uint32_t wait_time;
    uint32_t target_time;
    bool auto_reset;
    bool has_elapsed;
} TIMER_TypeDef;

typedef enum ALState_TypeDef {
    ALState_Sync,
    ALState_WaitForUpdateReq,
    ALState_DeviceIDReq,
    ALState_DeviceIDRes,
    ALState_FirmwareLengthReq,
    ALState_FirmwareLengthRes,
    ALState_EraseApplication,
    ALState_ReceiveFirmware,
    ALState_Done
} ALState_TypeDef;
/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
#define DEVICE_ID                    (0x01)

#define SYNC_SEQ_0                   (0x01)
#define SYNC_SEQ_1                   (0x02)
#define SYNC_SEQ_2                   (0x03)
#define SYNC_SEQ_3                   (0x04)

#define DEFAULT_TIMEOUT              (1000)

#define BOOTLOADER_SIZE              (0x4000U) // 16 KByte (16384 Byte)
#define FIRMWARE_IMAGE_START_ADDRESS (FLASH_BASE + BOOTLOADER_SIZE) // 0x08000000 + 0x4000 (0x08004000)
#define FIRMWARE_ENTRY_POINT_ADDRESS (FIRMWARE_IMAGE_START_ADDRESS + sizeof(FirmwareHeader_TypeDef))
#define MAX_FIRMWARE_IMAGE_SIZE      (FLASH_SIZE - BOOTLOADER_SIZE) // 48 Kbyte (49152 Byte)

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
/* USER CODE BEGIN PV */
UART_HandleTypeDef huart2;
static ALState_TypeDef al_state = ALState_Sync;
static TLPacket_TypeDef temp_packet;

static TIMER_TypeDef timer;
static uint32_t firmware_size = 0;
static uint32_t bytes_written = 0;
static uint8_t sync_seq[4] = {0U};

static RB_TypeDef ring_buffer = {
	.buffer = 0,
	.mask = 0,
	.read_index = 0,
	.write_index = 0
};

static uint8_t data_buffer[128] = {0U};
static uint8_t uart_rx_temp[2] = {0U};

static FLASH_EraseInitTypeDef pEraseInit = {
	.TypeErase   = FLASH_TYPEERASE_PAGES,
	.PageAddress = FIRMWARE_IMAGE_START_ADDRESS,
	.NbPages	 = 384
};

static uint32_t PageError = 0;
typedef void (*pFunction)(void);
static FirmwareHeader_TypeDef* firmware_header = (FirmwareHeader_TypeDef*)(FIRMWARE_IMAGE_START_ADDRESS);
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_USART2_UART_Init(void);
/* USER CODE BEGIN PFP */
static void Main_Firmware(void);
void TIMER_Init(TIMER_TypeDef* timer, uint32_t wait_time, bool auto_reset);
bool TIMER_Is_Elapsed(TIMER_TypeDef* timer);
void TIMER_Reset(TIMER_TypeDef* timer);
void HAL_UART_RxCpltCallback(UART_HandleTypeDef *huart);

static bool IS_MESSAGE_Device_ID(const TLPacket_TypeDef* packet);
static bool IS_MESSAGE_Firmware_Size(const TLPacket_TypeDef* packet);
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

	/* USER CODE BEGIN 1 */

	/* USER CODE END 1 */

	/* MCU Configuration--------------------------------------------------------*/

	/* Reset of all peripherals, Initializes the Flash interface and the Systick. */
	HAL_Init();

	/* USER CODE BEGIN Init */

	/* USER CODE END Init */

	/* Configure the system clock */
	SystemClock_Config();

	/* USER CODE BEGIN SysInit */

	/* USER CODE END SysInit */

	/* Initialize all configured peripherals */
	MX_GPIO_Init();
	MX_USART2_UART_Init();
	/* USER CODE BEGIN 2 */
	TIMER_Init(&timer, DEFAULT_TIMEOUT, false);
	TL_Init(&huart2);
	RB_Init(&ring_buffer, data_buffer, 128);
	HAL_UART_Receive_IT(&huart2, uart_rx_temp, 1);
	/* USER CODE END 2 */

	/* Infinite loop */
	/* USER CODE BEGIN WHILE */
	while (al_state != ALState_Done) 
	{
		/* USER CODE END WHILE */
		
		/* USER CODE BEGIN 3 */
		if (al_state == ALState_Sync) {
            if (!RB_Is_Empty(&ring_buffer)) {
                sync_seq[0] = sync_seq[1];
                sync_seq[1] = sync_seq[2];
                sync_seq[2] = sync_seq[3];
				RB_Read(&ring_buffer, &sync_seq[3]);

                bool is_match = sync_seq[0] == SYNC_SEQ_0;
                is_match = is_match && (sync_seq[1] == SYNC_SEQ_1);
                is_match = is_match && (sync_seq[2] == SYNC_SEQ_2);
                is_match = is_match && (sync_seq[3] == SYNC_SEQ_3);
            
                if (is_match) {
                    TL_Create_Single_Byte_Packet(&temp_packet, AL_MESSAGE_SEQ_OBSERVED);
                    TL_Write(&temp_packet);
                    al_state = ALState_WaitForUpdateReq;
                } else {
                    if (TIMER_Is_Elapsed(&timer)) {
                        al_state = ALState_Done;
                        continue;
                    } else {
                        continue;
                    }
                }
            } else {
                if (TIMER_Is_Elapsed(&timer)) {
                    al_state = ALState_Done;
                    continue;
                } else {
                    continue;
                }
            }
        }

        TL_Update(&ring_buffer);

        switch (al_state) {
            case ALState_WaitForUpdateReq: {
                if (TL_Is_Packet_Available()) {
                    TL_Read(&temp_packet);

                    if (TL_Is_Single_Byte_Packet(&temp_packet, AL_MESSAGE_FW_UPDATE_REQ)) {
                        TL_Create_Single_Byte_Packet(&temp_packet, AL_MESSAGE_FW_UPDATE_RES);
                        TL_Write(&temp_packet);
                        al_state = ALState_DeviceIDReq;
                    } else {
                        continue;
                    }
                } else {
                    continue;
                }
            } break;
            
            case ALState_DeviceIDReq: {
                TL_Create_Single_Byte_Packet(&temp_packet, AL_MESSAGE_DEVICE_ID_REQ);
                TL_Write(&temp_packet);
                al_state = ALState_DeviceIDRes;
            } break;
            
            case ALState_DeviceIDRes: {
                if (TL_Is_Packet_Available()) {
                    TL_Read(&temp_packet);

                    if (IS_MESSAGE_Device_ID(&temp_packet) && temp_packet.data[1] == DEVICE_ID) {
                        al_state = ALState_FirmwareLengthReq;
                    } else {
                        continue;
                    }
                } else {
                    continue;
                }
            } break;
            
            case ALState_FirmwareLengthReq: {
                TL_Create_Single_Byte_Packet(&temp_packet, AL_MESSAGE_FW_LENGTH_REQ);
                TL_Write(&temp_packet);
                al_state = ALState_FirmwareLengthRes;
            } break;
            
            case ALState_FirmwareLengthRes: {
                if (TL_Is_Packet_Available()) {
                    TL_Read(&temp_packet);
                    firmware_size = (
                        (temp_packet.data[1])       |
                        (temp_packet.data[2] << 8)  |
                        (temp_packet.data[3] << 16) |
                        (temp_packet.data[4] << 24) 
                    );

                    if (IS_MESSAGE_Firmware_Size(&temp_packet) && (firmware_size <= MAX_FIRMWARE_IMAGE_SIZE) && (firmware_size % 4 == 0)) {
                        al_state = ALState_EraseApplication;
                    } else {
                        continue;
                    }
                } else {
                    continue;
                }
            } break;
            
            case ALState_EraseApplication: {
                HAL_FLASH_Unlock();
    			HAL_FLASHEx_Erase(&pEraseInit, &PageError);
    			HAL_FLASH_Lock();
                TL_Create_Single_Byte_Packet(&temp_packet, AL_MESSAGE_READY_FOR_DATA);
                TL_Write(&temp_packet);
                al_state = ALState_ReceiveFirmware; 
            } break;
            
            case ALState_ReceiveFirmware: {
                if (TL_Is_Packet_Available()) {
                    TL_Read(&temp_packet);
                    
                    for (uint8_t i = 0; i < temp_packet.packet_data_size; i = i + 4) {
                        uint32_t firmware_data = (
                            (temp_packet.data[i])           |
                            (temp_packet.data[i + 1] << 8)  |
                            (temp_packet.data[i + 2] << 16) |
                            (temp_packet.data[i + 3] << 24) 
                        );
                        HAL_FLASH_Unlock();
                        HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, FIRMWARE_IMAGE_START_ADDRESS + bytes_written, firmware_data);
                        HAL_FLASH_Lock();
                        bytes_written += 4;
                    }
                    
                    if (bytes_written >= MAX_FIRMWARE_IMAGE_SIZE) {
                        TL_Create_Single_Byte_Packet(&temp_packet, AL_MESSAGE_UPDATE_SUCCESSFUL);
                        TL_Write(&temp_packet);
                        al_state = ALState_Done;
                    } else {
                        TL_Create_Single_Byte_Packet(&temp_packet, AL_MESSAGE_READY_FOR_DATA);
                        TL_Write(&temp_packet);
                    }
                } else {
                    continue;
                }
            } break;

            default: {
                al_state = ALState_Sync;
            }
        }
	}

	HAL_Delay(1000);
	Main_Firmware();
	/* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void) 
{
	RCC_OscInitTypeDef RCC_OscInitStruct = {0};
	RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};
	RCC_PeriphCLKInitTypeDef PeriphClkInit = {0};

	/** Configure the main internal regulator output voltage
	*/
	__HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

	/** Initializes the RCC Oscillators according to the specified parameters
	* in the RCC_OscInitTypeDef structure.
	*/
	RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
	RCC_OscInitStruct.HSIState = RCC_HSI_ON;
	RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
	RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
	RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSI;
	RCC_OscInitStruct.PLL.PLLMUL = RCC_PLLMUL_4;
	RCC_OscInitStruct.PLL.PLLDIV = RCC_PLLDIV_2;
	if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
	{
		Error_Handler();
	}

	/** Initializes the CPU, AHB and APB buses clocks
	*/
	RCC_ClkInitStruct.ClockType = 
		RCC_CLOCKTYPE_HCLK   |
		RCC_CLOCKTYPE_SYSCLK |
		RCC_CLOCKTYPE_PCLK1  |
		RCC_CLOCKTYPE_PCLK2;
	RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
	RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
	RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
	RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

	if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_1) != HAL_OK)
	{
		Error_Handler();
	}
	PeriphClkInit.PeriphClockSelection = RCC_PERIPHCLK_USART2;
	PeriphClkInit.Usart2ClockSelection = RCC_USART2CLKSOURCE_PCLK1;
	if (HAL_RCCEx_PeriphCLKConfig(&PeriphClkInit) != HAL_OK)
	{
		Error_Handler();
	}
}

/**
  * @brief USART2 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART2_UART_Init(void)
{
	/* USER CODE BEGIN USART2_Init 0 */

	/* USER CODE END USART2_Init 0 */

	/* USER CODE BEGIN USART2_Init 1 */

	/* USER CODE END USART2_Init 1 */
	huart2.Instance = USART2;
	huart2.Init.BaudRate = 115200;
	huart2.Init.WordLength = UART_WORDLENGTH_8B;
	huart2.Init.StopBits = UART_STOPBITS_1;
	huart2.Init.Parity = UART_PARITY_NONE;
	huart2.Init.Mode = UART_MODE_TX_RX;
	huart2.Init.HwFlowCtl = UART_HWCONTROL_NONE;
	huart2.Init.OverSampling = UART_OVERSAMPLING_16;
	huart2.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
	huart2.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
	if (HAL_UART_Init(&huart2) != HAL_OK)
	{
		Error_Handler();
	}
	/* USER CODE BEGIN USART2_Init 2 */

	/* USER CODE END USART2_Init 2 */
}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
	GPIO_InitTypeDef GPIO_InitStruct = {0};
	/* USER CODE BEGIN MX_GPIO_Init_1 */

	/* USER CODE END MX_GPIO_Init_1 */

	/* GPIO Ports Clock Enable */
	__HAL_RCC_GPIOC_CLK_ENABLE();
	__HAL_RCC_GPIOH_CLK_ENABLE();
	__HAL_RCC_GPIOA_CLK_ENABLE();

	/*Configure GPIO pin Output Level */
	HAL_GPIO_WritePin(LD2_GPIO_Port, LD2_Pin, GPIO_PIN_RESET);

	/*Configure GPIO pin : B1_Pin */
	GPIO_InitStruct.Pin = B1_Pin;
	GPIO_InitStruct.Mode = GPIO_MODE_IT_FALLING;
	GPIO_InitStruct.Pull = GPIO_NOPULL;
	HAL_GPIO_Init(B1_GPIO_Port, &GPIO_InitStruct);

	/*Configure GPIO pin : LD2_Pin */
	GPIO_InitStruct.Pin = LD2_Pin;
	GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
	GPIO_InitStruct.Pull = GPIO_NOPULL;
	GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
	HAL_GPIO_Init(LD2_GPIO_Port, &GPIO_InitStruct);

	/* USER CODE BEGIN MX_GPIO_Init_2 */

	/* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */
static void Main_Firmware(void) {
	uint32_t target_address = *(__IO uint32_t*)(firmware_header->EntryPointAddress + 4);
    pFunction Firmware = (pFunction)target_address;
    __disable_irq();
    HAL_DeInit();
	HAL_RCC_DeInit();
    Firmware();
}

void TIMER_Init(TIMER_TypeDef* timer, uint32_t wait_time, bool auto_reset) {
    timer->wait_time = wait_time;
    timer->auto_reset = auto_reset;
    timer->target_time = HAL_GetTick() + wait_time;
    timer->has_elapsed = false;
}

bool TIMER_Is_Elapsed(TIMER_TypeDef* timer) {
    uint32_t now = HAL_GetTick();
    bool has_elapsed = now >= timer->target_time;

    if (timer->has_elapsed) return false;

    if (has_elapsed) {
        if (timer->auto_reset) {
            uint32_t drift = now - timer->target_time;
            timer->target_time = (now + timer->wait_time) - drift;
        } else {
            timer->has_elapsed = true;
        }
    }
    
    return has_elapsed;
}
 
void TIMER_Reset(TIMER_TypeDef* timer) {
    TIMER_Init(timer, timer->wait_time, timer->auto_reset);
}

void HAL_UART_RxCpltCallback(UART_HandleTypeDef *huart) {
	RB_Write(&ring_buffer, uart_rx_temp[0]);
	HAL_UART_Receive_IT(&huart2, uart_rx_temp, 1);
}

static bool IS_MESSAGE_Device_ID(const TLPacket_TypeDef* packet) {
    if (packet->packet_data_size != 2) {
        return false;
    }

    if (packet->packet_type == PACKET_ACK || packet->packet_type == PACKET_RETX || packet->packet_type != 0) {
        return false;
    }

    if (packet->data[0] != AL_MESSAGE_DEVICE_ID_RES) {
        return false;
    }

    for (uint8_t i = 2; i < PACKET_DATA_SIZE; i++) {
        if (packet->data[i] != 0xff) {
            return false;
        }
    }

    return true;
}

static bool IS_MESSAGE_Firmware_Size(const TLPacket_TypeDef* packet) {
    if (packet->packet_data_size != 5) {
        return false;
    }

    if (packet->packet_type == PACKET_ACK || packet->packet_type == PACKET_RETX || packet->packet_type != 0) {
        return false;
    }

    if (packet->data[0] != AL_MESSAGE_FW_LENGTH_RES) {
        return false;
    }

    for (uint8_t i = 5; i < PACKET_DATA_SIZE; i++) {
        if (packet->data[i] != 0xff) {
            return false;
        }
    }

    return true;
}

/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
	/* USER CODE BEGIN Error_Handler_Debug */
	/* User can add his own implementation to report the HAL error return state */
	__disable_irq();
	while (1)
	{
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
