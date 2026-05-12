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

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "transport-layer.h"
#include "crc8.h"
#include "ring-buffer.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */
typedef struct TIMER_TypeDef {
    uint32_t WAIT_TIME;
    uint32_t TARGET_TIME;
    bool AUTO_RESET;
    bool HAS_ELAPSED;
} TIMER_TypeDef;

typedef enum AL_State_TypeDef {
    AL_State_Sync,
    AL_State_WaitForUpdateRequest,
	AL_State_ReceiveFirmwareHeader,
    AL_State_EraseFlash,
    AL_State_ReceiveFirmware,
	AL_State_VerifyFirmwareSignature,
    AL_State_Done
} AL_State_TypeDef;

typedef void (*pFunction)(void);
/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
CRC_HandleTypeDef hcrc;

UART_HandleTypeDef huart2;
DMA_HandleTypeDef hdma_usart2_rx;

/* USER CODE BEGIN PV */
static AL_State_TypeDef al_state = AL_State_Sync;
static TL_Packet_TypeDef temp_packet;

static TIMER_TypeDef timer;
static uint32_t bytes_written = 0;
static uint8_t sync_seq[4] = {0U};

static RB_TypeDef ring_buffer = {
	.buffer = 0,
	.mask = 0,
	.read_index = 0,
	.write_index = 0
};

static uint8_t data_buffer[128] = {0U};

static FLASH_EraseInitTypeDef pEraseInit = {
	.TypeErase   = FLASH_TYPEERASE_PAGES,
	.PageAddress = FIRMWARE_IMAGE_START_ADDRESS_BANK_2,
	.NbPages	 = 192
};

static uint32_t PageError = 0;

static uint32_t firmware_header_byte_receive = 0;

static FirmwareHeader_TypeDef* firmware_header_bank_1 = (FirmwareHeader_TypeDef*)(FIRMWARE_IMAGE_START_ADDRESS_BANK_1);
static FirmwareHeader_TypeDef  firmware_header_bank_1_tmp = {0};
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_DMA_Init(void);
static void MX_USART2_UART_Init(void);
static void MX_CRC_Init(void);
/* USER CODE BEGIN PFP */
static void Main_Firmware(void);
static void TIMER_Init(TIMER_TypeDef* timer, uint32_t WAIT_TIME, bool AUTO_RESET);
static void TIMER_Reset(TIMER_TypeDef* timer);
static bool TIMER_Is_Elapsed(TIMER_TypeDef* timer);

// void HAL_UART_RxCpltCallback(UART_HandleTypeDef *huart);
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
  	MX_DMA_Init();
  	MX_USART2_UART_Init();
  	MX_CRC_Init();
 	/* USER CODE BEGIN 2 */
	TIMER_Init(&timer, DEFAULT_TIMEOUT, false);
	TL_Init();
	RB_Init(&ring_buffer, data_buffer, 128);
	// HAL_UART_Receive_IT(&huart2, uart_rx_temp, 1);
	HAL_UART_Receive_DMA(&huart2, ring_buffer.buffer, 128);
  	/* USER CODE END 2 */

  	/* Infinite loop */
  	/* USER CODE BEGIN WHILE */
	while (al_state != AL_State_Done) 
	{
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
		if (al_state == AL_State_Sync) {
			// ASK THE DMA HARDWARE HOW MANY BYTES ARE LEFT TO TRANSFER
    		uint32_t current_ndtr = __HAL_DMA_GET_COUNTER(huart2.hdmarx);
    		// SYNCHRONIZE OUR SOFTWARE write_index TO MATCH THE HARDWARE
    		RB_Sync_Write_Index(&ring_buffer, current_ndtr);

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
                    TL_PACKET_Create_Message(&temp_packet, AL_MESSAGE_SEQUENCE_OBSERVED);
                    TL_Write(&temp_packet);
					TIMER_Reset(&timer);
                    al_state = AL_State_WaitForUpdateRequest;
                } else {
                    if (TIMER_Is_Elapsed(&timer)) {
                        al_state = AL_State_Done;
                        continue;
                    } else {
                        continue;
                    }
                }
            } else {
                if (TIMER_Is_Elapsed(&timer)) {
                    al_state = AL_State_Done;
                    continue;
                } else {
                    continue;
                }
            }
        }

        TL_Update(&ring_buffer);

        switch (al_state) {
            case AL_State_WaitForUpdateRequest: {
                if (TL_IS_Packet_Available()) {
                    TL_Read(&temp_packet);

                    if (TL_PACKET_VALIDATE_Message_Type(&temp_packet, AL_MESSAGE_FIRMWARE_UPDATE_REQUEST)) {
						uint8_t temp[8] = {0};
						memcpy(&temp[0], &firmware_header_bank_1->DeviceID, sizeof(uint32_t));
						memcpy(&temp[4], &firmware_header_bank_1->Version, sizeof(uint32_t));
						TL_PACKET_Create_MultiByte_Message(&temp_packet, temp, 8, AL_MESSAGE_SENT_CURRENT_FIRMWARE_VERSION);
                        TL_Write(&temp_packet);
                        al_state = AL_State_ReceiveFirmwareHeader;
                    } else {
                        continue;
                    }
                } else {
                    continue;
                }
            } break;

			case AL_State_ReceiveFirmwareHeader: {
				if (TL_IS_Packet_Available()) {
                    TL_Read(&temp_packet);

                    if (TL_PACKET_VALIDATE_Message_Type(&temp_packet, AL_MESSAGE_SENT_NEW_FIRMWARE_HEADER_DATA)) {
						memcpy((uint8_t*)(&firmware_header_bank_1_tmp) + firmware_header_byte_receive, &temp_packet.data[0], PACKET_DATA_BYTE_SIZE);
						TL_PACKET_Create_MultiByte_Message(
							&temp_packet, 
							(uint8_t*)(&firmware_header_bank_1_tmp) + firmware_header_byte_receive, 
							PACKET_DATA_BYTE_SIZE,
							AL_MESSAGE_RECEIVED_NEW_FIRMWARE_HEADER_DATA
						);
                        TL_Write(&temp_packet);
						firmware_header_byte_receive = firmware_header_byte_receive + PACKET_DATA_BYTE_SIZE;
						if (firmware_header_byte_receive == sizeof(FirmwareHeader_TypeDef)) {
							al_state = AL_State_EraseFlash;
						} else {
							continue;
						}
                    } else {
                        continue;
                    }
                } else {
                    continue;
                }
			} break;

            case AL_State_EraseFlash: {
				uint32_t* firmware_header_bank_1_tmp_ptr = (uint32_t*)&firmware_header_bank_1_tmp;
                uint32_t word_count = sizeof(FirmwareHeader_TypeDef) / 4;
                HAL_FLASH_Unlock();
                HAL_FLASHEx_Erase(&pEraseInit, &PageError);
				for (uint32_t i = 0; i < word_count; i++) {
                    HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, FIRMWARE_IMAGE_START_ADDRESS_BANK_2 + (i * 4), firmware_header_bank_1_tmp_ptr[i]);
                }
                HAL_FLASH_Lock();
				TL_PACKET_Create_Message(&temp_packet, AL_MESSAGE_FIRMWARE_HEADER_WRITTEN);
                TL_Write(&temp_packet);
				al_state = AL_State_ReceiveFirmware; 
            } break;

            case AL_State_ReceiveFirmware: {
                if (TL_IS_Packet_Available()) {
                    TL_Read(&temp_packet);
                    
                    for (uint8_t i = 0; i < temp_packet.packet_data_size; i = i + 4) {
                        uint32_t firmware_data = (
                            (temp_packet.data[i])           |
                            (temp_packet.data[i + 1] << 8)  |
                            (temp_packet.data[i + 2] << 16) |
                            (temp_packet.data[i + 3] << 24) 
                        );
                        HAL_FLASH_Unlock();
                        HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, FIRMWARE_ENTRY_POINT_ADDRESS_BANK_2 + bytes_written, firmware_data);
                        HAL_FLASH_Lock();
                        bytes_written += 4;
                    }
                    
                    if (bytes_written == firmware_header_bank_1_tmp.Size) {
						TL_PACKET_Create_Message(&temp_packet, AL_MESSAGE_UPDATE_SUCCESSFUL);
                		TL_Write(&temp_packet);
                        al_state = AL_State_Done;
                    } else {
                        TL_PACKET_Create_Message(&temp_packet, AL_MESSAGE_RECEIVED_NEW_FIRMWARE_DATA);
                        TL_Write(&temp_packet);
                    }
                } else {
                    continue;
                }
            } break;

            default: {
                al_state = AL_State_Sync;
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
		RCC_CLOCKTYPE_PCLK1	 |
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
  * @brief CRC Initialization Function
  * @param None
  * @retval None
  */
static void MX_CRC_Init(void)
{
	/* USER CODE BEGIN CRC_Init 0 */

	/* USER CODE END CRC_Init 0 */

	/* USER CODE BEGIN CRC_Init 1 */

	/* USER CODE END CRC_Init 1 */
	hcrc.Instance = CRC;
	hcrc.Init.DefaultPolynomialUse = DEFAULT_POLYNOMIAL_ENABLE;
	hcrc.Init.DefaultInitValueUse = DEFAULT_INIT_VALUE_ENABLE;
	hcrc.Init.InputDataInversionMode = CRC_INPUTDATA_INVERSION_NONE;
	hcrc.Init.OutputDataInversionMode = CRC_OUTPUTDATA_INVERSION_DISABLE;
	hcrc.InputDataFormat = CRC_INPUTDATA_FORMAT_BYTES;
	if (HAL_CRC_Init(&hcrc) != HAL_OK)
	{
		Error_Handler();
	}
	/* USER CODE BEGIN CRC_Init 2 */

	/* USER CODE END CRC_Init 2 */
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
  * Enable DMA controller clock
  */
static void MX_DMA_Init(void)
{
	/* DMA controller clock enable */
	__HAL_RCC_DMA1_CLK_ENABLE();

	/* DMA interrupt init */
	/* DMA1_Channel4_5_6_7_IRQn interrupt configuration */
	HAL_NVIC_SetPriority(DMA1_Channel4_5_6_7_IRQn, 0, 0);
	HAL_NVIC_EnableIRQ(DMA1_Channel4_5_6_7_IRQn);
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
	VectorTable_TypeDef* vector_table = (VectorTable_TypeDef*)FIRMWARE_ENTRY_POINT_ADDRESS_BANK_1;
	__HAL_RCC_DMA1_CLK_ENABLE();
    __disable_irq();
    HAL_DeInit();
	HAL_RCC_DeInit();
    vector_table->Reset_Handler();
}

static void TIMER_Init(TIMER_TypeDef* timer, uint32_t WAIT_TIME, bool AUTO_RESET) {
    timer->WAIT_TIME = WAIT_TIME;
    timer->AUTO_RESET = AUTO_RESET;
    timer->TARGET_TIME = HAL_GetTick() + WAIT_TIME;
    timer->HAS_ELAPSED = false;
}

static void TIMER_Reset(TIMER_TypeDef* timer) {
    TIMER_Init(timer, timer->WAIT_TIME, timer->AUTO_RESET);
}

static bool TIMER_Is_Elapsed(TIMER_TypeDef* timer) {
    uint32_t now = HAL_GetTick();
    bool HAS_ELAPSED = now >= timer->TARGET_TIME;

    if (timer->HAS_ELAPSED) return false;

    if (HAS_ELAPSED) {
        if (timer->AUTO_RESET) {
            uint32_t drift = now - timer->TARGET_TIME;
            timer->TARGET_TIME = (now + timer->WAIT_TIME) - drift;
        } else {
            timer->HAS_ELAPSED = true;
        }
    }
    
    return HAS_ELAPSED;
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
