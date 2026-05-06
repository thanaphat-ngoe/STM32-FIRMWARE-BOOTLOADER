/* USER CODE BEGIN Header */

/* USER CODE END Header */

/* Includes ------------------------------------------------------------------*/
#include "main.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "system.h"
#include "uart.h"
#include "timer.h"
#include "transport-layer.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */
typedef enum bl_al_state_t {
    BL_AL_STATE_Sync,
    BL_AL_STATE_WaitForUpdateReq,
    BL_AL_STATE_DeviceIDReq,
    BL_AL_STATE_DeviceIDRes,
    BL_AL_STATE_FirmwareLengthReq,
    BL_AL_STATE_FirmwareLengthRes,
    BL_AL_STATE_EraseApplication,
    BL_AL_STATE_ReceiveFirmware,
    BL_AL_STATE_Done
} bl_al_state_t;
/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
#define BOOTLOADER_SIZE                (0x4000U)                      // 16 KByte (16384 Byte)
#define MAIN_APPLICATION_START_ADDRESS (FLASH_BASE + BOOTLOADER_SIZE) // (0x0800_0000 + 0x4000) = 0x0800_4000
#define FLASH_SIZE                     (0x10000U)                     // 64 Kbyte (65536 Byte)
#define MAX_FIRMWARE_SIZE              (FLASH_SIZE - BOOTLOADER_SIZE) // (64 - 16) = 48 Kbyte (49152 Byte)

#define UART_PORT 				       (GPIOA)
#define TX_PIN    					   (GPIO2)
#define RX_PIN    					   (GPIO3)

#define DEVICE_ID 					   (0x01)

#define SYNC_SEQ_0 					   (0x01)
#define SYNC_SEQ_1 					   (0x02)
#define SYNC_SEQ_2 				       (0x03)
#define SYNC_SEQ_3 					   (0x04)

#define DEFAULT_TIMEOUT 			   (5000)
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
UART_HandleTypeDef huart2;

/* USER CODE BEGIN PV */
static bl_al_state_t state = BL_AL_STATE_Sync;
static uint32_t  	 firmware_size = 0;
static uint32_t      bytes_written = 0;
static uint8_t       sync_seq[4] = {0};

static tl_segment_t temp_segment;

static timer_t timer;

static FLASH_EraseInitTypeDef pEraseInit = {
	.TypeErase   = FLASH_TYPEERASE_PAGES,
	.PageAddress = MAIN_APPLICATION_START_ADDRESS,
	.NbPages	 = 384
};

static uint32_t PageError = 0;
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_USART2_UART_Init(void);
/* USER CODE BEGIN PFP */
static void JUMP_TO_MAIN_APPLICATION(void);
static bool IS_MESSAGE_Device_ID(const tl_segment_t* segment);
static bool IS_MESSAGE_Firmware_Size(const tl_segment_t* segment);
/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
**/
int main(void) {
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
	TL_Init();
    TIMER_Init(&timer, DEFAULT_TIMEOUT, false);
  	/* USER CODE END 2 */

  	/* Infinite loop */
  	/* USER CODE BEGIN WHILE */
  	while (state != BL_AL_STATE_Done) {
    /* USER CODE END WHILE */
	
	/* USER CODE BEGIN 3 */
		if (state == BL_AL_STATE_Sync) {
			if (uart_data_available()) {
				sync_seq[0] = sync_seq[1];
				sync_seq[1] = sync_seq[2];
				sync_seq[2] = sync_seq[3];
				sync_seq[3] = uart_read_byte();

				bool is_match = sync_seq[0] == SYNC_SEQ_0;
				is_match = is_match && (sync_seq[1] == SYNC_SEQ_1);
				is_match = is_match && (sync_seq[2] == SYNC_SEQ_2);
				is_match = is_match && (sync_seq[3] == SYNC_SEQ_3);
			
				if (is_match) {
					tl_create_single_byte_segment(&temp_segment, BL_AL_MESSAGE_SEQ_OBSERVED);
					tl_write(&temp_segment);
					state = BL_AL_STATE_WaitForUpdateReq;
				} else {
					if (TIMER_Is_Elapsed(&timer)) {
						state = BL_AL_STATE_Done;
						continue;
					} else {
						continue;
					}
				}
			} else {
				if (TIMER_Is_Elapsed(&timer)) {
					state = BL_AL_STATE_Done;
					continue;
				} else {
					continue;
				}
			}
		}

		TL_Update();

		switch (state) {
			case BL_AL_STATE_WaitForUpdateReq: {
				if (tl_segment_available()) {
					tl_read(&temp_segment);

					if (tl_is_single_byte_segment(&temp_segment, BL_AL_MESSAGE_FW_UPDATE_REQ)) {
						tl_create_single_byte_segment(&temp_segment,  BL_AL_MESSAGE_FW_UPDATE_RES);
						tl_write(&temp_segment);
						state = BL_AL_STATE_DeviceIDReq;
					} else {
						continue;
					}
				} else {
					continue;
				}
			} break;
			
			case BL_AL_STATE_DeviceIDReq: {
				tl_create_single_byte_segment(&temp_segment, BL_AL_MESSAGE_DEVICE_ID_REQ);
				tl_write(&temp_segment);
				state = BL_AL_STATE_DeviceIDRes;
			} break;
			
			case BL_AL_STATE_DeviceIDRes: {
				if (tl_segment_available()) {
					tl_read(&temp_segment);

					if (IS_MESSAGE_Device_ID(&temp_segment) && temp_segment.data[1] == DEVICE_ID) {
						state = BL_AL_STATE_FirmwareLengthReq;
					} else {
						continue;
					}
				} else {
					continue;
				}
			} break;
			
			case BL_AL_STATE_FirmwareLengthReq: {
				tl_create_single_byte_segment(&temp_segment, BL_AL_MESSAGE_FW_LENGTH_REQ);
				tl_write(&temp_segment);
				state = BL_AL_STATE_FirmwareLengthRes;
			} break;
			
			case BL_AL_STATE_FirmwareLengthRes: {
				if (tl_segment_available()) {
					tl_read(&temp_segment);
					firmware_size = (
						(temp_segment.data[1])       |
						(temp_segment.data[2] << 8)  |
						(temp_segment.data[3] << 16) |
						(temp_segment.data[4] << 24) 
					);

					if (IS_MESSAGE_Firmware_Size(&temp_segment) && (firmware_size <= MAX_FIRMWARE_SIZE) && (firmware_size % 4 == 0)) {
						state = BL_AL_STATE_EraseApplication;
					} else {
						continue;
					}
				} else {
					continue;
				}
			} break;
			
			case BL_AL_STATE_EraseApplication: {
				HAL_FLASHEx_Erase(&pEraseInit, &PageError);
				tl_create_single_byte_segment(&temp_segment, BL_AL_MESSAGE_READY_FOR_DATA);
				tl_write(&temp_segment);
				state = BL_AL_STATE_ReceiveFirmware; 
			} break;
			
			case BL_AL_STATE_ReceiveFirmware: {
				if (tl_segment_available()) {
					tl_read(&temp_segment);
					
					for (uint8_t i = 0; i < temp_segment.segment_data_size; i = i + 4) {
						uint32_t firmware_data = (
							(temp_segment.data[i])           |
							(temp_segment.data[i + 1] << 8)  |
							(temp_segment.data[i + 2] << 16) |
							(temp_segment.data[i + 3] << 24) 
						);
						HAL_FLASH_Unlock();
						HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, MAIN_APPLICATION_START_ADDRESS + bytes_written, firmware_data);
						HAL_FLASH_Lock();
						bytes_written += 4;
					}
					
					if (bytes_written >= MAX_FIRMWARE_SIZE) {
						tl_create_single_byte_segment(&temp_segment, BL_AL_MESSAGE_UPDATE_SUCCESSFUL);
						tl_write(&temp_segment);
						state = BL_AL_STATE_Done;
					} else {
						tl_create_single_byte_segment(&temp_segment, BL_AL_MESSAGE_READY_FOR_DATA);
						tl_write(&temp_segment);
					}
				} else {
					continue;
				}
			} break;

			default: {
				state = BL_AL_STATE_Sync;
			}
		}
	}

	// RESET ALL SYSTEM BEFORE PASS CONTROL OVER TO THE MAIN APPLICATION
	HAL_Delay(500);
	JUMP_TO_MAIN_APPLICATION();

	// SHOULD NEVER RETURN
	return 0;
	/* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
**/
void SystemClock_Config(void) {
  	RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  	RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};
  	RCC_PeriphCLKInitTypeDef PeriphClkInit = {0};

  	/* Configure the main internal regulator output voltage */
  	__HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

  	/* Initializes the RCC Oscillators according to the specified parameters in the RCC_OscInitTypeDef structure. */
  	RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
  	RCC_OscInitStruct.HSIState = RCC_HSI_ON;
  	RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
  	RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  	RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSI;
  	RCC_OscInitStruct.PLL.PLLMUL = RCC_PLLMUL_4;
  	RCC_OscInitStruct.PLL.PLLDIV = RCC_PLLDIV_2;
  	if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK) {
    	Error_Handler();
  	}

  	/* Initializes the CPU, AHB and APB buses clocks */
  	RCC_ClkInitStruct.ClockType = 
		RCC_CLOCKTYPE_HCLK   | 
		RCC_CLOCKTYPE_SYSCLK |
		RCC_CLOCKTYPE_PCLK1  |
		RCC_CLOCKTYPE_PCLK2;
  	RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  	RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  	RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
  	RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;
  	if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_1) != HAL_OK) {
    	Error_Handler();
  	}

  	PeriphClkInit.PeriphClockSelection = RCC_PERIPHCLK_USART2;
  	PeriphClkInit.Usart2ClockSelection = RCC_USART2CLKSOURCE_PCLK1;
  	if (HAL_RCCEx_PeriphCLKConfig(&PeriphClkInit) != HAL_OK) {
    	Error_Handler();
  	}
}

/**
  * @brief USART2 Initialization Function
  * @param None
  * @retval None
**/
static void MX_USART2_UART_Init(void) {
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
  	if (HAL_UART_Init(&huart2) != HAL_OK) {
    	Error_Handler();
  	}
  	/* USER CODE BEGIN USART2_Init 2 */

  	/* USER CODE END USART2_Init 2 */
}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
**/
static void MX_GPIO_Init(void) {
  	GPIO_InitTypeDef GPIO_InitStruct = {0};
  	/* USER CODE BEGIN MX_GPIO_Init_1 */

  	/* USER CODE END MX_GPIO_Init_1 */

  	/* GPIO Ports Clock Enable */
  	__HAL_RCC_GPIOC_CLK_ENABLE();
  	__HAL_RCC_GPIOH_CLK_ENABLE();
  	__HAL_RCC_GPIOA_CLK_ENABLE();

  	/* Configure GPIO pin Output Level */
  	HAL_GPIO_WritePin(LD2_GPIO_Port, LD2_Pin, GPIO_PIN_RESET);

  	/* Configure GPIO pin : B1_Pin */
  	GPIO_InitStruct.Pin = B1_Pin;
  	GPIO_InitStruct.Mode = GPIO_MODE_IT_FALLING;
  	GPIO_InitStruct.Pull = GPIO_NOPULL;
  	HAL_GPIO_Init(B1_GPIO_Port, &GPIO_InitStruct);

  	/* Configure GPIO pin : LD2_Pin */
  	GPIO_InitStruct.Pin = LD2_Pin;
  	GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  	GPIO_InitStruct.Pull = GPIO_NOPULL;
  	GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  	HAL_GPIO_Init(LD2_GPIO_Port, &GPIO_InitStruct);

  	/* USER CODE BEGIN MX_GPIO_Init_2 */

  	/* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */
static void JUMP_TO_MAIN_APPLICATION(void) {
    VectorTable_t* main_application_vector_table = (vector_table_t*)(MAIN_APPLICATION_START_ADDRESS);
    main_application_vector_table->Reset_Handler();
}

static bool IS_MESSAGE_Device_ID(const tl_segment_t* segment) {
    if (segment->segment_data_size != 2) {
		return false;
	}

	if (
		segment->segment_type == SEGMENT_ACK  || 
		segment->segment_type == SEGMENT_RETX || 
		segment->segment_type != 0
	) {
		return false;
	}
	
	if (segment->data[0] != BL_AL_MESSAGE_DEVICE_ID_RES) {
		return false;
	}
    
	for (uint8_t i = 2; i < SEGMENT_DATA_SIZE; i++) {
        if (segment->data[i] != 0xff) {
			return false;
		}
    }

    return true;
}

static bool IS_MESSAGE_Firmware_Size(const tl_segment_t* segment) {
    if (segment->segment_data_size != 5) {
		return false;
	}

    if (
		segment->segment_type == SEGMENT_ACK  || 
		segment->segment_type == SEGMENT_RETX || 
		segment->segment_type != 0
	) {
        return false;
    }

    if (segment->data[0] != BL_AL_MESSAGE_FW_LENGTH_RES) {
		return false;
	}

    for (uint8_t i = 5; i < SEGMENT_DATA_SIZE; i++) {
        if (segment->data[i] != 0xff) {
			return false;
		}
    }

    return true;
}
/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
**/
void Error_Handler(void) {
  	/* USER CODE BEGIN Error_Handler_Debug */
  	/* User can add his own implementation to report the HAL error return state */
  	__disable_irq();
  	while (1) {
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
**/
void assert_failed(uint8_t *file, uint32_t line) {
  	/* USER CODE BEGIN 6 */
  	/* User can add his own implementation to report the file name and line number,
     	ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  	/* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
