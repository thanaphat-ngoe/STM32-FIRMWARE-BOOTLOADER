#include "uart.h"
#include "ring-buffer.h"

#define BAUD_RATE (115200)
#define RING_BUFFER_SIZE (128)

static ring_buffer_t rb = {0U};
static uint8_t data_buffer[RING_BUFFER_SIZE] = {0U};

void USART2_IRQHandler(void) {
    const bool overrun_occurred = usart_get_flag(USART2, USART_FLAG_ORE) == 1;
    const bool received_data = usart_get_flag(USART2, USART_FLAG_RXNE) == 1;

    if (received_data || overrun_occurred) {
        if (ring_buffer_write(&rb, (uint8_t)usart_recv(USART2))) {
            // Handle error
        }
    }
}


void UART_Write(uint8_t* data, const uint32_t length) {
    for (uint32_t i = 0; i < length; i++) {
        uart_write_byte(data[i]);
    }
}

void UART_Write_Byte(uint8_t data) {
    usart_send_blocking(USART2, (uint16_t)data);
}

uint32_t UART_Read(uint8_t* data, const uint32_t length) {
    if (length <= 0) {
        return 0;
    }

    for (uint32_t bytes_read = 0; bytes_read < length; bytes_read ++) {
        if (!ring_buffer_read(&rb, &data[bytes_read])) {
            return bytes_read;
        }
    }

    return length;
}

uint8_t UART_Read_byte(void) {
    uint8_t byte = 0;
    (void)uart_read(&byte, 1);
    return byte;
}

bool UART_Data_Available(void) {
    return !ring_buffer_empty(&rb);
}
