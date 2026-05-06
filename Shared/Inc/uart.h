#ifndef INC_UART_H
#define INC_UART_H

#include "main.h"

void UART_Write(uint8_t* data, const uint32_t length);
void UART_Write_Byte(uint8_t data);
uint32_t UART_Read(uint8_t* data, const uint32_t length);
uint8_t UART_Read_Byte(void);
bool UART_Data_Available(void);

#endif
