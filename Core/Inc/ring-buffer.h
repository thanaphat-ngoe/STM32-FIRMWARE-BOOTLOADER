#ifndef INC_RINGBUFFER_H
#define INC_RINGBUFFER_H

#include "main.h"

typedef struct RB_TypeDef {
    uint8_t* buffer;
    uint32_t mask;
    uint32_t read_index;
    uint32_t write_index;
} RB_TypeDef;

void RB_Init(RB_TypeDef* ring_buffer, uint8_t* buffer, uint32_t size);
bool RB_Is_Empty(RB_TypeDef* ring_buffer);
bool RB_Read(RB_TypeDef* ring_buffer, uint8_t* byte);
// bool RB_Write(RB_TypeDef* ring_buffer, uint8_t byte);
void RB_Sync_Write_Index(RB_TypeDef* ring_buffer, uint32_t dma_ndtr);

#endif
