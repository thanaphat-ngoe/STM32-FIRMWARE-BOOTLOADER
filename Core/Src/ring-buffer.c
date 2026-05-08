#include "ring-buffer.h"

void RB_Init(RB_TypeDef* ring_buffer, uint8_t* buffer, uint32_t size) {
    ring_buffer->buffer = buffer;
    ring_buffer->read_index = 0;
    ring_buffer->write_index = 0;
    ring_buffer->mask = size - 1;
}

bool RB_Is_Empty(RB_TypeDef* ring_buffer) {
    return ring_buffer->read_index == ring_buffer->write_index;
}

bool RB_Read(RB_TypeDef* ring_buffer, uint8_t* byte) {
    uint32_t local_read_index = ring_buffer->read_index;
    uint32_t local_write_index = ring_buffer->write_index;

    if (local_read_index == local_write_index) {
        return false;
    }

    *byte = ring_buffer->buffer[local_read_index];
    local_read_index = (local_read_index + 1) & ring_buffer->mask; // Round value back to zero if variable went to the end
    ring_buffer->read_index = local_read_index;
    
    return true;
}

bool RB_Write(RB_TypeDef* ring_buffer, uint8_t byte) {
    uint32_t local_write_index = ring_buffer->write_index;
    uint32_t local_read_index = ring_buffer->read_index;

    uint32_t next_wirte_index = (local_write_index + 1) & ring_buffer->mask; 

    if (next_wirte_index == local_read_index) {
        return false;
    }

    ring_buffer->buffer[local_write_index] = byte;
    ring_buffer->write_index = next_wirte_index;

    return true;
}
