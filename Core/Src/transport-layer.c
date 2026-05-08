#include "transport-layer.h"

#include "string.h"

#define PACKET_BUFFER_LENGTH (8)

typedef enum TLState_TypeDef {
    TLState_Packet_Data_Size,
    TLState_Packet_Type,
    TLState_Data,
    TLState_Packet_CRC,
} TLState_TypeDef;

static TLState_TypeDef state = TLState_Packet_Data_Size;
static uint8_t data_byte_count = 0;

static TLPacket_TypeDef temp_packet = { 
	.packet_data_size = 0, 
	.data = {0}, 
	.packet_crc = 0 
};

static TLPacket_TypeDef retx_packet = { 
	.packet_data_size = 0, 
	.data = {0}, 
	.packet_crc = 0 
};

static TLPacket_TypeDef ack_packet = { 
	.packet_data_size = 0, 
	.data = {0}, 
	.packet_crc = 0 
};

static TLPacket_TypeDef last_transmitted_packet = { 
	.packet_data_size = 0, 
	.data = {0}, 
	.packet_crc = 0 
};

static TLPacket_TypeDef packet_buffer[PACKET_BUFFER_LENGTH];
static uint32_t packet_read_index = 0;
static uint32_t packet_write_index = 0;
static uint32_t packet_buffer_mask = PACKET_BUFFER_LENGTH - 1;

static UART_HandleTypeDef* huart2;

bool TL_Is_RETX_Packet(const TLPacket_TypeDef* packet) {
    if (packet->packet_data_size != 0) {
        return false;
    }

    if (packet->packet_type != PACKET_RETX) {
        return false;
    }

    for (uint8_t i = 0; i < PACKET_DATA_SIZE; i++) {
        if (packet->data[i] != 0xff) {
            return false;
        }
    }

    return true;
}

bool TL_Is_ACK_Packet(const TLPacket_TypeDef* packet) {
    if (packet->packet_data_size != 0) {
        return false;
    }

    if (packet->packet_type != PACKET_ACK) {
        return false;
    }

    for (uint8_t i = 0; i < PACKET_DATA_SIZE; i++) {
        if (packet->data[i] != 0xff) {
            return false;
        }
    }

    return true;
}

bool TL_Is_Single_Byte_Packet(const TLPacket_TypeDef* packet, const uint8_t byte) {
    if (packet->packet_data_size == 0 || packet->packet_data_size > 1) {
        return false;
    }

    if (packet->packet_type == PACKET_ACK || packet->packet_type == PACKET_RETX || packet->packet_type != 0) {
        return false;
    }

    if (packet->data[0] != byte) {
        return false;
    }

    for (uint8_t i = 1; i < PACKET_DATA_SIZE; i++) {
        if (packet->data[i] != 0xff) {
            return false;
        }
    }

    return true;
}

void TL_Create_RETX_Packet(TLPacket_TypeDef* packet) {
    memset(packet, 0xff, sizeof(TLPacket_TypeDef));
    packet->packet_data_size = 0;
    packet->packet_type = PACKET_RETX;
    packet->packet_crc = TL_Compute_CRC(packet);
}

void TL_Create_ACK_Packet(TLPacket_TypeDef* packet) {
    memset(packet, 0xff, sizeof(TLPacket_TypeDef));
    packet->packet_data_size = 0;
    packet->packet_type = PACKET_ACK;
    packet->packet_crc = TL_Compute_CRC(packet);
}

void TL_Create_Single_Byte_Packet(TLPacket_TypeDef* packet, uint8_t byte) {
    memset(packet, 0xff, sizeof(TLPacket_TypeDef));
    packet->packet_data_size = 1;
    packet->packet_type = 0;
    packet->data[0] = byte;
    packet->packet_crc = TL_Compute_CRC(packet);
}

void TL_Init(UART_HandleTypeDef* huart2) {
	huart2 = huart2;
    TL_Create_RETX_Packet(&retx_packet);
    TL_Create_ACK_Packet(&ack_packet);
}

void TL_Update(RB_TypeDef* ring_buffer) {
    while (!RB_Is_Empty(ring_buffer)) {
        switch (state) {
            case TLState_Packet_Data_Size: {
				RB_Read(ring_buffer, &temp_packet.packet_data_size);
                state = TLState_Packet_Type;
            }  break;
            
            case TLState_Packet_Type: {
				RB_Read(ring_buffer, &temp_packet.packet_type);
                state = TLState_Data;
            } break;

            case TLState_Data: {
				RB_Read(ring_buffer, &temp_packet.data[data_byte_count++]);
                if (data_byte_count >= PACKET_DATA_SIZE) {
                    data_byte_count = 0;
                    state = TLState_Packet_CRC;
                }
            } break;

            case TLState_Packet_CRC: {
				RB_Read(ring_buffer, &temp_packet.packet_crc);
                if (temp_packet.packet_crc != TL_Compute_CRC(&temp_packet)) {
                    TL_Write(&retx_packet);
                    state = TLState_Packet_Data_Size;
                    break;
                }

                if (TL_Is_RETX_Packet(&temp_packet)) {
                    TL_Write(&last_transmitted_packet);
                    state = TLState_Packet_Data_Size;
                    break;
                }

                if (TL_Is_ACK_Packet(&temp_packet)) {
                    state = TLState_Packet_Data_Size;
                    break;
                }

                uint32_t next_write_index = (packet_write_index + 1) & packet_buffer_mask;
                if (next_write_index == packet_read_index) {
                    __asm__("BKPT #0");
                }
                
                memcpy(&packet_buffer[packet_write_index], &temp_packet, sizeof(TLPacket_TypeDef));
                packet_write_index = next_write_index;
                TL_Write(&ack_packet);
                state = TLState_Packet_Data_Size;
            } break;

            default: {
                state = TLState_Packet_Data_Size;
            }
        }
    }
}

bool TL_Is_Packet_Available(void) {
    return packet_read_index != packet_write_index;
}

void TL_Write(TLPacket_TypeDef* packet) {
    HAL_UART_Transmit(huart2, (uint8_t*)packet, PACKET_LENGTH, 500);
    memcpy(&last_transmitted_packet, packet, sizeof(TLPacket_TypeDef));
}

void TL_Read(TLPacket_TypeDef* packet) {
    memcpy(packet, &packet_buffer[packet_read_index], sizeof(TLPacket_TypeDef));
    packet_read_index = (packet_read_index + 1) & packet_buffer_mask;
}

uint8_t TL_Compute_CRC(TLPacket_TypeDef* packet) {
    return crc8((uint8_t*)packet, PACKET_LENGTH - PACKET_CRC_SIZE);
}
