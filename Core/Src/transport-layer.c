#include "transport-layer.h"

typedef enum TL_State_TypeDef {
    TL_State_Packet_Data_Size,
    TL_State_Packet_Type,
	TL_State_Packet_Message_Type,
    TL_State_Data,
    TL_State_Packet_CRC,
} TL_State_TypeDef;

static TL_State_TypeDef state = TL_State_Packet_Data_Size;
static uint8_t data_byte_count = 0;

static TL_Packet_TypeDef temp_packet = { 
    .packet_data_size = 0, 
    .packet_type = 0,
    .packet_message_type = 0,
    .data = {0},
    .packet_crc = 0 
};

static TL_Packet_TypeDef retx_packet = { 
	.packet_data_size = 0, 
	.packet_type = 0,
	.packet_message_type = 0,
	.data = {0}, 
	.packet_crc = 0 
};

static TL_Packet_TypeDef ack_packet = { 
	.packet_data_size = 0, 
	.packet_type = 0,
	.packet_message_type = 0,
	.data = {0}, 
	.packet_crc = 0 
};

static TL_Packet_TypeDef last_transmitted_packet = { 
	.packet_data_size = 0, 
	.packet_type = 0,
	.packet_message_type = 0,
	.data = {0}, 
	.packet_crc = 0 
};

static TL_Packet_TypeDef packet_buffer[PACKET_BUFFER_LENGTH];
static uint32_t packet_read_index = 0;
static uint32_t packet_write_index = 0;
static uint32_t packet_buffer_mask = PACKET_BUFFER_LENGTH - 1;

extern UART_HandleTypeDef huart2;

bool TL_PACKET_VALIDATE_RETX_Packet(const TL_Packet_TypeDef* packet) {
    if (packet->packet_data_size != 0) {
        return false;
    }

    if (packet->packet_type != PACKET_RETX) {
        return false;
    }

	if (packet->packet_message_type != 0) {
		return false;
	}

    for (uint8_t i = 0; i < PACKET_DATA_BYTE_SIZE; i++) {
        if (packet->data[i] != 0xff) {
            return false;
        }
    }

    return true;
}

bool TL_PACKET_VALIDATE_ACK_Packet(const TL_Packet_TypeDef* packet) {
    if (packet->packet_data_size != 0) {
        return false;
    }

    if (packet->packet_type != PACKET_ACK) {
        return false;
    }

	if (packet->packet_message_type != 0) {
		return false;
	}

    for (uint8_t i = 0; i < PACKET_DATA_BYTE_SIZE; i++) {
        if (packet->data[i] != 0xff) {
            return false;
        }
    }

    return true;
}

bool TL_PACKET_VALIDATE_Message_Type(const TL_Packet_TypeDef* packet, const uint8_t message_type) {
	if (packet->packet_type != PACKET_NONE) {
        return false;
    }

	if (packet->packet_message_type != message_type) {
        return false;
    }

	return true;
}

void TL_CREATE_RETX_Packet(TL_Packet_TypeDef* packet) {
    memset(packet, 0xff, sizeof(TL_Packet_TypeDef));
    packet->packet_data_size    = 0;
    packet->packet_type         = PACKET_RETX;
	packet->packet_message_type = 0;
    packet->packet_crc          = TL_Compute_CRC(packet);
}

void TL_CREATE_ACK_Packet(TL_Packet_TypeDef* packet) {
    memset(packet, 0xff, sizeof(TL_Packet_TypeDef));
    packet->packet_data_size    = 0;
    packet->packet_type         = PACKET_ACK;
	packet->packet_message_type = 0;
    packet->packet_crc          = TL_Compute_CRC(packet);
}

void TL_PACKET_Create_Message(TL_Packet_TypeDef* packet, uint8_t message_type) {
	memset(packet, 0xff, sizeof(TL_Packet_TypeDef));
	packet->packet_data_size    = 0;
	packet->packet_type         = PACKET_NONE;
	packet->packet_message_type = message_type;
	packet->packet_crc          = TL_Compute_CRC(packet);
}

uint8_t TL_PACKET_Create_SingleByte_Message(TL_Packet_TypeDef* packet, uint8_t data, uint8_t message_type) {
	memset(packet, 0xff, sizeof(TL_Packet_TypeDef));
	packet->packet_data_size    = 1;
	packet->packet_type         = PACKET_NONE;
	packet->packet_message_type = message_type;
	packet->data[0]             = data;
	packet->packet_crc          = TL_Compute_CRC(packet);
	return 1;
}

uint8_t TL_PACKET_Create_MultiByte_Message(TL_Packet_TypeDef* packet, uint8_t* data, uint8_t size, uint8_t message_type) {
	if (size > PACKET_DATA_BYTE_SIZE) {
		return 0;
	}
	memset(packet, 0xff, sizeof(TL_Packet_TypeDef));
	packet->packet_data_size    = size;
	packet->packet_type         = PACKET_NONE;
	packet->packet_message_type = message_type;
	for (int i = 0; i < size; i++) {
		packet->data[i] = data[i];
	}
	packet->packet_crc          = TL_Compute_CRC(packet);
	return size;
}

void TL_Init(void) {
    TL_CREATE_RETX_Packet(&retx_packet);
    TL_CREATE_ACK_Packet(&ack_packet);
}

void TL_Update(RB_TypeDef* ring_buffer) {
	// ASK THE DMA HARDWARE HOW MANY BYTES ARE LEFT TO TRANSFER
    uint32_t current_ndtr = __HAL_DMA_GET_COUNTER(huart2.hdmarx);
    // SYNCHRONIZE OUR SOFTWARE write_index TO MATCH THE HARDWARE
    RB_Sync_Write_Index(ring_buffer, current_ndtr);

    while (!RB_Is_Empty(ring_buffer)) {
        switch (state) {
            case TL_State_Packet_Data_Size: {
				RB_Read(ring_buffer, &temp_packet.packet_data_size);
                state = TL_State_Packet_Type;
            }  break;
            
            case TL_State_Packet_Type: {
				RB_Read(ring_buffer, &temp_packet.packet_type);
                state = TL_State_Packet_Message_Type;
            } break;
			
			case TL_State_Packet_Message_Type: {
				RB_Read(ring_buffer, &temp_packet.packet_message_type);
                state = TL_State_Data;
			} break;

            case TL_State_Data: {
				RB_Read(ring_buffer, &temp_packet.data[data_byte_count++]);
                if (data_byte_count >= PACKET_DATA_BYTE_SIZE) {
                    data_byte_count = 0;
                    state = TL_State_Packet_CRC;
                }
            } break;

            case TL_State_Packet_CRC: {
				RB_Read(ring_buffer, &temp_packet.packet_crc);
                if (temp_packet.packet_crc != TL_Compute_CRC(&temp_packet)) {
                    TL_Write(&retx_packet);
                    state = TL_State_Packet_Data_Size;
                    break;
                }

                if (TL_PACKET_VALIDATE_RETX_Packet(&temp_packet)) {
                    TL_Write(&last_transmitted_packet);
                    state = TL_State_Packet_Data_Size;
                    break;
                }

                if (TL_PACKET_VALIDATE_ACK_Packet(&temp_packet)) {
                    state = TL_State_Packet_Data_Size;
                    break;
                }

                uint32_t next_write_index = (packet_write_index + 1) & packet_buffer_mask;
                if (next_write_index == packet_read_index) {
                    __asm__("BKPT #0");
                }
                
                memcpy(&packet_buffer[packet_write_index], &temp_packet, sizeof(TL_Packet_TypeDef));
                packet_write_index = next_write_index;
                TL_Write(&ack_packet);
                state = TL_State_Packet_Data_Size;
            } break;

            default: {
                state = TL_State_Packet_Data_Size;
            }
        }
    }
}

bool TL_IS_Packet_Available(void) {
    return packet_read_index != packet_write_index;
}

void TL_Write(TL_Packet_TypeDef* packet) {
    HAL_UART_Transmit(&huart2, (uint8_t*)packet, PACKET_LENGTH, 500);
    memcpy(&last_transmitted_packet, packet, sizeof(TL_Packet_TypeDef));
}

void TL_Read(TL_Packet_TypeDef* packet) {
    memcpy(packet, &packet_buffer[packet_read_index], sizeof(TL_Packet_TypeDef));
    packet_read_index = (packet_read_index + 1) & packet_buffer_mask;
}

uint8_t TL_Compute_CRC(TL_Packet_TypeDef* packet) {
    return crc8((uint8_t*)packet, PACKET_LENGTH - PACKET_CRC_BYTE_SIZE);
}
