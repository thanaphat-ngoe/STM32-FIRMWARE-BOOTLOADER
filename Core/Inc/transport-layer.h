#ifndef INC_TL_H
#define INC_TL_H

#include "main.h"

#include "ring-buffer.h"
#include "crc8.h"

#define PACKET_DATA_SIZE   		     (32) // Up to 32 Bytes
#define PACKET_TYPE_SIZE   		     (1) // 1 Byte
#define PACKET_LENGTH_SIZE 		     (1) // 1 Byte
#define PACKET_CRC_SIZE    		     (1) // 1 Byte
#define PACKET_LENGTH                (PACKET_DATA_SIZE + PACKET_LENGTH_SIZE + PACKET_CRC_SIZE + PACKET_TYPE_SIZE) // Up to 35 Byte

#define PACKET_RETX                  (0x52)
#define PACKET_ACK                   (0x41)

#define AL_MESSAGE_SEQ_OBSERVED      (0x20)
#define AL_MESSAGE_FW_UPDATE_REQ     (0x31)
#define AL_MESSAGE_FW_UPDATE_RES     (0x37)
#define AL_MESSAGE_DEVICE_ID_REQ     (0x3C)
#define AL_MESSAGE_DEVICE_ID_RES     (0x3F)
#define AL_MESSAGE_FW_LENGTH_REQ     (0x42)
#define AL_MESSAGE_FW_LENGTH_RES     (0x45)
#define AL_MESSAGE_READY_FOR_DATA    (0x48)
#define AL_MESSAGE_UPDATE_SUCCESSFUL (0x54)
#define AL_MESSAGE_NACK              (0x59)

typedef struct TLPacket_TypeDef {
    uint8_t packet_data_size;
    uint8_t packet_type;
    uint8_t data[PACKET_DATA_SIZE];
    uint8_t packet_crc;
} TLPacket_TypeDef;

void TL_Init(UART_HandleTypeDef* temp_huart2);
void TL_Update(RB_TypeDef* ring_buffer);

void TL_Write(TLPacket_TypeDef* packet);
void TL_Read(TLPacket_TypeDef* packet);

void TL_Create_RETX_Packet(TLPacket_TypeDef* packet);
void TL_Create_ACK_Packet(TLPacket_TypeDef* packet);
void TL_Create_Single_Byte_Packet(TLPacket_TypeDef* packet, uint8_t byte);

bool TL_Is_RETX_Packet(const TLPacket_TypeDef* packet);
bool TL_Is_ACK_Packet(const TLPacket_TypeDef* packet);
bool TL_Is_Packet_Available(void);
bool TL_Is_Single_Byte_Packet(const TLPacket_TypeDef* packet, const uint8_t byte);

uint8_t TL_Compute_CRC(TLPacket_TypeDef* packet);

#endif
