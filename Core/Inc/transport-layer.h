#ifndef INC_TL_H
#define INC_TL_H

#include "main.h"
#include "ring-buffer.h"
#include "crc8.h"

#define PACKET_DATA_SIZE_BYTE_SIZE (1)  // 1 Byte
#define PACKET_TYPE_BYTE_SIZE      (1)  // 1 Byte
#define PACKET_MESSAGE_BYTE_SIZE   (1)  // 1 Byte
#define PACKET_DATA_BYTE_SIZE      (32) // 32 Bytes
#define PACKET_CRC_BYTE_SIZE       (1)  // 1 Byte

#define PACKET_LENGTH ( \
    PACKET_DATA_SIZE_BYTE_SIZE + \
    PACKET_TYPE_BYTE_SIZE      + \
    PACKET_MESSAGE_BYTE_SIZE   + \
    PACKET_DATA_BYTE_SIZE      + \
    PACKET_CRC_BYTE_SIZE \
) // 36 Bytes

#define PACKET_RETX                (0xFF)
#define PACKET_ACK                 (0xEF)
#define PACKET_NONE                (0xDF)

#define PACKET_BUFFER_LENGTH       (8)

typedef struct TL_Packet_TypeDef {
    uint8_t packet_data_size;
    uint8_t packet_type;
    uint8_t packet_message_type;
    uint8_t data[PACKET_DATA_BYTE_SIZE];
    uint8_t packet_crc;
} TL_Packet_TypeDef;

bool TL_PACKET_VALIDATE_RETX_Packet(const TL_Packet_TypeDef* packet);
bool TL_PACKET_VALIDATE_ACK_Packet(const TL_Packet_TypeDef* packet);
bool TL_PACKET_VALIDATE_Message_Type(const TL_Packet_TypeDef* packet, const uint8_t message_type);
void TL_CREATE_RETX_Packet(TL_Packet_TypeDef* packet);
void TL_CREATE_ACK_Packet(TL_Packet_TypeDef* packet);
void TL_PACKET_Create_Message(TL_Packet_TypeDef* packet, uint8_t message_type);
uint8_t TL_PACKET_Create_SingleByte_Message(TL_Packet_TypeDef* packet, uint8_t data, uint8_t message_type);
uint8_t TL_PACKET_Create_MultiByte_Message(TL_Packet_TypeDef* packet, uint8_t* data, uint8_t size, uint8_t message_type);

void TL_Init(void);
void TL_Update(RB_TypeDef* ring_buffer);
void TL_Write(TL_Packet_TypeDef* packet);
void TL_Read(TL_Packet_TypeDef* packet);
uint8_t TL_Compute_CRC(TL_Packet_TypeDef* packet);
bool TL_IS_Packet_Available(void);

#endif
