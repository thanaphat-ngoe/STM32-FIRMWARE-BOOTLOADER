#include "crypto.h"

#include "uECC.h"
#include "cmox_crypto.h"

const uint8_t FIRMWARE_PUBLIC_KEY[64] = {
    // PUBLIC KEY X
    0x0c, 0x25, 0x66, 0x59, 0xb6, 0xcf, 0x9b, 0xd2, 
	0x2b, 0x46, 0xd5, 0x5a, 0x56, 0x20, 0x3e, 0x5b, 
	0x90, 0xcb, 0x60, 0x54, 0x3c, 0xc1, 0xcc, 0xbe, 
	0x39, 0x44, 0x7c, 0xf7, 0x04, 0x12, 0x0d, 0x2e,
	
    // PUBLIC KEY Y
	0xd2, 0x5a, 0x20, 0x2b, 0x02, 0x18, 0xb4, 0xab, 
	0xca, 0x29, 0x36, 0x37, 0x00, 0x42, 0xb1, 0x73, 
	0xb6, 0x31, 0xb2, 0x7a, 0x64, 0x94, 0x5d, 0x3a, 
	0xae, 0x4a, 0x9d, 0xa2, 0xb8, 0x9a, 0x8a, 0xcd
};

bool Verify_Firmware_Signature(uint32_t firmware_start_address) {
    FirmwareHeader_TypeDef* header = (FirmwareHeader_TypeDef*)firmware_start_address;

    cmox_initialize(NULL);

    uint8_t hash_result[CMOX_SHA256_SIZE];
    uint32_t payload_address = firmware_start_address + sizeof(FirmwareHeader_TypeDef);

    cmox_hash_retval_t retval = cmox_hash_compute(
        CMOX_SHA256_ALGO,                  
        (const uint8_t*)payload_address, 
        header->Size,                     
        hash_result,                   
        CMOX_SHA256_SIZE,                  
        NULL                             
    );

    // ตรวจสอบว่าคณิตศาสตร์ของ ST ทำงานสำเร็จหรือไม่
    if (retval != CMOX_HASH_SUCCESS) {
        return false;
    }

    // 3. เตรียมข้อมูล Signature (R และ S) ให้ micro-ecc (เหมือนเดิม)
    uint8_t signature[64];
    memcpy(&signature[0],  header->Signature_R, 32);
    memcpy(&signature[32], header->Signature_S, 32);

    // 4. ตรวจสอบความถูกต้องด้วย micro-ecc (เหมือนเดิม)
    int is_valid = uECC_verify(
        FIRMWARE_PUBLIC_KEY, 
        hash_result, 
        sizeof(hash_result), 
        signature, 
        uECC_secp256r1()
    );

    return (is_valid == 1);
}
