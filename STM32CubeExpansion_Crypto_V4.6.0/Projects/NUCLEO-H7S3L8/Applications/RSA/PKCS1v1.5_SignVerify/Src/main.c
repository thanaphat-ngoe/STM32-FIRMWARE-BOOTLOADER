/**
  ******************************************************************************
  * @file    RSA/PKCS1v1.5_SignVerify/Src/main.c
  * @author  MCD Application Team
  * @brief   This example provides a short description of how to use the
  *          STM32 Cryptographic Library
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2021 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file in
  * the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */

/* Includes ------------------------------------------------------------------*/
#include <string.h>
#include "main.h"
#include "cmox_crypto.h"

/* Global variables ----------------------------------------------------------*/
/* RSA context */
cmox_rsa_handle_t Rsa_Ctx;
/* RSA key */
cmox_rsa_key_t Rsa_Key;

/* RSA working buffer */
uint8_t Working_Buffer[3500];

__IO TestStatus glob_status = FAILED;

/* Private typedef -----------------------------------------------------------*/
/* Private defines -----------------------------------------------------------*/
/* Private macros ------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
/** Extract from pkcs1v15sign-vectors.txt
  * # Example 1: A 1024-bit RSA key pair
# -----------------------------------

# Public key
# ----------

# Modulus:
a5 6e 4a 0e 70 10 17 58 9a 51 87 dc 7e a8 41 d1
56 f2 ec 0e 36 ad 52 a4 4d fe b1 e6 1f 7a d9 91
d8 c5 10 56 ff ed b1 62 b4 c0 f2 83 a1 2a 88 a3
94 df f5 26 ab 72 91 cb b3 07 ce ab fc e0 b1 df
d5 cd 95 08 09 6d 5b 2b 8b 6d f5 d6 71 ef 63 77
c0 92 1c b2 3c 27 0a 70 e2 59 8e 6f f8 9d 19 f1
05 ac c2 d3 f0 cb 35 f2 92 80 e1 38 6b 6f 64 c4
ef 22 e1 e1 f2 0d 0c e8 cf fb 22 49 bd 9a 21 37

# Exponent:
01 00 01

# Private key
# -----------

# Modulus:
a5 6e 4a 0e 70 10 17 58 9a 51 87 dc 7e a8 41 d1
56 f2 ec 0e 36 ad 52 a4 4d fe b1 e6 1f 7a d9 91
d8 c5 10 56 ff ed b1 62 b4 c0 f2 83 a1 2a 88 a3
94 df f5 26 ab 72 91 cb b3 07 ce ab fc e0 b1 df
d5 cd 95 08 09 6d 5b 2b 8b 6d f5 d6 71 ef 63 77
c0 92 1c b2 3c 27 0a 70 e2 59 8e 6f f8 9d 19 f1
05 ac c2 d3 f0 cb 35 f2 92 80 e1 38 6b 6f 64 c4
ef 22 e1 e1 f2 0d 0c e8 cf fb 22 49 bd 9a 21 37

# Public exponent:
01 00 01

# Exponent:
33 a5 04 2a 90 b2 7d 4f 54 51 ca 9b bb d0 b4 47
71 a1 01 af 88 43 40 ae f9 88 5f 2a 4b be 92 e8
94 a7 24 ac 3c 56 8c 8f 97 85 3a d0 7c 02 66 c8
c6 a3 ca 09 29 f1 e8 f1 12 31 88 44 29 fc 4d 9a
e5 5f ee 89 6a 10 ce 70 7c 3e d7 e7 34 e4 47 27
a3 95 74 50 1a 53 26 83 10 9c 2a ba ca ba 28 3c
31 b4 bd 2f 53 c3 ee 37 e3 52 ce e3 4f 9e 50 3b
d8 0c 06 22 ad 79 c6 dc ee 88 35 47 c6 a3 b3 25

# Prime 1:
e7 e8 94 27 20 a8 77 51 72 73 a3 56 05 3e a2 a1
bc 0c 94 aa 72 d5 5c 6e 86 29 6b 2d fc 96 79 48
c0 a7 2c bc cc a7 ea cb 35 70 6e 09 a1 df 55 a1
53 5b d9 b3 cc 34 16 0b 3b 6d cd 3e da 8e 64 43

# Prime 2:
b6 9d ca 1c f7 d4 d7 ec 81 e7 5b 90 fc ca 87 4a
bc de 12 3f d2 70 01 80 aa 90 47 9b 6e 48 de 8d
67 ed 24 f9 f1 9d 85 ba 27 58 74 f5 42 cd 20 dc
72 3e 69 63 36 4a 1f 94 25 45 2b 26 9a 67 99 fd

# Prime exponent 1:
28 fa 13 93 86 55 be 1f 8a 15 9c ba ca 5a 72 ea
19 0c 30 08 9e 19 cd 27 4a 55 6f 36 c4 f6 e1 9f
55 4b 34 c0 77 79 04 27 bb dd 8d d3 ed e2 44 83
28 f3 85 d8 1b 30 e8 e4 3b 2f ff a0 27 86 19 79

# Prime exponent 2:
1a 8b 38 f3 98 fa 71 20 49 89 8d 7f b7 9e e0 a7
76 68 79 12 99 cd fa 09 ef c0 e5 07 ac b2 1e d7
43 01 ef 5b fd 48 be 45 5e ae b6 e1 67 82 55 82
75 80 a8 e4 e8 e1 41 51 d1 51 0a 82 a3 f2 e7 29

# Coefficient:
27 15 6a ba 41 26 d2 4a 81 f3 a5 28 cb fb 27 f5
68 86 f8 40 a9 f6 e8 6e 17 a4 4b 94 fe 93 19 58
4b 8e 22 fd de 1e 5a 2e 3b d8 aa 5b a8 d8 58 41
94 eb 21 90 ac f8 32 b8 47 f1 3a 3d 24 a7 9f 4d

# PKCS#1 v1.5 Signature Example 1.1

# -----------------

# Message to be signed:
cd c8 7d a2 23 d7 86 df 3b 45 e0 bb bc 72 13 26
d1 ee 2a f8 06 cc 31 54 75 cc 6f 0d 9c 66 e1 b6
23 71 d4 5c e2 39 2e 1a c9 28 44 c3 10 10 2f 15
6a 0d 8d 52 c1 f4 c4 0b a3 aa 65 09 57 86 cb 76
97 57 a6 56 3b a9 58 fe d0 bc c9 84 e8 b5 17 a3
d5 f5 15 b2 3b 8a 41 e7 4a a8 67 69 3f 90 df b0
61 a6 e8 6d fa ae e6 44 72 c0 0e 5f 20 94 57 29
cb eb e7 7f 06 ce 78 e0 8f 40 98 fb a4 1f 9d 61
93 c0 31 7e 8b 60 d4 b6 08 4a cb 42 d2 9e 38 08
a3 bc 37 2d 85 e3 31 17 0f cb f7 cc 72 d0 b7 1c
29 66 48 b3 a4 d1 0f 41 62 95 d0 80 7a a6 25 ca
b2 74 4f d9 ea 8f d2 23 c4 25 37 02 98 28 bd 16
be 02 54 6f 13 0f d2 e3 3b 93 6d 26 76 e0 8a ed
1b 73 31 8b 75 0a 01 67 d0

# Signature:
6b c3 a0 66 56 84 29 30 a2 47 e3 0d 58 64 b4 d8
19 23 6b a7 c6 89 65 86 2a d7 db c4 e2 4a f2 8e
86 bb 53 1f 03 35 8b e5 fb 74 77 7c 60 86 f8 50
ca ef 89 3f 0d 6f cc 2d 0c 91 ec 01 36 93 b4 ea
00 b8 0c d4 9a ac 4e cb 5f 89 11 af e5 39 ad a4
a8 f3 82 3d 1d 13 e4 72 d1 49 05 47 c6 59 c7 61
7f 3d 24 08 7d db 6f 2b 72 09 61 67 fc 09 7c ab
18 e9 a4 58 fc b6 34 cd ce 8e e3 58 94 c4 84 d7

  */
const uint8_t Message[] =
{
  0xcd, 0xc8, 0x7d, 0xa2, 0x23, 0xd7, 0x86, 0xdf, 0x3b, 0x45, 0xe0, 0xbb, 0xbc, 0x72, 0x13, 0x26,
  0xd1, 0xee, 0x2a, 0xf8, 0x06, 0xcc, 0x31, 0x54, 0x75, 0xcc, 0x6f, 0x0d, 0x9c, 0x66, 0xe1, 0xb6,
  0x23, 0x71, 0xd4, 0x5c, 0xe2, 0x39, 0x2e, 0x1a, 0xc9, 0x28, 0x44, 0xc3, 0x10, 0x10, 0x2f, 0x15,
  0x6a, 0x0d, 0x8d, 0x52, 0xc1, 0xf4, 0xc4, 0x0b, 0xa3, 0xaa, 0x65, 0x09, 0x57, 0x86, 0xcb, 0x76,
  0x97, 0x57, 0xa6, 0x56, 0x3b, 0xa9, 0x58, 0xfe, 0xd0, 0xbc, 0xc9, 0x84, 0xe8, 0xb5, 0x17, 0xa3,
  0xd5, 0xf5, 0x15, 0xb2, 0x3b, 0x8a, 0x41, 0xe7, 0x4a, 0xa8, 0x67, 0x69, 0x3f, 0x90, 0xdf, 0xb0,
  0x61, 0xa6, 0xe8, 0x6d, 0xfa, 0xae, 0xe6, 0x44, 0x72, 0xc0, 0x0e, 0x5f, 0x20, 0x94, 0x57, 0x29,
  0xcb, 0xeb, 0xe7, 0x7f, 0x06, 0xce, 0x78, 0xe0, 0x8f, 0x40, 0x98, 0xfb, 0xa4, 0x1f, 0x9d, 0x61,
  0x93, 0xc0, 0x31, 0x7e, 0x8b, 0x60, 0xd4, 0xb6, 0x08, 0x4a, 0xcb, 0x42, 0xd2, 0x9e, 0x38, 0x08,
  0xa3, 0xbc, 0x37, 0x2d, 0x85, 0xe3, 0x31, 0x17, 0x0f, 0xcb, 0xf7, 0xcc, 0x72, 0xd0, 0xb7, 0x1c,
  0x29, 0x66, 0x48, 0xb3, 0xa4, 0xd1, 0x0f, 0x41, 0x62, 0x95, 0xd0, 0x80, 0x7a, 0xa6, 0x25, 0xca,
  0xb2, 0x74, 0x4f, 0xd9, 0xea, 0x8f, 0xd2, 0x23, 0xc4, 0x25, 0x37, 0x02, 0x98, 0x28, 0xbd, 0x16,
  0xbe, 0x02, 0x54, 0x6f, 0x13, 0x0f, 0xd2, 0xe3, 0x3b, 0x93, 0x6d, 0x26, 0x76, 0xe0, 0x8a, 0xed,
  0x1b, 0x73, 0x31, 0x8b, 0x75, 0x0a, 0x01, 0x67, 0xd0
};
const uint8_t Known_Signature[] =
{
  0x6b, 0xc3, 0xa0, 0x66, 0x56, 0x84, 0x29, 0x30, 0xa2, 0x47, 0xe3, 0x0d, 0x58, 0x64, 0xb4, 0xd8,
  0x19, 0x23, 0x6b, 0xa7, 0xc6, 0x89, 0x65, 0x86, 0x2a, 0xd7, 0xdb, 0xc4, 0xe2, 0x4a, 0xf2, 0x8e,
  0x86, 0xbb, 0x53, 0x1f, 0x03, 0x35, 0x8b, 0xe5, 0xfb, 0x74, 0x77, 0x7c, 0x60, 0x86, 0xf8, 0x50,
  0xca, 0xef, 0x89, 0x3f, 0x0d, 0x6f, 0xcc, 0x2d, 0x0c, 0x91, 0xec, 0x01, 0x36, 0x93, 0xb4, 0xea,
  0x00, 0xb8, 0x0c, 0xd4, 0x9a, 0xac, 0x4e, 0xcb, 0x5f, 0x89, 0x11, 0xaf, 0xe5, 0x39, 0xad, 0xa4,
  0xa8, 0xf3, 0x82, 0x3d, 0x1d, 0x13, 0xe4, 0x72, 0xd1, 0x49, 0x05, 0x47, 0xc6, 0x59, 0xc7, 0x61,
  0x7f, 0x3d, 0x24, 0x08, 0x7d, 0xdb, 0x6f, 0x2b, 0x72, 0x09, 0x61, 0x67, 0xfc, 0x09, 0x7c, 0xab,
  0x18, 0xe9, 0xa4, 0x58, 0xfc, 0xb6, 0x34, 0xcd, 0xce, 0x8e, 0xe3, 0x58, 0x94, 0xc4, 0x84, 0xd7
};

const uint8_t Modulus[] =
{
  0xa5, 0x6e, 0x4a, 0x0e, 0x70, 0x10, 0x17, 0x58, 0x9a, 0x51, 0x87, 0xdc, 0x7e, 0xa8, 0x41, 0xd1,
  0x56, 0xf2, 0xec, 0x0e, 0x36, 0xad, 0x52, 0xa4, 0x4d, 0xfe, 0xb1, 0xe6, 0x1f, 0x7a, 0xd9, 0x91,
  0xd8, 0xc5, 0x10, 0x56, 0xff, 0xed, 0xb1, 0x62, 0xb4, 0xc0, 0xf2, 0x83, 0xa1, 0x2a, 0x88, 0xa3,
  0x94, 0xdf, 0xf5, 0x26, 0xab, 0x72, 0x91, 0xcb, 0xb3, 0x07, 0xce, 0xab, 0xfc, 0xe0, 0xb1, 0xdf,
  0xd5, 0xcd, 0x95, 0x08, 0x09, 0x6d, 0x5b, 0x2b, 0x8b, 0x6d, 0xf5, 0xd6, 0x71, 0xef, 0x63, 0x77,
  0xc0, 0x92, 0x1c, 0xb2, 0x3c, 0x27, 0x0a, 0x70, 0xe2, 0x59, 0x8e, 0x6f, 0xf8, 0x9d, 0x19, 0xf1,
  0x05, 0xac, 0xc2, 0xd3, 0xf0, 0xcb, 0x35, 0xf2, 0x92, 0x80, 0xe1, 0x38, 0x6b, 0x6f, 0x64, 0xc4,
  0xef, 0x22, 0xe1, 0xe1, 0xf2, 0x0d, 0x0c, 0xe8, 0xcf, 0xfb, 0x22, 0x49, 0xbd, 0x9a, 0x21, 0x37
};
const uint8_t Public_Exponent[] =
{
  0x01, 0x00, 0x01
};
const uint8_t Private_Exponent[] =
{
  0x33, 0xa5, 0x04, 0x2a, 0x90, 0xb2, 0x7d, 0x4f, 0x54, 0x51, 0xca, 0x9b, 0xbb, 0xd0, 0xb4, 0x47,
  0x71, 0xa1, 0x01, 0xaf, 0x88, 0x43, 0x40, 0xae, 0xf9, 0x88, 0x5f, 0x2a, 0x4b, 0xbe, 0x92, 0xe8,
  0x94, 0xa7, 0x24, 0xac, 0x3c, 0x56, 0x8c, 0x8f, 0x97, 0x85, 0x3a, 0xd0, 0x7c, 0x02, 0x66, 0xc8,
  0xc6, 0xa3, 0xca, 0x09, 0x29, 0xf1, 0xe8, 0xf1, 0x12, 0x31, 0x88, 0x44, 0x29, 0xfc, 0x4d, 0x9a,
  0xe5, 0x5f, 0xee, 0x89, 0x6a, 0x10, 0xce, 0x70, 0x7c, 0x3e, 0xd7, 0xe7, 0x34, 0xe4, 0x47, 0x27,
  0xa3, 0x95, 0x74, 0x50, 0x1a, 0x53, 0x26, 0x83, 0x10, 0x9c, 0x2a, 0xba, 0xca, 0xba, 0x28, 0x3c,
  0x31, 0xb4, 0xbd, 0x2f, 0x53, 0xc3, 0xee, 0x37, 0xe3, 0x52, 0xce, 0xe3, 0x4f, 0x9e, 0x50, 0x3b,
  0xd8, 0x0c, 0x06, 0x22, 0xad, 0x79, 0xc6, 0xdc, 0xee, 0x88, 0x35, 0x47, 0xc6, 0xa3, 0xb3, 0x25
};
const uint8_t P_Prime[] =
{
  0xe7, 0xe8, 0x94, 0x27, 0x20, 0xa8, 0x77, 0x51, 0x72, 0x73, 0xa3, 0x56, 0x05, 0x3e, 0xa2, 0xa1,
  0xbc, 0x0c, 0x94, 0xaa, 0x72, 0xd5, 0x5c, 0x6e, 0x86, 0x29, 0x6b, 0x2d, 0xfc, 0x96, 0x79, 0x48,
  0xc0, 0xa7, 0x2c, 0xbc, 0xcc, 0xa7, 0xea, 0xcb, 0x35, 0x70, 0x6e, 0x09, 0xa1, 0xdf, 0x55, 0xa1,
  0x53, 0x5b, 0xd9, 0xb3, 0xcc, 0x34, 0x16, 0x0b, 0x3b, 0x6d, 0xcd, 0x3e, 0xda, 0x8e, 0x64, 0x43
};
const uint8_t Q_Prime[] =
{
  0xb6, 0x9d, 0xca, 0x1c, 0xf7, 0xd4, 0xd7, 0xec, 0x81, 0xe7, 0x5b, 0x90, 0xfc, 0xca, 0x87, 0x4a,
  0xbc, 0xde, 0x12, 0x3f, 0xd2, 0x70, 0x01, 0x80, 0xaa, 0x90, 0x47, 0x9b, 0x6e, 0x48, 0xde, 0x8d,
  0x67, 0xed, 0x24, 0xf9, 0xf1, 0x9d, 0x85, 0xba, 0x27, 0x58, 0x74, 0xf5, 0x42, 0xcd, 0x20, 0xdc,
  0x72, 0x3e, 0x69, 0x63, 0x36, 0x4a, 0x1f, 0x94, 0x25, 0x45, 0x2b, 0x26, 0x9a, 0x67, 0x99, 0xfd
};
const uint8_t P_Prime_Exponent[] =
{
  0x28, 0xfa, 0x13, 0x93, 0x86, 0x55, 0xbe, 0x1f, 0x8a, 0x15, 0x9c, 0xba, 0xca, 0x5a, 0x72, 0xea,
  0x19, 0x0c, 0x30, 0x08, 0x9e, 0x19, 0xcd, 0x27, 0x4a, 0x55, 0x6f, 0x36, 0xc4, 0xf6, 0xe1, 0x9f,
  0x55, 0x4b, 0x34, 0xc0, 0x77, 0x79, 0x04, 0x27, 0xbb, 0xdd, 0x8d, 0xd3, 0xed, 0xe2, 0x44, 0x83,
  0x28, 0xf3, 0x85, 0xd8, 0x1b, 0x30, 0xe8, 0xe4, 0x3b, 0x2f, 0xff, 0xa0, 0x27, 0x86, 0x19, 0x79
};
const uint8_t Q_Prime_Exponent[] =
{
  0x1a, 0x8b, 0x38, 0xf3, 0x98, 0xfa, 0x71, 0x20, 0x49, 0x89, 0x8d, 0x7f, 0xb7, 0x9e, 0xe0, 0xa7,
  0x76, 0x68, 0x79, 0x12, 0x99, 0xcd, 0xfa, 0x09, 0xef, 0xc0, 0xe5, 0x07, 0xac, 0xb2, 0x1e, 0xd7,
  0x43, 0x01, 0xef, 0x5b, 0xfd, 0x48, 0xbe, 0x45, 0x5e, 0xae, 0xb6, 0xe1, 0x67, 0x82, 0x55, 0x82,
  0x75, 0x80, 0xa8, 0xe4, 0xe8, 0xe1, 0x41, 0x51, 0xd1, 0x51, 0x0a, 0x82, 0xa3, 0xf2, 0xe7, 0x29
};
const uint8_t Coefficient[] =
{
  0x27, 0x15, 0x6a, 0xba, 0x41, 0x26, 0xd2, 0x4a, 0x81, 0xf3, 0xa5, 0x28, 0xcb, 0xfb, 0x27, 0xf5,
  0x68, 0x86, 0xf8, 0x40, 0xa9, 0xf6, 0xe8, 0x6e, 0x17, 0xa4, 0x4b, 0x94, 0xfe, 0x93, 0x19, 0x58,
  0x4b, 0x8e, 0x22, 0xfd, 0xde, 0x1e, 0x5a, 0x2e, 0x3b, 0xd8, 0xaa, 0x5b, 0xa8, 0xd8, 0x58, 0x41,
  0x94, 0xeb, 0x21, 0x90, 0xac, 0xf8, 0x32, 0xb8, 0x47, 0xf1, 0x3a, 0x3d, 0x24, 0xa7, 0x9f, 0x4d
};

/* Computed data buffer */
uint8_t Computed_Hash[CMOX_SHA1_SIZE];
uint8_t Computed_Signature[sizeof(Known_Signature)];

/* Private function prototypes -----------------------------------------------*/
static void SystemClock_Config(void);
static void CPU_CACHE_Enable(void);
static void Error_Handler(void);
/* Functions Definition ------------------------------------------------------*/

/**
  * @brief  Main program
  * @param  None
  * @retval None
  */
int main(void)
{
  cmox_hash_retval_t hretval;
  cmox_rsa_retval_t retval;
  size_t computed_size;
  /* Fault check verification variable */
  uint32_t fault_check = CMOX_RSA_AUTH_FAIL;

  /* Enable the CPU Cache */
  CPU_CACHE_Enable();

  /* STM32H7RSxx HAL library initialization:
       - Systick timer is configured by default as source of time base, but user
             can eventually implement his proper time base source (a general purpose
             timer for example or other time source), keeping in mind that Time base
             duration should be kept 1ms since PPP_TIMEOUT_VALUEs are defined and
             handled in milliseconds basis.
       - Set NVIC Group Priority to 4
       - Low Level Initialization
     */
  HAL_Init();

  /* Configure the System clock */
  SystemClock_Config();


  cmox_init_arg_t init_target = {CMOX_INIT_TARGET_H7RS, NULL};

  /* Configure LD3 */
  BSP_LED_Init(LD3);

  /* Initialize cryptographic library */
  if (cmox_initialize(&init_target) != CMOX_INIT_SUCCESS)
  {
    Error_Handler();
  }

  /* Compute directly the digest passing all the needed parameters */
  hretval = cmox_hash_compute(CMOX_SHA1_ALGO,           /* Use SHA1 algorithm */
                              Message, sizeof(Message), /* Message to digest */
                              Computed_Hash,            /* Data buffer to receive digest data */
                              CMOX_SHA1_SIZE,           /* Expected digest size */
                              &computed_size);          /* Size of computed digest */

  /* Verify API returned value */
  if (hretval != CMOX_HASH_SUCCESS)
  {
    Error_Handler();
  }

  /* Verify generated data size is the expected one */
  if (computed_size != CMOX_SHA1_SIZE)
  {
    Error_Handler();
  }

  /* --------------------------------------------------------------------------
   * USING REGULAR PRIVATE KEY REPRESENTATION
   * --------------------------------------------------------------------------
   */

  /* Construct a RSA context, specifying mathematics implementation and working buffer for later processing */
  /* Note: CMOX_RSA_MATH_FUNCS refer to the default mathematics implementation
   * selected in cmox_default_config.h. To use a specific implementation, user can
   * directly choose:
   * - CMOX_MATH_FUNCS_SMALL to select the mathematics small implementation
   * - CMOX_MATH_FUNCS_FAST to select the mathematics fast implementation
   */
  /* Note: CMOX_MODEXP_PRIVATE refer to the default modular exponentiation implementation
   * selected in cmox_default_config.h. To use a specific implementation, user can
   * directly choose:
   * - CMOX_MODEXP_PRIVATE_LOWMEM  to select the modular exponentiation low RAM usage implementation
   * - CMOX_MODEXP_PRIVATE_MIDMEM to select the modular exponentiation mid RAM usage implementation
   * - CMOX_MODEXP_PRIVATE_HIGHMEM to select the modular exponentiation high RAM usage implementation
   */
  cmox_rsa_construct(&Rsa_Ctx, CMOX_RSA_MATH_FUNCS, CMOX_MODEXP_PRIVATE, Working_Buffer, sizeof(Working_Buffer));

  /* Fill in RSA key structure using the regular private key representation */
  retval = cmox_rsa_setKey(&Rsa_Key,                                      /* RSA key structure to fill */
                           Modulus, sizeof(Modulus),                      /* Private key modulus */
                           Private_Exponent, sizeof(Private_Exponent));   /* Private key exponent */

  /* Verify API returned value */
  if (retval != CMOX_RSA_SUCCESS)
  {
    Error_Handler();
  }

  /* Compute directly the signature passing all the needed parameters */
  retval = cmox_rsa_pkcs1v15_sign(&Rsa_Ctx,                                 /* RSA context */
                                  &Rsa_Key,                                 /* RSA key to use */
                                  Computed_Hash,                            /* Digest to sign */
                                  CMOX_RSA_PKCS1V15_HASH_SHA1,              /* Method used to compute the digest */
                                  Computed_Signature, &computed_size);      /* Data buffer to receive signature */

  /* Verify API returned value */
  if (retval != CMOX_RSA_SUCCESS)
  {
    Error_Handler();
  }

  /* Verify generated data size is the expected one */
  if (computed_size != sizeof(Known_Signature))
  {
    Error_Handler();
  }

  /* Verify generated data are the expected ones */
  if (memcmp(Computed_Signature, Known_Signature, computed_size) != 0)
  {
    Error_Handler();
  }

  /* Cleanup context */
  cmox_rsa_cleanup(&Rsa_Ctx);

  /* --------------------------------------------------------------------------
   * USING CHINESE REMAINDERTHEOREM (CRT) PRIVATE KEY REPRESENTATION
   * --------------------------------------------------------------------------
   */

  /* Construct a RSA context, specifying mathematics implementation and working buffer for later processing */
  /* Note: CMOX_RSA_MATH_FUNCS refer to the default mathematics implementation
   * selected in cmox_default_config.h. To use a specific implementation, user can
   * directly choose:
   * - CMOX_MATH_FUNCS_SMALL to select the mathematics small implementation
   * - CMOX_MATH_FUNCS_FAST to select the mathematics fast implementation
   */
  /* Note: CMOX_MODEXP_PRIVATE refer to the default modular exponentiation implementation
   * selected in cmox_default_config.h. To use a specific implementation, user can
   * directly choose:
   * - CMOX_MODEXP_PRIVATE_LOWMEM  to select the modular exponentiation low RAM usage implementation
   * - CMOX_MODEXP_PRIVATE_MIDMEM to select the modular exponentiation mid RAM usage implementation
   * - CMOX_MODEXP_PRIVATE_HIGHMEM to select the modular exponentiation high RAM usage implementation
   */
  cmox_rsa_construct(&Rsa_Ctx, CMOX_RSA_MATH_FUNCS, CMOX_MODEXP_PRIVATE, Working_Buffer, sizeof(Working_Buffer));

  /* Fill in RSA key structure using the CRT private key representation */
  /* Note: when using CRT representation with RSA PKCS#1 V1.5 signature
   * scheme, better enable the fault attack countermeasure to be protected
   * against Bellcore attack
   * This is done by using the cmox_rsa_setKeyCRTwithFACM API to fill the key structure
   */
  retval = cmox_rsa_setKeyCRTwithFACM(&Rsa_Key,                                     /* RSA key structure to fill */
                                      sizeof(Modulus) * 8,                          /* Private key modulus bit length */
                                      P_Prime_Exponent, sizeof(P_Prime_Exponent),   /* P prime */
                                      Q_Prime_Exponent, sizeof(Q_Prime_Exponent),   /* Q prime */
                                      P_Prime, sizeof(P_Prime),                     /* P prime exponent */
                                      Q_Prime, sizeof(Q_Prime),                     /* Q prime exponent */
                                      Coefficient, sizeof(Coefficient),             /* Coefficient */
                                      Public_Exponent, sizeof(Public_Exponent));    /* Public exponent */

  /* Verify API returned value */
  if (retval != CMOX_RSA_SUCCESS)
  {
    Error_Handler();
  }

  /* Compute directly the signature passing all the needed parameters */
  retval = cmox_rsa_pkcs1v15_sign(&Rsa_Ctx,                                 /* RSA context */
                                  &Rsa_Key,                                 /* RSA key to use */
                                  Computed_Hash,                            /* Digest to sign */
                                  CMOX_RSA_PKCS1V15_HASH_SHA1,              /* Method used to compute the digest */
                                  Computed_Signature, &computed_size);      /* Data buffer to receive signature */

  /* Verify API returned value */
  if (retval != CMOX_RSA_SUCCESS)
  {
    Error_Handler();
  }

  /* Verify generated data size is the expected one */
  if (computed_size != sizeof(Known_Signature))
  {
    Error_Handler();
  }

  /* Verify generated data are the expected ones */
  if (memcmp(Computed_Signature, Known_Signature, computed_size) != 0)
  {
    Error_Handler();
  }

  /* Cleanup context */
  cmox_rsa_cleanup(&Rsa_Ctx);


  /* Construct a RSA context, specifying mathematics implementation and working buffer for later processing */
  /* Note: CMOX_RSA_MATH_FUNCS refer to the default mathematics implementation
   * selected in cmox_default_config.h. To use a specific implementation, user can
   * directly choose:
   * - CMOX_MATH_FUNCS_SMALL to select the mathematics small implementation
   * - CMOX_MATH_FUNCS_FAST to select the mathematics fast implementation
   */
  cmox_rsa_construct(&Rsa_Ctx, CMOX_RSA_MATH_FUNCS, CMOX_MODEXP_PUBLIC, Working_Buffer, sizeof(Working_Buffer));

  /* Fill in RSA key structure using the public key representation */
  retval = cmox_rsa_setKey(&Rsa_Key,                                      /* RSA key structure to fill */
                           Modulus, sizeof(Modulus),                      /* Key modulus */
                           Public_Exponent, sizeof(Public_Exponent));     /* Public key exponent */

  /* Verify API returned value */
  if (retval != CMOX_RSA_SUCCESS)
  {
    Error_Handler();
  }

  /* Compute directly the signature passing all the needed parameters */
  retval = cmox_rsa_pkcs1v15_verify(&Rsa_Ctx,                                 /* RSA context */
                                    &Rsa_Key,                                 /* RSA key to use */
                                    Computed_Hash,                            /* Digest to sign */
                                    CMOX_RSA_PKCS1V15_HASH_SHA1,              /* Method used to compute the digest */
                                    Known_Signature, sizeof(Known_Signature), /* Signature to verify */
                                    &fault_check);                            /* Fault check variable:
                                                            to ensure no fault injection occurs during this API call */

  /* Verify API returned value */
  if (retval != CMOX_RSA_AUTH_SUCCESS)
  {
    Error_Handler();
  }
  /* Verify Fault check variable value */
  if (fault_check != CMOX_RSA_AUTH_SUCCESS)
  {
    Error_Handler();
  }

  /* Cleanup context */
  cmox_rsa_cleanup(&Rsa_Ctx);

  /* No more need of cryptographic services, finalize cryptographic library */
  if (cmox_finalize(NULL) != CMOX_INIT_SUCCESS)
  {
    Error_Handler();
  }

  /* Turn on LD3 in an infinite loop in case of RSA operations are successful */
  BSP_LED_On(LD3);
  glob_status = PASSED;
  while (1)
  {}
}

/**
  * @brief  System Clock Configuration
  *         The system Clock is configured as follow :
  *            System Clock source            = PLL1 (HSI)
  *            SYSCLK(Hz)                     = 600000000
  *            HSI Frequency(Hz)              = 64000000
  *            HSI Divider                    = 1
  *            PLL1_M                         = 32
  *            PLL1_N                         = 300
  *            PLL1_P                         = 1
  *            PLL1_Q                         = 2
  *            PLL1_R                         = 2
  *            PLL1_S                         = 2
  *            PLL1_T                         = 2
  *            PLL2                           not used
  *            PLL3                           not used
  *            Flash Latency(WS)              = 7
  * @param  None
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
  */
  if (HAL_PWREx_ControlVoltageScaling(PWR_REGULATOR_VOLTAGE_SCALE0) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
  RCC_OscInitStruct.HSIState = RCC_HSI_ON;
  RCC_OscInitStruct.HSIDiv = RCC_HSI_DIV1;
  RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.PLL1.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL1.PLLSource = RCC_PLLSOURCE_HSI;
  RCC_OscInitStruct.PLL1.PLLM = 32;
  RCC_OscInitStruct.PLL1.PLLN = 300;
  RCC_OscInitStruct.PLL1.PLLP = 1;
  RCC_OscInitStruct.PLL1.PLLQ = 2;
  RCC_OscInitStruct.PLL1.PLLR = 2;
  RCC_OscInitStruct.PLL1.PLLS = 2;
  RCC_OscInitStruct.PLL1.PLLT = 2;
  RCC_OscInitStruct.PLL1.PLLFractional = 0;
  RCC_OscInitStruct.PLL2.PLLState = RCC_PLL_NONE;
  RCC_OscInitStruct.PLL3.PLLState = RCC_PLL_NONE;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2
                              |RCC_CLOCKTYPE_PCLK4|RCC_CLOCKTYPE_PCLK5;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.SYSCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_HCLK_DIV2;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_APB1_DIV2;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_APB2_DIV2;
  RCC_ClkInitStruct.APB4CLKDivider = RCC_APB4_DIV2;
  RCC_ClkInitStruct.APB5CLKDivider = RCC_APB5_DIV2;
  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_7) != HAL_OK)
  {
    Error_Handler();
  }
}


/**
  * @brief  CPU L1-Cache enable.
  * @param  None
  * @retval None
  */
static void CPU_CACHE_Enable(void)
{
  /* Enable I-Cache */
  SCB_EnableICache();

  /* Enable D-Cache */
  SCB_EnableDCache();
}

/**
  * @brief  This function is executed in case of error occurrence
  * @param  None
  * @retval None
  */
static void Error_Handler(void)
{
  /* User may add here some code to deal with this error */
  /* Toggle LD3 @2Hz to notify error condition */
  while (1)
  {
    BSP_LED_Toggle(LD3);
    HAL_Delay(250);
  }
}

#ifdef USE_FULL_ASSERT

/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */

  /* Infinite loop */
  while (1)
  {}
}
#endif /* USE_FULL_ASSERT */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
