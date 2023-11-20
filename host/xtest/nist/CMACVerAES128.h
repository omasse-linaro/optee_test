// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023, Linaro Limited
 * All rights reserved.
 */

{ TEE_ALG_AES_CMAC, TEE_TYPE_AES,
/* Key */ (const uint8_t []){0x80, 0x20, 0x47, 0xee, 0x13, 0x09, 0xe5, 0x48, 0xae, 0x81, 0xe9, 0x3a, 0x17, 0xbf, 0xf9, 0xe7, }, 16.0,
0,
/* Msg */ NULL, 0,
/* Mac  */ (const uint8_t []){0x14, 0x72, 0xae, 0xca, 0xa0, 0xa0, 0x9e, 0x45, 0x89, 0x3a, 0x14, 0x09, 0x0e, 0xd9, 0xa1, 0x7f, }, 16.0,
false },
{ TEE_ALG_AES_CMAC, TEE_TYPE_AES,
/* Key */ (const uint8_t []){0x9d, 0x45, 0xf6, 0xd9, 0x7d, 0x15, 0x73, 0xde, 0x3c, 0xb3, 0x48, 0x8b, 0xef, 0xaf, 0x5b, 0x7f, }, 16.0,
0,
/* Msg */ NULL, 0,
/* Mac  */ (const uint8_t []){0x96, 0xec, 0x3c, 0xf2, 0x34, 0xd6, 0x70, 0x44, 0x83, 0xa9, 0x38, 0x85, 0xbd, 0x67, 0xe6, 0xdc, }, 16.0,
false },
{ TEE_ALG_AES_CMAC, TEE_TYPE_AES,
/* Key */ (const uint8_t []){0x17, 0x37, 0x8e, 0x17, 0xc4, 0x15, 0x86, 0xb8, 0x85, 0x23, 0xa6, 0xb6, 0xaf, 0x73, 0x8d, 0xc4, }, 16.0,
0,
/* Msg */ NULL, 0,
/* Mac  */ (const uint8_t []){0x40, 0xcc, 0x8b, 0x38, 0x8b, 0xe6, 0x78, 0x9a, 0xca, 0x58, 0x46, 0x59, 0xac, 0xc7, 0xaa, 0x06, }, 16.0,
false },
{ TEE_ALG_AES_CMAC, TEE_TYPE_AES,
/* Key */ (const uint8_t []){0x06, 0xf0, 0xe4, 0x61, 0x8e, 0x0e, 0xa8, 0xfa, 0x54, 0x43, 0xb5, 0x0e, 0xa0, 0x05, 0xb6, 0x72, }, 16.0,
0,
/* Msg */ NULL, 0,
/* Mac  */ (const uint8_t []){0x29, 0x5c, 0x6c, 0xd0, 0x8b, 0x1d, 0x66, 0x8d, 0x9f, 0xa8, 0x5e, 0xf8, 0x51, 0xb1, 0xe0, 0x29, }, 16.0,
false },
{ TEE_ALG_AES_CMAC, TEE_TYPE_AES,
/* Key */ (const uint8_t []){0x7c, 0x0b, 0x7d, 0xb9, 0x81, 0x1f, 0x10, 0xd0, 0x0e, 0x47, 0x6c, 0x7a, 0x0d, 0x92, 0xf6, 0xe0, }, 16.0,
0,
/* Msg */ (const uint8_t []){0x1e, 0xe0, 0xec, 0x46, 0x6d, 0x46, 0xfd, 0x84, 0x9b, 0x40, 0xc0, 0x66, 0xb4, 0xfb, 0xbd, 0x22, 0xa2, 0x0a, 0x4d, 0x80, 0xa0, 0x08, 0xac, 0x9a, 0xf1, 0x7e, 0x4f, 0xdf, 0xd1, 0x06, 0x78, 0x5e, }, 32.0,
/* Mac  */ (const uint8_t []){0xba, 0xec, 0xdc, 0x91, 0xe9, 0xa1, 0xfc, 0x35, 0x72, 0xad, 0xf1, 0xe4, 0x23, 0x2a, 0xe2, 0x85, }, 16.0,
false },
{ TEE_ALG_AES_CMAC, TEE_TYPE_AES,
/* Key */ (const uint8_t []){0x63, 0x8d, 0x7d, 0x95, 0xff, 0x5f, 0x57, 0x57, 0x12, 0x61, 0xe2, 0x3f, 0xfa, 0x08, 0x11, 0x89, }, 16.0,
0,
/* Msg */ (const uint8_t []){0x5f, 0x5b, 0xc4, 0xe3, 0x27, 0x64, 0xbb, 0x00, 0x08, 0x56, 0x67, 0xb7, 0xf1, 0xb1, 0x54, 0x33, 0xf0, 0x9c, 0x1f, 0x6f, 0xa4, 0x86, 0x89, 0xf8, 0xf5, 0x0d, 0xca, 0xf5, 0x02, 0x1f, 0x28, 0x64, }, 32.0,
/* Mac  */ (const uint8_t []){0x96, 0xb2, 0x70, 0x62, 0x9b, 0x2b, 0xfb, 0xf7, 0x21, 0xf1, 0xa7, 0x0e, 0xcc, 0xf9, 0xab, 0xe0, }, 16.0,
false },
{ TEE_ALG_AES_CMAC, TEE_TYPE_AES,
/* Key */ (const uint8_t []){0x8d, 0x56, 0x0d, 0xe2, 0xe3, 0x10, 0xea, 0x69, 0x38, 0x92, 0x21, 0xce, 0x2e, 0x85, 0x06, 0x25, }, 16.0,
0,
/* Msg */ (const uint8_t []){0x04, 0xd9, 0xdb, 0x45, 0xe4, 0xdf, 0x19, 0xdb, 0x75, 0x7b, 0x9b, 0x95, 0xc2, 0x5b, 0xe4, 0x3e, 0x82, 0x2b, 0x83, 0x72, 0xed, 0x14, 0x8d, 0x49, 0xce, 0x82, 0x4a, 0x36, 0xda, 0x2b, 0x2f, 0x2e, }, 32.0,
/* Mac  */ (const uint8_t []){0x64, 0x7f, 0x28, 0x74, 0xa0, 0x83, 0xe8, 0x2f, 0xa8, 0x04, 0xb6, 0xc5, 0x8c, 0x7b, 0x5c, 0x90, }, 16.0,
false },
{ TEE_ALG_AES_CMAC, TEE_TYPE_AES,
/* Key */ (const uint8_t []){0x8a, 0xf7, 0xb7, 0x4e, 0x35, 0xeb, 0x38, 0xf4, 0x08, 0x63, 0x43, 0xbc, 0x32, 0x9a, 0xb4, 0x65, }, 16.0,
0,
/* Msg */ (const uint8_t []){0xad, 0xa1, 0xfa, 0x43, 0x9c, 0x65, 0x3d, 0x0c, 0xc8, 0x8c, 0x0d, 0x12, 0x9b, 0xa2, 0x52, 0xe8, 0x6c, 0x7d, 0x20, 0xa3, 0x08, 0x7b, 0xe9, 0x3e, 0x92, 0x0b, 0xf1, 0x3d, 0x8e, 0x6f, 0x03, 0x91, }, 32.0,
/* Mac  */ (const uint8_t []){0x0f, 0xc9, 0xb1, 0x77, 0xc8, 0x74, 0xea, 0x90, 0x9b, 0x6b, 0xeb, 0x1d, 0xb1, 0xb8, 0x02, 0xb4, }, 16.0,
false },
{ TEE_ALG_AES_CMAC, TEE_TYPE_AES,
/* Key */ (const uint8_t []){0x17, 0x28, 0x1a, 0xcb, 0x52, 0x5b, 0x13, 0x65, 0x30, 0x00, 0xab, 0x45, 0xd8, 0x6e, 0x70, 0x10, }, 16.0,
0,
/* Msg */ (const uint8_t []){0x22, 0x57, 0x50, 0xca, 0x98, 0x2e, 0x5b, 0x34, 0xfc, 0x62, 0xe2, 0x77, 0xea, 0xaa, 0x0f, 0x24, 0x85, 0x32, 0xab, 0xf3, 0x74, 0x93, 0x3e, 0x57, 0x2b, 0x02, 0x78, 0x56, 0x6c, 0xc7, 0xcf, 0x98, 0x0d, 0xf2, 0x6a, 0xbe, 0xfb, 0x49, 0x3e, 0xf5, 0x7f, 0x84, 0x77, 0xca, 0xc0, 0xbd, 0x19, 0x40, 0x8a, 0x22, 0xe7, 0x1f, 0x4d, 0xed, 0x84, 0x90, 0x69, 0x96, 0xd8, 0xe7, 0xa8, 0x46, 0xb5, 0xc0, }, 64.0,
/* Mac  */ (const uint8_t []){0x0f, 0x2a, 0xa7, 0xf2, 0xdf, 0xfc, 0xf7, 0xdf, 0x34, 0xc8, 0x4d, 0x10, 0x1a, 0xa9, 0xba, 0xb5, }, 16.0,
false },
{ TEE_ALG_AES_CMAC, TEE_TYPE_AES,
/* Key */ (const uint8_t []){0x5d, 0xf2, 0x95, 0xbe, 0x7c, 0x44, 0xd5, 0x9c, 0x44, 0xfe, 0xad, 0x3f, 0x19, 0x88, 0x35, 0x6f, }, 16.0,
0,
/* Msg */ (const uint8_t []){0x3d, 0x73, 0x70, 0xcc, 0x2d, 0x61, 0xaf, 0x35, 0xbf, 0x7b, 0x2b, 0xa5, 0x0a, 0x14, 0x3b, 0x23, 0xbf, 0xa0, 0xd1, 0xef, 0xf6, 0x6c, 0x5a, 0xce, 0x2d, 0x8d, 0xe5, 0xa2, 0x8d, 0x17, 0x88, 0x3d, 0x70, 0x8f, 0xff, 0x77, 0x21, 0xa2, 0x97, 0x7e, 0xe2, 0x16, 0x4b, 0x6e, 0x34, 0x02, 0x2c, 0x22, 0x52, 0x3a, 0x06, 0x49, 0xff, 0x0e, 0x40, 0xbc, 0x81, 0x34, 0x04, 0x0f, 0xee, 0x02, 0xa0, 0x65, }, 64.0,
/* Mac  */ (const uint8_t []){0x81, 0xb3, 0x18, 0x1a, 0xcb, 0xc2, 0xd6, 0xd2, 0x96, 0x0e, 0xc5, 0x74, 0x41, 0xff, 0x3c, 0x40, }, 16.0,
false },
{ TEE_ALG_AES_CMAC, TEE_TYPE_AES,
/* Key */ (const uint8_t []){0xd9, 0xbd, 0x6a, 0xc1, 0x53, 0xcb, 0x0b, 0xc4, 0xe1, 0x9e, 0x59, 0xc4, 0x5c, 0xfe, 0x0d, 0x6f, }, 16.0,
0,
/* Msg */ (const uint8_t []){0xc6, 0x80, 0x94, 0xc2, 0x6c, 0x7f, 0x01, 0x7b, 0x79, 0xf1, 0x26, 0xdc, 0x26, 0xb3, 0xbb, 0xcb, 0x95, 0xf9, 0x75, 0x35, 0xca, 0x41, 0x2d, 0xa5, 0xf7, 0x85, 0x3e, 0x15, 0xfc, 0xb5, 0x2f, 0x04, 0x2e, 0x64, 0x92, 0xc8, 0x57, 0xc2, 0x2b, 0x26, 0xff, 0xca, 0x55, 0x20, 0xea, 0xbc, 0xa2, 0x0e, 0xe2, 0xce, 0xc2, 0xf0, 0xb7, 0x1e, 0xa6, 0x03, 0x83, 0xec, 0xe4, 0x92, 0x32, 0x06, 0x5e, 0x0f, }, 64.0,
/* Mac  */ (const uint8_t []){0x3b, 0x17, 0x77, 0x89, 0x55, 0x99, 0x0a, 0xe5, 0x8e, 0x03, 0xfe, 0xda, 0x7f, 0xc4, 0x39, 0x98, }, 16.0,
false },
{ TEE_ALG_AES_CMAC, TEE_TYPE_AES,
/* Key */ (const uint8_t []){0x3c, 0x1b, 0xa9, 0x2d, 0x09, 0x6f, 0xba, 0x13, 0x4d, 0xfb, 0x4e, 0xf4, 0x12, 0xb2, 0x56, 0x8d, }, 16.0,
0,
/* Msg */ (const uint8_t []){0xba, 0x77, 0x25, 0xd7, 0x44, 0x65, 0xf5, 0xd9, 0x24, 0x54, 0xbf, 0xf7, 0x94, 0xe0, 0xbe, 0x51, 0xc4, 0xd0, 0xaf, 0x7d, 0x88, 0xf7, 0x29, 0x83, 0x4d, 0x57, 0x31, 0x2c, 0x52, 0x8d, 0x0a, 0x7d, 0x15, 0x69, 0x4a, 0x7e, 0x0b, 0xdc, 0x33, 0x40, 0x93, 0x17, 0x3f, 0x1d, 0x2d, 0xf1, 0xfd, 0x42, 0xe7, 0x89, 0x1c, 0x6b, 0x19, 0x2d, 0xc5, 0xee, 0x52, 0x7b, 0x2f, 0xfb, 0x92, 0xc6, 0x6d, 0x22, }, 64.0,
/* Mac  */ (const uint8_t []){0xcf, 0xe6, 0x02, 0x2a, 0xd2, 0x9a, 0x54, 0x62, 0x7a, 0xe7, 0xc4, 0xf9, 0x07, 0xef, 0x4d, 0xa1, }, 16.0,
false },
{ TEE_ALG_AES_CMAC, TEE_TYPE_AES,
/* Key */ (const uint8_t []){0xe8, 0xb1, 0x33, 0x46, 0xb6, 0x1d, 0xae, 0xdc, 0x1f, 0x9e, 0x3b, 0x49, 0xdf, 0x8d, 0x1c, 0xd6, }, 16.0,
0,
/* Msg */ (const uint8_t []){0x05, 0x93, 0x36, 0x54, 0x19, 0xe0, 0xf7, 0x5b, 0x63, 0x23, }, 10.0,
/* Mac  */ (const uint8_t []){0x87, 0x1e, 0xb9, 0x78, 0x50, 0xa7, 0x76, 0xe7, 0xad, 0x49, 0x84, 0x67, 0x06, 0x44, 0x84, 0xf9, }, 16.0,
false },
{ TEE_ALG_AES_CMAC, TEE_TYPE_AES,
/* Key */ (const uint8_t []){0x85, 0xe4, 0xe6, 0x33, 0x41, 0x65, 0x81, 0x44, 0xa9, 0x9f, 0xbd, 0x17, 0xd9, 0x4e, 0x31, 0x77, }, 16.0,
0,
/* Msg */ (const uint8_t []){0x21, 0xff, 0x83, 0x4b, 0xec, 0x4e, 0xc6, 0x38, 0x45, 0x22, }, 10.0,
/* Mac  */ (const uint8_t []){0x58, 0x0c, 0x1e, 0x54, 0x9a, 0x2c, 0xec, 0xa4, 0x74, 0x32, 0x56, 0xa9, 0xcc, 0x97, 0x2e, 0x84, }, 16.0,
false },
{ TEE_ALG_AES_CMAC, TEE_TYPE_AES,
/* Key */ (const uint8_t []){0xcf, 0x37, 0x27, 0x50, 0x95, 0x77, 0xf1, 0x93, 0x2b, 0xd7, 0xa9, 0x25, 0x89, 0xc1, 0x1e, 0x67, }, 16.0,
0,
/* Msg */ (const uint8_t []){0x83, 0x11, 0x88, 0xef, 0xc5, 0xd1, 0xf6, 0xdc, 0x9b, 0xb8, }, 10.0,
/* Mac  */ (const uint8_t []){0xb5, 0xd1, 0x62, 0xc8, 0x85, 0xd7, 0xd4, 0xf6, 0xf6, 0x5f, 0x41, 0x88, 0xd6, 0x58, 0x22, 0x40, }, 16.0,
false },
{ TEE_ALG_AES_CMAC, TEE_TYPE_AES,
/* Key */ (const uint8_t []){0xa1, 0xf8, 0x2c, 0x99, 0x24, 0x41, 0x1e, 0x98, 0xe6, 0xf9, 0x3f, 0xa0, 0xd0, 0x75, 0x59, 0xe2, }, 16.0,
0,
/* Msg */ (const uint8_t []){0x7d, 0x47, 0x48, 0x14, 0x75, 0x75, 0xbc, 0x01, 0x13, 0xab, }, 10.0,
/* Mac  */ (const uint8_t []){0xc2, 0x3d, 0xbc, 0x58, 0xfe, 0x22, 0xb3, 0x4f, 0x7b, 0x00, 0x75, 0x90, 0x55, 0x8a, 0x30, 0x80, }, 16.0,
false },
{ TEE_ALG_AES_CMAC, TEE_TYPE_AES,
/* Key */ (const uint8_t []){0xe3, 0xce, 0xb9, 0x29, 0xb5, 0x2a, 0x6e, 0xec, 0x02, 0xb9, 0x9b, 0x13, 0xbf, 0x30, 0x72, 0x1b, }, 16.0,
0,
/* Msg */ (const uint8_t []){0xd2, 0xe8, 0xa3, 0xe8, 0x6a, 0xe0, 0xb9, 0xed, 0xc7, 0xcc, 0x31, 0x16, 0xd9, 0x29, 0xa1, 0x6f, 0x13, 0xee, 0x36, 0x43, }, 20.0,
/* Mac  */ (const uint8_t []){0x10, 0xf3, 0xd2, 0x9e, 0x89, 0xe4, 0x03, 0x9b, 0x85, 0xe1, 0x64, 0x38, 0xb2, 0xb2, 0xa4, 0x70, }, 16.0,
false },
{ TEE_ALG_AES_CMAC, TEE_TYPE_AES,
/* Key */ (const uint8_t []){0x20, 0xf6, 0xf5, 0x61, 0x17, 0x75, 0x8b, 0xa4, 0x7a, 0x08, 0xda, 0xdf, 0x93, 0xa5, 0x90, 0x56, }, 16.0,
0,
/* Msg */ (const uint8_t []){0x75, 0x14, 0xe0, 0xf4, 0x02, 0xe7, 0x3d, 0x9c, 0x0b, 0x05, 0x76, 0x78, 0x20, 0x11, 0xb2, 0xe6, 0xb2, 0x08, 0x0a, 0x6a, }, 20.0,
/* Mac  */ (const uint8_t []){0x11, 0xcd, 0xa4, 0x89, 0xb6, 0xdc, 0x0a, 0xb4, 0x8d, 0x11, 0x1e, 0xe6, 0xcb, 0x26, 0xa8, 0x29, }, 16.0,
false },
{ TEE_ALG_AES_CMAC, TEE_TYPE_AES,
/* Key */ (const uint8_t []){0xb4, 0x7a, 0xa8, 0x90, 0xb0, 0x3a, 0x8a, 0xc0, 0xdb, 0xc8, 0xf9, 0x6c, 0x30, 0xfd, 0xf7, 0xdb, }, 16.0,
0,
/* Msg */ (const uint8_t []){0x58, 0xb0, 0x6c, 0x99, 0xe0, 0xd0, 0x25, 0x6c, 0xb1, 0xc5, 0x56, 0xec, 0x3b, 0x48, 0xa3, 0xbc, 0xe7, 0x34, 0x50, 0xa0, }, 20.0,
/* Mac  */ (const uint8_t []){0x33, 0x76, 0xca, 0xcc, 0x24, 0x76, 0x86, 0x83, 0x27, 0x36, 0xce, 0xa7, 0xe6, 0x7e, 0x13, 0xaf, }, 16.0,
false },
{ TEE_ALG_AES_CMAC, TEE_TYPE_AES,
/* Key */ (const uint8_t []){0xba, 0xf5, 0xaf, 0xaf, 0xd7, 0xd0, 0xc8, 0xad, 0x42, 0xa4, 0x4e, 0x4e, 0x0a, 0x90, 0xfd, 0x2c, }, 16.0,
0,
/* Msg */ (const uint8_t []){0xcc, 0x5a, 0x42, 0x09, 0xa6, 0xa6, 0x0d, 0xcf, 0x12, 0x62, 0x1e, 0x17, 0x15, 0x0b, 0x45, 0x76, 0xb9, 0x18, 0x73, 0x2e, }, 20.0,
/* Mac  */ (const uint8_t []){0x5a, 0x43, 0x00, 0x2d, 0x91, 0x44, 0xa1, 0xd5, 0xe4, 0x8c, 0x2d, 0xc8, 0xdc, 0x16, 0x7a, 0x52, }, 16.0,
false },
{ TEE_ALG_AES_CMAC, TEE_TYPE_AES,
/* Key */ (const uint8_t []){0xc9, 0x8f, 0xc3, 0x41, 0x64, 0x57, 0xd9, 0xee, 0xd0, 0xfa, 0x7a, 0xb1, 0xdc, 0x1b, 0x8a, 0x6a, }, 16.0,
0,
/* Msg */ (const uint8_t []){0x19, 0x0a, 0xe5, 0x7a, 0xb8, 0xbb, 0x70, 0x46, 0x4e, 0x4a, 0x10, 0xc1, 0x12, 0xa5, 0x4c, 0x64, 0x64, 0x38, 0x30, 0x1b, 0x56, 0x62, 0xf3, 0x53, 0x6c, 0x26, 0xd7, 0x54, 0xa0, 0x24, 0x51, 0xd1, 0xa9, 0xc7, 0x6a, 0xbd, 0x7d, 0xbf, 0x65, 0x61, 0x15, 0xb2, 0xa2, 0xac, 0x70, 0x2e, 0xc2, 0xca, 0xda, 0xe3, 0x0c, 0xf8, 0x6e, 0x0f, 0x0f, 0x96, 0xda, 0x39, 0x89, 0x7d, 0x62, 0x22, 0x88, 0x94, 0x28, }, 65.0,
/* Mac  */ (const uint8_t []){0x1b, 0xea, 0x94, 0xa4, 0x57, 0xb2, 0x88, 0x6e, 0x90, 0x98, 0xbf, 0x3d, 0xed, 0x93, 0x2a, 0x3a, }, 16.0,
false },
{ TEE_ALG_AES_CMAC, TEE_TYPE_AES,
/* Key */ (const uint8_t []){0xb6, 0x6e, 0xdc, 0xc5, 0x9d, 0xc9, 0xd8, 0xe3, 0x4b, 0xea, 0x3b, 0xaf, 0x4b, 0xfc, 0x0d, 0x5e, }, 16.0,
0,
/* Msg */ (const uint8_t []){0x57, 0xca, 0xad, 0xbb, 0x1a, 0x56, 0xcc, 0x5b, 0x8a, 0x5c, 0xf9, 0x58, 0x45, 0x52, 0xe1, 0x7e, 0x7a, 0xf9, 0x54, 0x2b, 0xa1, 0x3e, 0x9c, 0x54, 0x69, 0x5e, 0x0d, 0xc8, 0xf2, 0x4e, 0xdd, 0xb9, 0x3d, 0x5a, 0x36, 0x78, 0xe1, 0x0c, 0x8a, 0x80, 0xff, 0x4f, 0x27, 0xb6, 0x77, 0xd4, 0x0b, 0xef, 0x5c, 0xb5, 0xf9, 0xb3, 0xa6, 0x59, 0xcc, 0x41, 0x27, 0x97, 0x0c, 0xd2, 0xc1, 0x1e, 0xbf, 0x22, 0xd5, }, 65.0,
/* Mac  */ (const uint8_t []){0x0c, 0x58, 0x64, 0xee, 0xfc, 0x04, 0xa6, 0xca, 0xc4, 0xf0, 0x53, 0xab, 0x2f, 0x65, 0xf8, 0x51, }, 16.0,
false },
{ TEE_ALG_AES_CMAC, TEE_TYPE_AES,
/* Key */ (const uint8_t []){0xb7, 0x47, 0x1a, 0x8b, 0x2e, 0x50, 0xfb, 0x31, 0x9f, 0x19, 0x8a, 0x09, 0xcd, 0xae, 0xb3, 0x19, }, 16.0,
0,
/* Msg */ (const uint8_t []){0x38, 0x5f, 0x9f, 0xb1, 0x39, 0xdb, 0xf8, 0x85, 0x61, 0xb7, 0xa5, 0x00, 0xb0, 0xc7, 0xb8, 0x35, 0xfe, 0x57, 0xe2, 0x69, 0x8c, 0x6d, 0x9f, 0x76, 0xde, 0x4f, 0xae, 0x6d, 0xcd, 0x45, 0xc4, 0x7f, 0xd8, 0xa0, 0x81, 0x1e, 0xbb, 0xfb, 0xa3, 0x5f, 0x43, 0xc1, 0x7a, 0xa3, 0x60, 0xf0, 0x9c, 0x76, 0x7c, 0x1c, 0xd9, 0xb7, 0x0b, 0xb6, 0x71, 0xfa, 0x63, 0x8e, 0x85, 0x2a, 0xce, 0x97, 0xcc, 0x73, 0xde, }, 65.0,
/* Mac  */ (const uint8_t []){0x1a, 0x8b, 0x81, 0xbe, 0x87, 0x5a, 0x48, 0x14, 0xe3, 0xf9, 0x88, 0xc2, 0x74, 0x78, 0x4a, 0x63, }, 16.0,
false },
{ TEE_ALG_AES_CMAC, TEE_TYPE_AES,
/* Key */ (const uint8_t []){0xd1, 0x49, 0x44, 0x1e, 0x66, 0x7b, 0x24, 0x5d, 0x46, 0x40, 0xe0, 0x4c, 0x53, 0xca, 0x6f, 0x51, }, 16.0,
0,
/* Msg */ (const uint8_t []){0xcb, 0xb3, 0x47, 0x94, 0xbc, 0x8b, 0xfd, 0xf9, 0x3d, 0x3c, 0x8d, 0x9f, 0x87, 0xec, 0x14, 0x82, 0xb5, 0x16, 0xb4, 0x8b, 0x1e, 0x8a, 0x89, 0xb5, 0xe3, 0xb5, 0xdf, 0x70, 0xc4, 0x23, 0xa2, 0x43, 0x38, 0x42, 0x15, 0xb4, 0xbc, 0x69, 0xc7, 0x6c, 0x6b, 0x18, 0xc4, 0x97, 0xcf, 0x82, 0x08, 0x8a, 0xf7, 0x48, 0x39, 0xa8, 0xc9, 0x88, 0x95, 0x86, 0x9a, 0x16, 0x29, 0x4d, 0xfc, 0x09, 0x43, 0x60, 0xd7, }, 65.0,
/* Mac  */ (const uint8_t []){0x64, 0xf5, 0xe8, 0xdc, 0xe5, 0xc3, 0xe0, 0xf9, 0xcc, 0x22, 0x4e, 0x30, 0x6d, 0xe7, 0x0b, 0x87, }, 16.0,
false },