// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023, Linaro Limited
 * All rights reserved.
 */

{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x84, }, 1.0,
/* MD */ (const uint8_t []){0x3c, 0xd3, 0x69, 0x21, 0xdf, 0x5d, 0x69, 0x63, 0xe7, 0x37, 0x39, 0xcf, 0x4d, 0x20, 0x21, 0x1e, 0x2d, 0x88, 0x77, 0xc1, 0x9c, 0xff, 0x08, 0x7a, 0xde, 0x9d, 0x0e, 0x3a, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x5c, 0x7b, }, 2.0,
/* MD */ (const uint8_t []){0xda, 0xff, 0x9b, 0xce, 0x68, 0x5e, 0xb8, 0x31, 0xf9, 0x7f, 0xc1, 0x22, 0x5b, 0x03, 0xc2, 0x75, 0xa6, 0xc1, 0x12, 0xe2, 0xd6, 0xe7, 0x6f, 0x5f, 0xaf, 0x7a, 0x36, 0xe6, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x51, 0xca, 0x3d, }, 3.0,
/* MD */ (const uint8_t []){0x2c, 0x89, 0x59, 0x02, 0x35, 0x15, 0x47, 0x6e, 0x38, 0x38, 0x8a, 0xbb, 0x43, 0x59, 0x9a, 0x29, 0x87, 0x6b, 0x4b, 0x33, 0xd5, 0x6a, 0xdc, 0x06, 0x03, 0x2d, 0xe3, 0xa2, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x60, 0x84, 0x34, 0x7e, }, 4.0,
/* MD */ (const uint8_t []){0xae, 0x57, 0xc0, 0xa6, 0xd4, 0x97, 0x39, 0xba, 0x33, 0x8a, 0xdf, 0xa5, 0x3b, 0xda, 0xe0, 0x63, 0xe5, 0xc0, 0x91, 0x22, 0xb7, 0x76, 0x04, 0x78, 0x0a, 0x8e, 0xea, 0xa3, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x49, 0x3e, 0x14, 0x62, 0x3c, }, 5.0,
/* MD */ (const uint8_t []){0x7f, 0x63, 0x1f, 0x29, 0x5e, 0x02, 0x4e, 0x74, 0x55, 0x20, 0x83, 0x24, 0x5c, 0xa8, 0xf9, 0x88, 0xa3, 0xfb, 0x65, 0x68, 0x0a, 0xe9, 0x7c, 0x30, 0x40, 0xd2, 0xe6, 0x5c, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0xd7, 0x29, 0xd8, 0xcd, 0x16, 0x31, }, 6.0,
/* MD */ (const uint8_t []){0x34, 0x2e, 0x8e, 0x6b, 0x23, 0xc1, 0xc6, 0xa5, 0x49, 0x10, 0x63, 0x1f, 0x09, 0x8e, 0x08, 0xe8, 0x36, 0x25, 0x9c, 0x57, 0xe4, 0x9c, 0x1b, 0x1d, 0x02, 0x3d, 0x16, 0x6d, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0xcb, 0xf2, 0x06, 0x1e, 0x10, 0xfa, 0xa5, }, 7.0,
/* MD */ (const uint8_t []){0x3a, 0xa7, 0x02, 0xb1, 0xb6, 0x6d, 0xc5, 0x7d, 0x7a, 0xec, 0x3c, 0xcd, 0xbd, 0xfb, 0xd8, 0x85, 0x92, 0xd7, 0x52, 0x0f, 0x84, 0x3b, 0xa5, 0xd0, 0xfa, 0x48, 0x11, 0x68, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x5f, 0x77, 0xb3, 0x66, 0x48, 0x23, 0xc3, 0x3e, }, 8.0,
/* MD */ (const uint8_t []){0xbd, 0xf2, 0x1f, 0xf3, 0x25, 0xf7, 0x54, 0x15, 0x7c, 0xcf, 0x41, 0x7f, 0x48, 0x55, 0x36, 0x0a, 0x72, 0xe8, 0xfd, 0x11, 0x7d, 0x28, 0xc8, 0xfe, 0x7d, 0xa3, 0xea, 0x38, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x10, 0x71, 0x3b, 0x89, 0x4d, 0xe4, 0xa7, 0x34, 0xc0, }, 9.0,
/* MD */ (const uint8_t []){0x03, 0x84, 0x26, 0x00, 0xc8, 0x6f, 0x5c, 0xd6, 0x0c, 0x3a, 0x21, 0x47, 0xa0, 0x67, 0xcb, 0x96, 0x2a, 0x05, 0x30, 0x3c, 0x34, 0x88, 0xb0, 0x5c, 0xb4, 0x53, 0x27, 0xbd, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x00, 0x64, 0x70, 0xd5, 0x7d, 0xad, 0x98, 0x93, 0xdc, 0x03, }, 10.0,
/* MD */ (const uint8_t []){0xc9, 0x00, 0x26, 0xcd, 0xa5, 0xad, 0x24, 0x11, 0x50, 0x59, 0xc6, 0x2a, 0xe9, 0xad, 0xd5, 0x77, 0x93, 0xad, 0xe4, 0x45, 0xd4, 0x74, 0x22, 0x73, 0x28, 0x8b, 0xbc, 0xe7, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x6f, 0x29, 0xca, 0x27, 0x41, 0x90, 0x40, 0x07, 0x20, 0xbb, 0xa2, }, 11.0,
/* MD */ (const uint8_t []){0xac, 0x53, 0x15, 0x79, 0x47, 0xaa, 0x4b, 0x2a, 0x19, 0x08, 0x91, 0x82, 0x38, 0x2a, 0x43, 0x63, 0xd1, 0x82, 0xdd, 0x8e, 0x4c, 0xa7, 0x9c, 0xd8, 0x57, 0x13, 0x90, 0xbe, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x17, 0xe8, 0x55, 0x61, 0x76, 0xfc, 0xca, 0x2a, 0xdd, 0xbd, 0xde, 0x29, }, 12.0,
/* MD */ (const uint8_t []){0xcc, 0x6a, 0xd0, 0x48, 0x8d, 0xb0, 0x22, 0x20, 0x66, 0xf7, 0x40, 0x55, 0x7b, 0x57, 0x58, 0xa1, 0x9b, 0x30, 0x37, 0x2b, 0x30, 0x23, 0x32, 0x29, 0x5d, 0x8c, 0x3a, 0xff, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0xdb, 0xf1, 0x63, 0x60, 0x1d, 0xb9, 0xa1, 0x22, 0xa4, 0x02, 0x68, 0x24, 0xde, }, 13.0,
/* MD */ (const uint8_t []){0x98, 0x49, 0x84, 0x5f, 0x4e, 0x47, 0xe1, 0xec, 0xe9, 0xa1, 0xc1, 0xe0, 0x1a, 0x0d, 0x89, 0x6f, 0xfe, 0xa6, 0x1c, 0x6c, 0x88, 0x94, 0xa7, 0x5a, 0x11, 0xce, 0x5f, 0x49, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x5e, 0x1e, 0xf2, 0xad, 0x86, 0xce, 0xaf, 0x54, 0x39, 0xfe, 0x87, 0xd2, 0xec, 0x9b, }, 14.0,
/* MD */ (const uint8_t []){0x22, 0x3c, 0x5d, 0x5d, 0x4a, 0x01, 0x16, 0xb3, 0x2c, 0xea, 0x04, 0x4f, 0x9a, 0xf0, 0xfe, 0x44, 0xba, 0xbe, 0xa1, 0xc5, 0xab, 0x20, 0x15, 0x02, 0x59, 0x1b, 0xcd, 0x5f, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x65, 0xf3, 0xb9, 0x86, 0x6f, 0xb8, 0x00, 0x2b, 0x53, 0xcf, 0xaf, 0x80, 0x6f, 0x70, 0x2f, }, 15.0,
/* MD */ (const uint8_t []){0xb1, 0xe0, 0x80, 0x6a, 0x21, 0x8d, 0x59, 0x38, 0x21, 0xfd, 0xe8, 0xe9, 0xea, 0xcc, 0x44, 0xab, 0x52, 0x87, 0xc3, 0x22, 0x09, 0xa9, 0x4f, 0x01, 0x1a, 0xb6, 0x6b, 0x75, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0xb7, 0x76, 0x70, 0x8f, 0xfb, 0x91, 0xb3, 0x51, 0x5a, 0xc4, 0x65, 0x98, 0xab, 0x9f, 0xa7, 0x96, }, 16.0,
/* MD */ (const uint8_t []){0x42, 0x73, 0x11, 0xb1, 0xd7, 0xab, 0x24, 0x88, 0x79, 0x1c, 0x4d, 0xee, 0xb4, 0x25, 0x1d, 0x78, 0x3f, 0xe5, 0xf9, 0x80, 0x6b, 0xfd, 0xfb, 0x51, 0x88, 0xc5, 0x44, 0x3d, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0xa4, 0xbc, 0x10, 0xb1, 0xa6, 0x2c, 0x96, 0xd4, 0x59, 0xfb, 0xaf, 0x3a, 0x5a, 0xa3, 0xfa, 0xce, 0x73, }, 17.0,
/* MD */ (const uint8_t []){0xd7, 0xe6, 0x63, 0x47, 0x23, 0xac, 0x25, 0xcb, 0x18, 0x79, 0xbd, 0xb1, 0x50, 0x8d, 0xa0, 0x53, 0x13, 0x53, 0x04, 0x19, 0x01, 0x3f, 0xe2, 0x55, 0x96, 0x7a, 0x39, 0xe1, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x9e, 0x8f, 0x3c, 0x66, 0x45, 0xc1, 0x74, 0x9b, 0x55, 0xc5, 0x0d, 0x20, 0x18, 0xce, 0x40, 0xdc, 0x24, 0x27, }, 18.0,
/* MD */ (const uint8_t []){0x2f, 0x5a, 0x58, 0x3b, 0xf5, 0x88, 0xc8, 0x98, 0x8a, 0x57, 0x2d, 0x12, 0x8a, 0x95, 0xbe, 0xa5, 0xef, 0x1b, 0x66, 0x78, 0x0a, 0x7d, 0x4b, 0xe9, 0xc2, 0x9e, 0xfc, 0x31, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x2d, 0xb6, 0xd2, 0x07, 0xc0, 0xb7, 0xd9, 0x11, 0x7f, 0x24, 0xd7, 0x8e, 0xe5, 0x9a, 0xbf, 0x2f, 0x31, 0x69, 0x78, }, 19.0,
/* MD */ (const uint8_t []){0x35, 0x68, 0x1f, 0xce, 0x28, 0x30, 0x7c, 0xae, 0x19, 0x52, 0x2c, 0x23, 0xcb, 0xd4, 0xa7, 0x79, 0x69, 0x34, 0x7f, 0x7d, 0x8e, 0xe4, 0xa3, 0x08, 0x8b, 0xa9, 0x0a, 0xda, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x3d, 0xf5, 0xe7, 0xf3, 0x99, 0xf6, 0xdd, 0x61, 0xa1, 0x2a, 0x9d, 0x4e, 0x94, 0x64, 0xfc, 0x49, 0x97, 0xc1, 0xf3, 0x7b, }, 20.0,
/* MD */ (const uint8_t []){0xa3, 0xe6, 0x80, 0x76, 0xe3, 0x07, 0x51, 0x08, 0x5a, 0x84, 0x3a, 0x6c, 0xbf, 0xbf, 0x0f, 0x3d, 0xee, 0x63, 0xd9, 0xc4, 0x21, 0x9c, 0x91, 0x43, 0x72, 0xe5, 0x0b, 0x28, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x65, 0x78, 0x1d, 0x01, 0x8f, 0x27, 0xca, 0x0c, 0x72, 0xa9, 0xfa, 0x9a, 0xb4, 0x64, 0x8e, 0xd3, 0x69, 0x64, 0x6d, 0xd3, 0xce, }, 21.0,
/* MD */ (const uint8_t []){0xd1, 0x5e, 0xf0, 0xd8, 0x72, 0xd0, 0x2d, 0xa6, 0x42, 0x7b, 0x8d, 0x03, 0x49, 0xde, 0xa2, 0xf2, 0x04, 0xe6, 0x71, 0x33, 0xb7, 0x36, 0x5b, 0x4b, 0x15, 0x0e, 0xfc, 0x3c, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0xaf, 0x48, 0xee, 0xdd, 0xd9, 0x3f, 0xee, 0x69, 0xd1, 0xbd, 0x7d, 0xe4, 0x28, 0xa6, 0x39, 0x86, 0x01, 0x1d, 0x10, 0x94, 0x5e, 0xaf, }, 22.0,
/* MD */ (const uint8_t []){0xb8, 0x9d, 0x42, 0x8e, 0xe4, 0x2e, 0x39, 0x7c, 0xf1, 0x10, 0x29, 0xec, 0xbb, 0x27, 0xba, 0xdd, 0xd0, 0x36, 0xc8, 0x93, 0x8f, 0x51, 0xc8, 0xab, 0x56, 0xb8, 0x75, 0xac, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0xdf, 0x2b, 0xf0, 0xd5, 0xf9, 0xc9, 0x94, 0xac, 0x69, 0xd7, 0x8b, 0xaa, 0x0d, 0x51, 0x2e, 0xce, 0xb7, 0x4d, 0x8a, 0x04, 0x75, 0x31, 0xc1, }, 23.0,
/* MD */ (const uint8_t []){0xdb, 0x8e, 0x1c, 0xe6, 0x8c, 0x8c, 0x6b, 0x84, 0xd6, 0xdb, 0x75, 0x5c, 0x2b, 0x8b, 0xf5, 0x4f, 0x3c, 0x4b, 0x08, 0x1a, 0x88, 0x1e, 0xfc, 0xdd, 0xaf, 0x30, 0x32, 0x94, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x48, 0xd2, 0xf2, 0x09, 0x55, 0xea, 0x2d, 0x13, 0x43, 0x3c, 0x20, 0xbc, 0x04, 0x04, 0xeb, 0x2e, 0x6a, 0xd7, 0x9e, 0xd2, 0x8f, 0x7c, 0xb4, 0xc0, }, 24.0,
/* MD */ (const uint8_t []){0x36, 0x17, 0xcc, 0x31, 0x79, 0xf8, 0xb5, 0x9a, 0xdc, 0xe1, 0x81, 0xee, 0xbe, 0xed, 0x5e, 0x27, 0x63, 0xf6, 0x26, 0x50, 0x94, 0x92, 0x24, 0xa6, 0x7e, 0x53, 0x69, 0x4b, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x21, 0x8f, 0x74, 0xa4, 0x2d, 0x3a, 0x47, 0xef, 0x3b, 0x80, 0x66, 0x01, 0xfb, 0xa0, 0x24, 0xb0, 0x78, 0xcb, 0xff, 0x4e, 0x4b, 0x85, 0x77, 0x2e, 0x0e, }, 25.0,
/* MD */ (const uint8_t []){0xb5, 0xf4, 0x0b, 0x95, 0xdc, 0xc3, 0x63, 0xb9, 0x7e, 0x9d, 0x00, 0xb6, 0x7c, 0x5d, 0x7c, 0x37, 0xf1, 0x7a, 0xb5, 0x63, 0x29, 0x7d, 0x2d, 0x67, 0xa4, 0xdf, 0x20, 0xc9, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0xef, 0x55, 0xb1, 0xe7, 0x97, 0x00, 0x0b, 0x04, 0xfc, 0xdb, 0x9b, 0x30, 0x21, 0xb0, 0x93, 0x27, 0xe3, 0xb4, 0xe2, 0x69, 0xd2, 0x0c, 0xab, 0xdf, 0x41, 0x8f, }, 26.0,
/* MD */ (const uint8_t []){0x82, 0x7b, 0x22, 0x3d, 0x51, 0x24, 0x0c, 0x2e, 0x32, 0x71, 0xc5, 0x34, 0xc1, 0x9c, 0x56, 0x37, 0xb6, 0xfe, 0x10, 0x08, 0x3e, 0x85, 0xbc, 0xf0, 0x67, 0x61, 0xef, 0x21, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x96, 0xdf, 0x43, 0x87, 0xdc, 0x2c, 0x40, 0x29, 0x70, 0x43, 0xbe, 0xa3, 0x64, 0x83, 0xf6, 0x5e, 0x4e, 0xb1, 0xe0, 0x7e, 0x93, 0x35, 0x9c, 0xb7, 0xe6, 0x86, 0x10, }, 27.0,
/* MD */ (const uint8_t []){0x98, 0xe4, 0x30, 0xa6, 0x3f, 0xcd, 0xed, 0xaf, 0xc9, 0x41, 0x90, 0x10, 0xf7, 0xf5, 0x9a, 0x4d, 0x81, 0x6a, 0x45, 0xb4, 0xf9, 0x73, 0xbe, 0xb6, 0x25, 0x30, 0xff, 0x8c, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x3e, 0xc0, 0xaa, 0x8d, 0x30, 0xd5, 0xed, 0x82, 0x5b, 0x77, 0xdc, 0x70, 0x95, 0xf4, 0x21, 0xb1, 0xe6, 0x08, 0x15, 0x87, 0x97, 0xa3, 0x77, 0xff, 0x8b, 0xed, 0x64, 0x1b, }, 28.0,
/* MD */ (const uint8_t []){0x31, 0x08, 0x32, 0x1e, 0xb7, 0xff, 0x85, 0x7f, 0x6a, 0xae, 0x69, 0x10, 0x1b, 0x93, 0x7f, 0x32, 0xa5, 0x1e, 0xa2, 0x79, 0xa6, 0xc1, 0x4b, 0xa5, 0x23, 0x2a, 0xc8, 0xc1, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x8b, 0x02, 0x39, 0x71, 0x20, 0x39, 0xf0, 0x77, 0xce, 0x32, 0x3b, 0x35, 0xf4, 0xe3, 0x06, 0x78, 0x7b, 0x9b, 0x35, 0x27, 0x00, 0x96, 0xe5, 0x77, 0x35, 0xcf, 0xf4, 0x5d, 0x84, }, 29.0,
/* MD */ (const uint8_t []){0xa5, 0xc7, 0x40, 0xd3, 0xce, 0x46, 0xbb, 0x2e, 0x0a, 0x04, 0x84, 0x88, 0xf2, 0xb0, 0x60, 0x5c, 0x6d, 0x0c, 0xa0, 0xea, 0x2f, 0x38, 0x2d, 0x04, 0x3d, 0x13, 0xdb, 0x97, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x04, 0x4b, 0xe3, 0x01, 0x67, 0xa9, 0x75, 0x8c, 0x46, 0xc7, 0x27, 0x92, 0x1d, 0xc4, 0xeb, 0x4e, 0x0d, 0xcb, 0x96, 0x56, 0x23, 0x42, 0x3e, 0x6f, 0xdd, 0x44, 0xe7, 0xa4, 0xea, 0x52, }, 30.0,
/* MD */ (const uint8_t []){0x6e, 0xb7, 0x83, 0x13, 0xc7, 0x43, 0xea, 0x87, 0x69, 0xd8, 0x34, 0x0f, 0x28, 0x4d, 0xda, 0x6d, 0xed, 0x64, 0xa1, 0xdb, 0x64, 0x39, 0x2f, 0x21, 0xab, 0xb8, 0x2c, 0x5c, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x57, 0xf6, 0x11, 0x8b, 0xac, 0xce, 0x47, 0xec, 0xc3, 0x1c, 0xe8, 0xb0, 0xc0, 0x83, 0xd3, 0xc9, 0x21, 0x9e, 0x0d, 0xbe, 0x9e, 0x4f, 0xbe, 0xa1, 0x54, 0x53, 0x7c, 0x41, 0x23, 0x1a, 0xcc, }, 31.0,
/* MD */ (const uint8_t []){0x0d, 0xbb, 0x53, 0xc8, 0x66, 0xd6, 0x3a, 0xf4, 0x4c, 0x22, 0x2c, 0x76, 0xc8, 0x25, 0xdf, 0x0e, 0x37, 0x9d, 0xce, 0xdf, 0xb9, 0x58, 0xdb, 0x03, 0xb6, 0xfd, 0x29, 0xa5, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0xfe, 0x1f, 0x0f, 0xb0, 0x2c, 0x90, 0x11, 0xf4, 0xc8, 0xc5, 0x90, 0x59, 0x34, 0xed, 0x15, 0x13, 0x67, 0x71, 0x73, 0x7c, 0xe3, 0x1c, 0x58, 0x59, 0xe6, 0x7f, 0x23, 0x5f, 0xe5, 0x94, 0xf5, 0xf6, }, 32.0,
/* MD */ (const uint8_t []){0xbb, 0xea, 0xac, 0xc6, 0x32, 0xc2, 0xa3, 0xdb, 0x2a, 0x9b, 0x47, 0xf1, 0x57, 0xab, 0x54, 0xaa, 0x27, 0x77, 0x6c, 0x6e, 0x74, 0xcf, 0x0b, 0xca, 0xa9, 0x1b, 0x06, 0xd5, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x14, 0xfb, 0x01, 0xae, 0x9d, 0x60, 0x15, 0xec, 0xb3, 0xe5, 0x6d, 0x6e, 0xcd, 0xfa, 0x4b, 0xc0, 0x53, 0x31, 0x86, 0xad, 0xf8, 0x45, 0x7f, 0x5e, 0x4a, 0x5c, 0x57, 0xc6, 0x87, 0x89, 0x5f, 0x3d, 0xb3, }, 33.0,
/* MD */ (const uint8_t []){0x17, 0x82, 0x72, 0xc7, 0xd7, 0xcc, 0x71, 0xb1, 0x50, 0x74, 0xc2, 0x7e, 0x3b, 0x79, 0x97, 0xd4, 0xa3, 0xba, 0x99, 0x62, 0x69, 0x86, 0xa1, 0xa1, 0x6c, 0xf3, 0x00, 0x30, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0xff, 0x6c, 0x49, 0x71, 0x2f, 0x04, 0x4f, 0x40, 0x63, 0xc1, 0x41, 0x25, 0xc0, 0xcd, 0xfb, 0xa1, 0x8e, 0xd8, 0xb7, 0x13, 0x84, 0x53, 0x76, 0x8a, 0x45, 0xdf, 0xa2, 0xd8, 0x2a, 0x05, 0xf1, 0xe8, 0x42, 0x27, }, 34.0,
/* MD */ (const uint8_t []){0x40, 0x32, 0x84, 0xc8, 0x88, 0xa7, 0x28, 0x0b, 0xc8, 0xbf, 0xc2, 0x5f, 0x0c, 0x34, 0x18, 0x2c, 0xd3, 0x78, 0x30, 0x6a, 0x21, 0xa1, 0x40, 0x4d, 0x4e, 0x1c, 0x40, 0xcf, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0xf9, 0x00, 0xbd, 0x7e, 0x01, 0x17, 0x24, 0x7f, 0x97, 0xc8, 0xfc, 0x7a, 0x66, 0x5c, 0x76, 0xa3, 0x5f, 0x57, 0x1c, 0x33, 0x66, 0x57, 0x1d, 0x6c, 0x4a, 0x3e, 0xe5, 0xd7, 0xfb, 0x93, 0xf1, 0xd1, 0xf7, 0x26, 0xe2, }, 35.0,
/* MD */ (const uint8_t []){0x48, 0x23, 0x5b, 0x98, 0x20, 0xd6, 0x6d, 0x88, 0x85, 0xfa, 0xab, 0xf6, 0xa9, 0xed, 0xe6, 0x3b, 0xa2, 0xa2, 0x1b, 0x61, 0x77, 0xe9, 0x87, 0xa3, 0x32, 0x42, 0x37, 0x3e, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x42, 0xd3, 0x81, 0x88, 0xac, 0x49, 0x44, 0x0c, 0xfe, 0xfb, 0x77, 0xdb, 0x97, 0x5e, 0x08, 0x3e, 0x6b, 0x22, 0x34, 0x8c, 0x4c, 0x67, 0xf0, 0xf8, 0x69, 0x2e, 0x88, 0xad, 0x14, 0x0d, 0x86, 0x1d, 0xc8, 0x28, 0xd5, 0x95, }, 36.0,
/* MD */ (const uint8_t []){0x61, 0x53, 0x44, 0xf8, 0x90, 0xe5, 0xbc, 0xf7, 0x1b, 0x5e, 0xfe, 0x39, 0xde, 0x1f, 0xc9, 0x42, 0xba, 0x1f, 0xe3, 0x0d, 0xd9, 0xe9, 0x14, 0x6a, 0xdb, 0x6a, 0x41, 0xbf, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x74, 0xfd, 0xd7, 0xd9, 0x58, 0xb8, 0xae, 0x7c, 0x2c, 0x3c, 0x5c, 0xff, 0x42, 0x66, 0xdf, 0xb2, 0xb3, 0xb8, 0x42, 0xc9, 0xf5, 0x9e, 0xcb, 0xbc, 0xaf, 0xf5, 0x75, 0xed, 0xcb, 0xcd, 0xa0, 0x8c, 0xcd, 0x6e, 0x08, 0xb7, 0x64, }, 37.0,
/* MD */ (const uint8_t []){0x66, 0xd7, 0xd6, 0xc5, 0x4f, 0xc7, 0x77, 0x5a, 0x0b, 0xa8, 0x45, 0xba, 0x3e, 0x11, 0x71, 0x9f, 0xa5, 0x35, 0xb9, 0x28, 0x9f, 0x20, 0xb0, 0x98, 0xc5, 0xf7, 0xa3, 0x42, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x93, 0x44, 0x16, 0xdd, 0x05, 0x81, 0xe2, 0x2f, 0x2b, 0xfb, 0xec, 0xe7, 0xbb, 0x64, 0xaf, 0xe8, 0x20, 0x45, 0x1f, 0xa2, 0x13, 0x42, 0xdf, 0x7e, 0x6f, 0x9f, 0xb3, 0x7c, 0x41, 0x03, 0x38, 0x1a, 0x1f, 0x7c, 0xd3, 0x79, 0xbc, 0xc4, }, 38.0,
/* MD */ (const uint8_t []){0xfa, 0xe8, 0xf1, 0xaa, 0x22, 0xde, 0xf4, 0xdb, 0xaa, 0x81, 0x4c, 0x5b, 0x0b, 0xab, 0xde, 0xc4, 0x33, 0x94, 0x95, 0x17, 0x92, 0xc9, 0x37, 0x05, 0x0d, 0x29, 0x63, 0xa6, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x10, 0x24, 0x01, 0xc8, 0x4a, 0x71, 0x6a, 0xe7, 0x25, 0x79, 0xc6, 0xae, 0x79, 0xc3, 0x59, 0xea, 0x30, 0x9f, 0xfd, 0x95, 0xab, 0xff, 0xae, 0x4c, 0x61, 0x88, 0x4c, 0x03, 0xc9, 0xe9, 0x9d, 0xf7, 0x7b, 0x6c, 0x92, 0xe4, 0x92, 0xca, 0xcb, }, 39.0,
/* MD */ (const uint8_t []){0x8f, 0x34, 0x81, 0x2d, 0x57, 0xa1, 0x6e, 0xf8, 0xa5, 0x1a, 0xd9, 0x87, 0x66, 0x0c, 0x5f, 0x86, 0x23, 0xe0, 0xfa, 0x9d, 0x89, 0x84, 0x6e, 0x28, 0xd4, 0x6d, 0x14, 0xd9, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x79, 0xbc, 0x8f, 0xb6, 0x0f, 0x85, 0xd1, 0x5a, 0x23, 0x86, 0x56, 0x6e, 0x3e, 0x73, 0x14, 0xdf, 0x28, 0x45, 0x33, 0x08, 0x5a, 0xdd, 0x1c, 0x7b, 0xb6, 0xea, 0xd3, 0xff, 0x76, 0x0c, 0x86, 0xd5, 0x63, 0x3a, 0x66, 0x40, 0x47, 0x61, 0xb5, 0x44, }, 40.0,
/* MD */ (const uint8_t []){0x65, 0xc5, 0x40, 0x14, 0xcf, 0xa3, 0x0f, 0x0b, 0xc2, 0x7d, 0x1c, 0x6e, 0xfa, 0x96, 0xae, 0x84, 0x81, 0xf4, 0xc2, 0x50, 0x5b, 0xff, 0x27, 0x29, 0x56, 0xea, 0xb0, 0xdf, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0xdb, 0x31, 0x21, 0xea, 0x71, 0x29, 0x49, 0x83, 0xb1, 0x85, 0x20, 0x7a, 0x9d, 0x8d, 0xe3, 0xe4, 0x84, 0xa6, 0x6c, 0x04, 0x31, 0xbf, 0x07, 0xc9, 0x62, 0xeb, 0x82, 0x97, 0x7c, 0x4f, 0x83, 0x4b, 0x7c, 0x3f, 0x1e, 0x79, 0x31, 0xa4, 0xa7, 0xf7, 0xa9, }, 41.0,
/* MD */ (const uint8_t []){0x93, 0x16, 0xd2, 0xf0, 0x21, 0xc2, 0x91, 0x3d, 0x63, 0xa7, 0xe6, 0x69, 0x24, 0xc8, 0x7c, 0x16, 0x1c, 0x3c, 0xfd, 0xe0, 0xea, 0x7b, 0xa0, 0x7f, 0x54, 0x77, 0x28, 0x62, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x0d, 0xd5, 0x1a, 0xa6, 0x60, 0xc5, 0xcb, 0x4b, 0x7f, 0x78, 0xc4, 0x68, 0x52, 0xc1, 0xdb, 0x87, 0x07, 0xab, 0x45, 0x1c, 0x13, 0x67, 0xb6, 0x18, 0x73, 0x88, 0xc8, 0xbb, 0x38, 0x73, 0xa1, 0xaa, 0x42, 0x10, 0xd0, 0x41, 0x4c, 0xc6, 0x79, 0x2a, 0x29, 0xa7, }, 42.0,
/* MD */ (const uint8_t []){0x31, 0x98, 0x9e, 0x7a, 0x62, 0xa5, 0x13, 0x2a, 0x50, 0x70, 0xd7, 0x72, 0x50, 0xd8, 0x90, 0x4b, 0xb8, 0x2d, 0x45, 0x7d, 0xc6, 0x34, 0x69, 0xd0, 0x6b, 0x50, 0x18, 0x5e, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x48, 0x7f, 0xd2, 0xe5, 0xb6, 0x94, 0xb7, 0x07, 0x1d, 0x37, 0x89, 0xa2, 0x58, 0xa5, 0x1e, 0x86, 0x04, 0xdc, 0x0d, 0x3e, 0x8f, 0x5d, 0x62, 0xf3, 0x91, 0x31, 0x96, 0x8e, 0x60, 0x2a, 0xbe, 0x1d, 0xdf, 0x6b, 0x02, 0x78, 0x96, 0x2a, 0x51, 0x24, 0x08, 0xb5, 0x53, }, 43.0,
/* MD */ (const uint8_t []){0xe7, 0x98, 0x68, 0x34, 0x38, 0x28, 0x46, 0x26, 0xd7, 0x10, 0x87, 0x7d, 0x9e, 0xea, 0x3a, 0x0e, 0x02, 0xf3, 0x49, 0xfc, 0x43, 0xac, 0xb7, 0xf9, 0xf8, 0xf9, 0xe8, 0x1c, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x11, 0x18, 0x3b, 0xde, 0xbf, 0xef, 0x58, 0xe4, 0xda, 0x5b, 0x1c, 0xb7, 0x3b, 0xe0, 0xd3, 0x0b, 0x20, 0xda, 0x30, 0x4d, 0x86, 0x59, 0xd9, 0x21, 0xda, 0x2e, 0x27, 0x0f, 0xd1, 0x46, 0x26, 0x79, 0x95, 0x37, 0xe4, 0xd1, 0x21, 0x19, 0xe8, 0x09, 0xee, 0x97, 0x00, 0x4a, }, 44.0,
/* MD */ (const uint8_t []){0x96, 0x87, 0x06, 0x57, 0xd6, 0xcb, 0x66, 0x8b, 0xe3, 0x99, 0x5a, 0xa8, 0xbd, 0x31, 0xdf, 0x77, 0x84, 0x0d, 0x1d, 0x19, 0x15, 0xd7, 0x24, 0x82, 0xe8, 0x3b, 0x6b, 0x2c, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0xa2, 0x39, 0xde, 0x5c, 0x8e, 0x26, 0x44, 0xe8, 0xf0, 0x30, 0xd9, 0x4d, 0x98, 0xf1, 0xa3, 0x06, 0x64, 0xe6, 0xfd, 0x96, 0x1d, 0xc2, 0x97, 0x7a, 0x9c, 0x08, 0xbe, 0x5c, 0x31, 0xd8, 0xde, 0x89, 0x45, 0x09, 0x45, 0xa5, 0x3d, 0x79, 0x29, 0x9e, 0xa2, 0xa1, 0xed, 0xde, 0x7f, }, 45.0,
/* MD */ (const uint8_t []){0xe9, 0x97, 0x43, 0xd4, 0xfd, 0x26, 0xc8, 0x80, 0x0c, 0x36, 0xa6, 0x7b, 0x67, 0x62, 0x24, 0x7c, 0x29, 0xda, 0x6b, 0x62, 0x79, 0x41, 0x23, 0xc5, 0x9d, 0xe0, 0x6d, 0xc0, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x91, 0x7c, 0x45, 0x77, 0xaa, 0x6b, 0x0f, 0x9d, 0xf4, 0x99, 0x99, 0xfc, 0x1c, 0x95, 0x8c, 0xb0, 0x9b, 0x7f, 0xd5, 0xfc, 0x80, 0xbe, 0x94, 0x96, 0x70, 0xf0, 0x35, 0x45, 0xeb, 0x27, 0xdc, 0xae, 0xd0, 0x52, 0x07, 0x6b, 0x24, 0xf9, 0x6f, 0x5e, 0x0f, 0x2e, 0x2f, 0x45, 0x27, 0xc0, }, 46.0,
/* MD */ (const uint8_t []){0x7e, 0xcd, 0x69, 0x3d, 0x4d, 0x9c, 0xf4, 0x39, 0x29, 0x46, 0x46, 0x98, 0xef, 0xa0, 0xba, 0xc3, 0x3c, 0x2e, 0x14, 0x24, 0xf8, 0x16, 0xed, 0xc7, 0x69, 0x26, 0x09, 0x78, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0xc3, 0xf1, 0xe7, 0x35, 0xa6, 0x74, 0x1a, 0xa4, 0x81, 0xad, 0x57, 0x7a, 0x98, 0xdb, 0xac, 0x1f, 0x03, 0xcc, 0x80, 0xea, 0x0d, 0xae, 0x1b, 0x94, 0xdb, 0x23, 0x69, 0xed, 0x4e, 0x93, 0xfa, 0xcd, 0x29, 0xc6, 0x4e, 0x4e, 0x77, 0xb2, 0x50, 0x38, 0x27, 0x91, 0x20, 0xbd, 0xfa, 0x37, 0x15, }, 47.0,
/* MD */ (const uint8_t []){0x86, 0xf0, 0xd8, 0x9d, 0x8e, 0x14, 0xfd, 0x8b, 0x66, 0x06, 0x41, 0x2d, 0x71, 0xa7, 0xa5, 0x4a, 0x34, 0x7b, 0x30, 0x4e, 0xa5, 0xd4, 0x9c, 0x20, 0x8f, 0x22, 0x66, 0xab, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0xde, 0x4f, 0xbf, 0xd5, 0x53, 0xcd, 0xf3, 0x70, 0x19, 0xf2, 0x5a, 0xfa, 0x82, 0xdc, 0x6b, 0x99, 0x70, 0xf4, 0xbb, 0x1e, 0xbb, 0xc3, 0x7f, 0x80, 0xd3, 0x08, 0x4c, 0x88, 0xa7, 0x07, 0x22, 0xcd, 0xc5, 0x23, 0xa9, 0xe3, 0xc2, 0xaf, 0xba, 0xd0, 0xdc, 0x02, 0x21, 0xbf, 0xde, 0xc9, 0xa2, 0xf9, }, 48.0,
/* MD */ (const uint8_t []){0x4c, 0x52, 0x62, 0xac, 0xb4, 0xa2, 0xa4, 0x4e, 0xaa, 0x9b, 0xc6, 0x75, 0x70, 0x24, 0xfb, 0x20, 0x2e, 0xf4, 0xd5, 0xa7, 0xa1, 0x6f, 0xa3, 0x72, 0x52, 0xa4, 0x22, 0xb5, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0xdb, 0x2e, 0x2e, 0xb6, 0x36, 0x61, 0x0c, 0xf4, 0x2e, 0x9b, 0x33, 0x43, 0x3a, 0xcc, 0xe1, 0xb3, 0xb9, 0x25, 0x94, 0x9f, 0x29, 0x7d, 0xd8, 0x31, 0x99, 0xf4, 0x5d, 0x28, 0x61, 0xd6, 0x4c, 0xd9, 0x10, 0xc2, 0xdb, 0x74, 0xa6, 0x0b, 0x20, 0x89, 0x04, 0x5e, 0x22, 0xcb, 0xa0, 0xa5, 0x36, 0x13, 0x7d, }, 49.0,
/* MD */ (const uint8_t []){0x16, 0xbf, 0x4e, 0x45, 0xbc, 0xdc, 0x60, 0x44, 0x7c, 0x68, 0xdc, 0xb3, 0x0e, 0x6b, 0x08, 0xf5, 0x5c, 0xe9, 0xf4, 0x12, 0x4a, 0x29, 0xcf, 0x1f, 0x9a, 0x9d, 0x06, 0x5d, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0xa8, 0xe7, 0x29, 0xd3, 0x36, 0xd5, 0xd6, 0xac, 0x50, 0xe1, 0xe2, 0x2f, 0x0b, 0x19, 0x3b, 0x66, 0xe2, 0x60, 0x42, 0xfc, 0x64, 0x59, 0x21, 0x41, 0x29, 0x87, 0x5e, 0x74, 0x0a, 0xb2, 0xb1, 0x42, 0x91, 0x8c, 0x13, 0x8a, 0xaf, 0x94, 0x18, 0x63, 0xad, 0x3b, 0x7e, 0x60, 0x65, 0x45, 0x06, 0x13, 0xb2, 0x73, }, 50.0,
/* MD */ (const uint8_t []){0x45, 0x2b, 0xf2, 0xe5, 0xeb, 0xfc, 0x4e, 0x45, 0x1c, 0xc4, 0x34, 0xbc, 0x09, 0xe2, 0xa1, 0x00, 0x32, 0xee, 0xd0, 0xb7, 0x62, 0x7c, 0xf5, 0x5e, 0x7e, 0x5e, 0xd0, 0xe2, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0xd0, 0x53, 0x17, 0xd4, 0xb5, 0x35, 0xf9, 0xd1, 0x0f, 0x73, 0x9d, 0x0c, 0x2d, 0xed, 0xf3, 0xff, 0xb0, 0x90, 0xc1, 0xad, 0x9d, 0x20, 0x50, 0x89, 0xb1, 0x34, 0x66, 0x93, 0xf5, 0x82, 0x73, 0xc4, 0x92, 0x5c, 0x0f, 0xac, 0xe5, 0x7b, 0xa4, 0x5a, 0xd6, 0xfc, 0x68, 0x7c, 0x66, 0xa8, 0x8f, 0xc7, 0x88, 0x78, 0xbe, }, 51.0,
/* MD */ (const uint8_t []){0x4f, 0x03, 0xc4, 0x39, 0xe0, 0x97, 0xb5, 0x1b, 0x00, 0xe3, 0x14, 0xf6, 0x75, 0x93, 0x7c, 0x4d, 0x91, 0x15, 0x05, 0x85, 0x9f, 0xb7, 0xab, 0x16, 0xad, 0xc6, 0x5e, 0x44, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x26, 0xbb, 0x4e, 0xd4, 0xf0, 0x42, 0x4c, 0x60, 0xfe, 0x42, 0x12, 0xff, 0x8c, 0x95, 0x5e, 0x89, 0xe2, 0xf5, 0x53, 0xa7, 0xd7, 0x70, 0x1b, 0xe5, 0x94, 0x16, 0xd2, 0x08, 0x9a, 0xf5, 0x9f, 0xa1, 0x07, 0x47, 0x24, 0xe2, 0x14, 0xe9, 0x19, 0xb1, 0xe3, 0x0f, 0x33, 0xfb, 0x78, 0x37, 0x4b, 0x4b, 0x05, 0x5b, 0xbc, 0x9b, }, 52.0,
/* MD */ (const uint8_t []){0xe7, 0xc8, 0x99, 0xe2, 0x70, 0x09, 0xd4, 0xdc, 0x77, 0xc2, 0xd3, 0x00, 0xf1, 0x91, 0xb7, 0x57, 0xe5, 0x2c, 0x9e, 0x7e, 0xac, 0x4b, 0x02, 0x3b, 0xfa, 0xb2, 0xb5, 0x2a, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0xf0, 0x15, 0xec, 0x83, 0x94, 0x4f, 0x03, 0x29, 0x24, 0x63, 0xc4, 0x34, 0x5f, 0xdb, 0x1c, 0x26, 0xd1, 0xea, 0x07, 0x64, 0x5f, 0xac, 0xbc, 0x95, 0x20, 0xae, 0x24, 0x4b, 0x6e, 0xb1, 0x91, 0xe5, 0x3d, 0xab, 0xad, 0xb4, 0xac, 0x0f, 0xb1, 0x5c, 0xda, 0x4e, 0xd7, 0x7d, 0xfb, 0x9e, 0x11, 0x93, 0xab, 0xfa, 0xfb, 0x1b, 0x81, }, 53.0,
/* MD */ (const uint8_t []){0x45, 0x9e, 0x40, 0xb3, 0xfb, 0xd6, 0x12, 0x91, 0x2f, 0x02, 0x17, 0xc6, 0x00, 0x99, 0x37, 0x9c, 0xe0, 0x77, 0xcd, 0x02, 0x50, 0x58, 0x71, 0xb0, 0xc9, 0xc1, 0x4e, 0x7a, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x07, 0x86, 0x70, 0x6f, 0x68, 0x0c, 0x27, 0xb7, 0x92, 0xd0, 0x54, 0xfa, 0xa6, 0x3f, 0x49, 0x9a, 0x8e, 0x6b, 0x5d, 0xdb, 0x90, 0x50, 0x29, 0x46, 0x23, 0x5b, 0xf7, 0x4c, 0x02, 0x2d, 0x77, 0x2c, 0x80, 0x9c, 0xb4, 0x17, 0x1b, 0xfa, 0x47, 0x91, 0x53, 0x9a, 0xca, 0x1a, 0xbd, 0x91, 0x90, 0x0e, 0x53, 0xba, 0x93, 0xca, 0x0e, 0xfd, }, 54.0,
/* MD */ (const uint8_t []){0xfa, 0xde, 0xba, 0xb7, 0xc3, 0xd0, 0xfb, 0x8e, 0x97, 0xe4, 0x29, 0xb7, 0x90, 0x83, 0x08, 0x77, 0x35, 0xe4, 0xab, 0x38, 0x5a, 0x78, 0x95, 0x21, 0x26, 0x0e, 0xf3, 0xad, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x44, 0x5e, 0x86, 0x98, 0xee, 0xb8, 0xac, 0xcb, 0xaa, 0xc4, 0xff, 0xa7, 0xd9, 0x34, 0xff, 0xfd, 0x16, 0x01, 0x4a, 0x43, 0x0e, 0xf7, 0x0f, 0x3a, 0x91, 0x74, 0xc6, 0xcf, 0xe9, 0x6d, 0x1e, 0x3f, 0x6a, 0xb1, 0x37, 0x7f, 0x4a, 0x72, 0x12, 0xdb, 0xb3, 0x01, 0x46, 0xdd, 0x17, 0xd9, 0xf4, 0x70, 0xc4, 0xdf, 0xfc, 0x45, 0xb8, 0xe8, 0x71, }, 55.0,
/* MD */ (const uint8_t []){0x4c, 0x7a, 0xe0, 0x28, 0xc0, 0xfe, 0x61, 0xf2, 0xa9, 0xca, 0xda, 0x61, 0xfa, 0xe3, 0x06, 0x85, 0xb7, 0x7f, 0x04, 0xc6, 0x44, 0x25, 0x76, 0xe9, 0x12, 0xaf, 0x9f, 0xa6, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x52, 0x83, 0x9f, 0x2f, 0x08, 0x53, 0xa3, 0x0d, 0xf1, 0x4e, 0xc8, 0x97, 0xa1, 0x91, 0x4c, 0x68, 0x5c, 0x1a, 0xc2, 0x14, 0x70, 0xd0, 0x06, 0x54, 0xc8, 0xc3, 0x76, 0x63, 0xbf, 0xb6, 0x5f, 0xa7, 0x32, 0xdb, 0xb6, 0x94, 0xd9, 0xdd, 0x09, 0xce, 0xd7, 0x23, 0xb4, 0x8d, 0x8f, 0x54, 0x58, 0x46, 0xba, 0x16, 0x89, 0x88, 0xb6, 0x1c, 0xc7, 0x24, }, 56.0,
/* MD */ (const uint8_t []){0x2f, 0x75, 0x5a, 0x57, 0x67, 0x4b, 0x49, 0xd5, 0xc2, 0x5c, 0xb3, 0x73, 0x48, 0xf3, 0x5b, 0x6f, 0xd2, 0xde, 0x25, 0x52, 0xc7, 0x49, 0xf2, 0x64, 0x5b, 0xa6, 0x3d, 0x20, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x5f, 0xe8, 0xc2, 0x07, 0x2d, 0x89, 0x00, 0x28, 0x7c, 0xca, 0xf0, 0x7f, 0x3f, 0x66, 0xb0, 0xc2, 0x2a, 0xcd, 0x3e, 0x0b, 0xb9, 0x1d, 0x95, 0x73, 0x75, 0x4e, 0x19, 0xe3, 0x73, 0xac, 0x35, 0x27, 0x1d, 0x8b, 0x43, 0x44, 0x34, 0x36, 0xac, 0x0c, 0x16, 0x28, 0x50, 0xef, 0x3d, 0x7f, 0x28, 0x14, 0x09, 0xad, 0x29, 0xa9, 0xbf, 0x71, 0x6c, 0x77, 0xd1, }, 57.0,
/* MD */ (const uint8_t []){0x42, 0x90, 0x97, 0x57, 0xf6, 0xe2, 0x29, 0xf6, 0x9f, 0x04, 0xcc, 0x7a, 0x86, 0x3c, 0x4e, 0x70, 0xe4, 0x8c, 0x7c, 0x35, 0x75, 0x05, 0x7b, 0x45, 0x5c, 0x95, 0x97, 0x75, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0xe8, 0x06, 0x4d, 0x83, 0xf3, 0xd6, 0x43, 0xaf, 0x87, 0x18, 0xc8, 0x7e, 0x3c, 0xcd, 0x6a, 0x97, 0x33, 0x68, 0x5e, 0xac, 0x61, 0xd5, 0x72, 0xa2, 0x2a, 0xb9, 0x43, 0xf2, 0x32, 0xfc, 0xb0, 0x4f, 0x70, 0x85, 0x8e, 0x89, 0x84, 0x44, 0x9d, 0xb1, 0x4a, 0x76, 0xbb, 0x7e, 0xaf, 0x24, 0x58, 0xef, 0xc3, 0xed, 0x2a, 0x32, 0x10, 0x06, 0x22, 0xc5, 0x2b, 0x7f, }, 58.0,
/* MD */ (const uint8_t []){0x1a, 0x1d, 0x8e, 0xd5, 0x4c, 0xb4, 0x5c, 0x97, 0xbc, 0x97, 0x07, 0x54, 0xb4, 0x3e, 0xb9, 0x3d, 0x9e, 0xab, 0xde, 0x4c, 0x7b, 0x07, 0xf7, 0x6a, 0xd8, 0x2d, 0x8e, 0xde, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x87, 0xc9, 0xa5, 0x17, 0xe2, 0x8d, 0x1b, 0xb5, 0x4a, 0xd2, 0x0f, 0xca, 0x76, 0x46, 0x0e, 0xfd, 0x89, 0x4d, 0x77, 0x86, 0xe6, 0x8e, 0xe8, 0xd7, 0x46, 0xb2, 0xf6, 0x82, 0x08, 0x68, 0x21, 0x57, 0xc8, 0xad, 0x06, 0xcc, 0x32, 0x4a, 0xd7, 0xa3, 0x18, 0x9e, 0x09, 0xc6, 0xc3, 0x9d, 0x4c, 0x76, 0x87, 0x19, 0xc0, 0xa4, 0x9a, 0x41, 0x66, 0x9f, 0x27, 0x67, 0xd5, }, 59.0,
/* MD */ (const uint8_t []){0x60, 0x59, 0x77, 0xcf, 0x87, 0xb9, 0xb3, 0x09, 0xbb, 0xdd, 0xaa, 0xa6, 0x4e, 0x52, 0x8a, 0xce, 0x66, 0xb0, 0x4d, 0xf9, 0xf7, 0x2c, 0x0e, 0x7e, 0xc8, 0x8b, 0xe1, 0xda, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x59, 0xfd, 0xac, 0x3b, 0x6b, 0x32, 0x03, 0x92, 0x91, 0x80, 0x1c, 0x7d, 0x6f, 0x46, 0xed, 0xe8, 0xd2, 0x6d, 0xc5, 0xb7, 0xa1, 0x92, 0xe0, 0x07, 0x11, 0x67, 0x39, 0xb6, 0x17, 0x56, 0x9f, 0x25, 0x23, 0x68, 0x0b, 0x3c, 0x0b, 0x66, 0x31, 0xaf, 0x45, 0x3e, 0x55, 0x80, 0x5a, 0xa7, 0x60, 0xc6, 0x97, 0x08, 0x33, 0xac, 0x06, 0x96, 0x3b, 0xbc, 0x9d, 0xbd, 0x45, 0x5e, }, 60.0,
/* MD */ (const uint8_t []){0xe9, 0xf0, 0xcb, 0x1d, 0xc8, 0x33, 0x7e, 0x90, 0x63, 0x85, 0x89, 0x2f, 0x23, 0x48, 0xa8, 0xba, 0x44, 0x12, 0x31, 0x8e, 0xca, 0xd9, 0xb9, 0x6e, 0x37, 0x11, 0x53, 0x1f, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x30, 0x35, 0x0a, 0x4d, 0xf0, 0xb5, 0x8f, 0xf4, 0x9c, 0x0f, 0xa0, 0x9e, 0x42, 0x6f, 0xcd, 0x70, 0x07, 0xb2, 0x90, 0xc7, 0x60, 0xc8, 0x25, 0xc1, 0x85, 0x5d, 0x9b, 0x00, 0x23, 0xb8, 0x2c, 0xaa, 0x51, 0xe3, 0xca, 0xb4, 0xc6, 0x0c, 0xfa, 0x61, 0x49, 0x2b, 0xe5, 0x05, 0x68, 0xe5, 0xac, 0x0f, 0x6d, 0xb0, 0xfd, 0x46, 0x8e, 0x39, 0xe4, 0x53, 0x64, 0x03, 0xe3, 0x80, 0x9f, }, 61.0,
/* MD */ (const uint8_t []){0x77, 0x6c, 0xc6, 0x63, 0x6c, 0x02, 0x40, 0x8f, 0xbf, 0x65, 0xac, 0xe7, 0x3a, 0xe8, 0x00, 0x17, 0x10, 0x8b, 0x91, 0x7c, 0x16, 0xc5, 0xa9, 0x12, 0xfd, 0x86, 0x02, 0x41, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0xef, 0x79, 0x7a, 0x0d, 0x43, 0xc3, 0x0b, 0x4f, 0xe1, 0x01, 0x4b, 0xdb, 0x94, 0x20, 0x87, 0x9c, 0x2f, 0xf8, 0x45, 0xd2, 0x7e, 0x73, 0xd5, 0x5a, 0x7d, 0xf2, 0x29, 0x30, 0xc8, 0xec, 0xe7, 0x32, 0x53, 0xd8, 0xbb, 0x26, 0x5b, 0x4e, 0xf2, 0xff, 0x9c, 0x69, 0x45, 0x5c, 0xc5, 0x6f, 0xf2, 0x52, 0x29, 0xb4, 0x12, 0x6b, 0xb7, 0xbb, 0x26, 0xee, 0x2c, 0x9f, 0xf3, 0x61, 0x87, 0xb1, }, 62.0,
/* MD */ (const uint8_t []){0xf5, 0xb9, 0xff, 0xb1, 0x02, 0xaf, 0xfa, 0xc3, 0x52, 0xa4, 0xa5, 0x35, 0xa0, 0x0f, 0x89, 0xb0, 0x6c, 0x26, 0x8c, 0xf4, 0x88, 0x1d, 0x71, 0x26, 0x68, 0x90, 0x60, 0x25, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0x71, 0x69, 0x44, 0xde, 0x41, 0x71, 0x0c, 0x29, 0xb6, 0x59, 0xbe, 0x10, 0x48, 0x0b, 0xb2, 0x5a, 0x35, 0x1a, 0x39, 0xe5, 0x77, 0xee, 0x30, 0xe8, 0xf4, 0x22, 0xd5, 0x7c, 0xf6, 0x2a, 0xd9, 0x5b, 0xda, 0x39, 0xb6, 0xe7, 0x0c, 0x61, 0x42, 0x6e, 0x33, 0xfd, 0x84, 0xac, 0xa8, 0x4c, 0xc7, 0x91, 0x2d, 0x5e, 0xee, 0x45, 0xdc, 0x34, 0x07, 0x6a, 0x5d, 0x23, 0x23, 0xa1, 0x5c, 0x79, 0x64, }, 63.0,
/* MD */ (const uint8_t []){0x61, 0x64, 0x5a, 0xc7, 0x48, 0xdb, 0x56, 0x7a, 0xc8, 0x62, 0x79, 0x6b, 0x8d, 0x06, 0xa4, 0x7a, 0xfe, 0xbf, 0xa2, 0xe1, 0x78, 0x3d, 0x5c, 0x5f, 0x3b, 0xcd, 0x81, 0xe2, }, 28.0,
},
{ TEE_ALG_SHA224, 1,
/* Msg */ (const uint8_t []){0xa3, 0x31, 0x0b, 0xa0, 0x64, 0xbe, 0x2e, 0x14, 0xad, 0x32, 0x27, 0x6e, 0x18, 0xcd, 0x03, 0x10, 0xc9, 0x33, 0xa6, 0xe6, 0x50, 0xc3, 0xc7, 0x54, 0xd0, 0x24, 0x3c, 0x6c, 0x61, 0x20, 0x78, 0x65, 0xb4, 0xb6, 0x52, 0x48, 0xf6, 0x6a, 0x08, 0xed, 0xf6, 0xe0, 0x83, 0x26, 0x89, 0xa9, 0xdc, 0x3a, 0x2e, 0x5d, 0x20, 0x95, 0xee, 0xea, 0x50, 0xbd, 0x86, 0x2b, 0xac, 0x88, 0xc8, 0xbd, 0x31, 0x8d, }, 64.0,
/* MD */ (const uint8_t []){0xb2, 0xa5, 0x58, 0x6d, 0x9c, 0xbf, 0x0b, 0xaa, 0x99, 0x91, 0x57, 0xb4, 0xaf, 0x06, 0xd8, 0x8a, 0xe0, 0x8d, 0x7c, 0x9f, 0xaa, 0xb4, 0xbc, 0x1a, 0x96, 0x82, 0x9d, 0x65, }, 28.0,
},
