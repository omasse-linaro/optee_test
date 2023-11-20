// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023, Linaro Limited
 * All rights reserved.
 */

{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x36, }, 1.0,
/* MD */ (const uint8_t []){0xc1, 0xdf, 0xd9, 0x6e, 0xea, 0x8c, 0xc2, 0xb6, 0x27, 0x85, 0x27, 0x5b, 0xca, 0x38, 0xac, 0x26, 0x12, 0x56, 0xe2, 0x78, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x19, 0x5a, }, 2.0,
/* MD */ (const uint8_t []){0x0a, 0x1c, 0x2d, 0x55, 0x5b, 0xbe, 0x43, 0x1a, 0xd6, 0x28, 0x8a, 0xf5, 0xa5, 0x4f, 0x93, 0xe0, 0x44, 0x9c, 0x92, 0x32, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0xdf, 0x4b, 0xd2, }, 3.0,
/* MD */ (const uint8_t []){0xbf, 0x36, 0xed, 0x5d, 0x74, 0x72, 0x7d, 0xfd, 0x5d, 0x78, 0x54, 0xec, 0x6b, 0x1d, 0x49, 0x46, 0x8d, 0x8e, 0xe8, 0xaa, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x54, 0x9e, 0x95, 0x9e, }, 4.0,
/* MD */ (const uint8_t []){0xb7, 0x8b, 0xae, 0x6d, 0x14, 0x33, 0x8f, 0xfc, 0xcf, 0xd5, 0xd5, 0xb5, 0x67, 0x4a, 0x27, 0x5f, 0x6e, 0xf9, 0xc7, 0x17, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0xf7, 0xfb, 0x1b, 0xe2, 0x05, }, 5.0,
/* MD */ (const uint8_t []){0x60, 0xb7, 0xd5, 0xbb, 0x56, 0x0a, 0x1a, 0xcf, 0x6f, 0xa4, 0x57, 0x21, 0xbd, 0x0a, 0xbb, 0x41, 0x9a, 0x84, 0x1a, 0x89, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0xc0, 0xe5, 0xab, 0xea, 0xea, 0x63, }, 6.0,
/* MD */ (const uint8_t []){0xa6, 0xd3, 0x38, 0x45, 0x97, 0x80, 0xc0, 0x83, 0x63, 0x09, 0x0f, 0xd8, 0xfc, 0x7d, 0x28, 0xdc, 0x80, 0xe8, 0xe0, 0x1f, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x63, 0xbf, 0xc1, 0xed, 0x7f, 0x78, 0xab, }, 7.0,
/* MD */ (const uint8_t []){0x86, 0x03, 0x28, 0xd8, 0x05, 0x09, 0x50, 0x0c, 0x17, 0x83, 0x16, 0x9e, 0xbf, 0x0b, 0xa0, 0xc4, 0xb9, 0x4d, 0xa5, 0xe5, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x7e, 0x3d, 0x7b, 0x3e, 0xad, 0xa9, 0x88, 0x66, }, 8.0,
/* MD */ (const uint8_t []){0x24, 0xa2, 0xc3, 0x4b, 0x97, 0x63, 0x05, 0x27, 0x7c, 0xe5, 0x8c, 0x2f, 0x42, 0xd5, 0x09, 0x20, 0x31, 0x57, 0x25, 0x20, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x9e, 0x61, 0xe5, 0x5d, 0x9e, 0xd3, 0x7b, 0x1c, 0x20, }, 9.0,
/* MD */ (const uint8_t []){0x41, 0x1c, 0xce, 0xe1, 0xf6, 0xe3, 0x67, 0x7d, 0xf1, 0x26, 0x98, 0x41, 0x1e, 0xb0, 0x9d, 0x3f, 0xf5, 0x80, 0xaf, 0x97, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x97, 0x77, 0xcf, 0x90, 0xdd, 0x7c, 0x7e, 0x86, 0x35, 0x06, }, 10.0,
/* MD */ (const uint8_t []){0x05, 0xc9, 0x15, 0xb5, 0xed, 0x4e, 0x4c, 0x4a, 0xff, 0xfc, 0x20, 0x29, 0x61, 0xf3, 0x17, 0x43, 0x71, 0xe9, 0x0b, 0x5c, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x4e, 0xb0, 0x8c, 0x9e, 0x68, 0x3c, 0x94, 0xbe, 0xa0, 0x0d, 0xfa, }, 11.0,
/* MD */ (const uint8_t []){0xaf, 0x32, 0x0b, 0x42, 0xd7, 0x78, 0x5c, 0xa6, 0xc8, 0xdd, 0x22, 0x04, 0x63, 0xbe, 0x23, 0xa2, 0xd2, 0xcb, 0x5a, 0xfc, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x09, 0x38, 0xf2, 0xe2, 0xeb, 0xb6, 0x4f, 0x8a, 0xf8, 0xbb, 0xfc, 0x91, }, 12.0,
/* MD */ (const uint8_t []){0x9f, 0x4e, 0x66, 0xb6, 0xce, 0xea, 0x40, 0xdc, 0xf4, 0xb9, 0x16, 0x6c, 0x28, 0xf1, 0xc8, 0x84, 0x74, 0x14, 0x1d, 0xa9, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x74, 0xc9, 0x99, 0x6d, 0x14, 0xe8, 0x7d, 0x3e, 0x6c, 0xbe, 0xa7, 0x02, 0x9d, }, 13.0,
/* MD */ (const uint8_t []){0xe6, 0xc4, 0x36, 0x3c, 0x08, 0x52, 0x95, 0x19, 0x91, 0x05, 0x7f, 0x40, 0xde, 0x27, 0xec, 0x08, 0x90, 0x46, 0x6f, 0x01, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x51, 0xdc, 0xa5, 0xc0, 0xf8, 0xe5, 0xd4, 0x95, 0x96, 0xf3, 0x2d, 0x3e, 0xb8, 0x74, }, 14.0,
/* MD */ (const uint8_t []){0x04, 0x6a, 0x7b, 0x39, 0x6c, 0x01, 0x37, 0x9a, 0x68, 0x4a, 0x89, 0x45, 0x58, 0x77, 0x9b, 0x07, 0xd8, 0xc7, 0xda, 0x20, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x3a, 0x36, 0xea, 0x49, 0x68, 0x48, 0x20, 0xa2, 0xad, 0xc7, 0xfc, 0x41, 0x75, 0xba, 0x78, }, 15.0,
/* MD */ (const uint8_t []){0xd5, 0x8a, 0x26, 0x2e, 0xe7, 0xb6, 0x57, 0x7c, 0x07, 0x22, 0x8e, 0x71, 0xae, 0x9b, 0x3e, 0x04, 0xc8, 0xab, 0xcd, 0xa9, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x35, 0x52, 0x69, 0x4c, 0xdf, 0x66, 0x3f, 0xd9, 0x4b, 0x22, 0x47, 0x47, 0xac, 0x40, 0x6a, 0xaf, }, 16.0,
/* MD */ (const uint8_t []){0xa1, 0x50, 0xde, 0x92, 0x74, 0x54, 0x20, 0x2d, 0x94, 0xe6, 0x56, 0xde, 0x4c, 0x7c, 0x0c, 0xa6, 0x91, 0xde, 0x95, 0x5d, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0xf2, 0x16, 0xa1, 0xcb, 0xde, 0x24, 0x46, 0xb1, 0xed, 0xf4, 0x1e, 0x93, 0x48, 0x1d, 0x33, 0xe2, 0xed, }, 17.0,
/* MD */ (const uint8_t []){0x35, 0xa4, 0xb3, 0x9f, 0xef, 0x56, 0x0e, 0x7e, 0xa6, 0x12, 0x46, 0x67, 0x6e, 0x1b, 0x7e, 0x13, 0xd5, 0x87, 0xbe, 0x30, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0xa3, 0xcf, 0x71, 0x4b, 0xf1, 0x12, 0x64, 0x7e, 0x72, 0x7e, 0x8c, 0xfd, 0x46, 0x49, 0x9a, 0xcd, 0x35, 0xa6, }, 18.0,
/* MD */ (const uint8_t []){0x7c, 0xe6, 0x9b, 0x1a, 0xcd, 0xce, 0x52, 0xea, 0x7d, 0xbd, 0x38, 0x25, 0x31, 0xfa, 0x1a, 0x83, 0xdf, 0x13, 0xca, 0xe7, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x14, 0x8d, 0xe6, 0x40, 0xf3, 0xc1, 0x15, 0x91, 0xa6, 0xf8, 0xc5, 0xc4, 0x86, 0x32, 0xc5, 0xfb, 0x79, 0xd3, 0xb7, }, 19.0,
/* MD */ (const uint8_t []){0xb4, 0x7b, 0xe2, 0xc6, 0x41, 0x24, 0xfa, 0x9a, 0x12, 0x4a, 0x88, 0x7a, 0xf9, 0x55, 0x1a, 0x74, 0x35, 0x4c, 0xa4, 0x11, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x63, 0xa3, 0xcc, 0x83, 0xfd, 0x1e, 0xc1, 0xb6, 0x68, 0x0e, 0x99, 0x74, 0xa0, 0x51, 0x4e, 0x1a, 0x9e, 0xce, 0xbb, 0x6a, }, 20.0,
/* MD */ (const uint8_t []){0x8b, 0xb8, 0xc0, 0xd8, 0x15, 0xa9, 0xc6, 0x8a, 0x1d, 0x29, 0x10, 0xf3, 0x9d, 0x94, 0x26, 0x03, 0xd8, 0x07, 0xfb, 0xcc, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x87, 0x5a, 0x90, 0x90, 0x9a, 0x8a, 0xfc, 0x92, 0xfb, 0x70, 0x70, 0x04, 0x7e, 0x9d, 0x08, 0x1e, 0xc9, 0x2f, 0x3d, 0x08, 0xb8, }, 21.0,
/* MD */ (const uint8_t []){0xb4, 0x86, 0xf8, 0x7f, 0xb8, 0x33, 0xeb, 0xf0, 0x32, 0x83, 0x93, 0x12, 0x86, 0x46, 0xa6, 0xf6, 0xe6, 0x60, 0xfc, 0xb1, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x44, 0x4b, 0x25, 0xf9, 0xc9, 0x25, 0x9d, 0xc2, 0x17, 0x77, 0x2c, 0xc4, 0x47, 0x8c, 0x44, 0xb6, 0xfe, 0xff, 0x62, 0x35, 0x36, 0x73, }, 22.0,
/* MD */ (const uint8_t []){0x76, 0x15, 0x93, 0x68, 0xf9, 0x9d, 0xec, 0xe3, 0x0a, 0xad, 0xcf, 0xb9, 0xb7, 0xb4, 0x1d, 0xab, 0x33, 0x68, 0x88, 0x58, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x48, 0x73, 0x51, 0xc8, 0xa5, 0xf4, 0x40, 0xe4, 0xd0, 0x33, 0x86, 0x48, 0x3d, 0x5f, 0xe7, 0xbb, 0x66, 0x9d, 0x41, 0xad, 0xcb, 0xfd, 0xb7, }, 23.0,
/* MD */ (const uint8_t []){0xdb, 0xc1, 0xcb, 0x57, 0x5c, 0xe6, 0xae, 0xb9, 0xdc, 0x4e, 0xbf, 0x0f, 0x84, 0x3b, 0xa8, 0xae, 0xb1, 0x45, 0x1e, 0x89, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x46, 0xb0, 0x61, 0xef, 0x13, 0x2b, 0x87, 0xf6, 0xd3, 0xb0, 0xee, 0x24, 0x62, 0xf6, 0x7d, 0x91, 0x09, 0x77, 0xda, 0x20, 0xae, 0xd1, 0x37, 0x05, }, 24.0,
/* MD */ (const uint8_t []){0xd7, 0xa9, 0x82, 0x89, 0x67, 0x90, 0x05, 0xeb, 0x93, 0x0a, 0xb7, 0x5e, 0xfd, 0x8f, 0x65, 0x0f, 0x99, 0x1e, 0xe9, 0x52, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x38, 0x42, 0xb6, 0x13, 0x7b, 0xb9, 0xd2, 0x7f, 0x3c, 0xa5, 0xba, 0xfe, 0x5b, 0xbb, 0x62, 0x85, 0x83, 0x44, 0xfe, 0x4b, 0xa5, 0xc4, 0x15, 0x89, 0xa5, }, 25.0,
/* MD */ (const uint8_t []){0xfd, 0xa2, 0x6f, 0xa9, 0xb4, 0x87, 0x4a, 0xb7, 0x01, 0xed, 0x0b, 0xb6, 0x4d, 0x13, 0x4f, 0x89, 0xb9, 0xc4, 0xcc, 0x50, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x44, 0xd9, 0x1d, 0x3d, 0x46, 0x5a, 0x41, 0x11, 0x46, 0x2b, 0xa0, 0xc7, 0xec, 0x22, 0x3d, 0xa6, 0x73, 0x5f, 0x4f, 0x52, 0x00, 0x45, 0x3c, 0xf1, 0x32, 0xc3, }, 26.0,
/* MD */ (const uint8_t []){0xc2, 0xff, 0x7c, 0xcd, 0xe1, 0x43, 0xc8, 0xf0, 0x60, 0x1f, 0x69, 0x74, 0xb1, 0x90, 0x3e, 0xb8, 0xd5, 0x74, 0x1b, 0x6e, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0xcc, 0xe7, 0x3f, 0x2e, 0xab, 0xcb, 0x52, 0xf7, 0x85, 0xd5, 0xa6, 0xdf, 0x63, 0xc0, 0xa1, 0x05, 0xf3, 0x4a, 0x91, 0xca, 0x23, 0x7f, 0xe5, 0x34, 0xee, 0x39, 0x9d, }, 27.0,
/* MD */ (const uint8_t []){0x64, 0x3c, 0x9d, 0xc2, 0x0a, 0x92, 0x96, 0x08, 0xf6, 0xca, 0xa9, 0x70, 0x9d, 0x84, 0x3c, 0xa6, 0xfa, 0x7a, 0x76, 0xf4, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x66, 0x4e, 0x6e, 0x79, 0x46, 0x83, 0x92, 0x03, 0x03, 0x7a, 0x65, 0xa1, 0x21, 0x74, 0xb2, 0x44, 0xde, 0x8c, 0xbc, 0x6e, 0xc3, 0xf5, 0x78, 0x96, 0x7a, 0x84, 0xf9, 0xce, }, 28.0,
/* MD */ (const uint8_t []){0x50, 0x9e, 0xf7, 0x87, 0x34, 0x3d, 0x5b, 0x5a, 0x26, 0x92, 0x29, 0xb9, 0x61, 0xb9, 0x62, 0x41, 0x86, 0x4a, 0x3d, 0x74, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x95, 0x97, 0xf7, 0x14, 0xb2, 0xe4, 0x5e, 0x33, 0x99, 0xa7, 0xf0, 0x2a, 0xec, 0x44, 0x92, 0x1b, 0xd7, 0x8b, 0xe0, 0xfe, 0xfe, 0xe0, 0xc5, 0xe9, 0xb4, 0x99, 0x48, 0x8f, 0x6e, }, 29.0,
/* MD */ (const uint8_t []){0xb6, 0x1c, 0xe5, 0x38, 0xf1, 0xa1, 0xe6, 0xc9, 0x04, 0x32, 0xb2, 0x33, 0xd7, 0xaf, 0x5b, 0x65, 0x24, 0xeb, 0xfb, 0xe3, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x75, 0xc5, 0xad, 0x1f, 0x3c, 0xbd, 0x22, 0xe8, 0xa9, 0x5f, 0xc3, 0xb0, 0x89, 0x52, 0x67, 0x88, 0xfb, 0x4e, 0xbc, 0xee, 0xd3, 0xe7, 0xd4, 0x44, 0x3d, 0xa6, 0xe0, 0x81, 0xa3, 0x5e, }, 30.0,
/* MD */ (const uint8_t []){0x5b, 0x7b, 0x94, 0x07, 0x6b, 0x2f, 0xc2, 0x0d, 0x6a, 0xdb, 0x82, 0x47, 0x9e, 0x6b, 0x28, 0xd0, 0x7c, 0x90, 0x2b, 0x75, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0xdd, 0x24, 0x5b, 0xff, 0xe6, 0xa6, 0x38, 0x80, 0x66, 0x67, 0x76, 0x83, 0x60, 0xa9, 0x5d, 0x05, 0x74, 0xe1, 0xa0, 0xbd, 0x0d, 0x18, 0x32, 0x9f, 0xdb, 0x91, 0x5c, 0xa4, 0x84, 0xac, 0x0d, }, 31.0,
/* MD */ (const uint8_t []){0x60, 0x66, 0xdb, 0x99, 0xfc, 0x35, 0x89, 0x52, 0xcf, 0x7f, 0xb0, 0xec, 0x4d, 0x89, 0xcb, 0x01, 0x58, 0xed, 0x91, 0xd7, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x03, 0x21, 0x79, 0x4b, 0x73, 0x94, 0x18, 0xc2, 0x4e, 0x7c, 0x2e, 0x56, 0x52, 0x74, 0x79, 0x1c, 0x4b, 0xe7, 0x49, 0x75, 0x2a, 0xd2, 0x34, 0xed, 0x56, 0xcb, 0x0a, 0x63, 0x47, 0x43, 0x0c, 0x6b, }, 32.0,
/* MD */ (const uint8_t []){0xb8, 0x99, 0x62, 0xc9, 0x4d, 0x60, 0xf6, 0xa3, 0x32, 0xfd, 0x60, 0xf6, 0xf0, 0x7d, 0x4f, 0x03, 0x2a, 0x58, 0x6b, 0x76, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x4c, 0x3d, 0xcf, 0x95, 0xc2, 0xf0, 0xb5, 0x25, 0x8c, 0x65, 0x1f, 0xcd, 0x1d, 0x51, 0xbd, 0x10, 0x42, 0x5d, 0x62, 0x03, 0x06, 0x7d, 0x07, 0x48, 0xd3, 0x7d, 0x13, 0x40, 0xd9, 0xdd, 0xda, 0x7d, 0xb3, }, 33.0,
/* MD */ (const uint8_t []){0x17, 0xbd, 0xa8, 0x99, 0xc1, 0x3d, 0x35, 0x41, 0x3d, 0x25, 0x46, 0x21, 0x2b, 0xcd, 0x8a, 0x93, 0xce, 0xb0, 0x65, 0x7b, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0xb8, 0xd1, 0x25, 0x82, 0xd2, 0x5b, 0x45, 0x29, 0x0a, 0x6e, 0x1b, 0xb9, 0x5d, 0xa4, 0x29, 0xbe, 0xfc, 0xfd, 0xbf, 0x5b, 0x4d, 0xd4, 0x1c, 0xdf, 0x33, 0x11, 0xd6, 0x98, 0x8f, 0xa1, 0x7c, 0xec, 0x07, 0x23, }, 34.0,
/* MD */ (const uint8_t []){0xba, 0xdc, 0xdd, 0x53, 0xfd, 0xc1, 0x44, 0xb8, 0xbf, 0x2c, 0xc1, 0xe6, 0x4d, 0x10, 0xf6, 0x76, 0xee, 0xbe, 0x66, 0xed, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x6f, 0xda, 0x97, 0x52, 0x7a, 0x66, 0x25, 0x52, 0xbe, 0x15, 0xef, 0xae, 0xba, 0x32, 0xa3, 0xae, 0xa4, 0xed, 0x44, 0x9a, 0xbb, 0x5c, 0x1e, 0xd8, 0xd9, 0xbf, 0xff, 0x54, 0x47, 0x08, 0xa4, 0x25, 0xd6, 0x9b, 0x72, }, 35.0,
/* MD */ (const uint8_t []){0x01, 0xb4, 0x64, 0x61, 0x80, 0xf1, 0xf6, 0xd2, 0xe0, 0x6b, 0xbe, 0x22, 0xc2, 0x0e, 0x50, 0x03, 0x03, 0x22, 0x67, 0x3a, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x09, 0xfa, 0x27, 0x92, 0xac, 0xbb, 0x24, 0x17, 0xe8, 0xed, 0x26, 0x90, 0x41, 0xcc, 0x03, 0xc7, 0x70, 0x06, 0x46, 0x6e, 0x6e, 0x7a, 0xe0, 0x02, 0xcf, 0x3f, 0x1a, 0xf5, 0x51, 0xe8, 0xce, 0x0b, 0xb5, 0x06, 0xd7, 0x05, }, 36.0,
/* MD */ (const uint8_t []){0x10, 0x01, 0x6d, 0xc3, 0xa2, 0x71, 0x9f, 0x90, 0x34, 0xff, 0xcc, 0x68, 0x94, 0x26, 0xd2, 0x82, 0x92, 0xc4, 0x2f, 0xc9, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x5e, 0xfa, 0x29, 0x87, 0xda, 0x0b, 0xaf, 0x0a, 0x54, 0xd8, 0xd7, 0x28, 0x79, 0x2b, 0xcf, 0xa7, 0x07, 0xa1, 0x57, 0x98, 0xdc, 0x66, 0x74, 0x37, 0x54, 0x40, 0x69, 0x14, 0xd1, 0xcf, 0xe3, 0x70, 0x9b, 0x13, 0x74, 0xea, 0xeb, }, 37.0,
/* MD */ (const uint8_t []){0x9f, 0x42, 0xfa, 0x2b, 0xce, 0x6e, 0xf0, 0x21, 0xd9, 0x3c, 0x6b, 0x2d, 0x90, 0x22, 0x73, 0x79, 0x7e, 0x42, 0x65, 0x35, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x28, 0x36, 0xde, 0x99, 0xc0, 0xf6, 0x41, 0xcd, 0x55, 0xe8, 0x9f, 0x5a, 0xf7, 0x66, 0x38, 0x94, 0x7b, 0x82, 0x27, 0x37, 0x7e, 0xf8, 0x8b, 0xfb, 0xa6, 0x62, 0xe5, 0x68, 0x2b, 0xab, 0xc1, 0xec, 0x96, 0xc6, 0x99, 0x2b, 0xc9, 0xa0, }, 38.0,
/* MD */ (const uint8_t []){0xcd, 0xf4, 0x8b, 0xac, 0xbf, 0xf6, 0xf6, 0x15, 0x25, 0x15, 0x32, 0x3f, 0x9b, 0x43, 0xa2, 0x86, 0xe0, 0xcb, 0x81, 0x13, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x42, 0x14, 0x3a, 0x2b, 0x9e, 0x1d, 0x0b, 0x35, 0x4d, 0xf3, 0x26, 0x4d, 0x08, 0xf7, 0xb6, 0x02, 0xf5, 0x4a, 0xad, 0x92, 0x2a, 0x3d, 0x63, 0x00, 0x6d, 0x09, 0x7f, 0x68, 0x3d, 0xc1, 0x1b, 0x90, 0x17, 0x84, 0x23, 0xbf, 0xf2, 0xf7, 0xfe, }, 39.0,
/* MD */ (const uint8_t []){0xb8, 0x8f, 0xb7, 0x52, 0x74, 0xb9, 0xb0, 0xfd, 0x57, 0xc0, 0x04, 0x59, 0x88, 0xcf, 0xce, 0xf6, 0xc3, 0xce, 0x65, 0x54, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0xeb, 0x60, 0xc2, 0x8a, 0xd8, 0xae, 0xda, 0x80, 0x7d, 0x69, 0xeb, 0xc8, 0x75, 0x52, 0x02, 0x4a, 0xd8, 0xac, 0xa6, 0x82, 0x04, 0xf1, 0xbc, 0xd2, 0x9d, 0xc5, 0xa8, 0x1d, 0xd2, 0x28, 0xb5, 0x91, 0xe2, 0xef, 0xb7, 0xc4, 0xdf, 0x75, 0xef, 0x03, }, 40.0,
/* MD */ (const uint8_t []){0xc0, 0x6d, 0x3a, 0x6a, 0x12, 0xd9, 0xe8, 0xdb, 0x62, 0xe8, 0xcf, 0xf4, 0x0c, 0xa2, 0x38, 0x20, 0xd6, 0x1d, 0x8a, 0xa7, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x7d, 0xe4, 0xba, 0x85, 0xec, 0x54, 0x74, 0x7c, 0xdc, 0x42, 0xb1, 0xf2, 0x35, 0x46, 0xb7, 0xe4, 0x90, 0xe3, 0x12, 0x80, 0xf0, 0x66, 0xe5, 0x2f, 0xac, 0x11, 0x7f, 0xd3, 0xb0, 0x79, 0x2e, 0x4d, 0xe6, 0x2d, 0x58, 0x43, 0xee, 0x98, 0xc7, 0x20, 0x15, }, 41.0,
/* MD */ (const uint8_t []){0x6e, 0x40, 0xf9, 0xe8, 0x3a, 0x4b, 0xe9, 0x38, 0x74, 0xbc, 0x97, 0xcd, 0xeb, 0xb8, 0xda, 0x68, 0x89, 0xae, 0x2c, 0x7a, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0xe7, 0x06, 0x53, 0x63, 0x7b, 0xc5, 0xe3, 0x88, 0xcc, 0xd8, 0xdc, 0x44, 0xe5, 0xea, 0xce, 0x36, 0xf7, 0x39, 0x8f, 0x2b, 0xac, 0x99, 0x30, 0x42, 0xb9, 0xbc, 0x2f, 0x4f, 0xb3, 0xb0, 0xee, 0x7e, 0x23, 0xa9, 0x64, 0x39, 0xdc, 0x01, 0x13, 0x4b, 0x8c, 0x7d, }, 42.0,
/* MD */ (const uint8_t []){0x3e, 0xfc, 0x94, 0x0c, 0x31, 0x2e, 0xf0, 0xdf, 0xd4, 0xe1, 0x14, 0x38, 0x12, 0x24, 0x8d, 0xb8, 0x95, 0x42, 0xf6, 0xa5, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0xdd, 0x37, 0xbc, 0x9f, 0x0b, 0x3a, 0x47, 0x88, 0xf9, 0xb5, 0x49, 0x66, 0xf2, 0x52, 0x17, 0x4c, 0x8c, 0xe4, 0x87, 0xcb, 0xe5, 0x9c, 0x53, 0xc2, 0x2b, 0x81, 0xbf, 0x77, 0x62, 0x1a, 0x7c, 0xe7, 0x61, 0x6d, 0xcb, 0x5b, 0x1e, 0x2e, 0xe6, 0x3c, 0x2c, 0x30, 0x9b, }, 43.0,
/* MD */ (const uint8_t []){0xa0, 0xcf, 0x03, 0xf7, 0xba, 0xdd, 0x0c, 0x3c, 0x3c, 0x4e, 0xa3, 0x71, 0x7f, 0x5a, 0x4f, 0xb7, 0xe6, 0x7b, 0x2e, 0x56, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x5f, 0x48, 0x5c, 0x63, 0x7a, 0xe3, 0x0b, 0x1e, 0x30, 0x49, 0x7f, 0x0f, 0xb7, 0xec, 0x36, 0x4e, 0x13, 0xc9, 0x06, 0xe2, 0x81, 0x3d, 0xaa, 0x34, 0x16, 0x1b, 0x7a, 0xc4, 0xa4, 0xfd, 0x7a, 0x1b, 0xdd, 0xd7, 0x96, 0x01, 0xbb, 0xd2, 0x2c, 0xef, 0x1f, 0x57, 0xcb, 0xc7, }, 44.0,
/* MD */ (const uint8_t []){0xa5, 0x44, 0xe0, 0x6f, 0x1a, 0x07, 0xce, 0xb1, 0x75, 0xa5, 0x1d, 0x6d, 0x9c, 0x01, 0x11, 0xb3, 0xe1, 0x5e, 0x98, 0x59, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0xf6, 0xc2, 0x37, 0xfb, 0x3c, 0xfe, 0x95, 0xec, 0x84, 0x14, 0xcc, 0x16, 0xd2, 0x03, 0xb4, 0x87, 0x4e, 0x64, 0x4c, 0xc9, 0xa5, 0x43, 0x46, 0x5c, 0xad, 0x2d, 0xc5, 0x63, 0x48, 0x8a, 0x65, 0x9e, 0x8a, 0x2e, 0x7c, 0x98, 0x1e, 0x2a, 0x9f, 0x22, 0xe5, 0xe8, 0x68, 0xff, 0xe1, }, 45.0,
/* MD */ (const uint8_t []){0x19, 0x9d, 0x98, 0x6e, 0xd9, 0x91, 0xb9, 0x9a, 0x07, 0x1f, 0x45, 0x0c, 0x6b, 0x11, 0x21, 0xa7, 0x27, 0xe8, 0xc7, 0x35, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0xda, 0x7a, 0xb3, 0x29, 0x15, 0x53, 0xc6, 0x59, 0x87, 0x3c, 0x95, 0x91, 0x37, 0x68, 0x95, 0x3c, 0x6e, 0x52, 0x6d, 0x3a, 0x26, 0x59, 0x08, 0x98, 0xc0, 0xad, 0xe8, 0x9f, 0xf5, 0x6f, 0xbd, 0x11, 0x0f, 0x14, 0x36, 0xaf, 0x59, 0x0b, 0x17, 0xfe, 0xd4, 0x9f, 0x8c, 0x4b, 0x2b, 0x1e, }, 46.0,
/* MD */ (const uint8_t []){0x33, 0xba, 0xc6, 0x10, 0x4b, 0x0a, 0xd6, 0x12, 0x8d, 0x09, 0x1b, 0x5d, 0x5e, 0x29, 0x99, 0x09, 0x9c, 0x9f, 0x05, 0xde, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x8c, 0xfa, 0x5f, 0xd5, 0x6e, 0xe2, 0x39, 0xca, 0x47, 0x73, 0x75, 0x91, 0xcb, 0xa1, 0x03, 0xe4, 0x1a, 0x18, 0xac, 0xf8, 0xe8, 0xd2, 0x57, 0xb0, 0xdb, 0xe8, 0x85, 0x11, 0x34, 0xa8, 0x1f, 0xf6, 0xb2, 0xe9, 0x71, 0x04, 0xb3, 0x9b, 0x76, 0xe1, 0x9d, 0xa2, 0x56, 0xa1, 0x7c, 0xe5, 0x2d, }, 47.0,
/* MD */ (const uint8_t []){0x76, 0xd7, 0xdb, 0x6e, 0x18, 0xc1, 0xf4, 0xae, 0x22, 0x5c, 0xe8, 0xcc, 0xc9, 0x3c, 0x8f, 0x9a, 0x0d, 0xfe, 0xb9, 0x69, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x57, 0xe8, 0x96, 0x59, 0xd8, 0x78, 0xf3, 0x60, 0xaf, 0x6d, 0xe4, 0x5a, 0x9a, 0x5e, 0x37, 0x2e, 0xf4, 0x0c, 0x38, 0x49, 0x88, 0xe8, 0x26, 0x40, 0xa3, 0xd5, 0xe4, 0xb7, 0x6d, 0x2e, 0xf1, 0x81, 0x78, 0x0b, 0x9a, 0x09, 0x9a, 0xc0, 0x6e, 0xf0, 0xf8, 0xa7, 0xf3, 0xf7, 0x64, 0x20, 0x97, 0x20, }, 48.0,
/* MD */ (const uint8_t []){0xf6, 0x52, 0xf3, 0xb1, 0x54, 0x9f, 0x16, 0x71, 0x0c, 0x74, 0x02, 0x89, 0x59, 0x11, 0xe2, 0xb8, 0x6a, 0x9b, 0x2a, 0xee, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0xb9, 0x1e, 0x64, 0x23, 0x5d, 0xbd, 0x23, 0x4e, 0xea, 0x2a, 0xe1, 0x4a, 0x92, 0xa1, 0x73, 0xeb, 0xe8, 0x35, 0x34, 0x72, 0x39, 0xcf, 0xf8, 0xb0, 0x20, 0x74, 0x41, 0x6f, 0x55, 0xc6, 0xb6, 0x0d, 0xc6, 0xce, 0xd0, 0x6a, 0xe9, 0xf8, 0xd7, 0x05, 0x50, 0x5f, 0x0d, 0x61, 0x7e, 0x4b, 0x29, 0xae, 0xf9, }, 49.0,
/* MD */ (const uint8_t []){0x63, 0xfa, 0xeb, 0xb8, 0x07, 0xf3, 0x2b, 0xe7, 0x08, 0xcf, 0x00, 0xfc, 0x35, 0x51, 0x99, 0x91, 0xdc, 0x4e, 0x7f, 0x68, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0xe4, 0x2a, 0x67, 0x36, 0x2a, 0x58, 0x1e, 0x8c, 0xf3, 0xd8, 0x47, 0x50, 0x22, 0x15, 0x75, 0x5d, 0x7a, 0xd4, 0x25, 0xca, 0x03, 0x0c, 0x43, 0x60, 0xb0, 0xf7, 0xef, 0x51, 0x3e, 0x69, 0x80, 0x26, 0x5f, 0x61, 0xc9, 0xfa, 0x18, 0xdd, 0x9c, 0xe6, 0x68, 0xf3, 0x8d, 0xbc, 0x2a, 0x1e, 0xf8, 0xf8, 0x3c, 0xd6, }, 50.0,
/* MD */ (const uint8_t []){0x0e, 0x67, 0x30, 0xbc, 0x4a, 0x0e, 0x93, 0x22, 0xea, 0x20, 0x5f, 0x4e, 0xdf, 0xff, 0x1f, 0xff, 0xda, 0x26, 0xaf, 0x0a, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x63, 0x4d, 0xb9, 0x2c, 0x22, 0x01, 0x0e, 0x1c, 0xbf, 0x1e, 0x16, 0x23, 0x92, 0x31, 0x80, 0x40, 0x6c, 0x51, 0x52, 0x72, 0x20, 0x9a, 0x8a, 0xcc, 0x42, 0xde, 0x05, 0xcc, 0x2e, 0x96, 0xa1, 0xe9, 0x4c, 0x1f, 0x9f, 0x6b, 0x93, 0x23, 0x4b, 0x7f, 0x4c, 0x55, 0xde, 0x8b, 0x19, 0x61, 0xa3, 0xbf, 0x35, 0x22, 0x59, }, 51.0,
/* MD */ (const uint8_t []){0xb6, 0x1a, 0x3a, 0x6f, 0x42, 0xe8, 0xe6, 0x60, 0x4b, 0x93, 0x19, 0x6c, 0x43, 0xc9, 0xe8, 0x4d, 0x53, 0x59, 0xe6, 0xfe, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0xcc, 0x6c, 0xa3, 0xa8, 0xcb, 0x39, 0x1c, 0xd8, 0xa5, 0xaf, 0xf1, 0xfa, 0xa7, 0xb3, 0xff, 0xbd, 0xd2, 0x1a, 0x5a, 0x3c, 0xe6, 0x6c, 0xfa, 0xdd, 0xbf, 0xe8, 0xb1, 0x79, 0xe4, 0xc8, 0x60, 0xbe, 0x5e, 0xc6, 0x6b, 0xd2, 0xc6, 0xde, 0x6a, 0x39, 0xa2, 0x56, 0x22, 0xf9, 0xf2, 0xfc, 0xb3, 0xfc, 0x05, 0xaf, 0x12, 0xb5, }, 52.0,
/* MD */ (const uint8_t []){0x32, 0xd9, 0x79, 0xca, 0x1b, 0x3e, 0xd0, 0xed, 0x8c, 0x89, 0x0d, 0x99, 0xec, 0x6d, 0xd8, 0x5e, 0x6c, 0x16, 0xab, 0xf4, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x7c, 0x0e, 0x6a, 0x0d, 0x35, 0xf8, 0xac, 0x85, 0x4c, 0x72, 0x45, 0xeb, 0xc7, 0x36, 0x93, 0x73, 0x1b, 0xbb, 0xc3, 0xe6, 0xfa, 0xb6, 0x44, 0x46, 0x6d, 0xe2, 0x7b, 0xb5, 0x22, 0xfc, 0xb9, 0x93, 0x07, 0x12, 0x6a, 0xe7, 0x18, 0xfe, 0x8f, 0x00, 0x74, 0x2e, 0x6e, 0x5c, 0xb7, 0xa6, 0x87, 0xc8, 0x84, 0x47, 0xcb, 0xc9, 0x61, }, 53.0,
/* MD */ (const uint8_t []){0x6f, 0x18, 0x19, 0x0b, 0xd2, 0xd0, 0x2f, 0xc9, 0x3b, 0xce, 0x64, 0x75, 0x65, 0x75, 0xce, 0xa3, 0x6d, 0x08, 0xb1, 0xc3, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0xc5, 0x58, 0x1d, 0x40, 0xb3, 0x31, 0xe2, 0x40, 0x03, 0x90, 0x1b, 0xd6, 0xbf, 0x24, 0x4a, 0xca, 0x9e, 0x96, 0x01, 0xb9, 0xd8, 0x12, 0x52, 0xbb, 0x38, 0x04, 0x86, 0x42, 0x73, 0x1f, 0x11, 0x46, 0xb8, 0xa4, 0xc6, 0x9f, 0x88, 0xe1, 0x48, 0xb2, 0xc8, 0xf8, 0xc1, 0x4f, 0x15, 0xe1, 0xd6, 0xda, 0x57, 0xb2, 0xda, 0xa9, 0x99, 0x1e, }, 54.0,
/* MD */ (const uint8_t []){0x68, 0xf5, 0x25, 0xfe, 0xea, 0x1d, 0x8d, 0xbe, 0x01, 0x17, 0xe4, 0x17, 0xca, 0x46, 0x70, 0x8d, 0x18, 0xd7, 0x62, 0x9a, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0xec, 0x6b, 0x4a, 0x88, 0x71, 0x3d, 0xf2, 0x7c, 0x0f, 0x2d, 0x02, 0xe7, 0x38, 0xb6, 0x9d, 0xb4, 0x3a, 0xbd, 0xa3, 0x92, 0x13, 0x17, 0x25, 0x9c, 0x86, 0x4c, 0x1c, 0x38, 0x6e, 0x9a, 0x5a, 0x3f, 0x53, 0x3d, 0xc0, 0x5f, 0x3b, 0xee, 0xb2, 0xbe, 0xc2, 0xaa, 0xc8, 0xe0, 0x6d, 0xb4, 0xc6, 0xcb, 0x3c, 0xdd, 0xcf, 0x69, 0x7e, 0x03, 0xd5, }, 55.0,
/* MD */ (const uint8_t []){0xa7, 0x27, 0x2e, 0x23, 0x08, 0x62, 0x2f, 0xf7, 0xa3, 0x39, 0x46, 0x0a, 0xdc, 0x61, 0xef, 0xd0, 0xea, 0x8d, 0xab, 0xdc, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x03, 0x21, 0x73, 0x6b, 0xeb, 0xa5, 0x78, 0xe9, 0x0a, 0xbc, 0x1a, 0x90, 0xaa, 0x56, 0x15, 0x7d, 0x87, 0x16, 0x18, 0xf6, 0xde, 0x0d, 0x76, 0x4c, 0xc8, 0xc9, 0x1e, 0x06, 0xc6, 0x8e, 0xcd, 0x3b, 0x9d, 0xe3, 0x82, 0x40, 0x64, 0x50, 0x33, 0x84, 0xdb, 0x67, 0xbe, 0xb7, 0xfe, 0x01, 0x22, 0x32, 0xda, 0xca, 0xef, 0x93, 0xa0, 0x00, 0xfb, 0xa7, }, 56.0,
/* MD */ (const uint8_t []){0xae, 0xf8, 0x43, 0xb8, 0x69, 0x16, 0xc1, 0x6f, 0x66, 0xc8, 0x4d, 0x83, 0xa6, 0x00, 0x5d, 0x23, 0xfd, 0x00, 0x5c, 0x9e, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0xd0, 0xa2, 0x49, 0xa9, 0x7b, 0x5f, 0x14, 0x86, 0x72, 0x1a, 0x50, 0xd4, 0xc4, 0xab, 0x3f, 0x5d, 0x67, 0x4a, 0x0e, 0x29, 0x92, 0x5d, 0x5b, 0xf2, 0x67, 0x8e, 0xf6, 0xd8, 0xd5, 0x21, 0xe4, 0x56, 0xbd, 0x84, 0xaa, 0x75, 0x53, 0x28, 0xc8, 0x3f, 0xc8, 0x90, 0x83, 0x77, 0x26, 0xa8, 0xe7, 0x87, 0x7b, 0x57, 0x0d, 0xba, 0x39, 0x57, 0x9a, 0xab, 0xdd, }, 57.0,
/* MD */ (const uint8_t []){0xbe, 0x2c, 0xd6, 0xf3, 0x80, 0x96, 0x9b, 0xe5, 0x9c, 0xde, 0x2d, 0xff, 0x5e, 0x84, 0x8a, 0x44, 0xe7, 0x88, 0x0b, 0xd6, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0xc3, 0x21, 0x38, 0x53, 0x11, 0x18, 0xf0, 0x8c, 0x7d, 0xcc, 0x29, 0x24, 0x28, 0xad, 0x20, 0xb4, 0x5a, 0xb2, 0x7d, 0x95, 0x17, 0xa1, 0x84, 0x45, 0xf3, 0x8b, 0x8f, 0x0c, 0x27, 0x95, 0xbc, 0xdf, 0xe3, 0xff, 0xe3, 0x84, 0xe6, 0x5e, 0xcb, 0xf7, 0x4d, 0x2c, 0x9d, 0x0d, 0xa8, 0x83, 0x98, 0x57, 0x53, 0x26, 0x07, 0x49, 0x04, 0xc1, 0x70, 0x9b, 0xa0, 0x72, }, 58.0,
/* MD */ (const uint8_t []){0xe5, 0xeb, 0x45, 0x43, 0xde, 0xee, 0x8f, 0x6a, 0x52, 0x87, 0x84, 0x5a, 0xf8, 0xb5, 0x93, 0xa9, 0x5a, 0x97, 0x49, 0xa1, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0xb0, 0xf4, 0xcf, 0xb9, 0x39, 0xea, 0x78, 0x5e, 0xab, 0xb7, 0xe7, 0xca, 0x7c, 0x47, 0x6c, 0xdd, 0x9b, 0x22, 0x7f, 0x01, 0x5d, 0x90, 0x53, 0x68, 0xba, 0x00, 0xae, 0x96, 0xb9, 0xaa, 0xf7, 0x20, 0x29, 0x74, 0x91, 0xb3, 0x92, 0x12, 0x67, 0x57, 0x6b, 0x72, 0xc8, 0xf5, 0x8d, 0x57, 0x76, 0x17, 0xe8, 0x44, 0xf9, 0xf0, 0x75, 0x9b, 0x39, 0x9c, 0x6b, 0x06, 0x4c, }, 59.0,
/* MD */ (const uint8_t []){0x53, 0x4c, 0x85, 0x04, 0x48, 0xdd, 0x48, 0x67, 0x87, 0xb6, 0x2b, 0xde, 0xc2, 0xd4, 0xa0, 0xb1, 0x40, 0xa1, 0xb1, 0x70, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0xbd, 0x02, 0xe5, 0x1b, 0x0c, 0xf2, 0xc2, 0xb8, 0xd2, 0x04, 0xa0, 0x26, 0xb4, 0x1a, 0x66, 0xfb, 0xfc, 0x2a, 0xc3, 0x7e, 0xe9, 0x41, 0x1f, 0xc4, 0x49, 0xc8, 0xd1, 0x19, 0x4a, 0x07, 0x92, 0xa2, 0x8e, 0xe7, 0x31, 0x40, 0x7d, 0xfc, 0x89, 0xb6, 0xdf, 0xc2, 0xb1, 0x0f, 0xaa, 0x27, 0x72, 0x3a, 0x18, 0x4a, 0xfe, 0xf8, 0xfd, 0x83, 0xde, 0xf8, 0x58, 0xa3, 0x2d, 0x3f, }, 60.0,
/* MD */ (const uint8_t []){0x6f, 0xbf, 0xa6, 0xe4, 0xed, 0xce, 0x4c, 0xc8, 0x5a, 0x84, 0x5b, 0xf0, 0xd2, 0x28, 0xdc, 0x39, 0xac, 0xef, 0xc2, 0xfa, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0xe3, 0x31, 0x46, 0xb8, 0x3e, 0x4b, 0xb6, 0x71, 0x39, 0x22, 0x18, 0xda, 0x9a, 0x77, 0xf8, 0xd9, 0xf5, 0x97, 0x41, 0x47, 0x18, 0x2f, 0xb9, 0x5b, 0xa6, 0x62, 0xcb, 0x66, 0x01, 0x19, 0x89, 0xc1, 0x6d, 0x9a, 0xf1, 0x04, 0x73, 0x5d, 0x6f, 0x79, 0x84, 0x1a, 0xa4, 0xd1, 0xdf, 0x27, 0x66, 0x15, 0xb5, 0x01, 0x08, 0xdf, 0x8a, 0x29, 0xdb, 0xc9, 0xde, 0x31, 0xf4, 0x26, 0x0d, }, 61.0,
/* MD */ (const uint8_t []){0x01, 0x88, 0x72, 0x69, 0x1d, 0x9b, 0x04, 0xe8, 0x22, 0x0e, 0x09, 0x18, 0x7d, 0xf5, 0xbc, 0x5f, 0xa6, 0x25, 0x7c, 0xd9, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x41, 0x1c, 0x13, 0xc7, 0x50, 0x73, 0xc1, 0xe2, 0xd4, 0xb1, 0xec, 0xf1, 0x31, 0x39, 0xba, 0x96, 0x56, 0xcd, 0x35, 0xc1, 0x42, 0x01, 0xf1, 0xc7, 0xc6, 0xf0, 0xee, 0xb5, 0x8d, 0x2d, 0xbf, 0xe3, 0x5b, 0xfd, 0xec, 0xcc, 0x92, 0xc3, 0x96, 0x1c, 0xfa, 0xbb, 0x59, 0x0b, 0xc1, 0xeb, 0x77, 0xea, 0xc1, 0x57, 0x32, 0xfb, 0x02, 0x75, 0x79, 0x86, 0x80, 0xe0, 0xc7, 0x29, 0x2e, 0x50, }, 62.0,
/* MD */ (const uint8_t []){0xd9, 0x8d, 0x51, 0x2a, 0x35, 0x57, 0x2f, 0x8b, 0xd2, 0x0d, 0xe6, 0x2e, 0x95, 0x10, 0xcc, 0x21, 0x14, 0x5c, 0x5b, 0xf4, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0xf2, 0xc7, 0x6e, 0xf6, 0x17, 0xfa, 0x2b, 0xfc, 0x8a, 0x4d, 0x6b, 0xcb, 0xb1, 0x5f, 0xe8, 0x84, 0x36, 0xfd, 0xc2, 0x16, 0x5d, 0x30, 0x74, 0x62, 0x95, 0x79, 0x07, 0x9d, 0x4d, 0x5b, 0x86, 0xf5, 0x08, 0x1a, 0xb1, 0x77, 0xb4, 0xc3, 0xf5, 0x30, 0x37, 0x6c, 0x9c, 0x92, 0x4c, 0xbd, 0x42, 0x1a, 0x8d, 0xaf, 0x88, 0x30, 0xd0, 0x94, 0x0c, 0x4f, 0xb7, 0x58, 0x98, 0x65, 0x83, 0x06, 0x99, }, 63.0,
/* MD */ (const uint8_t []){0x9f, 0x3e, 0xa2, 0x55, 0xf6, 0xaf, 0x95, 0xc5, 0x45, 0x4e, 0x55, 0xd7, 0x35, 0x4c, 0xab, 0xb4, 0x53, 0x52, 0xea, 0x0b, }, 20.0,
},
{ TEE_ALG_SHA1, 1,
/* Msg */ (const uint8_t []){0x45, 0x92, 0x7e, 0x32, 0xdd, 0xf8, 0x01, 0xca, 0xf3, 0x5e, 0x18, 0xe7, 0xb5, 0x07, 0x8b, 0x7f, 0x54, 0x35, 0x27, 0x82, 0x12, 0xec, 0x6b, 0xb9, 0x9d, 0xf8, 0x84, 0xf4, 0x9b, 0x32, 0x7c, 0x64, 0x86, 0xfe, 0xae, 0x46, 0xba, 0x18, 0x7d, 0xc1, 0xcc, 0x91, 0x45, 0x12, 0x1e, 0x14, 0x92, 0xe6, 0xb0, 0x6e, 0x90, 0x07, 0x39, 0x4d, 0xc3, 0x3b, 0x77, 0x48, 0xf8, 0x6a, 0xc3, 0x20, 0x7c, 0xfe, }, 64.0,
/* MD */ (const uint8_t []){0xa7, 0x0c, 0xfb, 0xfe, 0x75, 0x63, 0xdd, 0x0e, 0x66, 0x5c, 0x7c, 0x67, 0x15, 0xa9, 0x6a, 0x8d, 0x75, 0x69, 0x50, 0xc0, }, 20.0,
},
