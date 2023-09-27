// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright NXP 2023
 */
#include "tee_api_defines.h"
#include "tee_api_types.h"
#include <stdint.h>
#include <stdbool.h>
#include <tee_ta_api.h>
#include <assert.h>
#include <util.h>

#include "ta_acipher_perf.h"
#include "ta_acipher_perf_priv.h"

/* diffie hellman test data */
/* p and g testdata generated using the following line:
 * for i in {256..2048..64}; do openssl dhparam -C -5 $i; done
 */
static const uint8_t keygen_dh256_p[] = {
	0xB6, 0x73, 0x91, 0xB5, 0xD6, 0xBC, 0x95, 0x73, 0x0D, 0x53, 0x64, 0x13,
	0xB0, 0x51, 0xC6, 0xB4, 0xEB, 0x9D, 0x74, 0x57, 0x8D, 0x65, 0x3A, 0x4B,
	0x7A, 0xB2, 0x93, 0x27, 0xA6, 0xC1, 0xBC, 0xAB,
};

static const uint8_t keygen_dh256_g[] = {
	0x05,
};

static const uint8_t keygen_dh320_p[] = {
	0x80, 0x72, 0x50, 0x4F, 0x85, 0xD2, 0x32, 0x70, 0xA3, 0x11, 0xF4, 0x46,
	0x01, 0x72, 0xD0, 0x72, 0x96, 0xA5, 0x1B, 0xFA, 0x8F, 0x35, 0x49, 0x75,
	0x04, 0xA5, 0x5A, 0x62, 0xB6, 0x33, 0xD6, 0x3C, 0x46, 0xD1, 0xED, 0xD7,
	0xB1, 0xD4, 0xBA, 0xF3,
};

static const uint8_t keygen_dh320_g[] = {
	0x05,
};

static const uint8_t keygen_dh384_p[] = {
	0xC2, 0x04, 0xC8, 0x0E, 0xE8, 0x3F, 0x02, 0x1F, 0xDE, 0x0C, 0xAA, 0x2E,
	0x67, 0x13, 0xF4, 0x33, 0x67, 0x82, 0x59, 0xE7, 0x80, 0xE5, 0x42, 0xEA,
	0x2F, 0xC4, 0x71, 0x93, 0xA7, 0x1C, 0x86, 0xEC, 0x8C, 0x39, 0xF8, 0xC7,
	0xF1, 0xE3, 0xE0, 0xEE, 0xC4, 0x55, 0xF5, 0x4F, 0xE7, 0x98, 0xF0, 0x47,
};

static const uint8_t keygen_dh384_g[] = {
	0x05,
};

static const uint8_t keygen_dh448_p[] = {
	0x91, 0xB9, 0x28, 0x8F, 0x01, 0x62, 0xA1, 0x40, 0x4D, 0x53, 0xC7, 0xD5,
	0xEE, 0x97, 0x40, 0x03, 0x39, 0x39, 0x41, 0x5F, 0x17, 0x0F, 0xA2, 0x78,
	0xBF, 0x3D, 0x6B, 0x33, 0x33, 0x39, 0x3B, 0x57, 0x21, 0x5B, 0xF9, 0xB1,
	0x6C, 0xE3, 0xB8, 0x19, 0xBE, 0x81, 0xBD, 0xC4, 0xFF, 0x4C, 0xFA, 0x48,
	0x63, 0x24, 0x10, 0x33, 0xDE, 0x3A, 0xFD, 0x3B,
};

static const uint8_t keygen_dh448_g[] = {
	0x05,
};

static const uint8_t keygen_dh512_p[] = {
	0xCF, 0x09, 0xB8, 0xCD, 0x0B, 0xC5, 0x9D, 0xBD, 0x7A, 0x34, 0x50, 0x55,
	0xEC, 0xD4, 0xED, 0x92, 0x9D, 0x63, 0x92, 0xF9, 0x1D, 0x42, 0xF3, 0x64,
	0x04, 0x3D, 0xCC, 0xAA, 0x5F, 0xD1, 0xBB, 0xEA, 0x44, 0x12, 0xFC, 0xF0,
	0xFB, 0xFF, 0x26, 0x57, 0xE3, 0x6E, 0xA8, 0x3F, 0x45, 0x43, 0x11, 0x81,
	0xC6, 0x79, 0xF0, 0x0B, 0x11, 0x23, 0x1D, 0x7B, 0x1E, 0x59, 0xA8, 0xB8,
	0x69, 0x44, 0xA7, 0xE3,
};

static const uint8_t keygen_dh512_g[] = {
	0x05,
};

static const uint8_t keygen_dh576_p[] = {
	0xEF, 0xA2, 0xD7, 0x81, 0x88, 0xAA, 0xBF, 0x70, 0x03, 0x70, 0xD4, 0x75,
	0xA6, 0x3E, 0x5B, 0xCF, 0x73, 0xDE, 0x7D, 0x45, 0x67, 0x47, 0xB1, 0xCF,
	0xA8, 0x62, 0xA9, 0x13, 0x9F, 0xC3, 0x9B, 0x96, 0xCE, 0xB9, 0x0C, 0x24,
	0xAC, 0xCB, 0xB6, 0x40, 0x30, 0x25, 0x26, 0x4E, 0x9D, 0x50, 0xA7, 0x8F,
	0x09, 0x1C, 0x9B, 0xDE, 0x77, 0x8A, 0xE8, 0xAA, 0xDA, 0xC2, 0x31, 0x08,
	0x55, 0x2C, 0xC1, 0x13, 0x24, 0x6E, 0x5A, 0xE7, 0xA1, 0xBC, 0xE5, 0x5B,
};

static const uint8_t keygen_dh576_g[] = {
	0x05,
};

static const uint8_t keygen_dh640_p[] = {
	0xED, 0xB6, 0x90, 0x9C, 0x72, 0x5C, 0x63, 0x11, 0x17, 0xA9, 0xB6, 0x0E,
	0x6C, 0x80, 0xA9, 0xF3, 0x15, 0x36, 0x9D, 0x49, 0x02, 0x2B, 0x4F, 0x12,
	0x1A, 0xFD, 0x00, 0xC0, 0x9B, 0x12, 0x10, 0x96, 0x18, 0x55, 0x3F, 0x0C,
	0x75, 0x46, 0x6E, 0xDF, 0x0A, 0x58, 0x8E, 0x1B, 0x4B, 0xFF, 0x24, 0x70,
	0xFC, 0x29, 0xE8, 0x67, 0x8F, 0x0B, 0x72, 0x14, 0x80, 0x6F, 0xE9, 0xCD,
	0x30, 0x3C, 0x16, 0xB9, 0xB0, 0x32, 0xBE, 0x6A, 0x1D, 0x06, 0xEE, 0x6D,
	0x15, 0x44, 0x49, 0x55, 0xA8, 0x08, 0x2D, 0x0F,
};

static const uint8_t keygen_dh640_g[] = {
	0x05,
};

static const uint8_t keygen_dh704_p[] = {
	0xA6, 0xBF, 0xA1, 0x02, 0x02, 0xA7, 0x7A, 0x6E, 0xFC, 0x48, 0x55, 0x81,
	0x23, 0x3F, 0x08, 0x8E, 0x83, 0xE9, 0x10, 0x92, 0x96, 0x82, 0x5F, 0xB8,
	0x88, 0x28, 0x0C, 0x6A, 0x04, 0x41, 0xEF, 0x4C, 0xCC, 0x2F, 0x16, 0xCD,
	0xA4, 0x2F, 0x24, 0x3B, 0xB6, 0x8A, 0x45, 0x76, 0xB3, 0xFA, 0x23, 0x83,
	0x53, 0xB2, 0x8F, 0x0C, 0xAE, 0xF9, 0xE8, 0xDB, 0x46, 0x5B, 0xBF, 0x7E,
	0xC3, 0x6F, 0x4F, 0xE6, 0xE7, 0x51, 0x75, 0x49, 0xB5, 0x4B, 0xBE, 0x48,
	0x51, 0x64, 0x9F, 0x5D, 0x56, 0xC7, 0x28, 0x9C, 0xC5, 0xBD, 0x0C, 0xD2,
	0x3A, 0x63, 0x49, 0x57,
};

static const uint8_t keygen_dh704_g[] = {
	0x05,
};

static const uint8_t keygen_dh768_p[] = {
	0xEA, 0x9B, 0x0E, 0xD5, 0xDF, 0xC6, 0x9C, 0x8A, 0x26, 0x29, 0xD4, 0x2A,
	0x94, 0x4F, 0xD5, 0x3E, 0xEA, 0xEC, 0xCD, 0x89, 0xDA, 0x9C, 0x12, 0x52,
	0x94, 0xA7, 0x1A, 0x7D, 0x14, 0x94, 0xB1, 0x89, 0x79, 0xF3, 0x4A, 0xC3,
	0xD6, 0xF5, 0x52, 0xA6, 0x65, 0xC6, 0x0C, 0xD2, 0x2B, 0x16, 0xCB, 0x4F,
	0x69, 0x4C, 0x41, 0x6C, 0xA6, 0xAF, 0xCE, 0xFD, 0x50, 0x0E, 0x8C, 0x9E,
	0xA7, 0x19, 0x46, 0x6E, 0xC2, 0x27, 0xB9, 0xAF, 0x61, 0x4B, 0xDA, 0x3A,
	0x60, 0xBA, 0x6D, 0xCE, 0xBA, 0x39, 0x1C, 0x02, 0xBF, 0x09, 0xF0, 0xF9,
	0x87, 0xBE, 0xA1, 0xDE, 0x4E, 0x34, 0x7B, 0x28, 0x3A, 0xC2, 0x9E, 0x83,
};

static const uint8_t keygen_dh768_g[] = {
	0x05,
};

static const uint8_t keygen_dh832_p[] = {
	0xB9, 0x0C, 0x79, 0x82, 0x7B, 0x23, 0xB7, 0x2F, 0x5A, 0x7B, 0xB1, 0xB9,
	0x63, 0x30, 0x7C, 0xD4, 0x0B, 0xEB, 0x7B, 0x8A, 0x67, 0x3E, 0x3B, 0x67,
	0xF1, 0x72, 0x90, 0x0E, 0xBF, 0x67, 0xEF, 0xBB, 0x95, 0xC1, 0x47, 0xED,
	0x89, 0x11, 0x79, 0x40, 0x63, 0x02, 0xF0, 0x41, 0x0C, 0xD1, 0x76, 0x15,
	0xAA, 0x24, 0x6A, 0xAE, 0x98, 0xFB, 0x19, 0x1F, 0x43, 0xB9, 0x92, 0xC7,
	0xB6, 0x33, 0xD8, 0x85, 0xBD, 0x06, 0x7D, 0x68, 0x32, 0xEE, 0xDB, 0x41,
	0xEF, 0x7B, 0xBD, 0xB4, 0xFE, 0x53, 0x4F, 0x6C, 0xA8, 0x26, 0xE0, 0x62,
	0x7D, 0x06, 0x06, 0xC5, 0xFB, 0x47, 0xD0, 0x3F, 0x4B, 0xC1, 0x7A, 0xC4,
	0x2A, 0xF3, 0x69, 0xF2, 0xDE, 0x77, 0xCD, 0x03,
};

static const uint8_t keygen_dh832_g[] = {
	0x05,
};

static const uint8_t keygen_dh896_p[] = {
	0xA8, 0x1A, 0xFB, 0xF4, 0x12, 0xF8, 0x17, 0x16, 0x89, 0x20, 0xAE, 0x6F,
	0x07, 0x55, 0x13, 0xCA, 0x99, 0x66, 0xA3, 0x1F, 0x07, 0xAC, 0x32, 0x5C,
	0xF5, 0xF0, 0x39, 0xA3, 0xDA, 0xF5, 0x55, 0xF9, 0x3C, 0xF3, 0x15, 0xF8,
	0x44, 0xC1, 0x10, 0x6A, 0x3D, 0x2F, 0x97, 0xFD, 0xAC, 0x74, 0x1E, 0xEE,
	0xCF, 0xDD, 0xEE, 0x70, 0x57, 0xBA, 0x4B, 0x41, 0xD6, 0x3F, 0xDD, 0x01,
	0xFB, 0x0C, 0x26, 0xA9, 0x06, 0xCD, 0x1B, 0xA2, 0xD3, 0x3E, 0xAD, 0x2D,
	0x29, 0xFB, 0x79, 0xB8, 0x8E, 0x50, 0xCC, 0xA1, 0x85, 0x37, 0xFA, 0xF1,
	0xBB, 0xB1, 0x5D, 0x3B, 0x51, 0x54, 0x16, 0x4C, 0x98, 0x2B, 0x26, 0xAD,
	0x70, 0x0B, 0x01, 0x87, 0x5C, 0xF1, 0xE8, 0x02, 0xF3, 0x57, 0xA9, 0x40,
	0x5C, 0xC5, 0xE0, 0xFF,
};

static const uint8_t keygen_dh896_g[] = {
	0x05,
};

static const uint8_t keygen_dh960_p[] = {
	0xD9, 0x31, 0xE0, 0xF3, 0x80, 0xED, 0xBD, 0xEC, 0x35, 0x99, 0xC9, 0x28,
	0xA8, 0x88, 0x3C, 0x84, 0x41, 0x8A, 0x6C, 0xC7, 0x83, 0x09, 0xCE, 0x07,
	0x51, 0x72, 0xBE, 0xE9, 0x21, 0x4F, 0xCB, 0x92, 0xAE, 0xA5, 0xF0, 0x9A,
	0x40, 0x9B, 0x02, 0x1D, 0xA5, 0x5E, 0xAB, 0x17, 0x25, 0x5B, 0x70, 0x0F,
	0xF9, 0x27, 0xEF, 0x49, 0xCD, 0x7F, 0x6E, 0x9A, 0x62, 0x51, 0xE6, 0xEA,
	0x4B, 0x7E, 0xBE, 0xB3, 0x72, 0xFB, 0xAF, 0x98, 0xA1, 0x7D, 0x77, 0x7E,
	0x53, 0xF9, 0xFC, 0x7A, 0xEB, 0xC7, 0xB0, 0x84, 0x2F, 0x70, 0xCC, 0xA2,
	0x34, 0x52, 0x9F, 0xD3, 0x46, 0xE3, 0x32, 0x2F, 0xE0, 0x6F, 0x83, 0x3B,
	0x8B, 0x17, 0x01, 0x0C, 0x1D, 0xEA, 0x04, 0x7D, 0xB1, 0xD4, 0xB2, 0x2D,
	0xC7, 0xD3, 0x2D, 0xE0, 0x47, 0x00, 0x6D, 0xE8, 0x1F, 0xAA, 0x39, 0x67,
};

static const uint8_t keygen_dh960_g[] = {
	0x05,
};

static const uint8_t keygen_dh1024_p[] = {
	0xB9, 0xF5, 0xB6, 0xFF, 0x49, 0xA7, 0x31, 0x3C, 0xD3, 0xAA, 0x42, 0xAE,
	0x3D, 0xA6, 0xD4, 0xC1, 0x92, 0xB0, 0x1C, 0xD5, 0x24, 0x9D, 0x67, 0x04,
	0xFA, 0xED, 0x0B, 0x2D, 0x8B, 0xA1, 0xB8, 0x72, 0x43, 0x48, 0xC2, 0x75,
	0x00, 0x9F, 0x43, 0xD7, 0xF0, 0x8F, 0xD8, 0xCD, 0x1C, 0x64, 0x48, 0x82,
	0x63, 0x52, 0x89, 0x78, 0x43, 0xEF, 0x00, 0xF6, 0x62, 0x04, 0x26, 0xD5,
	0x69, 0x2C, 0x2B, 0x9B, 0x53, 0x72, 0x57, 0xD5, 0x05, 0xA6, 0x53, 0x24,
	0x43, 0x81, 0x49, 0xEC, 0xBB, 0x43, 0x58, 0x66, 0x6A, 0xBD, 0xAC, 0xBA,
	0xD9, 0xC8, 0xC9, 0x95, 0x93, 0xCB, 0x79, 0x89, 0x86, 0x30, 0x0D, 0x45,
	0x3F, 0x89, 0x04, 0xC4, 0xEC, 0x96, 0xBF, 0x4E, 0x8E, 0x88, 0x51, 0xED,
	0xEF, 0x91, 0x8A, 0x03, 0xDC, 0x4E, 0x28, 0x69, 0x46, 0xDA, 0x1B, 0xD4,
	0x7E, 0xC5, 0xEB, 0x95, 0xBC, 0x9D, 0x14, 0x77,
};

static const uint8_t keygen_dh1024_g[] = {
	0x05,
};

static const uint8_t keygen_dh1088_p[] = {
	0xE3, 0x67, 0x7B, 0x2C, 0x68, 0xE3, 0x7C, 0xDB, 0x30, 0x3A, 0xF3, 0x20,
	0x33, 0x02, 0xB5, 0x08, 0x83, 0xC5, 0x8B, 0x07, 0xDD, 0x08, 0x92, 0x82,
	0xD6, 0x2A, 0x2B, 0x7F, 0xC6, 0xF0, 0xBD, 0xB8, 0x01, 0xF8, 0xCF, 0x78,
	0x4F, 0xFE, 0xE2, 0x9D, 0x2F, 0xF4, 0x2D, 0xC5, 0x48, 0xE0, 0xFD, 0x8A,
	0xC2, 0xCF, 0x1B, 0xD9, 0xE1, 0x23, 0xC6, 0xDA, 0xFC, 0x1C, 0x9B, 0xA4,
	0x70, 0x91, 0x1A, 0x6A, 0x35, 0x00, 0x5E, 0x63, 0x14, 0x04, 0xAB, 0x3B,
	0x00, 0xEE, 0x44, 0xE6, 0xAE, 0x49, 0xDB, 0xB7, 0xEF, 0xE1, 0x6E, 0xF9,
	0x88, 0xCC, 0xAB, 0x5E, 0x0A, 0x20, 0x84, 0x09, 0x03, 0xFA, 0xAA, 0x8C,
	0xFE, 0xB8, 0xEA, 0x31, 0x78, 0xD2, 0x92, 0xF3, 0x77, 0xCF, 0xEC, 0xB9,
	0xF8, 0x3C, 0x79, 0x4A, 0x9B, 0xB6, 0xCC, 0xC0, 0x5E, 0xAB, 0x92, 0xE6,
	0x39, 0x74, 0x5E, 0x8D, 0x2B, 0x28, 0x3B, 0x4D, 0x26, 0x6B, 0x2F, 0xF6,
	0xA8, 0xB1, 0x01, 0x53,
};

static const uint8_t keygen_dh1088_g[] = {
	0x05,
};

static const uint8_t keygen_dh1152_p[] = {
	0xCA, 0xD6, 0x34, 0x4F, 0xAE, 0x99, 0x47, 0x51, 0x14, 0x5D, 0xF4, 0xCA,
	0x47, 0xE2, 0xE7, 0x62, 0x7D, 0xB9, 0xC9, 0xE7, 0xF7, 0xEE, 0xD4, 0xF0,
	0x04, 0xC1, 0x93, 0x06, 0xC2, 0xC8, 0x5E, 0x9D, 0xD3, 0x9F, 0x4A, 0x87,
	0xF2, 0x22, 0x5A, 0x72, 0x8D, 0xEB, 0x8B, 0x12, 0x26, 0x82, 0x3A, 0xA7,
	0x6B, 0xE1, 0x55, 0xB0, 0x9F, 0x97, 0x4C, 0xC5, 0xEC, 0x5C, 0x1C, 0x23,
	0xAB, 0x95, 0xDC, 0x17, 0xD5, 0x80, 0x0A, 0xE6, 0x53, 0x9E, 0xD8, 0xC6,
	0xB9, 0x9E, 0xFA, 0x62, 0x60, 0x2A, 0x8D, 0xD5, 0x3D, 0x36, 0x5E, 0x4E,
	0x42, 0x1F, 0xAF, 0x2B, 0x87, 0x0E, 0xC6, 0x44, 0xB7, 0x55, 0x1C, 0x81,
	0x7E, 0x48, 0x96, 0x1B, 0xF9, 0x73, 0x1C, 0x3D, 0x80, 0xDF, 0x43, 0xDB,
	0x93, 0xB6, 0x1E, 0xC1, 0x04, 0x12, 0x9E, 0x33, 0x21, 0xCE, 0xF7, 0x49,
	0x41, 0x7E, 0x97, 0x31, 0xC3, 0x74, 0x1D, 0x95, 0x85, 0x6F, 0x3A, 0xA1,
	0xCF, 0x61, 0xD9, 0xEB, 0x67, 0x67, 0xED, 0x91, 0xDF, 0x23, 0xCD, 0xC3,
};

static const uint8_t keygen_dh1152_g[] = {
	0x05,
};

static const uint8_t keygen_dh1216_p[] = {
	0xB1, 0xFC, 0x4E, 0xF5, 0xDE, 0xC5, 0xDD, 0x33, 0xDD, 0xB2, 0x2E, 0x44,
	0x52, 0xDD, 0x74, 0x2F, 0x1F, 0x61, 0x20, 0x21, 0x72, 0x65, 0xC5, 0xEC,
	0x5A, 0xAA, 0xF1, 0x24, 0xA1, 0xD0, 0xEB, 0x4B, 0x4C, 0x32, 0x8A, 0xDD,
	0x4F, 0x9F, 0xEE, 0xFA, 0x5F, 0x81, 0xD4, 0x18, 0x3D, 0xCD, 0x39, 0x38,
	0xDC, 0x3D, 0x2E, 0x37, 0xEB, 0xFE, 0x73, 0xEF, 0x99, 0x53, 0x54, 0xA6,
	0xAB, 0x25, 0xFE, 0x9A, 0x10, 0xAE, 0x3E, 0xC9, 0x63, 0x45, 0x75, 0xAF,
	0xCA, 0xD9, 0x57, 0xF7, 0x71, 0xE0, 0xBE, 0x0D, 0x90, 0xE9, 0xC5, 0x5A,
	0xC6, 0x2E, 0x3D, 0xDE, 0xE4, 0x8B, 0x38, 0x8E, 0x83, 0x06, 0xA6, 0xE2,
	0x38, 0xA6, 0x88, 0x81, 0xDE, 0x8E, 0xA6, 0x6A, 0xBF, 0xF4, 0x75, 0xFB,
	0xAB, 0xAA, 0x02, 0xEA, 0x0E, 0xCF, 0xCA, 0xEA, 0x45, 0xFE, 0x1C, 0xC2,
	0xF9, 0xBE, 0x26, 0x31, 0xA6, 0x8F, 0xFE, 0x07, 0x9E, 0x79, 0x47, 0x11,
	0xA1, 0x25, 0xA4, 0xE5, 0xFB, 0xEA, 0xE7, 0xC1, 0xFF, 0x12, 0x12, 0x71,
	0x5D, 0xC1, 0x99, 0x44, 0xD1, 0xCE, 0x82, 0xA7,
};

static const uint8_t keygen_dh1216_g[] = {
	0x05,
};

static const uint8_t keygen_dh1280_p[] = {
	0xF0, 0x10, 0x04, 0x04, 0x08, 0x13, 0x79, 0x15, 0x62, 0x5C, 0xFA, 0x2A,
	0x6D, 0xFC, 0x3F, 0x23, 0x4C, 0x47, 0x83, 0x45, 0xE7, 0x6F, 0x64, 0x04,
	0x1A, 0xFD, 0xBF, 0xD2, 0xB9, 0x0A, 0x98, 0x14, 0x16, 0xA4, 0xB5, 0x03,
	0x13, 0xBB, 0xFB, 0x72, 0x1E, 0xF5, 0x23, 0x12, 0xB8, 0x74, 0x49, 0x3F,
	0x84, 0xF3, 0x02, 0x3A, 0x50, 0x6F, 0xB7, 0xC7, 0x6F, 0x37, 0x8F, 0x61,
	0x88, 0x60, 0x7C, 0xF1, 0xE7, 0x1E, 0xED, 0x55, 0xF1, 0xCD, 0x64, 0x93,
	0xA7, 0x12, 0xB7, 0x74, 0x5F, 0x23, 0x20, 0xF7, 0x87, 0xC2, 0x83, 0x2A,
	0x86, 0x0C, 0xF3, 0x4B, 0x88, 0x32, 0xF5, 0xB7, 0x86, 0x2F, 0xBF, 0xEE,
	0xA1, 0x59, 0xC4, 0xDB, 0x0F, 0xEF, 0x06, 0xC8, 0xF2, 0xEE, 0x39, 0xB4,
	0x19, 0x24, 0x8A, 0x2C, 0xE7, 0xF8, 0xA0, 0x34, 0x2A, 0x15, 0xA9, 0x54,
	0x4D, 0x04, 0x1B, 0xC0, 0xC5, 0x15, 0xCF, 0x38, 0x96, 0x83, 0x3E, 0xEE,
	0xD0, 0xFD, 0xBC, 0x62, 0xD9, 0x84, 0xA3, 0x02, 0x6D, 0x2A, 0x7B, 0x4B,
	0x3E, 0xCC, 0xAD, 0xA1, 0xF0, 0xA0, 0x44, 0xDD, 0x7E, 0x4B, 0xBD, 0x75,
	0xAD, 0x8F, 0xF1, 0x57,
};

static const uint8_t keygen_dh1280_g[] = {
	0x05,
};

static const uint8_t keygen_dh1344_p[] = {
	0x8E, 0x0F, 0xCC, 0x61, 0x96, 0xCA, 0xF2, 0x3A, 0x13, 0xD5, 0xF9, 0x2A,
	0xD0, 0xF0, 0x5A, 0x4C, 0x1B, 0xC2, 0xD2, 0xDE, 0xD6, 0x54, 0x53, 0x83,
	0x70, 0x1E, 0x0A, 0x17, 0x6D, 0x4C, 0xBA, 0xCD, 0xEE, 0x32, 0x08, 0x55,
	0xD8, 0xD3, 0x80, 0x81, 0x07, 0x04, 0xF3, 0x19, 0xDD, 0x20, 0x30, 0x6A,
	0x6C, 0x74, 0x25, 0x56, 0xEB, 0xA0, 0x9E, 0x0A, 0x08, 0x94, 0x88, 0xE8,
	0xD2, 0xFD, 0xC3, 0x16, 0x27, 0x51, 0xE2, 0xF8, 0xAE, 0x8B, 0x2B, 0xFF,
	0x2A, 0x75, 0xEC, 0x21, 0xEB, 0xA9, 0xE2, 0x24, 0x8A, 0xAE, 0xF9, 0x7D,
	0x90, 0x8B, 0x31, 0x10, 0x6B, 0x14, 0x97, 0x2D, 0xB2, 0x93, 0x59, 0xFF,
	0x4B, 0x9A, 0x0A, 0x90, 0xA8, 0x0E, 0xDE, 0x19, 0x2B, 0x74, 0xF2, 0xCC,
	0x2D, 0x5B, 0x4F, 0x91, 0xBE, 0x43, 0x86, 0xA2, 0x91, 0xDD, 0x01, 0xDD,
	0x24, 0x75, 0xD8, 0x9F, 0x85, 0x53, 0xC3, 0xDB, 0x08, 0x5F, 0x01, 0x24,
	0xA7, 0x45, 0xAA, 0x6E, 0xB4, 0xFB, 0x05, 0x1C, 0x58, 0x51, 0x3D, 0xFD,
	0x39, 0x57, 0xD4, 0xF9, 0x11, 0x81, 0x60, 0x48, 0xF1, 0xD7, 0x7C, 0xAE,
	0xDE, 0x58, 0x6E, 0x6A, 0x02, 0xC5, 0x51, 0x69, 0x47, 0xF3, 0xAC, 0x47,
};

static const uint8_t keygen_dh1344_g[] = {
	0x05,
};

static const uint8_t keygen_dh1408_p[] = {
	0xE1, 0xE7, 0xA6, 0xF3, 0x5C, 0x06, 0x00, 0x8B, 0x4B, 0x3C, 0x7A, 0xF9,
	0x4D, 0x30, 0x08, 0x73, 0x69, 0xCF, 0x79, 0x6F, 0xAB, 0x66, 0x47, 0x05,
	0x65, 0xA8, 0x4A, 0x5C, 0xA6, 0x5E, 0x3D, 0x46, 0x10, 0x0A, 0x58, 0x3E,
	0x7C, 0x3F, 0x0F, 0x3A, 0xE1, 0xFF, 0x2C, 0x7D, 0xE1, 0x40, 0x05, 0xED,
	0xC3, 0x0B, 0x6C, 0x36, 0x90, 0xDC, 0x10, 0x94, 0x9B, 0xEB, 0xA9, 0x31,
	0xD9, 0x1F, 0x46, 0xBF, 0xC0, 0xF4, 0x49, 0x44, 0x39, 0xF2, 0xE9, 0xB8,
	0x86, 0x52, 0xCB, 0x60, 0xAC, 0xAF, 0x2C, 0x38, 0x9A, 0x63, 0xCE, 0xB7,
	0x30, 0x17, 0x81, 0xA9, 0x1C, 0x3D, 0x73, 0x0D, 0x3F, 0xCE, 0xC8, 0xA6,
	0x95, 0x65, 0x8F, 0x9F, 0x5C, 0xE8, 0xEB, 0x5C, 0x69, 0x59, 0x8B, 0xA5,
	0x1D, 0x74, 0x23, 0x35, 0x3C, 0x35, 0x08, 0x50, 0x53, 0xE5, 0xDB, 0x93,
	0x69, 0x8F, 0x17, 0xF7, 0xA0, 0xBA, 0xED, 0xD6, 0xE9, 0x7C, 0x4F, 0x97,
	0xAB, 0x25, 0x26, 0x39, 0xF9, 0xF3, 0x12, 0x0A, 0xB1, 0xE0, 0x7C, 0xCD,
	0x60, 0x5C, 0x46, 0x2E, 0x22, 0xAB, 0xEF, 0x8D, 0x09, 0xB8, 0x3D, 0xB1,
	0xA6, 0xB0, 0x1C, 0x5D, 0x75, 0x66, 0x02, 0x0E, 0xFD, 0xB9, 0xD6, 0x47,
	0x5F, 0x80, 0xF3, 0xAF, 0xB3, 0x39, 0x7B, 0xF7,
};

static const uint8_t keygen_dh1408_g[] = {
	0x05,
};

static const uint8_t keygen_dh1472_p[] = {
	0x9D, 0x8A, 0x3D, 0x5A, 0xC0, 0x90, 0x55, 0x02, 0x4E, 0x28, 0xB7, 0x8F,
	0x33, 0x91, 0xDC, 0xEB, 0xD2, 0x81, 0x00, 0x16, 0x2D, 0x89, 0x9A, 0x3C,
	0x83, 0xD5, 0xF3, 0x2A, 0x59, 0x5D, 0x63, 0x86, 0xFB, 0xEB, 0xA8, 0xFD,
	0x27, 0x1E, 0x18, 0x9F, 0x3C, 0xF7, 0xEF, 0xAE, 0xDE, 0x6C, 0xA5, 0x30,
	0x16, 0x93, 0xF0, 0x00, 0xB3, 0x36, 0xD2, 0xF6, 0x2C, 0x95, 0xF1, 0x31,
	0x4A, 0x75, 0xA8, 0x4F, 0xF6, 0xA8, 0x0F, 0xE9, 0x0B, 0xB4, 0xAF, 0xEE,
	0xFF, 0x50, 0x6D, 0xE8, 0xFC, 0x3A, 0xCC, 0x04, 0x71, 0x21, 0x74, 0x38,
	0xEB, 0x7E, 0x66, 0x70, 0x85, 0xA7, 0x35, 0x50, 0x07, 0x21, 0x2D, 0x24,
	0x45, 0xCC, 0x00, 0xB1, 0x7F, 0x7A, 0x73, 0x54, 0x9B, 0x96, 0x7B, 0x60,
	0x46, 0xDE, 0x57, 0x4B, 0xE3, 0xF5, 0xEA, 0x0E, 0xFC, 0x7A, 0xC1, 0xFE,
	0x8D, 0x13, 0xD8, 0x2D, 0xAB, 0xDD, 0xA6, 0x61, 0x5C, 0x95, 0xB4, 0x15,
	0x6F, 0x2A, 0x40, 0x6C, 0xB3, 0xC6, 0xC2, 0x1C, 0xC6, 0x74, 0x6F, 0x31,
	0x73, 0x47, 0x94, 0x95, 0x23, 0x8D, 0xCD, 0x4F, 0x4D, 0xA8, 0xF3, 0x67,
	0x5D, 0xDE, 0x83, 0x49, 0x9C, 0xD3, 0xD9, 0xB5, 0x0D, 0xD4, 0x0E, 0xD1,
	0x99, 0xB7, 0x53, 0x2E, 0xE5, 0xFD, 0xB5, 0x75, 0xFD, 0xE6, 0xD6, 0xC6,
	0xA2, 0x43, 0x33, 0x83,
};

static const uint8_t keygen_dh1472_g[] = {
	0x05,
};

static const uint8_t keygen_dh1536_p[] = {
	0xE2, 0x5A, 0x3F, 0x8E, 0xE8, 0x72, 0x92, 0x84, 0x2F, 0xB2, 0xC0, 0x01,
	0x1F, 0xE9, 0x42, 0x0A, 0x0B, 0x1A, 0x71, 0x27, 0x51, 0xD8, 0xB5, 0xD8,
	0x31, 0x7B, 0xEE, 0xEE, 0xAA, 0xA5, 0x67, 0x67, 0x36, 0xAF, 0xAB, 0x55,
	0xB9, 0x07, 0xA7, 0xF7, 0x55, 0xE3, 0x08, 0x52, 0x7C, 0x55, 0xF3, 0x28,
	0x6F, 0x37, 0x84, 0xC7, 0x26, 0x66, 0x2F, 0x84, 0x8C, 0x09, 0xA5, 0x0C,
	0x5A, 0x60, 0x45, 0x7A, 0xDC, 0x11, 0x11, 0xB6, 0xF8, 0x6B, 0x2A, 0x63,
	0x6E, 0x86, 0x00, 0x65, 0x92, 0x8F, 0xE8, 0xB8, 0x4A, 0x2F, 0xDC, 0x62,
	0xE0, 0x2C, 0x1F, 0x95, 0x8F, 0x16, 0x7D, 0xB9, 0xC2, 0xCE, 0x58, 0x9A,
	0x12, 0x55, 0xC2, 0x01, 0xE2, 0xBE, 0xE5, 0xF0, 0x80, 0x04, 0xFD, 0xDD,
	0x95, 0x04, 0x11, 0xCA, 0xE3, 0xAA, 0x9E, 0x3F, 0x4C, 0x9A, 0xE9, 0x8C,
	0x11, 0xD9, 0x1C, 0x3A, 0x22, 0xEF, 0xEC, 0xB0, 0x9D, 0x73, 0x0C, 0xBB,
	0x4E, 0x3F, 0xFC, 0xF4, 0xFF, 0x63, 0x85, 0x7C, 0xE6, 0x5C, 0x22, 0x60,
	0x0A, 0x92, 0x32, 0xEC, 0x7C, 0x6B, 0x01, 0x72, 0x93, 0x42, 0x9D, 0x8D,
	0xC5, 0x78, 0x88, 0x8F, 0xCB, 0xA8, 0x93, 0xD1, 0x8F, 0x67, 0x74, 0x7A,
	0xA2, 0x93, 0x18, 0xDB, 0x84, 0xA5, 0xA6, 0xB9, 0x35, 0x0C, 0xCD, 0x8B,
	0x85, 0x2F, 0xC0, 0xBA, 0x27, 0x3D, 0x9C, 0x55, 0xDA, 0xB8, 0x94, 0x1F,
};

static const uint8_t keygen_dh1536_g[] = {
	0x05,
};

static const uint8_t keygen_dh1600_p[] = {
	0xAC, 0xF5, 0x91, 0x7E, 0xA3, 0x07, 0xD1, 0x24, 0x69, 0x38, 0x4D, 0x1B,
	0x1D, 0x60, 0x81, 0xF5, 0x22, 0x71, 0xE3, 0xEC, 0x17, 0x7B, 0x22, 0x81,
	0x22, 0xC7, 0x55, 0xBC, 0x61, 0x41, 0x03, 0xA5, 0x9D, 0xDC, 0x58, 0x28,
	0x6C, 0xE6, 0xF7, 0x9B, 0x0D, 0x2F, 0xD5, 0x4F, 0x3E, 0x4D, 0x6B, 0x26,
	0x5B, 0x09, 0x09, 0x79, 0x58, 0xC4, 0x39, 0x33, 0x8C, 0x29, 0x9E, 0x9F,
	0x5C, 0x76, 0xA5, 0xC8, 0x99, 0xF8, 0x69, 0xEE, 0x8F, 0xBA, 0x2C, 0xD4,
	0x68, 0x4F, 0xB2, 0xDC, 0xE6, 0xD9, 0x20, 0xE8, 0x02, 0xF2, 0x43, 0x9C,
	0xDD, 0x31, 0x79, 0xBD, 0x39, 0x78, 0x31, 0xC6, 0x03, 0x66, 0x69, 0x05,
	0xD6, 0x1E, 0xFE, 0x11, 0x1D, 0x9E, 0x01, 0xB8, 0xCB, 0xE8, 0xC7, 0x51,
	0xD9, 0xCD, 0x49, 0xEA, 0xD6, 0xC3, 0xC7, 0xF1, 0xC0, 0xA2, 0x6B, 0xD1,
	0x52, 0xD3, 0x80, 0xFD, 0x52, 0x35, 0x5C, 0x3D, 0xD3, 0x97, 0x61, 0x58,
	0x69, 0x1B, 0x4F, 0x9C, 0xF9, 0xC9, 0x34, 0xDA, 0x9B, 0x8B, 0x04, 0x18,
	0x12, 0x2F, 0xF1, 0x22, 0x78, 0x0F, 0xD3, 0xAA, 0x85, 0x06, 0xA9, 0xCA,
	0x9E, 0x80, 0x39, 0x25, 0x12, 0x41, 0xDD, 0x86, 0x58, 0x1F, 0x4D, 0x1F,
	0x9B, 0xDB, 0x63, 0xD0, 0x80, 0x5E, 0x53, 0xAC, 0x86, 0x0C, 0x1E, 0x11,
	0xB1, 0x0D, 0xB6, 0x1F, 0xFE, 0x7C, 0x23, 0x6A, 0x71, 0x47, 0xA5, 0xC2,
	0x20, 0x23, 0x9F, 0x1D, 0xDF, 0xB9, 0x91, 0x4B,
};

static const uint8_t keygen_dh1600_g[] = {
	0x05,
};

static const uint8_t keygen_dh1664_p[] = {
	0xAB, 0xF8, 0x74, 0x92, 0xCE, 0x1A, 0x3F, 0x89, 0xE1, 0xB7, 0x75, 0x5E,
	0x99, 0xBE, 0xFF, 0x73, 0x3E, 0x78, 0x86, 0xB0, 0x5E, 0x2F, 0x5C, 0xA4,
	0xB2, 0xE4, 0x72, 0x2C, 0x59, 0xB6, 0x64, 0x6F, 0x63, 0x72, 0xE3, 0x82,
	0xA4, 0xFB, 0x03, 0x57, 0x40, 0x6D, 0x6B, 0x1E, 0x2B, 0xB9, 0x8C, 0xB0,
	0x19, 0xB0, 0xE8, 0xC3, 0x3D, 0xEC, 0xC2, 0xA0, 0x91, 0x15, 0x02, 0x79,
	0x93, 0x31, 0xE4, 0x3A, 0x17, 0x9D, 0x9F, 0x68, 0xCD, 0x73, 0x28, 0x83,
	0xC3, 0x07, 0x43, 0x15, 0x05, 0x50, 0x9F, 0x78, 0x91, 0x2A, 0x98, 0x35,
	0xA3, 0xE4, 0x84, 0x84, 0x55, 0xDF, 0x32, 0x29, 0x27, 0x91, 0xC8, 0xFF,
	0x8B, 0x7B, 0x4E, 0x1B, 0xA1, 0x02, 0xBA, 0x31, 0x33, 0x79, 0x2E, 0x73,
	0x1D, 0x00, 0x30, 0xF2, 0x1E, 0x83, 0xB4, 0x7B, 0xD1, 0x76, 0xD4, 0x9E,
	0x2E, 0x32, 0xB6, 0xA5, 0x69, 0xB2, 0x28, 0x8E, 0xC4, 0xE3, 0xB0, 0x33,
	0x7E, 0x59, 0x90, 0x92, 0x40, 0x3F, 0x2C, 0x98, 0xC6, 0xEE, 0x26, 0xF1,
	0xE0, 0xE2, 0xB0, 0xA6, 0x50, 0xB0, 0x2E, 0xF1, 0xE3, 0x2D, 0x4F, 0xB5,
	0x58, 0xDA, 0x07, 0xBE, 0x9D, 0x20, 0x7C, 0x10, 0x23, 0x6D, 0x60, 0x96,
	0x11, 0xC9, 0xB4, 0xD4, 0x9C, 0xF0, 0x01, 0x8F, 0x9B, 0xC4, 0x83, 0xC6,
	0x47, 0x53, 0x74, 0xDD, 0x74, 0x01, 0x03, 0x9C, 0x99, 0xA0, 0x5E, 0xE2,
	0xA0, 0x05, 0x6E, 0x66, 0xB0, 0x01, 0xDD, 0x44, 0xFF, 0xA6, 0x65, 0x96,
	0x92, 0x2B, 0x89, 0x57,
};

static const uint8_t keygen_dh1664_g[] = {
	0x05,
};

static const uint8_t keygen_dh1728_p[] = {
	0xED, 0x9F, 0xF6, 0x0C, 0xD6, 0x18, 0x33, 0xE8, 0x26, 0x13, 0xF2, 0x56,
	0xE7, 0x9D, 0x03, 0x45, 0x99, 0xA0, 0x12, 0xB1, 0xBC, 0x45, 0xAD, 0xA7,
	0x14, 0xCC, 0x37, 0x97, 0x4D, 0x21, 0x6D, 0x52, 0x16, 0x6B, 0x20, 0x0B,
	0x8D, 0xA6, 0x43, 0xDF, 0x6C, 0x5C, 0x5A, 0xF2, 0x24, 0xBF, 0x04, 0x03,
	0x2E, 0xF6, 0xFE, 0x45, 0x30, 0x88, 0x2B, 0x07, 0x5C, 0xAA, 0xAE, 0x7E,
	0x33, 0xEF, 0xE6, 0x92, 0xD6, 0xFD, 0x61, 0x5F, 0xEF, 0xAC, 0xFB, 0x64,
	0x8D, 0x41, 0xE7, 0x52, 0xD2, 0x56, 0x74, 0x3A, 0xE5, 0x5E, 0x7E, 0x88,
	0x8D, 0xCD, 0xEA, 0xA8, 0xEF, 0x09, 0x9E, 0xDC, 0xBB, 0xC2, 0x10, 0xA8,
	0xE8, 0x7B, 0x24, 0x1B, 0x28, 0xA7, 0x1C, 0x0C, 0x53, 0xB8, 0xC2, 0xF3,
	0x01, 0x32, 0xBA, 0xE5, 0x8B, 0x6F, 0x3B, 0xB9, 0x36, 0x44, 0x5B, 0x3A,
	0x73, 0x44, 0x8F, 0xDE, 0x99, 0x69, 0x22, 0xE0, 0x2C, 0x45, 0x71, 0xA9,
	0x52, 0x1C, 0xCD, 0x19, 0x02, 0xBD, 0x06, 0xD2, 0x57, 0x45, 0xE3, 0x6C,
	0x96, 0x6D, 0x0B, 0x25, 0x56, 0x4C, 0x40, 0x2E, 0x7E, 0x83, 0xEE, 0xE1,
	0xB2, 0x65, 0x51, 0x04, 0x8D, 0x6A, 0x08, 0x44, 0xF0, 0x80, 0xB1, 0xFE,
	0x13, 0x15, 0x9B, 0x82, 0x65, 0xF0, 0x89, 0xBC, 0x7E, 0x63, 0xF6, 0x08,
	0xD3, 0xBA, 0xA9, 0x66, 0x35, 0x5F, 0x0C, 0xF7, 0xE9, 0x52, 0xA3, 0x4D,
	0x66, 0x01, 0xE7, 0x28, 0xF4, 0xDC, 0xF2, 0x46, 0xBB, 0x02, 0x95, 0x21,
	0x6A, 0x8F, 0x97, 0xA7, 0x3F, 0x06, 0x2E, 0xB2, 0x97, 0xEC, 0x5A, 0xFB,
};


static const uint8_t keygen_dh1728_g[] = {
	0x05,
};

static const uint8_t keygen_dh1792_p[] = {
	0x9A, 0x87, 0x16, 0x1D, 0x23, 0x55, 0xC7, 0x06, 0x55, 0xD7, 0xB1, 0xB3,
	0x71, 0x66, 0x9A, 0x16, 0x5A, 0xA6, 0x8F, 0x54, 0x50, 0x99, 0xBD, 0x90,
	0x8C, 0x84, 0xB3, 0xBC, 0x02, 0xFE, 0xCB, 0x07, 0x3A, 0x7E, 0x97, 0x12,
	0x32, 0xEC, 0xA0, 0x0B, 0xEA, 0x96, 0x51, 0xB4, 0x50, 0x4E, 0x3A, 0xCB,
	0x27, 0xA9, 0x42, 0x51, 0x49, 0x35, 0x9F, 0x45, 0x6B, 0xDA, 0xE0, 0x6C,
	0x10, 0x80, 0x00, 0x41, 0xC2, 0xFC, 0x91, 0xB6, 0x59, 0xCE, 0x76, 0x7F,
	0x21, 0xC6, 0x10, 0x8A, 0x68, 0x68, 0x54, 0x76, 0xCE, 0x33, 0xA6, 0x37,
	0xCF, 0x80, 0xDF, 0x37, 0x12, 0x77, 0xBA, 0xBF, 0x15, 0x10, 0x22, 0x4A,
	0xA1, 0x9B, 0xA6, 0x6B, 0x8E, 0x14, 0x4F, 0x64, 0xF4, 0x87, 0x64, 0xAA,
	0x6E, 0xBC, 0xB5, 0xB2, 0x96, 0x27, 0xD1, 0x1A, 0x6E, 0x6D, 0x4B, 0xC6,
	0x43, 0x28, 0xE9, 0xFC, 0xA4, 0xCB, 0x61, 0x8F, 0xEA, 0xE8, 0x40, 0xF2,
	0x0A, 0x19, 0xBA, 0x17, 0x49, 0x9A, 0x9F, 0xEF, 0x65, 0xBC, 0x70, 0x85,
	0xDD, 0x98, 0xB9, 0x8B, 0x25, 0x2C, 0xE1, 0x89, 0xC4, 0x60, 0xA0, 0xA9,
	0x7E, 0xFB, 0xEC, 0xBC, 0x4C, 0x1D, 0x25, 0x5D, 0x70, 0x2E, 0x73, 0x29,
	0x22, 0xA7, 0x83, 0x11, 0xC0, 0x64, 0xA9, 0xB6, 0xFA, 0x11, 0xC8, 0xC4,
	0x14, 0x30, 0x64, 0xE4, 0x76, 0xBE, 0x41, 0x62, 0xE6, 0x9F, 0xD6, 0x2A,
	0xEC, 0x60, 0xCF, 0xBD, 0x25, 0x2E, 0x3C, 0x6C, 0x40, 0x16, 0x32, 0x5C,
	0xB5, 0x3D, 0xFB, 0xD7, 0x3C, 0x59, 0x06, 0xBE, 0x37, 0x54, 0x40, 0x90,
	0x3D, 0x51, 0x01, 0x9A, 0x1E, 0x87, 0x05, 0xE3,
};

static const uint8_t keygen_dh1792_g[] = {
	0x05,
};

static const uint8_t keygen_dh1856_p[] = {
	0xA8, 0xD1, 0xC4, 0xCA, 0x89, 0xB5, 0xB3, 0x17, 0xEB, 0x4D, 0xB1, 0x58,
	0x73, 0x28, 0xDD, 0x7F, 0x67, 0x78, 0x13, 0x7D, 0x0D, 0x0E, 0x77, 0x43,
	0xB8, 0xA5, 0xCD, 0x84, 0xD3, 0x29, 0x3F, 0x00, 0xD7, 0xB0, 0x66, 0x95,
	0x52, 0x9D, 0x49, 0xAD, 0x9C, 0xCE, 0x83, 0xB1, 0xDB, 0x86, 0x90, 0x9A,
	0x40, 0xAD, 0x0A, 0xB0, 0x3A, 0x93, 0x33, 0x07, 0xC8, 0x32, 0x4D, 0x75,
	0x1E, 0x7B, 0xDC, 0xD3, 0x23, 0x5C, 0xCB, 0x83, 0x62, 0x79, 0x3A, 0x88,
	0xE8, 0xD0, 0x9B, 0x75, 0x4D, 0xA0, 0x1F, 0x3E, 0x08, 0x61, 0x5D, 0xEF,
	0x7C, 0xF0, 0x4D, 0xF8, 0xDD, 0x95, 0xEC, 0x31, 0xDD, 0x50, 0xA5, 0x4B,
	0xAA, 0x8E, 0xED, 0x45, 0x34, 0xCB, 0x87, 0x09, 0x4F, 0x36, 0xF6, 0xF4,
	0xF7, 0x08, 0x0D, 0xBA, 0xBC, 0x06, 0x22, 0x59, 0x83, 0x93, 0xF6, 0x4B,
	0xBC, 0x35, 0xAD, 0x48, 0x82, 0x40, 0x55, 0x51, 0xBC, 0xF8, 0xE2, 0x9A,
	0x11, 0xF2, 0x08, 0x1E, 0xCA, 0x55, 0x40, 0x36, 0x00, 0xBE, 0x1C, 0xC8,
	0x94, 0x2E, 0x35, 0x7D, 0xB0, 0xA4, 0xCD, 0x1C, 0xC1, 0xFF, 0x58, 0xE1,
	0xBB, 0x31, 0xE9, 0x13, 0x16, 0x7F, 0x43, 0x88, 0xB2, 0x43, 0x62, 0x2A,
	0x79, 0xE3, 0x61, 0xDF, 0xF5, 0xC9, 0x9C, 0x33, 0xDD, 0x93, 0x58, 0xFC,
	0x08, 0x51, 0xE8, 0xA8, 0x30, 0x61, 0x64, 0x83, 0xB3, 0x20, 0xC4, 0x53,
	0x95, 0xD6, 0xB3, 0x74, 0xB5, 0xFA, 0xB1, 0x65, 0xD1, 0xF9, 0xED, 0xB1,
	0x9B, 0x97, 0x86, 0xC6, 0xDE, 0x6E, 0x5F, 0xF4, 0x6A, 0x42, 0xFA, 0x1F,
	0x6E, 0xEA, 0x5B, 0x43, 0x4C, 0xCC, 0x62, 0x76, 0xFE, 0x9B, 0xA0, 0xB9,
	0x7C, 0x50, 0x5E, 0x8B,
};

static const uint8_t keygen_dh1856_g[] = {
	0x05,
};

static const uint8_t keygen_dh1920_p[] = {
	0xC2, 0x68, 0xB1, 0x2E, 0x41, 0xB7, 0xA3, 0xCC, 0xE8, 0x10, 0x48, 0xE8,
	0x80, 0xA5, 0x56, 0x82, 0x3C, 0x05, 0xA3, 0xC4, 0x20, 0xD5, 0xD7, 0x19,
	0x54, 0x60, 0xA4, 0x97, 0x95, 0x09, 0x3D, 0xDF, 0x10, 0xFF, 0x21, 0x0D,
	0x68, 0x19, 0x15, 0x89, 0xD1, 0x44, 0x14, 0x1E, 0xF2, 0xD8, 0xFD, 0x9D,
	0x35, 0x8C, 0xA6, 0x2B, 0x7D, 0x73, 0x9A, 0xEB, 0x86, 0x28, 0x4D, 0x3B,
	0x22, 0xEF, 0x1A, 0x35, 0xB6, 0x95, 0xA2, 0xFF, 0x03, 0x40, 0x49, 0x60,
	0x59, 0xD2, 0x2D, 0xAD, 0x00, 0xEF, 0x6A, 0x5B, 0xFB, 0xA6, 0x16, 0x01,
	0x92, 0x5E, 0x7D, 0x95, 0x2E, 0x18, 0xD5, 0x23, 0x9E, 0x9E, 0x87, 0xF2,
	0x2F, 0xFC, 0xE4, 0xF7, 0xC2, 0x28, 0x44, 0x97, 0xAB, 0xB5, 0xC1, 0xD3,
	0x8A, 0x53, 0xD7, 0xE5, 0x04, 0x78, 0xF2, 0xD9, 0x21, 0xD5, 0x46, 0x17,
	0x8A, 0xFC, 0xDB, 0x57, 0x29, 0xDD, 0x78, 0x5B, 0x05, 0xA9, 0xB0, 0x13,
	0x45, 0x1C, 0x84, 0xEE, 0x46, 0x73, 0x1B, 0x8E, 0x80, 0x45, 0x73, 0x04,
	0xF9, 0x23, 0x96, 0xBA, 0xBD, 0x51, 0x69, 0x81, 0xE4, 0xAE, 0x0D, 0x0A,
	0xC4, 0x93, 0xD9, 0x67, 0x14, 0x92, 0x5A, 0x96, 0x86, 0x9F, 0xCD, 0x6E,
	0x9A, 0x2A, 0x17, 0xA9, 0x1A, 0xDD, 0x00, 0x7C, 0x78, 0xD8, 0x06, 0xC5,
	0xB4, 0xA4, 0xF6, 0xCF, 0x22, 0xCD, 0xCA, 0x0E, 0x27, 0x97, 0xDD, 0x22,
	0x02, 0x31, 0x2B, 0x9C, 0xFF, 0x7E, 0x35, 0x3C, 0xDA, 0xAB, 0x51, 0x68,
	0x5A, 0x81, 0xF3, 0xA5, 0xA9, 0x04, 0xDA, 0x45, 0x07, 0xC6, 0x4A, 0xEF,
	0x5D, 0x0E, 0xC3, 0x41, 0xD6, 0xAC, 0xD0, 0x8D, 0x56, 0xAC, 0xB4, 0x89,
	0x53, 0x41, 0x06, 0x99, 0x83, 0x04, 0xBE, 0x6D, 0x2B, 0x28, 0xEB, 0x47,
};

static const uint8_t keygen_dh1920_g[] = {
	0x05,
};

static const uint8_t keygen_dh1984_p[] = {
	0xD8, 0xF3, 0xDC, 0x89, 0xE0, 0x6E, 0xD4, 0x07, 0xC3, 0x95, 0xC0, 0x17,
	0x39, 0xCE, 0xF6, 0xD0, 0x8A, 0xD7, 0x85, 0xD3, 0x83, 0x4D, 0xDC, 0x0B,
	0x85, 0x3B, 0xB7, 0x47, 0xEA, 0xDF, 0xE3, 0x34, 0xCA, 0xA9, 0x60, 0x9A,
	0x4F, 0x8E, 0x8B, 0xAE, 0x8A, 0xAF, 0xD3, 0x96, 0x56, 0xFC, 0x1D, 0x37,
	0x9A, 0x96, 0x57, 0x21, 0x32, 0xF0, 0x22, 0xE8, 0x68, 0x8B, 0x73, 0xAE,
	0x1B, 0xAB, 0xFB, 0x79, 0x1B, 0x7E, 0xDC, 0xAD, 0x9D, 0xA2, 0xF3, 0x5E,
	0x11, 0x46, 0x54, 0x4E, 0x88, 0x92, 0x2B, 0x79, 0x3B, 0xBB, 0x14, 0xD8,
	0x3B, 0x0B, 0xB0, 0x55, 0xE5, 0x9A, 0xA9, 0xA0, 0x94, 0x3C, 0x72, 0xE0,
	0x47, 0x58, 0xA5, 0x85, 0xDC, 0x4A, 0x6D, 0x50, 0x98, 0x28, 0x9B, 0xA1,
	0xB2, 0x95, 0xBB, 0x1A, 0x41, 0x05, 0xBC, 0x32, 0x02, 0x72, 0xBB, 0xF7,
	0x1A, 0x48, 0xC3, 0xD9, 0x4F, 0xBD, 0x32, 0xC8, 0x82, 0xAB, 0xCE, 0xDE,
	0x24, 0x6A, 0x0C, 0x92, 0xF8, 0xFB, 0xFF, 0x18, 0x33, 0x48, 0xAC, 0xD7,
	0xA3, 0x12, 0x0D, 0x52, 0x15, 0x3A, 0xA4, 0x6D, 0x85, 0x0A, 0xBF, 0x19,
	0x63, 0x82, 0x3E, 0xB9, 0x52, 0x98, 0xEA, 0xCC, 0x56, 0x66, 0x0F, 0x96,
	0x90, 0x1D, 0x35, 0xD6, 0xE1, 0xF6, 0x2B, 0x5B, 0xF7, 0x75, 0x12, 0xE5,
	0xD9, 0xED, 0x2E, 0x20, 0xA0, 0xF5, 0x68, 0xA8, 0xC9, 0x6E, 0x08, 0xD0,
	0xD2, 0xE7, 0xB6, 0xCB, 0x51, 0xA2, 0x5A, 0x34, 0x0B, 0xF3, 0x13, 0xAF,
	0x5A, 0x46, 0x8B, 0xCB, 0xC9, 0x46, 0x02, 0x15, 0xFE, 0x96, 0x45, 0x25,
	0x7D, 0x76, 0x56, 0x16, 0x8C, 0x97, 0xF3, 0x74, 0xFC, 0x2F, 0x5D, 0xFA,
	0xCD, 0x62, 0x23, 0x02, 0xF8, 0x19, 0x94, 0xEE, 0xE6, 0x18, 0x09, 0xDE,
	0x64, 0xB4, 0x3A, 0xDC, 0x0A, 0x5E, 0x26, 0x83,
};

static const uint8_t keygen_dh1984_g[] = {
	0x05,
};

static const uint8_t keygen_dh2048_p[] = {
	0x8F, 0x3E, 0xC1, 0x36, 0xCA, 0x60, 0xCE, 0xD1, 0xC5, 0xFD, 0x22, 0x05,
	0xD6, 0x94, 0x38, 0x20, 0x4F, 0xE1, 0xAF, 0xBC, 0xA6, 0x82, 0xBD, 0x71,
	0xFD, 0xD6, 0xC2, 0x61, 0xE8, 0xC1, 0xBD, 0xA9, 0x5E, 0xFD, 0x02, 0x51,
	0xB6, 0x1F, 0x38, 0x30, 0x44, 0x76, 0x94, 0xB3, 0x26, 0x79, 0x35, 0xC4,
	0xDF, 0x51, 0x80, 0xAF, 0x0D, 0x81, 0xCC, 0xA2, 0x33, 0xD1, 0x1E, 0x77,
	0xB8, 0x06, 0xD7, 0xE5, 0x83, 0x34, 0x04, 0xF2, 0x96, 0x24, 0x37, 0xFE,
	0xBC, 0x20, 0x9C, 0x66, 0x4C, 0xEB, 0x4F, 0xFD, 0x1F, 0x99, 0x56, 0x40,
	0xD9, 0xE8, 0x6B, 0x2A, 0x8D, 0x6B, 0x56, 0xB2, 0xB4, 0x6D, 0x83, 0x47,
	0x4C, 0x18, 0x53, 0x8B, 0xB1, 0xA3, 0x51, 0xC2, 0x07, 0xA3, 0x36, 0x43,
	0x4B, 0x94, 0x10, 0xFD, 0x24, 0xA3, 0x77, 0x74, 0x77, 0xFA, 0x98, 0x4B,
	0x43, 0x0B, 0xB6, 0xEC, 0x7F, 0x5C, 0x7E, 0xBA, 0xB7, 0xC7, 0xAA, 0x72,
	0x11, 0x9F, 0x73, 0x14, 0x45, 0x03, 0x7A, 0x4E, 0xE5, 0xE7, 0x5C, 0x64,
	0xB8, 0x66, 0x66, 0xCE, 0xEE, 0xF8, 0xFF, 0x61, 0x0F, 0x5D, 0x4E, 0xF6,
	0xED, 0xB1, 0xE5, 0x2F, 0x52, 0xAC, 0x2B, 0x8F, 0x34, 0x0D, 0x13, 0xF6,
	0x4A, 0x3A, 0x6C, 0x56, 0xB3, 0x3C, 0x52, 0xA8, 0xB9, 0xBC, 0x27, 0xCA,
	0x3B, 0xFB, 0x6E, 0xE7, 0x52, 0xFB, 0xB0, 0x2B, 0x4F, 0xC4, 0xBD, 0x24,
	0x36, 0xE4, 0x71, 0x07, 0x74, 0x69, 0x5F, 0xE0, 0xB8, 0x59, 0x5F, 0x74,
	0x2F, 0xCC, 0x03, 0xB0, 0x6D, 0x90, 0xD8, 0xD3, 0x7C, 0x5A, 0x31, 0x46,
	0x5C, 0x7D, 0x1C, 0xC8, 0x0D, 0x18, 0x80, 0x8E, 0x5A, 0xA8, 0x5E, 0x4D,
	0x11, 0x2B, 0x76, 0xAC, 0x1E, 0x00, 0x51, 0x80, 0xE3, 0xED, 0x7A, 0xC0,
	0x4F, 0x80, 0xFA, 0x5F, 0xD5, 0xD7, 0x4F, 0xA7, 0x14, 0xE1, 0x60, 0x3C,
	0x95, 0x77, 0xCA, 0x3B,
};

static const uint8_t keygen_dh2048_g[] = {
	0x05,
};

#define DH_ATTR(size) \
	attrs[0].attributeID = TEE_ATTR_DH_PRIME; \
	attrs[0].content.ref.buffer = (void *)keygen_dh##size##_p; \
	attrs[0].content.ref.length = ARRAY_SIZE(keygen_dh##size##_p); \
	attrs[1].attributeID = TEE_ATTR_DH_BASE; \
	attrs[1].content.ref.buffer = (void *)keygen_dh##size##_g; \
	attrs[1].content.ref.length = ARRAY_SIZE(keygen_dh##size##_g); \

TEE_Result dh_prepare_key(uint32_t ta_key __unused, TEE_ObjectHandle *key,
			  size_t key_size_bits, TEE_Attribute *attrs,
			  unsigned int *nb_attrs)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	assert(key);
	assert(attrs);
	assert(nb_attrs);

	switch (key_size_bits) {
	case 256:
		DH_ATTR(256);
		break;
	case 320:
		DH_ATTR(320);
		break;
	case 384:
		DH_ATTR(384);
		break;
	case 448:
		DH_ATTR(448);
		break;
	case 512:
		DH_ATTR(512);
		break;
	case 576:
		DH_ATTR(576);
		break;
	case 640:
		DH_ATTR(640);
		break;
	case 704:
		DH_ATTR(704);
		break;
	case 768:
		DH_ATTR(768);
		break;
	case 832:
		DH_ATTR(832);
		break;
	case 896:
		DH_ATTR(896);
		break;
	case 960:
		DH_ATTR(960);
		break;
	case 1024:
		DH_ATTR(1024);
		break;
	case 1088:
		DH_ATTR(1088);
		break;
	case 1152:
		DH_ATTR(1152);
		break;
	case 1216:
		DH_ATTR(1216);
		break;
	case 1280:
		DH_ATTR(1280);
		break;
	case 1344:
		DH_ATTR(1344);
		break;
	case 1408:
		DH_ATTR(1408);
		break;
	case 1472:
		DH_ATTR(1472);
		break;
	case 1536:
		DH_ATTR(1536);
		break;
	case 1600:
		DH_ATTR(1600);
		break;
	case 1664:
		DH_ATTR(1664);
		break;
	case 1728:
		DH_ATTR(1728);
		break;
	case 1792:
		DH_ATTR(1792);
		break;
	case 1856:
		DH_ATTR(1856);
		break;
	case 1920:
		DH_ATTR(1920);
		break;
	case 1984:
		DH_ATTR(1984);
		break;
	case 2048:
		DH_ATTR(2048);
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	*nb_attrs = 2;

	res = TEE_AllocateTransientObject(TEE_TYPE_DH_KEYPAIR, key_size_bits,
					  key);
	if (res) {
		EMSG("Fail to allocate the keypair");
		return res;
	}

	return TEE_SUCCESS;
}

