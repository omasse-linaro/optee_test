// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright NXP 2023
 */

#ifndef TA_ACIPHER_PERF_PRIV_H
#define TA_ACIPHER_PERF_PRIV_H

#include "tee_api_types.h"
#include <stdint.h>
#include <tee_api.h>

/* Digests of "OPTEE_acipher_benchmark" string */
static const uint8_t digest_md5[] = {
	0x8B, 0x92, 0x26, 0xA0, 0x2E, 0xE9, 0x56, 0x13,
	0x0C, 0x5B, 0xF9, 0x39, 0x8B, 0x99, 0xFF, 0xAC,
};
static const uint8_t digest_sha1[] = {
	0xB0, 0x79, 0x3F, 0xEC, 0xC5, 0x56, 0x6F, 0xEF, 0x9D, 0xEC,
	0x9A, 0xBB, 0xBD, 0x29, 0x3E, 0x06, 0x39, 0x15, 0xF9, 0x3C,
};
static const uint8_t digest_sha224[] = {
	0x9C, 0xD8, 0x13, 0xF2, 0xF1, 0x50, 0x59, 0xFC, 0xF0, 0xC6,
	0xF0, 0xF4, 0xFB, 0x7F, 0x38, 0xA0, 0xE2, 0x6E, 0xF0, 0x2D,
	0x6D, 0x5F, 0x2C, 0x68, 0xF1, 0x0B, 0x7F, 0xDD,
};
static const uint8_t digest_sha256[] = {
	0xCE, 0xD3, 0xC3, 0xEC, 0x43, 0x36, 0x99, 0xF2, 0xAF, 0x09, 0x41,
	0x2A, 0x89, 0xD7, 0x95, 0x5A, 0x41, 0x02, 0x1B, 0xFF, 0xCE, 0x82,
	0x31, 0xED, 0x39, 0x36, 0xC4, 0xAF, 0x69, 0xB8, 0x12, 0xC3,
};
static const uint8_t digest_sha384[] = {
	0x83, 0xA3, 0x3F, 0x95, 0xBC, 0x07, 0x48, 0xD7, 0x6C, 0xBF, 0x10, 0x7A,
	0x18, 0x0E, 0xD9, 0xF5, 0xBD, 0x97, 0x18, 0x96, 0xCB, 0x53, 0xD2, 0x39,
	0xF5, 0x13, 0xCC, 0xBC, 0x9B, 0x65, 0x52, 0xCF, 0xCA, 0xB4, 0x11, 0xF3,
	0x63, 0x5F, 0x1F, 0xD3, 0x2D, 0x46, 0xCF, 0xEC, 0xF7, 0x9B, 0x6A, 0xED,
};
static const uint8_t digest_sha512[] = {
	0x65, 0xAE, 0xFE, 0xD7, 0x5E, 0x29, 0x31, 0x08, 0xF7, 0xF2, 0x30,
	0xD0, 0xA8, 0x1E, 0xDB, 0x78, 0x63, 0x5B, 0xE0, 0x25, 0xA1, 0x28,
	0x7D, 0x29, 0x5B, 0x32, 0x09, 0xA6, 0x5F, 0x8E, 0xF6, 0x5E, 0xA2,
	0x27, 0xB3, 0x1F, 0xA0, 0x9C, 0xC4, 0x3E, 0x1A, 0x0C, 0x51, 0xDF,
	0xD9, 0x26, 0xAD, 0x4A, 0x58, 0xE5, 0xA2, 0x94, 0x2F, 0xFD, 0x32,
	0x25, 0x13, 0xF4, 0x58, 0x21, 0x25, 0xD8, 0x79, 0xE7,
};

struct ta_buf {
	uint8_t *data;
	size_t size;
};

TEE_Result rsa_prepare_key(uint32_t ta_key, TEE_ObjectHandle *key,
			   size_t key_size_bits, TEE_Attribute *attrs,
			   unsigned int *nb_attrs);
TEE_Result dsa_prepare_key(uint32_t ta_key, TEE_ObjectHandle *key,
			   size_t key_size_bits, TEE_Attribute *attrs,
			   unsigned int *nb_attrs);
TEE_Result dh_prepare_key(uint32_t ta_key, TEE_ObjectHandle *key,
			  size_t key_size_bits, TEE_Attribute *attrs,
			  unsigned int *nb_attrs);
TEE_Result ecdsa_prepare_key(uint32_t ta_key, TEE_ObjectHandle *key,
			     size_t key_size_bits, TEE_Attribute *attrs,
			     unsigned int *nb_attrs);
TEE_Result ecdh_prepare_key(uint32_t ta_key, TEE_ObjectHandle *key,
			    size_t key_size_bits, TEE_Attribute *attrs,
			    unsigned int *nb_attrs);
TEE_Result ed25519_prepare_key(uint32_t ta_key, TEE_ObjectHandle *key,
				size_t key_size_bits, TEE_Attribute *attrs,
				unsigned int *nb_attrs);
TEE_Result x25519_prepare_key(uint32_t ta_key, TEE_ObjectHandle *key,
			       size_t key_size_bits, TEE_Attribute *attrs,
			       unsigned int *nb_attrs);
TEE_Result sm2_prepare_key(uint32_t ta_key, TEE_ObjectHandle *key,
			   size_t key_size_bits, TEE_Attribute *attrs,
			   unsigned int *nb_attrs);

TEE_Result rsa_prepare_encrypt_decrypt(uint32_t ta_alg, size_t key_size_bits,
				       TEE_OperationHandle *encrypt_op,
				       TEE_OperationHandle *decrypt_op,
				       struct ta_buf *input,
				       struct ta_buf *output);
TEE_Result sm2_prepare_encrypt_decrypt(uint32_t ta_alg, size_t key_size_bits,
				       TEE_OperationHandle *encrypt_op,
				       TEE_OperationHandle *decrypt_op,
				       struct ta_buf *input,
				       struct ta_buf *output);
TEE_Result rsa_prepare_sign_verify(uint32_t ta_alg, size_t key_size_bits,
				   TEE_OperationHandle *sign_op,
				   TEE_OperationHandle *verify_op,
				   struct ta_buf *input, struct ta_buf *output);
TEE_Result dsa_prepare_sign_verify(uint32_t ta_alg, size_t key_size_bits,
				   TEE_OperationHandle *sign_op,
				   TEE_OperationHandle *verify_op,
				   struct ta_buf *input, struct ta_buf *output);
TEE_Result ecdsa_prepare_sign_verify(uint32_t ta_alg, size_t key_size_bits,
				     TEE_OperationHandle *sign_op,
				     TEE_OperationHandle *verify_op,
				     struct ta_buf *input,
				     struct ta_buf *output);
TEE_Result ed25519_prepare_sign_verify(uint32_t ta_alg, size_t key_size_bits,
				       TEE_OperationHandle *sign_op,
				       TEE_OperationHandle *verify_op,
				       struct ta_buf *input,
				       struct ta_buf *output);
TEE_Result sm2_dsa_sm3_prepare_sign_verify(uint32_t ta_alg,
					   size_t key_size_bits,
					   TEE_OperationHandle *sign_op,
					   TEE_OperationHandle *verify_op,
					   struct ta_buf *input,
					   struct ta_buf *output);

TEE_Result prepare_keygen(uint32_t ta_key, size_t key_size_bits);
TEE_Result keygen(uint32_t ta_key, size_t key_size_bits, unsigned int loops);
TEE_Result prepare_op(uint32_t ta_key, size_t key_size_bits, uint32_t ta_alg);
TEE_Result sign(uint32_t ta_alg, unsigned int loop);
TEE_Result verify(uint32_t ta_alg, unsigned int loop);
TEE_Result encrypt(uint32_t ta_alg, unsigned int loop);
TEE_Result decrypt(uint32_t ta_alg, unsigned int loop);
TEE_Result derive(uint32_t ta_alg, unsigned int loop);
void free_ta_ctx(void);

#endif /* TA_ACIPHER_PERF_PRIV_H */
