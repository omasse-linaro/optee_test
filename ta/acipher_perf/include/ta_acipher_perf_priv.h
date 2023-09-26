// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright NXP 2023
 */

#ifndef TA_ACIPHER_PERF_PRIV_H
#define TA_ACIPHER_PERF_PRIV_H

#include "tee_api_types.h"
#include <stdint.h>
#include <tee_api.h>

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
