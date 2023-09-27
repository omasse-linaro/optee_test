// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright NXP 2023
 */
#include "tee_api_defines.h"
#include "tee_api_types.h"
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <tee_ta_api.h>
#include <assert.h>
#include <util.h>

#include "ta_acipher_perf.h"
#include "ta_acipher_perf_priv.h"

TEE_Result ecdsa_prepare_key(uint32_t ta_key, TEE_ObjectHandle *key,
			     size_t key_size_bits, TEE_Attribute *attrs,
			     unsigned int *nb_attrs)
{
	uint32_t curve = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	assert(key);
	assert(attrs);
	assert(nb_attrs);

	switch (ta_key) {
	case TA_KEY_ECDSA_P192:
		curve = TEE_ECC_CURVE_NIST_P192;
		key_size_bits = 192;
		break;
	case TA_KEY_ECDSA_P224:
		curve = TEE_ECC_CURVE_NIST_P224;
		key_size_bits = 224;
		break;
	case TA_KEY_ECDSA_P256:
		curve = TEE_ECC_CURVE_NIST_P256;
		key_size_bits = 256;
		break;
	case TA_KEY_ECDSA_P384:
		curve = TEE_ECC_CURVE_NIST_P384;
		key_size_bits = 384;
		break;
	case TA_KEY_ECDSA_P521:
		curve = TEE_ECC_CURVE_NIST_P521;
		key_size_bits = 521;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	attrs[0].attributeID = TEE_ATTR_ECC_CURVE;
	attrs[0].content.value.b = sizeof(int);
	attrs[0].content.value.a = curve;
	*nb_attrs = 1;

	res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_KEYPAIR, key_size_bits,
					  key);
	if (res) {
		EMSG("Fail to allocate the keypair");
		return res;
	}

	return res;
}

TEE_Result ecdh_prepare_key(uint32_t ta_key, TEE_ObjectHandle *key,
			    size_t key_size_bits, TEE_Attribute *attrs,
			    unsigned int *nb_attrs)
{
	uint32_t curve = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	assert(key);
	assert(attrs);
	assert(nb_attrs);

	switch (ta_key) {
	case TA_KEY_ECDH_P192:
		curve = TEE_ECC_CURVE_NIST_P192;
		key_size_bits = 192;
		break;
	case TA_KEY_ECDH_P224:
		curve = TEE_ECC_CURVE_NIST_P224;
		key_size_bits = 224;
		break;
	case TA_KEY_ECDH_P256:
		curve = TEE_ECC_CURVE_NIST_P256;
		key_size_bits = 256;
		break;
	case TA_KEY_ECDH_P384:
		curve = TEE_ECC_CURVE_NIST_P384;
		key_size_bits = 384;
		break;
	case TA_KEY_ECDH_P521:
		curve = TEE_ECC_CURVE_NIST_P521;
		key_size_bits = 521;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	attrs[0].attributeID = TEE_ATTR_ECC_CURVE;
	attrs[0].content.value.b = sizeof(int);
	attrs[0].content.value.a = curve;
	*nb_attrs = 1;

	res = TEE_AllocateTransientObject(TEE_TYPE_ECDH_KEYPAIR, key_size_bits,
					  key);
	if (res) {
		EMSG("Fail to allocate the keypair");
		return res;
	}

	return res;
}

TEE_Result ecdsa_prepare_sign_verify(uint32_t ta_alg, size_t key_size_bits,
				     TEE_OperationHandle *sign_op,
				     TEE_OperationHandle *verify_op,
				     struct ta_buf *input,
				     struct ta_buf *output)
{
	uint32_t tee_alg = 0;
	TEE_Result res = TEE_ERROR_GENERIC;
	const uint8_t *digest = NULL;
	size_t digest_size = 0;
	size_t max_key_size = 0;

	switch (ta_alg) {
	case TA_ALG_ECDSA_SHA1:
		tee_alg = TEE_ALG_ECDSA_SHA1;
		digest = digest_sha1;
		digest_size = sizeof(digest_sha1);
		max_key_size = key_size_bits;
		break;
	case TA_ALG_ECDSA_SHA224:
		tee_alg = TEE_ALG_ECDSA_SHA224;
		digest = digest_sha224;
		digest_size = sizeof(digest_sha224);
		max_key_size = key_size_bits;
		break;
	case TA_ALG_ECDSA_SHA256:
		tee_alg = TEE_ALG_ECDSA_SHA256;
		digest = digest_sha256;
		digest_size = sizeof(digest_sha256);
		max_key_size = key_size_bits;
		break;
	case TA_ALG_ECDSA_SHA384:
		tee_alg = TEE_ALG_ECDSA_SHA384;
		digest = digest_sha384;
		digest_size = sizeof(digest_sha384);
		max_key_size = key_size_bits;
		break;
	case TA_ALG_ECDSA_SHA512:
		tee_alg = TEE_ALG_ECDSA_SHA512;
		digest = digest_sha512;
		digest_size = sizeof(digest_sha512);
		max_key_size = 521;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	input->data = calloc(1, digest_size);
	if (!input->data)
		return TEE_ERROR_OUT_OF_MEMORY;
	input->size = digest_size;
	memcpy(input->data, digest, digest_size);

	output->data = calloc(1, (key_size_bits / 8) * 2);
	if (!output->data)
		return TEE_ERROR_OUT_OF_MEMORY;
	output->size = (key_size_bits / 8) * 2;

	res = TEE_AllocateOperation(sign_op, tee_alg, TEE_MODE_SIGN,
				    max_key_size);
	if (res) {
		EMSG("Fail to allocate sign operation");
		return res;
	}

	res = TEE_AllocateOperation(verify_op, tee_alg, TEE_MODE_VERIFY,
				    max_key_size);
	if (res) {
		EMSG("Fail to allocate verify operation");
		return res;
	}

	return TEE_SUCCESS;
}
