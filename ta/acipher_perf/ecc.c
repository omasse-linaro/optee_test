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
