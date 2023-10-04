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

static const uint8_t nist_kas_ecc_cdh_testvector_1_public_x[] = {
/* QCAVSx */
	0x42, 0xea, 0x6d, 0xd9, 0x96, 0x9d, 0xd2, 0xa6, 0x1f, 0xea, 0x1a, 0xac,
	0x7f, 0x8e, 0x98, 0xed, 0xcc, 0x89, 0x6c, 0x6e, 0x55, 0x85, 0x7c, 0xc0
};
static const uint8_t nist_kas_ecc_cdh_testvector_1_public_y[] = {
/* QCAVSy */
	0xdf, 0xbe, 0x5d, 0x7c, 0x61, 0xfa, 0xc8, 0x8b, 0x11, 0x81, 0x1b, 0xde,
	0x32, 0x8e, 0x8a, 0x0d, 0x12, 0xbf, 0x01, 0xa9, 0xd2, 0x04, 0xb5, 0x23
};

static const uint8_t nist_kas_ecc_cdh_testvector_26_public_x[] = {
/* QCAVSx */
	0xaf, 0x33, 0xcd, 0x06, 0x29, 0xbc, 0x7e, 0x99, 0x63, 0x20, 0xa3, 0xf4,
	0x03, 0x68, 0xf7, 0x4d, 0xe8, 0x70, 0x4f, 0xa3, 0x7b, 0x8f, 0xab, 0x69,
	0xab, 0xaa, 0xe2, 0x80
};
static const uint8_t nist_kas_ecc_cdh_testvector_26_public_y[] = {
/* QCAVSy */
	0x88, 0x20, 0x92, 0xcc, 0xbb, 0xa7, 0x93, 0x0f, 0x41, 0x9a, 0x8a, 0x4f,
	0x9b, 0xb1, 0x69, 0x78, 0xbb, 0xc3, 0x83, 0x87, 0x29, 0x99, 0x25, 0x59,
	0xa6, 0xf2, 0xe2, 0xd7
};

static const uint8_t nist_kas_ecc_cdh_testvector_51_public_x[] = {
/* QCAVSx */
	0x70, 0x0c, 0x48, 0xf7, 0x7f, 0x56, 0x58, 0x4c, 0x5c, 0xc6, 0x32, 0xca,
	0x65, 0x64, 0x0d, 0xb9, 0x1b, 0x6b, 0xac, 0xce, 0x3a, 0x4d, 0xf6, 0xb4,
	0x2c, 0xe7, 0xcc, 0x83, 0x88, 0x33, 0xd2, 0x87
};
static const uint8_t nist_kas_ecc_cdh_testvector_51_public_y[] = {
/* QCAVSy */
	0xdb, 0x71, 0xe5, 0x09, 0xe3, 0xfd, 0x9b, 0x06, 0x0d, 0xdb, 0x20, 0xba,
	0x5c, 0x51, 0xdc, 0xc5, 0x94, 0x8d, 0x46, 0xfb, 0xf6, 0x40, 0xdf, 0xe0,
	0x44, 0x17, 0x82, 0xca, 0xb8, 0x5f, 0xa4, 0xac
};

static const uint8_t nist_kas_ecc_cdh_testvector_76_public_x[] = {
/* QCAVSx */
	0xa7, 0xc7, 0x6b, 0x97, 0x0c, 0x3b, 0x5f, 0xe8, 0xb0, 0x5d, 0x28, 0x38,
	0xae, 0x04, 0xab, 0x47, 0x69, 0x7b, 0x9e, 0xaf, 0x52, 0xe7, 0x64, 0x59,
	0x2e, 0xfd, 0xa2, 0x7f, 0xe7, 0x51, 0x32, 0x72, 0x73, 0x44, 0x66, 0xb4,
	0x00, 0x09, 0x1a, 0xdb, 0xf2, 0xd6, 0x8c, 0x58, 0xe0, 0xc5, 0x00, 0x66
};
static const uint8_t nist_kas_ecc_cdh_testvector_76_public_y[] = {
/* QCAVSy */
	0xac, 0x68, 0xf1, 0x9f, 0x2e, 0x1c, 0xb8, 0x79, 0xae, 0xd4, 0x3a, 0x99,
	0x69, 0xb9, 0x1a, 0x08, 0x39, 0xc4, 0xc3, 0x8a, 0x49, 0x74, 0x9b, 0x66,
	0x1e, 0xfe, 0xdf, 0x24, 0x34, 0x51, 0x91, 0x5e, 0xd0, 0x90, 0x5a, 0x32,
	0xb0, 0x60, 0x99, 0x2b, 0x46, 0x8c, 0x64, 0x76, 0x6f, 0xc8, 0x43, 0x7a
};

static const uint8_t nist_kas_ecc_cdh_testvector_101_public_x[] = {
/* QCAVSx */
	0x00, 0x68, 0x5a, 0x48, 0xe8, 0x6c, 0x79, 0xf0, 0xf0, 0x87, 0x5f, 0x7b,
	0xc1, 0x8d, 0x25, 0xeb, 0x5f, 0xc8, 0xc0, 0xb0, 0x7e, 0x5d, 0xa4, 0xf4,
	0x37, 0x0f, 0x3a, 0x94, 0x90, 0x34, 0x08, 0x54, 0x33, 0x4b, 0x1e, 0x1b,
	0x87, 0xfa, 0x39, 0x54, 0x64, 0xc6, 0x06, 0x26, 0x12, 0x4a, 0x4e, 0x70,
	0xd0, 0xf7, 0x85, 0x60, 0x1d, 0x37, 0xc0, 0x98, 0x70, 0xeb, 0xf1, 0x76,
	0x66, 0x68, 0x77, 0xa2, 0x04, 0x6d
};
static const uint8_t nist_kas_ecc_cdh_testvector_101_public_y[] = {
/* QCAVSy */
	0x01, 0xba, 0x52, 0xc5, 0x6f, 0xc8, 0x77, 0x6d, 0x9e, 0x8f, 0x5d, 0xb4,
	0xf0, 0xcc, 0x27, 0x63, 0x6d, 0x0b, 0x74, 0x1b, 0xbe, 0x05, 0x40, 0x06,
	0x97, 0x94, 0x2e, 0x80, 0xb7, 0x39, 0x88, 0x4a, 0x83, 0xbd, 0xe9, 0x9e,
	0x0f, 0x67, 0x16, 0x93, 0x9e, 0x63, 0x2b, 0xc8, 0x98, 0x6f, 0xa1, 0x8d,
	0xcc, 0xd4, 0x43, 0xa3, 0x48, 0xb6, 0xc3, 0xe5, 0x22, 0x49, 0x79, 0x55,
	0xa4, 0xf3, 0xc3, 0x02, 0xf6, 0x76
};

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

TEE_Result ecdh_prepare_derive(uint32_t ta_alg __unused, size_t key_size_bits,
			       TEE_OperationHandle *derive_op,
			       TEE_ObjectHandle *derived_key,
			       TEE_Attribute *attrs, unsigned int *nb_attrs)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	const uint8_t *public_value_x = NULL;
	const uint8_t *public_value_y = NULL;

	res = TEE_AllocateOperation(derive_op, TEE_ALG_ECDH_DERIVE_SHARED_SECRET,
				    TEE_MODE_DERIVE, key_size_bits);
	if (res) {
		EMSG("Fail to allocate derive operation");
		return res;
	}

	switch (key_size_bits) {
	case 192:
		public_value_x = nist_kas_ecc_cdh_testvector_1_public_x;
		public_value_y = nist_kas_ecc_cdh_testvector_1_public_y;
		break;
	case 224:
		public_value_x = nist_kas_ecc_cdh_testvector_26_public_x;
		public_value_y = nist_kas_ecc_cdh_testvector_26_public_y;
		break;
	case 256:
		public_value_x = nist_kas_ecc_cdh_testvector_51_public_x;
		public_value_y = nist_kas_ecc_cdh_testvector_51_public_y;
		break;
	case 384:
		public_value_x = nist_kas_ecc_cdh_testvector_76_public_x;
		public_value_y = nist_kas_ecc_cdh_testvector_76_public_y;
		break;
	case 521:
		public_value_x = nist_kas_ecc_cdh_testvector_101_public_x;
		public_value_y = nist_kas_ecc_cdh_testvector_101_public_y;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	attrs[0].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_X;
	attrs[0].content.ref.buffer = (void *)public_value_x;
	attrs[0].content.ref.length = (key_size_bits >> 3) +
				      ((key_size_bits & 7) != 0);
	attrs[1].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_Y;
	attrs[1].content.ref.buffer = (void *)public_value_y;
	attrs[1].content.ref.length = (key_size_bits >> 3) +
				      ((key_size_bits & 7) != 0);
	*nb_attrs = 2;

	res = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET,
					  key_size_bits, derived_key);
	if (res) {
		EMSG("Fail to allocate derived key");
		return res;
	}

	return TEE_SUCCESS;
}
