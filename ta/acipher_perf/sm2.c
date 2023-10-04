// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright NXP 2023
 */
#include "tee_api_defines.h"
#include "tee_api_types.h"
#include "utee_defines.h"
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <tee_ta_api.h>
#include <assert.h>

#include "ta_acipher_perf.h"
#include "ta_acipher_perf_priv.h"

static const uint8_t gmt_003_part5_b2_private_A[] = {
	/* dA */
	0x81, 0xEB, 0x26, 0xE9, 0x41, 0xBB, 0x5A, 0xF1, 0x6D, 0xF1, 0x16, 0x49,
	0x5F, 0x90, 0x69, 0x52, 0x72, 0xAE, 0x2C, 0xD6, 0x3D, 0x6C, 0x4A, 0xE1,
	0x67, 0x84, 0x18, 0xBE, 0x48, 0x23, 0x00, 0x29,
};
static const uint8_t gmt_003_part5_b2_public_xA[] = {
	/* xA */
	0x16, 0x0E, 0x12, 0x89, 0x7D, 0xF4, 0xED, 0xB6, 0x1D, 0xD8, 0x12, 0xFE,
	0xB9, 0x67, 0x48, 0xFB, 0xD3, 0xCC, 0xF4, 0xFF, 0xE2, 0x6A, 0xA6, 0xF6,
	0xDB, 0x95, 0x40, 0xAF, 0x49, 0xC9, 0x42, 0x32,
};
static const uint8_t gmt_003_part5_b2_public_yA[] = {
	/* xA */
	0x4A, 0x7D, 0xAD, 0x08, 0xBB, 0x9A, 0x45, 0x95, 0x31, 0x69, 0x4B, 0xEB,
	0x20, 0xAA, 0x48, 0x9D, 0x66, 0x49, 0x97, 0x5E, 0x1B, 0xFC, 0xF8, 0xC4,
	0x74, 0x1B, 0x78, 0xB4, 0xB2, 0x23, 0x00, 0x7F,
};
static const uint8_t gmt_003_part5_b2_eph_private_A[] = {
	/* rA */
	0xD4, 0xDE, 0x15, 0x47, 0x4D, 0xB7, 0x4D, 0x06, 0x49, 0x1C, 0x44, 0x0D,
	0x30, 0x5E, 0x01, 0x24, 0x00, 0x99, 0x0F, 0x3E, 0x39, 0x0C, 0x7E, 0x87,
	0x15, 0x3C, 0x12, 0xDB, 0x2E, 0xA6, 0x0B, 0xB3,
};
static const uint8_t gmt_003_part5_b2_eph_public_xA[] = {
	/* x1 where (x1, y1) = [rA]G */
	0x64, 0xCE, 0xD1, 0xBD, 0xBC, 0x99, 0xD5, 0x90, 0x04, 0x9B, 0x43, 0x4D,
	0x0F, 0xD7, 0x34, 0x28, 0xCF, 0x60, 0x8A, 0x5D, 0xB8, 0xFE, 0x5C, 0xE0,
	0x7F, 0x15, 0x02, 0x69, 0x40, 0xBA, 0xE4, 0x0E,
};
static const uint8_t gmt_003_part5_b2_eph_public_yA[] = {
	/* y1 where (x1, y1) = [rA]G */
	0x37, 0x66, 0x29, 0xC7, 0xAB, 0x21, 0xE7, 0xDB, 0x26, 0x09, 0x22, 0x49,
	0x9D, 0xDB, 0x11, 0x8F, 0x07, 0xCE, 0x8E, 0xAA, 0xE3, 0xE7, 0x72, 0x0A,
	0xFE, 0xF6, 0xA5, 0xCC, 0x06, 0x20, 0x70, 0xC0,
};
static const uint8_t gmt_003_part5_b2_public_xB[] = {
	/* xB */
	0x6A, 0xE8, 0x48, 0xC5, 0x7C, 0x53, 0xC7, 0xB1, 0xB5, 0xFA, 0x99, 0xEB,
	0x22, 0x86, 0xAF, 0x07, 0x8B, 0xA6, 0x4C, 0x64, 0x59, 0x1B, 0x8B, 0x56,
	0x6F, 0x73, 0x57, 0xD5, 0x76, 0xF1, 0x6D, 0xFB,
};
static const uint8_t gmt_003_part5_b2_public_yB[] = {
	/* yB */
	0xEE, 0x48, 0x9D, 0x77, 0x16, 0x21, 0xA2, 0x7B, 0x36, 0xC5, 0xC7, 0x99,
	0x20, 0x62, 0xE9, 0xCD, 0x09, 0xA9, 0x26, 0x43, 0x86, 0xF3, 0xFB, 0xEA,
	0x54, 0xDF, 0xF6, 0x93, 0x05, 0x62, 0x1C, 0x4D,
};
static const uint8_t gmt_003_part5_b2_private_B[] = {
	/* dB */
	0x78, 0x51, 0x29, 0x91, 0x7D, 0x45, 0xA9, 0xEA, 0x54, 0x37, 0xA5, 0x93,
	0x56, 0xB8, 0x23, 0x38, 0xEA, 0xAD, 0xDA, 0x6C, 0xEB, 0x19, 0x90, 0x88,
	0xF1, 0x4A, 0xE1, 0x0D, 0xEF, 0xA2, 0x29, 0xB5,
};
static const uint8_t gmt_003_part5_b2_eph_public_xB[] = {
	/* x2 where (x2, y2) = [rB]G */
	0xAC, 0xC2, 0x76, 0x88, 0xA6, 0xF7, 0xB7, 0x06, 0x09, 0x8B, 0xC9, 0x1F,
	0xF3, 0xAD, 0x1B, 0xFF, 0x7D, 0xC2, 0x80, 0x2C, 0xDB, 0x14, 0xCC, 0xCC,
	0xDB, 0x0A, 0x90, 0x47, 0x1F, 0x9B, 0xD7, 0x07,
};
static const uint8_t gmt_003_part5_b2_eph_public_yB[] = {
	/* y2 where (x2, y2) = [rB]G */
	0x2F, 0xED, 0xAC, 0x04, 0x94, 0xB2, 0xFF, 0xC4, 0xD6, 0x85, 0x38, 0x76,
	0xC7, 0x9B, 0x8F, 0x30, 0x1C, 0x65, 0x73, 0xAD, 0x0A, 0xA5, 0x0F, 0x39,
	0xFC, 0x87, 0x18, 0x1E, 0x1A, 0x1B, 0x46, 0xFE,
};
static const uint8_t gmt_003_part5_b2_eph_private_B[] = {
	/* rB */
	0x7E, 0x07, 0x12, 0x48, 0x14, 0xB3, 0x09, 0x48, 0x91, 0x25, 0xEA, 0xED,
	0x10, 0x11, 0x13, 0x16, 0x4E, 0xBF, 0x0F, 0x34, 0x58, 0xC5, 0xBD, 0x88,
	0x33, 0x5C, 0x1F, 0x9D, 0x59, 0x62, 0x43, 0xD6,
};
static const uint8_t gmt_003_part5_b2_id_A[] = {
	/* IDA */
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34,
	0x35, 0x36, 0x37, 0x38,
};
static const uint8_t gmt_003_part5_b2_id_B[] = {
	/* IDB */
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34,
	0x35, 0x36, 0x37, 0x38,
};
static const uint8_t gmt_003_part5_b2_conf_B[] = {
	/* S1 = SB */
	0xD3, 0xA0, 0xFE, 0x15, 0xDE, 0xE1, 0x85, 0xCE, 0xAE, 0x90, 0x7A, 0x6B,
	0x59, 0x5C, 0xC3, 0x2A, 0x26, 0x6E, 0xD7, 0xB3, 0x36, 0x7E, 0x99, 0x83,
	0xA8, 0x96, 0xDC, 0x32, 0xFA, 0x20, 0xF8, 0xEB,
};
uint8_t conf_A[32] = { };

TEE_Result sm2_prepare_key(uint32_t ta_key, TEE_ObjectHandle *key,
			   size_t key_size_bits __unused,
			   TEE_Attribute *attrs __unused,
			   unsigned int *nb_attrs __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t tee_alg = 0;

	assert(key);

	switch(ta_key) {
	case TA_KEY_SM2_DSA:
		tee_alg = TEE_TYPE_SM2_DSA_KEYPAIR;
		break;
	case TA_KEY_SM2_KEP:
		tee_alg = TEE_TYPE_SM2_KEP_KEYPAIR;
		break;
	case TA_KEY_SM2_PKE:
		tee_alg = TEE_TYPE_SM2_PKE_KEYPAIR;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	res = TEE_AllocateTransientObject(tee_alg, 256, key);
	if (res) {
		EMSG("Fail to allocate the keypair");
		return res;
	}

	return TEE_SUCCESS;
}

TEE_Result sm2_prepare_encrypt_decrypt(uint32_t ta_alg, size_t key_size_bits,
				       TEE_OperationHandle *encrypt_op,
				       TEE_OperationHandle *decrypt_op,
				       struct ta_buf *input,
				       struct ta_buf *output)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result sm2_dsa_sm3_prepare_sign_verify(uint32_t ta_alg,
					   size_t key_size_bits,
					   TEE_OperationHandle *sign_op,
					   TEE_OperationHandle *verify_op,
					   struct ta_buf *input,
					   struct ta_buf *output)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	const size_t input_size = 256 / 8;
	const size_t output_size = 512 / 8;
	const size_t max_key_size = 256;

	input->data = calloc(1, input_size);
	if (!input->data)
		return TEE_ERROR_OUT_OF_MEMORY;

	input->size = input_size;

	output->data = calloc(1, output_size);
	if (!output->data)
		return TEE_ERROR_OUT_OF_MEMORY;
	output->size = output_size;

	res = TEE_AllocateOperation(sign_op, TEE_ALG_SM2_DSA_SM3, TEE_MODE_SIGN,
				    max_key_size);
	if (res) {
		EMSG("Fail to allocate sign operation");
		return res;
	}

	res = TEE_AllocateOperation(verify_op, TEE_ALG_SM2_DSA_SM3,
				    TEE_MODE_VERIFY, max_key_size);
	if (res) {
		EMSG("Fail to allocate verify operation");
		return res;
	}

	return TEE_SUCCESS;
}

TEE_Result sm2_kep_populate_keys(TEE_ObjectHandle *key1, TEE_ObjectHandle *key2,
				 size_t key_size_bits)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_Attribute params[3] = { };

	if (key_size_bits != 256)
		return TEE_ERROR_NOT_SUPPORTED;

	res = TEE_AllocateTransientObject(TEE_TYPE_SM2_KEP_KEYPAIR,
					  key_size_bits,
					  key1);
	if (res) {
		EMSG("Fail to allocate the keypair");
		return res;
	}

	params[0].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_X;
	params[0].content.ref.buffer = (void*)gmt_003_part5_b2_public_xA;
	params[0].content.ref.length = sizeof(gmt_003_part5_b2_public_xA);
	params[1].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_Y;
	params[1].content.ref.buffer = (void*)gmt_003_part5_b2_public_yA;
	params[1].content.ref.length = sizeof(gmt_003_part5_b2_public_yA);
	params[2].attributeID = TEE_ATTR_ECC_PRIVATE_VALUE;
	params[2].content.ref.buffer = (void*)gmt_003_part5_b2_private_A;
	params[2].content.ref.length = sizeof(gmt_003_part5_b2_private_A);

	res = TEE_PopulateTransientObject(*key1, params, 3);
	if (res) {
		EMSG("Fail to populate the keypair");
		goto err;
	}

	res = TEE_AllocateTransientObject(TEE_TYPE_SM2_KEP_KEYPAIR,
					  key_size_bits,
					  key2);
	if (res) {
		EMSG("Fail to allocate the keypair");
		goto err;
	}

	params[0].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_X;
	params[0].content.ref.buffer = (void*)gmt_003_part5_b2_eph_public_xA;
	params[0].content.ref.length = sizeof(gmt_003_part5_b2_eph_public_xA);
	params[1].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_Y;
	params[1].content.ref.buffer = (void*)gmt_003_part5_b2_eph_public_yA;
	params[1].content.ref.length = sizeof(gmt_003_part5_b2_eph_public_yA);
	params[2].attributeID = TEE_ATTR_ECC_PRIVATE_VALUE;
	params[2].content.ref.buffer = (void*)gmt_003_part5_b2_eph_private_A;
	params[2].content.ref.length = sizeof(gmt_003_part5_b2_eph_private_A);

	res = TEE_PopulateTransientObject(*key2, params, 3);
	if (res) {
		EMSG("Fail to populate the keypair");
		goto err;
	}

	return TEE_SUCCESS;
err:
	TEE_FreeTransientObject(*key1);
	TEE_FreeTransientObject(*key2);

	return res;
}

TEE_Result sm2_kep_prepare_derive(uint32_t ta_alg, size_t key_size_bits,
				  TEE_OperationHandle *derive_op,
				  TEE_ObjectHandle *derived_key,
				  TEE_Attribute *attrs, unsigned int *nb_attrs)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	if (key_size_bits != 256)
		return TEE_ERROR_NOT_SUPPORTED;

	if (ta_alg != TA_ALG_SM2_KEP)
		return TEE_ERROR_NOT_SUPPORTED;

	res = TEE_AllocateOperation(derive_op, TEE_ALG_SM2_KEP,
				    TEE_MODE_DERIVE,
				    key_size_bits * 2 /* Two 256-bit keys */);
	if (res) {
		EMSG("Fail to allocate derive operation");
		return res;
	}

	attrs[0].attributeID = TEE_ATTR_SM2_KEP_USER;
	attrs[0].content.value.a = 0; /* Initiator role */
	attrs[0].content.value.b = 0; /* Not used */
	attrs[1].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_X;
	attrs[1].content.ref.buffer = (void*)gmt_003_part5_b2_public_xB;
	attrs[1].content.ref.length = sizeof(gmt_003_part5_b2_public_xB);
	attrs[2].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_Y;
	attrs[2].content.ref.buffer = (void*)gmt_003_part5_b2_public_yB;
	attrs[2].content.ref.length = sizeof(gmt_003_part5_b2_public_yB);
	attrs[3].attributeID = TEE_ATTR_ECC_EPHEMERAL_PUBLIC_VALUE_X;
	attrs[3].content.ref.buffer = (void*)gmt_003_part5_b2_eph_public_xB;
	attrs[3].content.ref.length = sizeof(gmt_003_part5_b2_eph_public_xB);
	attrs[4].attributeID = TEE_ATTR_ECC_EPHEMERAL_PUBLIC_VALUE_Y;
	attrs[4].content.ref.buffer = (void*)gmt_003_part5_b2_eph_public_yB;
	attrs[4].content.ref.length = sizeof(gmt_003_part5_b2_eph_public_yB);
	attrs[5].attributeID = TEE_ATTR_SM2_ID_INITIATOR;
	attrs[5].content.ref.buffer = (void*)gmt_003_part5_b2_id_A;
	attrs[5].content.ref.length = sizeof(gmt_003_part5_b2_id_A);
	attrs[6].attributeID = TEE_ATTR_SM2_ID_RESPONDER;
	attrs[6].content.ref.buffer = (void*)gmt_003_part5_b2_id_B;
	attrs[6].content.ref.length = sizeof(gmt_003_part5_b2_id_B);
	attrs[7].attributeID = TEE_ATTR_SM2_KEP_CONFIRMATION_IN;
	attrs[7].content.ref.buffer = (void*)gmt_003_part5_b2_conf_B;
	attrs[7].content.ref.length = sizeof(gmt_003_part5_b2_conf_B);
	attrs[8].attributeID = TEE_ATTR_SM2_KEP_CONFIRMATION_OUT;
	attrs[8].content.ref.buffer = (void*)conf_A;
	attrs[8].content.ref.length = sizeof(conf_A);
	*nb_attrs = 9;

	res = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET,
					  key_size_bits, derived_key);
	if (res) {
		EMSG("Fail to allocate derived key");
		return res;
	}

	return TEE_SUCCESS;
}
