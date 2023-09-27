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

TEE_Result sm2_kep_prepare_derive(uint32_t ta_alg, size_t key_size_bits,
				  TEE_OperationHandle *derive_op,
				  struct ta_buf *input, struct ta_buf *output)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
