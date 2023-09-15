// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright NXP 2023
 */
#include "tee_api_defines.h"
#include "tee_api_types.h"
#include "utee_defines.h"
#include <stdint.h>
#include <stdbool.h>
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
