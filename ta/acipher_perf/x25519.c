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

TEE_Result x25519_prepare_key(uint32_t ta_key __unused, TEE_ObjectHandle *key,
			      size_t key_size_bits __unused,
			      TEE_Attribute *attrs __unused,
			      unsigned int *nb_attrs __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	assert(key);

	res = TEE_AllocateTransientObject(TEE_TYPE_X25519_KEYPAIR, 256, key);
	if (res) {
		EMSG("Fail to allocate the keypair");
		return res;
	}

	return TEE_SUCCESS;
}
