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

static const uint8_t x25519_bob_public[] = {
	0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
	0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
	0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
	0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
};

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

TEE_Result x25519_prepare_derive(uint32_t ta_alg, size_t key_size_bits,
				  TEE_OperationHandle *derive_op,
				  TEE_ObjectHandle *derived_key,
				  TEE_Attribute *attrs, unsigned int *nb_attrs)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	if (key_size_bits != 256)
		return TEE_ERROR_NOT_SUPPORTED;

	res = TEE_AllocateOperation(derive_op, TEE_ALG_X25519,
				    TEE_MODE_DERIVE, key_size_bits);
	if (res) {
		EMSG("Fail to allocate derive operation");
		return res;
	}

	attrs[0].attributeID = TEE_ATTR_X25519_PUBLIC_VALUE;
	attrs[0].content.ref.buffer = (void *)x25519_bob_public;
	attrs[0].content.ref.length = sizeof(x25519_bob_public);
	*nb_attrs = 1;

	res = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET,
					  key_size_bits, derived_key);
	if (res) {
		EMSG("Fail to allocate derived key");
		return res;
	}

	return TEE_SUCCESS;
}

TEE_Result x448_prepare_derive(uint32_t ta_alg, size_t key_size_bits,
				  TEE_OperationHandle *derive_op,
				  TEE_ObjectHandle *derived_key,
				  TEE_Attribute *attrs, unsigned int *nb_attrs)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
