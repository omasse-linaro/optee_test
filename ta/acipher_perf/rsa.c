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

#include "ta_acipher_perf.h"
#include "ta_acipher_perf_priv.h"

#define MAX(a, b) ((a) > (b) ? (a) : (b))

/*
 * https://www.rfc-editor.org/rfc/rfc8017#section-7.1.1
 * message to be encrypted, an octet string of length mLen,
 * where mLen <= k - 2hLen - 2
 * The MAX macro is required because the macro could return a negative number
 * for PKCS1_OAEP_MGF1_SHA512 with a 1024 bits RSA keypair.
 */
#define MAX_SIZE_OAEP(key_size_bits, hash_size_bits) \
	MAX(((key_size_bits) / 8) - (2 * ((hash_size_bits) / 8)) - 2, 0);

static TEE_Result check_key_size(size_t key_size_bits)
{
	switch (key_size_bits) {
	case 256:
	case 512:
	case 768:
	case 1024:
	case 1536:
	case 2048:
	case 4096:
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

TEE_Result rsa_prepare_key(uint32_t ta_key __unused, TEE_ObjectHandle *key,
			   size_t key_size_bits, TEE_Attribute *attrs __unused,
			   unsigned int *nb_attrs __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	assert(key);

	res = check_key_size(key_size_bits);
	if (res) {
		EMSG("%zu bits RSA key is not supported", key_size_bits);
		return res;
	}

	res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size_bits,
					  key);
	if (res) {
		EMSG("Fail to allocate the keypair");
		return res;
	}

	return TEE_SUCCESS;
}

// TEE_Result rsa_get_buffer_sizes(uint32_t tee_alg, size_t key_size_bits,
// 				size_t *input_size, size_t *output_size)
// {
// 	assert(input_size);
// 	assert(output_size);

// 	switch (tee_alg) {
// 	/*
// 	 * For encryption/decryption RSA algorithms, allocate the maximum size
// 	 * possible as an input.
// 	 */
// 	case TEE_ALG_RSAES_PKCS1_V1_5:
// 		*input_size = (key_size_bits / 8) - 11;
// 		*output_size = key_size_bits / 8;
// 		break;
// 	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
// 		*input_size = MAX_SIZE_OAEP(key_size_bits, 160);
// 		*output_size = key_size_bits / 8;
// 		break;
// 	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
// 		*input_size = MAX_SIZE_OAEP(key_size_bits, 224);
// 		*output_size = key_size_bits / 8;
// 		break;
// 	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
// 		*input_size = MAX_SIZE_OAEP(key_size_bits, 256);
// 		*output_size = key_size_bits / 8;
// 		break;
// 	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
// 		*input_size = MAX_SIZE_OAEP(key_size_bits, 384);
// 		*output_size = key_size_bits / 8;
// 		break;
// 	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
// 		*input_size = MAX_SIZE_OAEP(key_size_bits, 512);
// 		*output_size = key_size_bits / 8;
// 		break;
// 	case TEE_ALG_RSA_NOPAD:
// 		*input_size = key_size_bits / 8;
// 		*output_size = key_size_bits / 8;
// 		break;
// 	/*
// 	 * For these operations, the input message is hashed and
// 	 * encoded, so the input message length has an impact on the
// 	 * hashing operation, not the sign/verify operations.
// 	 * 1024 bits buffer size is arbitrary.
// 	 */
// 	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
// 		*input_size = 1024 / 8;
// 		*output_size = 128 / 8;
// 		break;
// 	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
// 		*input_size = 1024 / 8;
// 		*output_size = 160 / 8;
// 		break;
// 	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
// 		*input_size = 1024 / 8;
// 		*output_size = 224 / 8;
// 		break;
// 	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
// 		*input_size = 1024 / 8;
// 		*output_size = 256 / 8;
// 		break;
// 	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
// 		*input_size = 1024 / 8;
// 		*output_size = 384 / 8;
// 		break;
// 	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
// 		*input_size = 1024 / 8;
// 		*output_size = 512 / 8;
// 		break;
// 	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
// 		*input_size = 1024 / 8;
// 		*output_size = 160 / 8;
// 		break;
// 	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
// 		*input_size = 1024 / 8;
// 		*output_size = 224 / 8;
// 		break;
// 	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
// 		*input_size = 1024 / 8;
// 		*output_size = 256 / 8;
// 		break;
// 	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
// 		*input_size = 1024 / 8;
// 		*output_size = 384 / 8;
// 		break;
// 	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
// 		*input_size = 1024 / 8;
// 		*output_size = 512 / 8;
// 		break;
// 	default:
// 		return TEE_ERROR_NOT_SUPPORTED;
// 	}

// 	if (*input_size == 0 || *output_size == 0)
// 		return TEE_ERROR_NOT_SUPPORTED;

// 	return TEE_SUCCESS;
// }
