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

TEE_Result rsa_prepare_encrypt_decrypt(uint32_t ta_alg, size_t key_size_bits,
				       TEE_OperationHandle *encrypt_op,
				       TEE_OperationHandle *decrypt_op,
				       struct ta_buf *input,
				       struct ta_buf *output)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t tee_alg = 0;
	size_t input_size = 0;
	size_t output_size = 0;

	assert(encrypt_op);
	assert(decrypt_op);
	assert(input);
	assert(output);

	switch (ta_alg) {
	case TA_ALG_RSAES_PKCS1_V1_5:
		tee_alg = TEE_ALG_RSAES_PKCS1_V1_5;
		input_size = (key_size_bits / 8) - 11;
		output_size = key_size_bits / 8;
		break;
	case TA_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
		tee_alg = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1;
		input_size = MAX_SIZE_OAEP(key_size_bits, 160);
		output_size = key_size_bits / 8;
		break;
	case TA_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
		tee_alg = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224;
		input_size = MAX_SIZE_OAEP(key_size_bits, 224);
		output_size = key_size_bits / 8;
		break;
	case TA_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
		tee_alg = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256;
		input_size = MAX_SIZE_OAEP(key_size_bits, 256);
		output_size = key_size_bits / 8;
		break;
	case TA_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
		tee_alg = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384;
		input_size = MAX_SIZE_OAEP(key_size_bits, 384);
		output_size = key_size_bits / 8;
		break;
	case TA_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
		tee_alg = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512;
		input_size = MAX_SIZE_OAEP(key_size_bits, 512);
		output_size = key_size_bits / 8;
		break;
	case TA_ALG_RSA_NOPAD:
		tee_alg = TEE_ALG_RSA_NOPAD;
		input_size = key_size_bits / 8;
		output_size = key_size_bits / 8;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	/* MAX_SIZE_OAEP can return zero */
	if (!input_size || !output_size)
		return TEE_ERROR_NOT_SUPPORTED;

	res = TEE_AllocateOperation(encrypt_op, tee_alg, TEE_MODE_ENCRYPT,
				    4096);
	if (res) {
		EMSG("Fail to allocate encrypt operation");
		return res;
	}

	res = TEE_AllocateOperation(decrypt_op, tee_alg, TEE_MODE_DECRYPT,
				    4096);
	if (res) {
		EMSG("Fail to allocate decrypt operation");
		return res;
	}

	input->data = calloc(1, input_size);
	if (!input->data)
		return TEE_ERROR_OUT_OF_MEMORY;
	input->size = input_size;

	output->data = calloc(1, output_size);
	if (!output->data)
		return TEE_ERROR_OUT_OF_MEMORY;
	output->size = output_size;

	return TEE_SUCCESS;
}

TEE_Result rsa_prepare_sign_verify(uint32_t ta_alg, size_t key_size_bits,
				   TEE_OperationHandle *sign_op,
				   TEE_OperationHandle *verify_op,
				   struct ta_buf *input, struct ta_buf *output)
{
	uint32_t tee_alg = 0;
	TEE_Result res = TEE_ERROR_GENERIC;
	const uint8_t *digest = NULL;
	size_t digest_size = 0;

	switch (ta_alg) {
	case TA_ALG_RSASSA_PKCS1_V1_5_MD5:
		tee_alg = TEE_ALG_RSASSA_PKCS1_V1_5_MD5;
		digest = digest_md5;
		digest_size = sizeof(digest_md5);
		break;
	case TA_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TA_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
		tee_alg = TEE_ALG_RSASSA_PKCS1_V1_5_SHA1;
		digest = digest_sha1;
		digest_size = sizeof(digest_sha1);
		break;
	case TA_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TA_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
		tee_alg = TEE_ALG_RSASSA_PKCS1_V1_5_SHA224;
		digest = digest_sha224;
		digest_size = sizeof(digest_sha224);
		break;
	case TA_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TA_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
		tee_alg = TEE_ALG_RSASSA_PKCS1_V1_5_SHA256;
		digest = digest_sha256;
		digest_size = sizeof(digest_sha256);
		break;
	case TA_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TA_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
		tee_alg = TEE_ALG_RSASSA_PKCS1_V1_5_SHA384;
		digest = digest_sha384;
		digest_size = sizeof(digest_sha384);
		break;
	case TA_ALG_RSASSA_PKCS1_V1_5_SHA512:
	case TA_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		tee_alg = TEE_ALG_RSASSA_PKCS1_V1_5_SHA512;
		digest = digest_sha512;
		digest_size = sizeof(digest_sha512);
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	input->data = calloc(1, digest_size);
	if (!input->data)
		return TEE_ERROR_OUT_OF_MEMORY;
	input->size = digest_size;
	memcpy(input->data, digest, digest_size);

	output->data = calloc(1, key_size_bits / 8);
	if (!output->data)
		return TEE_ERROR_OUT_OF_MEMORY;
	output->size = key_size_bits / 8;

	res = TEE_AllocateOperation(sign_op, tee_alg, TEE_MODE_SIGN,
				    key_size_bits);
	if (res) {
		EMSG("Fail to allocate encrypt operation");
		return res;
	}

	res = TEE_AllocateOperation(verify_op, tee_alg, TEE_MODE_VERIFY,
				    key_size_bits);
	if (res) {
		EMSG("Fail to allocate decrypt operation");
		return res;
	}

	return TEE_SUCCESS;
}
