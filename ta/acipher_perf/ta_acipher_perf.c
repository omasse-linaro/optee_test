// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright NXP 2023
 */
#include "tee_api_defines.h"
#include "tee_api_types.h"
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <tee_ta_api.h>
#include <assert.h>
#include <utee_defines.h>

#include "ta_acipher_perf.h"
#include "ta_acipher_perf_priv.h"

static TEE_ObjectHandle operation_key1;
static TEE_ObjectHandle operation_key2;
static TEE_ObjectHandle derived_key;
static TEE_OperationHandle encrypt_op;
static TEE_OperationHandle decrypt_op;
static TEE_OperationHandle sign_op;
static TEE_OperationHandle verify_op;
static TEE_OperationHandle derive_op;
static TEE_Attribute keygen_attrs[4];
static unsigned int keygen_nb_attrs;
static TEE_Attribute derive_attrs[9];
static unsigned int derive_nb_attrs;
static struct ta_buf input;
static struct ta_buf output;

static TEE_Result (*static_prepare_keygen[])(uint32_t ta_key,
					     TEE_ObjectHandle *key,
					     size_t key_size_bits,
					     TEE_Attribute *attrs,
					     unsigned int *nb_attrs) =
{
	/* TA_KEY_RSA */ rsa_prepare_key,
	/* TA_KEY_DSA */ dsa_prepare_key,
	/* TA_KEY_DH */ dh_prepare_key,
	/* TA_KEY_ECDSA_P192 */ ecdsa_prepare_key,
	/* TA_KEY_ECDSA_P224 */ ecdsa_prepare_key,
	/* TA_KEY_ECDSA_P256 */ ecdsa_prepare_key,
	/* TA_KEY_ECDSA_P384 */ ecdsa_prepare_key,
	/* TA_KEY_ECDSA_P521 */ ecdsa_prepare_key,

	/* TA_KEY_ECDH_P192 */ ecdh_prepare_key,
	/* TA_KEY_ECDH_P224 */ ecdh_prepare_key,
	/* TA_KEY_ECDH_P256 */ ecdh_prepare_key,
	/* TA_KEY_ECDH_P384 */ ecdh_prepare_key,
	/* TA_KEY_ECDH_P521 */ ecdh_prepare_key,

	/* TA_KEY_ED25519 */ ed25519_prepare_key,
	/* TA_KEY_X25519 */ x25519_prepare_key,

	/* TA_KEY_SM2_DSA */ sm2_prepare_key,
	/* TA_KEY_SM2_KEP */ sm2_prepare_key,
	/* TA_KEY_SM2_PKE */ sm2_prepare_key
};

static TEE_Result (*static_prepare_acipher[])(uint32_t ta_alg, size_t key_size_bits,
					      TEE_OperationHandle *encrypt_op,
					      TEE_OperationHandle *decrypt_op,
					      struct ta_buf *input,
					      struct ta_buf *output) =
{
	/* TA_ALG_NONE */ NULL,
	/* TA_ALG_RSAES_PKCS1_V1_5 */ rsa_prepare_encrypt_decrypt,
	/* TA_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1 */ rsa_prepare_encrypt_decrypt,
	/* TA_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224 */ rsa_prepare_encrypt_decrypt,
	/* TA_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256 */ rsa_prepare_encrypt_decrypt,
	/* TA_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384 */ rsa_prepare_encrypt_decrypt,
	/* TA_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512 */ rsa_prepare_encrypt_decrypt,
	/* TA_ALG_RSA_NOPAD */ rsa_prepare_encrypt_decrypt,
	/* TA_ALG_SM2_PKE */ sm2_prepare_encrypt_decrypt,
};

TEE_Result prepare_keygen(uint32_t ta_key,
			  size_t key_size_bits)
{
	if (ta_key < sizeof(static_prepare_keygen))
		return static_prepare_keygen[ta_key](ta_key, &operation_key1,
						     key_size_bits,
						     keygen_attrs,
						     &keygen_nb_attrs);
	return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result keygen(uint32_t ta_key, size_t key_size_bits, unsigned int loops)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	/* Eventually force the key size for some algo */
	switch (ta_key) {
	case TA_KEY_ECDSA_P192:
	case TA_KEY_ECDH_P192:
		key_size_bits = 192;
		break;
	case TA_KEY_ECDSA_P224:
	case TA_KEY_ECDH_P224:
		key_size_bits = 224;
		break;
	case TA_KEY_ECDSA_P256:
	case TA_KEY_ECDH_P256:
		key_size_bits = 256;
		break;
	case TA_KEY_ECDSA_P384:
	case TA_KEY_ECDH_P384:
		key_size_bits = 384;
		break;
	case TA_KEY_ECDSA_P521:
	case TA_KEY_ECDH_P521:
		key_size_bits = 521;
		break;
	case TA_KEY_ED25519:
	case TA_KEY_X25519:
	case TA_KEY_SM2_DSA:
	case TA_KEY_SM2_KEP:
	case TA_KEY_SM2_PKE:
		key_size_bits = 256;
		break;
	default:
		break;
	}

	while (loops-- > 0) {
		TEE_ResetTransientObject(operation_key1);

		if (keygen_nb_attrs) {
			res = TEE_GenerateKey(operation_key1, key_size_bits,
					      keygen_attrs, keygen_nb_attrs);
			if (res) {
				EMSG("Fail to generate key");
				return res;
			}
		} else {
			res = TEE_GenerateKey(operation_key1, key_size_bits,
					      NULL, 0);
			if (res) {
				EMSG("Fail to generate key");
				return res;
			}
		}
	}

	return res;
}

TEE_Result prepare_op(uint32_t ta_key, size_t key_size_bits, uint32_t ta_alg)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	if (ta_key != TA_KEY_INVALID) {
		res = prepare_keygen(ta_key, key_size_bits);
		if (res)
			return res;

		res = keygen(ta_key, key_size_bits, 1);
		if (res)
			return res;
	}

	if (ta_alg <= TA_ALG_SM2_PKE)
		res = static_prepare_acipher[ta_alg](ta_alg, key_size_bits,
						     &encrypt_op, &decrypt_op,
						     &input, &output);
	else
		res = TEE_ERROR_NOT_SUPPORTED;

	if (res) {
		EMSG("Fail to prepare operation");
		free_ta_ctx();
		return res;
	}

	if (encrypt_op != TEE_HANDLE_NULL && decrypt_op != TEE_HANDLE_NULL) {
		res = TEE_SetOperationKey(encrypt_op, operation_key1);
		if (res) {
			EMSG("Fail to set key");
			return res;
		}

		res = TEE_SetOperationKey(decrypt_op, operation_key1);
		if (res) {
			EMSG("Fail to set key");
			return res;
		}
	}

	return TEE_SUCCESS;
}

TEE_Result sign(uint32_t ta_alg, unsigned int loop)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result verify(uint32_t ta_alg, unsigned int loop)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result encrypt(uint32_t ta_alg, unsigned int loop)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	switch (ta_alg) {
	case TA_ALG_RSAES_PKCS1_V1_5:
	case TA_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
	case TA_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
	case TA_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
	case TA_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
	case TA_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
	case TA_ALG_RSA_NOPAD:
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	while (loop-- > 0) {
		res = TEE_AsymmetricEncrypt(encrypt_op, NULL, 0, input.data,
					    input.size, output.data,
					    &output.size);
		if (res) {
			EMSG("Fail to encrypt 0x%x", res);
			return res;
		}
	}

	return TEE_SUCCESS;
}

TEE_Result decrypt(uint32_t ta_alg, unsigned int loop)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	switch (ta_alg) {
	case TA_ALG_RSAES_PKCS1_V1_5:
	case TA_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
	case TA_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
	case TA_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
	case TA_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
	case TA_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
	case TA_ALG_RSA_NOPAD:
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	while (loop-- > 0) {
		res = TEE_AsymmetricDecrypt(decrypt_op, NULL, 0, output.data,
					    output.size, input.data,
					    &input.size);
		if (res) {
			EMSG("Fail to decrypt 0x%x", res);
			return res;
		}
	}

	return TEE_SUCCESS;
}

TEE_Result derive(uint32_t ta_alg, unsigned int loop)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

void free_ta_ctx(void)
{
	TEE_FreeTransientObject(operation_key1);
	TEE_FreeTransientObject(operation_key2);
	TEE_FreeOperation(encrypt_op);
	TEE_FreeOperation(decrypt_op);
	TEE_FreeOperation(sign_op);
	TEE_FreeOperation(verify_op);
	TEE_FreeOperation(derive_op);
	encrypt_op = TEE_HANDLE_NULL;
	decrypt_op = TEE_HANDLE_NULL;
	sign_op = TEE_HANDLE_NULL;
	verify_op = TEE_HANDLE_NULL;
	derive_op = TEE_HANDLE_NULL;
	keygen_nb_attrs = 0;
	TEE_Free(input.data);
	input.size = 0;
	TEE_Free(output.data);
	output.size = 0;
}
