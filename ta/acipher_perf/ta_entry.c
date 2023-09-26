// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright NXP 2023
 */

#include "tee_api_types.h"
#include <stdint.h>
#include <tee_ta_api.h>
#include <trace.h>

#include "ta_acipher_perf.h"
#include "ta_acipher_perf_priv.h"

/*
 * Prepare key for key generation benchmark
 *
 * [in] params[0].value.a	Key type (TA_KEY_*)
 * [in] params[0].value.b	Key size in bits
 */
static TEE_Result ta_cmd_prepare_keygen(uint32_t nParamTypes,
					TEE_Param pParams[4])
{
	uint32_t ta_alg = 0;
	size_t key_size_bits = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (exp_param_types != nParamTypes)
		return TEE_ERROR_BAD_PARAMETERS;

	ta_alg = pParams[0].value.a;
	key_size_bits = pParams[0].value.b;

	return prepare_keygen(ta_alg, key_size_bits);
}

/*
 * Benchmark key generation
 *
 * [in] params[0].value.a	Key type (TA_KEY_*)
 * [in] params[0].value.b	Key size in bits
 * [in] params[1].value.a	Loop count
 * [in] params[1].value.b	0
 */
static TEE_Result ta_cmd_keygen(uint32_t nParamTypes, TEE_Param pParams[4])
{
	uint32_t ta_key = 0;
	size_t key_size_bits = 0;
	unsigned int l = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (exp_param_types != nParamTypes)
		return TEE_ERROR_BAD_PARAMETERS;

	ta_key = pParams[0].value.a;
	key_size_bits = pParams[0].value.b;
	l = pParams[1].value.a;

	return keygen(ta_key, key_size_bits, l);
}

/*
 * Prepare encrypt/decrypt/sign/verify operations
 *
 * [in] params[0].value.a	Key type (TA_KEY_*)
 * [in] params[0].value.b	Key size in bits
 * [in] params[1].value.a	Crypto algorithm (TA_ALG_*)
 * [in] params[1].value.b	0
 */
static TEE_Result ta_cmd_prepare_op(uint32_t nParamTypes, TEE_Param pParams[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (exp_param_types != nParamTypes)
		return TEE_ERROR_BAD_PARAMETERS;

	return prepare_op(pParams[0].value.a, pParams[0].value.b,
		pParams[1].value.a);
}

/*
 * Benchmark sign operation
 *
 * [in] params[0].value.a	Crypto algorithm (TA_ALG_*)
 * [in] params[0].value.b	Loop count
 */
static TEE_Result ta_cmd_sign(uint32_t nParamTypes, TEE_Param pParams[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (exp_param_types != nParamTypes)
		return TEE_ERROR_BAD_PARAMETERS;

	return sign(pParams[0].value.a, pParams[0].value.b);
}

/*
 * Benchmark verify operation
 *
 * [in] params[0].value.a	Crypto algorithm (TA_ALG_*)
 * [in] params[0].value.b	Loop count
 */
static TEE_Result ta_cmd_verify(uint32_t nParamTypes, TEE_Param pParams[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (exp_param_types != nParamTypes)
		return TEE_ERROR_BAD_PARAMETERS;

	return verify(pParams[0].value.a, pParams[0].value.b);
}

/*
 * Benchmark encrypt operation
 *
 * [in] params[0].value.a	Crypto algorithm (TA_ALG_*)
 * [in] params[0].value.b	Loops
 */
static TEE_Result ta_cmd_encrypt(uint32_t nParamTypes, TEE_Param pParams[4])
{
	uint32_t ta_alg = 0;
	unsigned int loops = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (exp_param_types != nParamTypes)
		return TEE_ERROR_BAD_PARAMETERS;

	ta_alg = pParams[0].value.a;
	loops = pParams[0].value.b;

	return encrypt(ta_alg, loops);
}

/*
 * Benchmark decrypt operation
 *
 * [in] params[0].value.a	Crypto algorithm (TA_ALG_*)
 * [in] params[0].value.b	Loops
 */
static TEE_Result ta_cmd_decrypt(uint32_t nParamTypes, TEE_Param pParams[4])
{
	uint32_t ta_alg = 0;
	unsigned int loops = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (exp_param_types != nParamTypes)
		return TEE_ERROR_BAD_PARAMETERS;

	ta_alg = pParams[0].value.a;
	loops = pParams[0].value.b;

	return decrypt(ta_alg, loops);
}

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t nParamTypes __unused,
				    TEE_Param pParams[4] __unused,
				    void **ppSessionContext __unused)
{
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *pSessionContext __unused)
{
	free_ta_ctx();
}

TEE_Result TA_InvokeCommandEntryPoint(void *pSessionContext __unused,
				      uint32_t nCommandID, uint32_t nParamTypes,
				      TEE_Param pParams[4])
{
	switch (nCommandID) {
	case TA_ACIPHER_PERF_CMD_PREPARE_KEYGEN:
		return ta_cmd_prepare_keygen(nParamTypes, pParams);
	case TA_ACIPHER_PERF_CMD_KEYGEN:
		return ta_cmd_keygen(nParamTypes, pParams);
	case TA_ACIPHER_PERF_CMD_PREPARE_OP:
		return ta_cmd_prepare_op(nParamTypes, pParams);
	case TA_ACIPHER_PERF_CMD_SIGN:
		return ta_cmd_sign(nParamTypes, pParams);
	case TA_ACIPHER_PERF_CMD_VERIFY:
		return ta_cmd_verify(nParamTypes, pParams);
	case TA_ACIPHER_PERF_CMD_ENCRYPT:
		return ta_cmd_encrypt(nParamTypes, pParams);
	case TA_ACIPHER_PERF_CMD_DECRYPT:
		return ta_cmd_decrypt(nParamTypes, pParams);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
