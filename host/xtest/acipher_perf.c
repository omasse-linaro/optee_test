// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright NXP 2023
 */
#include <adbg.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <tee_client_api.h>
#include <tee_client_api_extensions.h>
#include <ta_acipher_perf.h>
#include <time.h>

#include "crypto_common.h"
#include "xtest_helpers.h"

struct statistics {
	int n;
	double m;
	double M2;
	double min;
	double max;
	int initialized;
};
static TEEC_Context ctx;
static TEEC_Session sess;

static void get_current_time(struct timespec *ts)
{
	if (clock_gettime(CLOCK_MONOTONIC, ts) < 0) {
		perror("clock_gettime");
		exit(1);
	}
}

static double timespec_diff_us(struct timespec *start, struct timespec *end)
{
	double us = 0;

	if (end->tv_nsec < start->tv_nsec) {
		us += 1000000 * (end->tv_sec - start->tv_sec - 1);
		us += (1000000000 - start->tv_nsec + end->tv_nsec) / 1000;
	} else {
		us += 1000000 * (end->tv_sec - start->tv_sec);
		us += (end->tv_nsec - start->tv_nsec) / 1000;
	}

	return us;
}

static void update_stats(struct statistics *s, double x)
{
	double delta = x - s->m;

	s->n++;
	if (!s->initialized) {
		s->m = s->min = s->max = x;
		s->initialized = 1;
	} else {
		s->m += delta / s->n;
		s->M2 += delta * (x - s->m);
		if (s->min > x)
			s->min = x;
		if (s->max < x)
			s->max = x;
	}
}

static double stddev(struct statistics *s)
{
	if (s->n < 2)
		return NAN;
	return sqrt(s->M2 / s->n);
}

static void print_stats(struct statistics *s, uint32_t loops)
{
	double sd = 0;

	sd = stddev(s);
	printf("min=%gms max=%gms mean=%gms stddev=%gms (cv %g%%) (%gms/op)\n",
	       s->min / 1000, s->max / 1000, s->m / 1000,
	       sd / 1000, 100 * sd / s->m, (s->m / 1000) / loops);
}

static TEEC_Result acipher_perf_prepare_key_gen(unsigned int key_alg,
						size_t key_size)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_origin = 0;
	TEEC_Result res = TEEC_ERROR_GENERIC;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);

	op.params[0].value.a = (uint32_t)key_alg;
	op.params[0].value.b = (uint32_t)key_size;

	res = TEEC_InvokeCommand(&sess, TA_ACIPHER_PERF_CMD_PREPARE_KEYGEN, &op,
				 &ret_origin);
	if (res)
		return res;

	return TEEC_SUCCESS;
}

static TEEC_Result acipher_perf_key_gen(unsigned int key_alg, size_t key_size,
					unsigned int n, unsigned int l)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_origin = 0;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	struct timespec t0 = {};
	struct timespec t1 = {};
	struct statistics stats = {};

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].value.a = (uint32_t)key_alg;
	op.params[0].value.b = (uint32_t)key_size;
	op.params[1].value.a = (uint32_t)l;
	op.params[1].value.b = 0;

	while (n-- > 0) {
		get_current_time(&t0);

		res = TEEC_InvokeCommand(&sess, TA_ACIPHER_PERF_CMD_KEYGEN, &op,
					 &ret_origin);
		if (res)
			return res;

		get_current_time(&t1);
		update_stats(&stats, timespec_diff_us(&t0, &t1));
	}

	printf("Keygen\n");
	print_stats(&stats, l);

	return TEEC_SUCCESS;
}

static TEEC_Result acipher_perf_prepare_op(unsigned int key_alg,
					   size_t key_size, unsigned int alg)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_origin = 0;
	TEEC_Result res = TEEC_ERROR_GENERIC;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].value.a = (uint32_t)key_alg;
	op.params[0].value.b = (uint32_t)key_size;
	op.params[1].value.a = (uint32_t)alg;
	op.params[1].value.b = 0;

	res = TEEC_InvokeCommand(&sess, TA_ACIPHER_PERF_CMD_PREPARE_OP, &op,
				 &ret_origin);
	if (res)
		return res;

	return TEEC_SUCCESS;
}

static TEEC_Result acipher_perf_encrypt(unsigned int key_alg, size_t key_size,
					unsigned int alg, unsigned int n,
					unsigned int l)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_origin = 0;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	struct timespec t0 = {};
	struct timespec t1 = {};
	struct statistics stats = {};

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].value.a = (uint32_t)alg;
	op.params[0].value.b = (uint32_t)l;

	while (n-- > 0) {
		get_current_time(&t0);

		res = TEEC_InvokeCommand(&sess, TA_ACIPHER_PERF_CMD_ENCRYPT,
					 &op, &ret_origin);
		if (res)
			return res;

		get_current_time(&t1);
		update_stats(&stats, timespec_diff_us(&t0, &t1));
	}

	printf("Encryption\n");
	print_stats(&stats, l);

	return TEEC_SUCCESS;
}

static TEEC_Result acipher_perf_decrypt(unsigned int key_alg, size_t key_size,
					unsigned int alg, unsigned int n,
					unsigned int l)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_origin = 0;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	struct timespec t0 = {};
	struct timespec t1 = {};
	struct statistics stats = {};

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].value.a = (uint32_t)alg;
	op.params[0].value.b = (uint32_t)l;

	while (n-- > 0) {
		get_current_time(&t0);

		res = TEEC_InvokeCommand(&sess, TA_ACIPHER_PERF_CMD_DECRYPT,
					 &op, &ret_origin);
		if (res)
			return res;

		get_current_time(&t1);
		update_stats(&stats, timespec_diff_us(&t0, &t1));
	}

	printf("Decryption\n");
	print_stats(&stats, l);

	return TEEC_SUCCESS;
}

static TEEC_Result acipher_perf_sign(unsigned int key_alg, size_t key_size,
			   unsigned int alg, unsigned int n)
{
	return TEEC_ERROR_GENERIC;
}

static TEEC_Result acipher_perf_verify(unsigned int key_alg, size_t key_size,
			   unsigned int alg, unsigned int n)
{
	return TEEC_ERROR_GENERIC;
}

static TEEC_Result __unused acipher_perf_op(unsigned int key_alg, size_t key_size,
				   unsigned int alg, unsigned int n, unsigned int l)
{
	TEEC_Result ret = TEEC_ERROR_GENERIC;

	switch (alg) {
	case TA_ALG_RSAES_PKCS1_V1_5:
	case TA_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
	case TA_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
	case TA_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
	case TA_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
	case TA_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
	case TA_ALG_RSA_NOPAD:
	case TA_ALG_SM2_PKE:
		ret = acipher_perf_encrypt(key_alg, key_size, alg, n, l);
		if (ret)
			return ret;

		ret = acipher_perf_decrypt(key_alg, key_size, alg, n, l);
		if (ret)
			return ret;

		break;
	case TA_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TA_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TA_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TA_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TA_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TA_ALG_RSASSA_PKCS1_V1_5_SHA512:
	case TA_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TA_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TA_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TA_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TA_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
	case TA_ALG_DSA_SHA1:
	case TA_ALG_DSA_SHA224:
	case TA_ALG_DSA_SHA256:
	case TA_ALG_ECDSA_SHA1:
	case TA_ALG_ECDSA_SHA224:
	case TA_ALG_ECDSA_SHA256:
	case TA_ALG_ECDSA_SHA384:
	case TA_ALG_ECDSA_SHA512:
	case TA_ALG_ED25519:
	case TA_ALG_SM2_DSA_SM3:
		ret = acipher_perf_sign(key_alg, key_size, alg, n);
		if (ret)
			return ret;

		ret = acipher_perf_verify(key_alg, key_size, alg, n);
		if (ret)
			return ret;
		break;
	case TA_ALG_INVALID:
	default:
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	return TEEC_SUCCESS;
}

static void usage(const char *progname, unsigned int keysize,
		  unsigned int warmup, unsigned int l, unsigned int n)
{
	fprintf(stderr, "Usage: %s [-h]\n", progname);
	fprintf(stderr, "Usage: %s -k KEY", progname);
	fprintf(stderr, " [-l LOOP] [-a ALGO] [-n LOOP] [-r|--no-inited]");
	fprintf(stderr, " [-v [-v]] [-w SEC]");
	fprintf(stderr, "\n");
	fprintf(stderr,
		"Asymmetric cipher performance testing tool for OP-TEE\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -h|--help     Print this help and exit\n");
	fprintf(stderr,
		"  -s SIZE       Key size in bits (if supported) [%d]:\n",
		keysize);
	fprintf(stderr,
		"                - RSA: 256, 512, 768, 1024, 1535, 2048\n");
	fprintf(stderr,
		"                - DSA_SHA1: between 512 and 1024 (multiple of 64 bits)\n");
	fprintf(stderr, "                - DSA_SHA224: 2048\n");
	fprintf(stderr, "                - DSA_SHA256: 2048, 3072\n");
	fprintf(stderr,
		"                - DH: between 256 and 2048 (multiple of 8 bits)\n");
	fprintf(stderr,
		"                - ECDSA/ECDH: 192, 224, 256, 384, 521 (equal to the curve)\n");
	fprintf(stderr, "  -l LOOP       Inner loop iterations [%u]\n", l);
	fprintf(stderr, "  -n LOOP       Outer test loop iterations [%u]\n", n);
	fprintf(stderr, "  -a ALGO       Algorithms (if supported):\n");
	fprintf(stderr, "                - Encrypt/Decrypt operation:\n");
	fprintf(stderr, "                  - RSAES_PKCS1_V1_5\n");
	fprintf(stderr,
		"                  - RSAES_PKCS1_OAEP_MGF1_SHA[1|224|256|384|512]\n");
	fprintf(stderr, "                  - RSA_NOPAD\n");
	fprintf(stderr, "                  - SM2_PKE\n");
	fprintf(stderr, "                - Sign/Verify operation:\n");
	fprintf(stderr, "                  - RSASSA_PKCS1_V1_5_MD5\n");
	fprintf(stderr,
		"                  - RSASSA_PKCS1_V1_5_SHA[1|224|256|384|512]\n");
	fprintf(stderr,
		"                  - RSASSA_PKCS1_PSS_MGF1_SHA[1|224|256|384|512]\n");
	fprintf(stderr, "                  - DSA_SHA[1|224|256]\n");
	fprintf(stderr, "                  - ECDSA_SHA[1|224|256|384|512]\n");
	fprintf(stderr, "                  - ED25519\n");
	fprintf(stderr, "                  - SM2_DSA_SM3\n");
	fprintf(stderr, "  -k KEY         Keypair to use\n");
	fprintf(stderr, "                  - RSA\n");
	fprintf(stderr, "                  - DSA\n");
	fprintf(stderr, "                  - DH\n");
	fprintf(stderr, "                  - ECDSA_P[192|224|256|384|521]\n");
	fprintf(stderr, "                  - ECDH_P[192|224|256|384|521]\n");
	fprintf(stderr, "                  - ED25519\n");
	fprintf(stderr, "                  - X25519\n");
	fprintf(stderr, "                  - SM2_DSA\n");
	fprintf(stderr, "                  - SM2_KEP\n");
	fprintf(stderr, "                  - SM2_PKE\n");
	fprintf(stderr,
		"  --not-inited  Do not initialize input buffer content.\n");
	fprintf(stderr,
		"  -r|--random   Get input data from /dev/urandom (default: all zeros)\n");
	fprintf(stderr,
		"  -v            Be verbose (use twice for greater effect)\n");
	fprintf(stderr,
		"  -w|--warmup SEC  Warm-up time in seconds: execute a busy loop before\n");
	fprintf(stderr,
		"                   the test to mitigate the effects of cpufreq etc. [%u]\n",
		warmup);
}

#define NEXT_ARG(i) \
	do { \
		if (++i == argc) { \
			fprintf(stderr, "%s: %s: missing argument\n", argv[0], \
				argv[i - 1]); \
			return 1; \
		} \
	} while (0);

int acipher_perf_runner_cmd_parser(int argc, char *argv[])
{
	int i = 0;
	unsigned int n = 10;
	unsigned int l = 1;
	unsigned int verbosity __unused = CRYPTO_DEF_VERBOSITY;
	unsigned int alg = TA_ALG_NONE;
	unsigned int key_alg = TA_KEY_INVALID;
	unsigned int key_size = 1024;
	unsigned int random_in __unused = CRYPTO_USE_ZEROS;
	unsigned int warmup __unused = CRYPTO_DEF_WARMUP;
	TEEC_UUID uuid = TA_ACIPHER_PERF_UUID;
	uint32_t err_origin = 0;
	TEEC_Result res = TEEC_ERROR_GENERIC;

	if (argc < 2) {
		usage(argv[0], key_size, warmup, l, n);
		return 0;
	}

	/* Parse command line */
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			usage(argv[0], key_size, warmup, l, n);
			return 0;
		}
	}

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-l")) {
			NEXT_ARG(i);
			l = atoi(argv[i]);
		} else if (!strcmp(argv[i], "-a")) {
			NEXT_ARG(i);
			if (!strcasecmp(argv[i], "RSAES_PKCS1_V1_5"))
				alg = TA_ALG_RSAES_PKCS1_V1_5;
			else if (!strcasecmp(argv[i],
					     "RSAES_PKCS1_OAEP_MGF1_SHA1"))
				alg = TA_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1;
			else if (!strcasecmp(argv[i],
					     "RSAES_PKCS1_OAEP_MGF1_SHA224"))
				alg = TA_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224;
			else if (!strcasecmp(argv[i],
					     "RSAES_PKCS1_OAEP_MGF1_SHA256"))
				alg = TA_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256;
			else if (!strcasecmp(argv[i],
					     "RSAES_PKCS1_OAEP_MGF1_SHA384"))
				alg = TA_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384;
			else if (!strcasecmp(argv[i],
					     "RSAES_PKCS1_OAEP_MGF1_SHA512"))
				alg = TA_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512;
			else if (!strcasecmp(argv[i], "RSA_NOPAD"))
				alg = TA_ALG_RSA_NOPAD;
			else if (!strcasecmp(argv[i], "SM2_PKE"))
				alg = TA_ALG_SM2_PKE;
			else if (!strcasecmp(argv[i], "RSASSA_PKCS1_V1_5_MD5"))
				alg = TA_ALG_RSASSA_PKCS1_V1_5_MD5;
			else if (!strcasecmp(argv[i], "RSASSA_PKCS1_V1_5_SHA1"))
				alg = TA_ALG_RSASSA_PKCS1_V1_5_SHA1;
			else if (!strcasecmp(argv[i],
					     "RSASSA_PKCS1_V1_5_SHA224"))
				alg = TA_ALG_RSASSA_PKCS1_V1_5_SHA224;
			else if (!strcasecmp(argv[i],
					     "RSASSA_PKCS1_V1_5_SHA256"))
				alg = TA_ALG_RSASSA_PKCS1_V1_5_SHA256;
			else if (!strcasecmp(argv[i],
					     "RSASSA_PKCS1_V1_5_SHA384"))
				alg = TA_ALG_RSASSA_PKCS1_V1_5_SHA384;
			else if (!strcasecmp(argv[i],
					     "RSASSA_PKCS1_V1_5_SHA512"))
				alg = TA_ALG_RSASSA_PKCS1_V1_5_SHA512;
			else if (!strcasecmp(argv[i],
					     "RSASSA_PKCS1_PSS_MGF1_SHA1"))
				alg = TA_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1;
			else if (!strcasecmp(argv[i],
					     "RSASSA_PKCS1_PSS_MGF1_SHA224"))
				alg = TA_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224;
			else if (!strcasecmp(argv[i],
					     "RSASSA_PKCS1_PSS_MGF1_SHA256"))
				alg = TA_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256;
			else if (!strcasecmp(argv[i],
					     "RSASSA_PKCS1_PSS_MGF1_SHA384"))
				alg = TA_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384;
			else if (!strcasecmp(argv[i],
					     "RSASSA_PKCS1_PSS_MGF1_SHA512"))
				alg = TA_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512;
			else if (!strcasecmp(argv[i], "DSA_SHA1"))
				alg = TA_ALG_DSA_SHA1;
			else if (!strcasecmp(argv[i], "DSA_SHA224"))
				alg = TA_ALG_DSA_SHA224;
			else if (!strcasecmp(argv[i], "DSA_SHA256"))
				alg = TA_ALG_DSA_SHA256;
			else if (!strcasecmp(argv[i], "ECDSA_SHA1"))
				alg = TA_ALG_ECDSA_SHA1;
			else if (!strcasecmp(argv[i], "ECDSA_SHA224"))
				alg = TA_ALG_ECDSA_SHA224;
			else if (!strcasecmp(argv[i], "ECDSA_SHA256"))
				alg = TA_ALG_ECDSA_SHA256;
			else if (!strcasecmp(argv[i], "ECDSA_SHA384"))
				alg = TA_ALG_ECDSA_SHA384;
			else if (!strcasecmp(argv[i], "ECDSA_SHA512"))
				alg = TA_ALG_ECDSA_SHA512;
			else if (!strcasecmp(argv[i], "ED25519"))
				alg = TA_ALG_ED25519;
			else if (!strcasecmp(argv[i], "SM2_DSA_SM3"))
				alg = TA_ALG_SM2_DSA_SM3;
			else {
				fprintf(stderr, "%s, invalid algorithm\n",
					argv[0]);
				usage(argv[0], key_size, warmup, l, n);
				return 1;
			}
		} else if (!strcmp(argv[i], "-k")) {
			NEXT_ARG(i);
			if (!strcasecmp(argv[i], "RSA"))
				key_alg = TA_KEY_RSA;
			else if (!strcasecmp(argv[i], "DSA"))
				key_alg = TA_KEY_DSA;
			else if (!strcasecmp(argv[i], "DH"))
				key_alg = TA_KEY_DH;
			else if (!strcasecmp(argv[i], "ECDSA_P192"))
				key_alg = TA_KEY_ECDSA_P192;
			else if (!strcasecmp(argv[i], "ECDSA_P224"))
				key_alg = TA_KEY_ECDSA_P224;
			else if (!strcasecmp(argv[i], "ECDSA_P256"))
				key_alg = TA_KEY_ECDSA_P256;
			else if (!strcasecmp(argv[i], "ECDSA_P384"))
				key_alg = TA_KEY_ECDSA_P384;
			else if (!strcasecmp(argv[i], "ECDSA_P521"))
				key_alg = TA_KEY_ECDSA_P521;
			else if (!strcasecmp(argv[i], "ECDH_P192"))
				key_alg = TA_KEY_ECDH_P192;
			else if (!strcasecmp(argv[i], "ECDH_P224"))
				key_alg = TA_KEY_ECDH_P224;
			else if (!strcasecmp(argv[i], "ECDH_P256"))
				key_alg = TA_KEY_ECDH_P256;
			else if (!strcasecmp(argv[i], "ECDH_P384"))
				key_alg = TA_KEY_ECDH_P384;
			else if (!strcasecmp(argv[i], "ECDH_P521"))
				key_alg = TA_KEY_ECDH_P521;
			else if (!strcasecmp(argv[i], "ED25519"))
				key_alg = TA_KEY_ED25519;
			else if (!strcasecmp(argv[i], "X25519"))
				key_alg = TA_KEY_X25519;
			else if (!strcasecmp(argv[i], "SM2_DSA"))
				key_alg = TA_KEY_SM2_DSA;
			else if (!strcasecmp(argv[i], "SM2_KEP"))
				key_alg = TA_KEY_SM2_KEP;
			else if (!strcasecmp(argv[i], "SM2_PKE"))
				key_alg = TA_KEY_SM2_PKE;
			else {
				fprintf(stderr, "%s, invalid algorithm\n",
					argv[0]);
				usage(argv[0], key_size, warmup, l, n);
				return 1;
			}
		} else if (!strcmp(argv[i], "-n")) {
			NEXT_ARG(i);
			n = atoi(argv[i]);
		} else if (!strcmp(argv[i], "--random") ||
			   !strcmp(argv[i], "-r")) {
			random_in = CRYPTO_USE_RANDOM;
		} else if (!strcmp(argv[i], "-s")) {
			NEXT_ARG(i);
			key_size = atoi(argv[i]);
		} else if (!strcmp(argv[i], "-v")) {
			verbosity++;
		} else if (!strcmp(argv[i], "--warmup") ||
			   !strcmp(argv[i], "-w")) {
			NEXT_ARG(i);
			warmup = atoi(argv[i]);
		} else {
			fprintf(stderr, "%s: invalid argument: %s\n", argv[0],
				argv[i]);
			usage(argv[0], key_size, warmup, l, n);
			return 1;
		}
	}
	if (key_alg == TA_KEY_INVALID) {
		fprintf(stderr, "%s: -k KEY is mandatory\n", argv[0]);
		usage(argv[0], key_size, warmup, l, n);
		return 1;
	}

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res)
		return -1;

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
			       NULL, &err_origin);
	if (res)
		return -1;

	/* Check if that's a key generation benchmark */
	if (alg == TA_ALG_NONE) {
		res = acipher_perf_prepare_key_gen(key_alg, key_size);
		if (res)
			return -1;

		res = acipher_perf_key_gen(key_alg, key_size, n, l);
		if (res)
			return -1;
	} else {
		res = acipher_perf_prepare_op(key_alg, key_size, alg);
		if (res)
			return -1;

		res = acipher_perf_op(key_alg, key_size, alg, n, l);
		if (res)
			return -1;
	}

	TEEC_CloseSession(&sess);

	return 0;
}
