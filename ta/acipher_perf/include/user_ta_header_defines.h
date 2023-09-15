// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright NXP 2023
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include "ta_acipher_perf.h"

#define TA_UUID TA_ACIPHER_PERF_UUID

#define TA_FLAGS                (TA_FLAG_USER_MODE | TA_FLAG_EXEC_DDR | \
				TA_FLAG_SECURE_DATA_PATH | \
				TA_FLAG_CACHE_MAINTENANCE)

#define TA_STACK_SIZE		(2 * 1024)
#define TA_DATA_SIZE		(32 * 1024)

#endif
