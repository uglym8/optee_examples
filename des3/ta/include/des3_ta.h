#ifndef __DES3_TA_H__
#define __DES3_TA_H__

/* UUID of the des3 example trusted application */
#define TA_DES3_UUID \
	{0xdf05b8c4, 0x35aa, 0x4921,\
	{0xab, 0xc5, 0x75, 0x9a, 0x77, 0x94, 0x00, 0x87}}

#define TA_DES3_CMD_PREPARE 0
#define TA_DES3_CMD_SET_KEY	1
#define TA_DES3_CMD_SET_IV	2
#define TA_DES3_CMD_CIPHER  3

#define DES3_BLOCK_SIZE		8
#define DES3_KEY_SIZE_192	24

#define TA_DES3_MODE_ENCODE		1
#define TA_DES3_MODE_DECODE		0

#define TA_DES3_ALGO_CBC			1

#endif /* __DES3_TA_H */

