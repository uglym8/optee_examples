#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <des3_ta.h>

#define DES3_TEST_BUFFER_SIZE	128

#define DECODE			0
#define ENCODE			1

/* TEE resources */
struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

void prepare_tee_session(struct test_ctx *ctx)
{
	TEEC_UUID uuid = TA_DES3_UUID;
	uint32_t origin;
	TEEC_Result res;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/* Open a session with the TA */
	res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, origin);
}

void terminate_tee_session(struct test_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

void prepare_des3(struct test_ctx *ctx, int encode)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_NONE);

	op.params[0].value.a = TA_DES3_ALGO_CBC;
	op.params[1].value.a = DES3_KEY_SIZE_192;
	op.params[2].value.a = encode ? TA_DES3_MODE_ENCODE :
					TA_DES3_MODE_DECODE;

	res = TEEC_InvokeCommand(&ctx->sess, TA_DES3_CMD_PREPARE,
				 &op, &origin);

	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(PREPARE) failed 0x%x origin 0x%x\n",
			res, origin);
}

void set_key(struct test_ctx *ctx, char *key, size_t key_sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = key;
	op.params[0].tmpref.size = key_sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_DES3_CMD_SET_KEY,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(SET_KEY) failed 0x%x origin 0x%x",
			res, origin);
}

void set_iv(struct test_ctx *ctx, char *iv, size_t iv_sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					  TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = iv;
	op.params[0].tmpref.size = iv_sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_DES3_CMD_SET_IV,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(SET_IV) failed 0x%x origin 0x%x",
			res, origin);
}

void cipher_buffer(struct test_ctx *ctx, char *in, char *out, size_t sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = in;
	op.params[0].tmpref.size = sz;
	op.params[1].tmpref.buffer = out;
	op.params[1].tmpref.size = sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_DES3_CMD_CIPHER,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(CIPHER) failed 0x%x origin 0x%x",
			res, origin);
}

int main(void)
{
	int i;
	struct test_ctx ctx;

	char key[DES3_KEY_SIZE_192];
	char iv[DES3_BLOCK_SIZE];

	char clear[DES3_TEST_BUFFER_SIZE];
	char ciph[DES3_TEST_BUFFER_SIZE] = {0};
	char temp[DES3_TEST_BUFFER_SIZE] = {0};

	char *res;
	char out_str[1024];

	printf("Prepare session with the TA\n");
	prepare_tee_session(&ctx);

	printf("Prepare encode operation\n");
	prepare_des3(&ctx, ENCODE);

	printf("Load key in TA\n");
	//memset(key, 0xa5, sizeof(key)); /* Load some dummy value */
	for (i = 0; i < DES3_KEY_SIZE_192; i++) key[i] = i;
	set_key(&ctx, key, DES3_KEY_SIZE_192);

	printf("Reset ciphering operation in TA (provides the initial vector)\n");
	//memset(iv, 0, sizeof(iv)); /* Load some dummy value */
	for (i = 0; i < DES3_BLOCK_SIZE; i++) iv[i] = i;
	set_iv(&ctx, iv, DES3_BLOCK_SIZE);

	printf("Encode buffer from TA\n");
	//memset(clear, 0x5a, sizeof(clear)); /* Load some dummy value */
	for (i = 0; i < DES3_TEST_BUFFER_SIZE; i++) clear[i] = i;
	cipher_buffer(&ctx, clear, ciph, DES3_TEST_BUFFER_SIZE);

	printf("===== Encrypted buffer (buflen = %d) =====\n", DES3_TEST_BUFFER_SIZE);

	res = ciph;

	for (i = 0; i < DES3_TEST_BUFFER_SIZE; i += 8) {
		snprintf(out_str, 1023, "%02x %02x %02x %02x %02x %02x %02x %02x", res[i], res[i + 1], res[i + 2], res[i + 3], res[i + 4],
				res[i + 5], res[i + 6], res[i + 7]);
		printf("%s\n", out_str);
	}

	printf("Prepare decode operation\n");
	prepare_des3(&ctx, DECODE);

	printf("Load key in TA\n");
	//memset(key, 0xa5, sizeof(key)); /* Load some dummy value */
	for (i = 0; i < DES3_KEY_SIZE_192; i++) key[i] = i;
	set_key(&ctx, key, DES3_KEY_SIZE_192);

	printf("Reset ciphering operation in TA (provides the initial vector)\n");
	//memset(iv, 0, sizeof(iv)); /* Load some dummy value */
	for (i = 0; i < DES3_BLOCK_SIZE; i++) iv[i] = i;
	set_iv(&ctx, iv, DES3_BLOCK_SIZE);

	printf("Decode buffer from TA\n");
	cipher_buffer(&ctx, ciph, temp, DES3_TEST_BUFFER_SIZE);

	printf("===== Decrypted buffer (buflen = %d) =====\n", DES3_TEST_BUFFER_SIZE);

	res = temp;

	for (i = 0; i < DES3_TEST_BUFFER_SIZE; i += 8) {
		snprintf(out_str, 1023, "%02x %02x %02x %02x %02x %02x %02x %02x", res[i], res[i + 1], res[i + 2], res[i + 3], res[i + 4],
				res[i + 5], res[i + 6], res[i + 7]);
		printf("%s\n", out_str);
	}


	/* Check decoded is the clear content */
	if (memcmp(clear, temp, DES3_TEST_BUFFER_SIZE))
		printf("Clear text and decoded text differ => ERROR\n");
	else
		printf("Clear text and decoded text match\n");

	terminate_tee_session(&ctx);
	return 0;
}

