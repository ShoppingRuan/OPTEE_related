/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <AES_decrypt_ta.h>

#define FILEPATH "/data/test"
#define BUFSIZE  255

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_AES_DECRYPT_UUID;
	uint32_t err_origin;
	
	FILE *fp = NULL;
	unsigned char cipher[BUFSIZE];
	unsigned char plain[BUFSIZE];
	uint32_t filelen = 0;
	const unsigned char msg[]="\x94\x24\x14\x32\xc3\x05\x6b\x1a\xd2\xc7\x1a\x73"
				  "\x7f\xc4\x72\x39\x57\xc5\xc2\xed\x18\x4a\x68\x75"
				  "\x48\xa7\x61\xf1\x3f\xa6\x20\xc1";
								
	memset(cipher,0,BUFSIZE);
	memset(plain,0,BUFSIZE);
	
	if(access(FILEPATH,F_OK) == -1)
	{
		fp = fopen(FILEPATH, "w");
		fprintf(fp,"%s",msg);
		fclose(fp);
		fp = NULL;
		printf("No file exist yet, create file success\n");
	}
	
	fp = fopen(FILEPATH, "r");
	if(fp == NULL){
		printf("File exist but fail to read,please check.\n");
		return -1;
	}
	else{
		fseek(fp,0,SEEK_END);
		filelen = ftell(fp);
		rewind(fp); 
		/*assume count char in file < 255 */
		fread(cipher,sizeof(unsigned char),filelen,fp);             
		fclose(fp);
		printf("read file,len is %d\n",filelen);
	}

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/*
	 * Open a session to the TA, the TA will decrypt ciphertext.
	 */
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	/* Clear the TEEC_Operation struct */
	memset(&op, 0, sizeof(op));
	
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = cipher;
	op.params[0].tmpref.size = filelen;
	op.params[1].tmpref.buffer = plain;
	op.params[1].tmpref.size = BUFSIZE;

	/*
	 * TA_AES_DECRYPT is the actual function in the TA to be
	 * called.
	 */
	res = TEEC_InvokeCommand(&sess, TA_AES_DECRYPT, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	printf("Get plain text: %s,return len is %d\n", (unsigned char*)op.params[1].tmpref.buffer,(int)op.params[1].tmpref.size);

	/*
	 * We're done with the TA, close the session and
	 * destroy the context.
	 *
	 * The TA will print "Goodbye!" in the log when the
	 * session is closed.
	 */

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
