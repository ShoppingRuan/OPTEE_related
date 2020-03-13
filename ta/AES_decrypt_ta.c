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

#define STR_TRACE_USER_TA "AES_DECRYPT"

#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "AES_decrypt_ta.h"

#define BLOCKSIZE  16

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("Session open!\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	IMSG("Goodbye!\n");
}

static TEE_Result Decrypt_Ciphertext(uint32_t param_types,
	TEE_Param params[4])
{	
	TEE_Attribute attr;
	TEE_OperationHandle oper = NULL;
	TEE_ObjectHandle obj = NULL;
    	unsigned char* inbuf = (unsigned char *)params[0].memref.buffer;
    	unsigned char* outbuf = (unsigned char *)params[1].memref.buffer;
    	uint32_t inlen = params[0].memref.size;
	uint32_t outlen = params[1].memref.size;
	uint32_t leavelen = outlen;
	uint32_t writelen = 0;
	TEE_Result ret = 0;
	
	char key[]="qxhzngy266a186ke";
	char IV[] ="1ci5crnda6ojzgtr";
	
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	
	/** 1) Allocate the operation handle */
    	ret = TEE_AllocateOperation(&oper, TEE_ALG_AES_CBC_NOPAD, TEE_MODE_DECRYPT, strlen(key)*8);
    	if(ret != TEE_SUCCESS)
    	{
		DMSG("TEE_AllocateOperation eeeor");
        	goto cleanup_1;
   	 }
	
	DMSG("has been called");
	
	/**2)  Allocate the key object handle */
    	ret = TEE_AllocateTransientObject(TEE_TYPE_AES, strlen(key)*8, &obj);
    	if(ret != TEE_SUCCESS)
    	{
        //l_Result = TEE_ERROR_OUT_OF_MEMORY 	;
		DMSG("TEE_AllocateTransientObject error");
        	goto cleanup_2;
    	}   
	
	DMSG("has been called");
	
	/**3) Set the key object parameter */
    	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, strlen(key)); 
    	ret = TEE_PopulateTransientObject(obj, &attr, 1);
    	if(ret != TEE_SUCCESS)
    	{
		DMSG("TEE_PopulateTransientObject error");
        	goto cleanup_3;
    	}
	
	DMSG("has been called");
	/**4) Assemble aes operation handle */
    	ret = TEE_SetOperationKey(oper, obj);
    	if(ret != TEE_SUCCESS)
    	{
        //l_Result = FAIL;
		DMSG("TEE_SetOperationKey error");
        	goto cleanup_3;
    	}
	DMSG("has been called");
	
	TEE_CipherInit(oper, IV, strlen(IV));
	while( inlen > BLOCKSIZE){
		ret = TEE_CipherUpdate(oper, inbuf, BLOCKSIZE, outbuf, &leavelen);
		if(ret != TEE_SUCCESS)
		{
			DMSG("TEE_CipherUpdate error");
			goto cleanup_3;
		}
		inlen -= BLOCKSIZE;
		inbuf  = &(inbuf[BLOCKSIZE]);
		outbuf = &(outbuf[BLOCKSIZE]);
		writelen += leavelen;
		leavelen = outlen-writelen;
	}
	if( inlen % BLOCKSIZE !=0){
		DMSG("Input cipher not satisfy");
		goto cleanup_3;
	}
	else{
		ret = TEE_CipherDoFinal(oper, inbuf, inlen, outbuf, &leavelen);
		if(ret != TEE_SUCCESS)
		{
			DMSG("TEE_CipherDoFinal error");
			goto cleanup_3;
		}
	}
	
	DMSG("Decrypt success");
	DMSG("writelen:%d,leavelen:%d",writelen,leavelen);

	outbuf[leavelen]='\0';

	params[1].memref.size = writelen+leavelen;

cleanup_3:
	TEE_FreeTransientObject(obj);
cleanup_2:
    	TEE_FreeOperation(oper);
cleanup_1:
    	return ret;
}
/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id) {
	case TA_AES_DECRYPT:
		return Decrypt_Ciphertext(param_types, params);
	//case TA_HELLO_WORLD_CMD_DEC_VALUE:
		//return dec_value(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
