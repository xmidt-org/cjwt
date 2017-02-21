/**
 * Copyright 2017 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <errno.h>

#include <base64.h>
#include <cJSON.h>

#include <openssl/hmac.h>
#include <openssl/err.h>

#include "cjwt.h"

/*----------------------------------------------------------------------------*/
/*                                   Macros                                   */
/*----------------------------------------------------------------------------*/

#ifdef _DEBUG

#define cjwt_error(...)	printf(__VA_ARGS__)
#define cjwt_warn(...)	printf(__VA_ARGS__)
#define cjwt_info(...)	printf(__VA_ARGS__)
 
#else

#define cjwt_error(...)	
#define cjwt_warn(...)	
#define cjwt_info(...)	

#endif


/*----------------------------------------------------------------------------*/
/*                               Data Structures                              */
/*----------------------------------------------------------------------------*/
/* none */

/*----------------------------------------------------------------------------*/
/*                            File Scoped Variables                           */
/*----------------------------------------------------------------------------*/
/* none */

/*----------------------------------------------------------------------------*/
/*                             Function Prototypes                            */
/*----------------------------------------------------------------------------*/
/* none */

/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/
/* none */

/*----------------------------------------------------------------------------*/
/*                             Internal functions                             */
/*----------------------------------------------------------------------------*/
/* none */

static cjwt_alg_t cjwt_alg_str_to_enum(const char *alg_str)
{
	cjwt_alg_t algo = alg_none;
	
	if (!strcasecmp(alg_str, "none"))
		algo = alg_none;
	else if (!strcasecmp(alg_str, "ES256"))
		algo = alg_es256;
	else if (!strcasecmp(alg_str, "ES384"))
		algo = alg_es384;
	else if (!strcasecmp(alg_str, "ES512"))
		algo = alg_es512;
	else if (!strcasecmp(alg_str, "HS256"))
		algo = alg_hs256;
	else if (!strcasecmp(alg_str, "HS384"))
		algo = alg_hs384;
	else if (!strcasecmp(alg_str, "HS512"))
		algo = alg_hs512;
	else if (!strcasecmp(alg_str, "PS256"))
		algo = alg_ps256;
	else if (!strcasecmp(alg_str, "PS384"))
		algo = alg_ps384;
	else if (!strcasecmp(alg_str, "PS512"))
		algo = alg_ps512;
	else if (!strcasecmp(alg_str, "RS256"))
		algo = alg_rs256;
	else if (!strcasecmp(alg_str, "RS384"))
		algo = alg_rs384;
	else if (!strcasecmp(alg_str, "RS512"))
		algo = alg_rs512;
	
	return algo;
}
 
static void inline cjwt_delete_child_json(cJSON* j,const char* s)
{
	if( j && cJSON_HasObjectItem(j,s) ) cJSON_DeleteItemFromObject(j,s);
}

static void cjwt_delete_public_claims(cJSON* val)
{
	cjwt_delete_child_json(val,"iss");
	cjwt_delete_child_json(val,"sub");
	cjwt_delete_child_json(val,"aud");
	cjwt_delete_child_json(val,"jti");
}

static int cjwt_base64uri_encode(char *str)
{
	 int len = strlen(str);
	 int i, t;
 
	 for (i = t = 0; i < len; i++) {
		 switch (str[i]) {
		 case '+':
			 str[t] = '-';
			 break;
		 case '/':
			 str[t] = '_';
			 break;
		 case '=':
			 str[t] = '\0';
			 break;
		 }
 
		 t++;
	 }
 
	 str[t] = '\0';
	 return strlen(str);
}

static int cjwt_sign_sha_hmac(cjwt_t *jwt, unsigned char **out,const EVP_MD *alg,
										   const char *in, int *out_len)
{
	 unsigned char res[EVP_MAX_MD_SIZE];
	 unsigned int res_len;
 
	 cjwt_info("string for signing : %s \n",in);
	 HMAC(alg, jwt->header.key, jwt->header.key_len,
		  (const unsigned char *)in, strlen(in), res, &res_len);
		  
	 unsigned char *resptr = malloc(res_len);
	 if(!resptr)
		 return ENOMEM;
	 memcpy(resptr,res,res_len);
	 resptr[res_len] = '\0';
	 
	 *out = resptr;
	 *out_len = res_len;
	 
	 return 0;
}
 
static int cjwt_sign(cjwt_t *cjwt, unsigned char **out, const char *in, int *out_len)
{
	 switch (cjwt->header.alg) 
	 {
		 case alg_none:
			 return 0;
		 case alg_hs256:
			 return cjwt_sign_sha_hmac(cjwt, out, EVP_sha256(), in, out_len);
		 case alg_hs384:
			 return cjwt_sign_sha_hmac(cjwt, out, EVP_sha384(), in, out_len);
		 case alg_hs512:
			 return cjwt_sign_sha_hmac(cjwt, out, EVP_sha512(), in, out_len);
		 default :
			 return  -1;
	 }//switch
 
	 return -1; 
}

static int cjwt_verify_signature(cjwt_t *p_jwt, char *p_in, const char *p_sign)
{
	int ret = 0;
	int sz_signed = 0;

	unsigned char* signed_out = NULL;

	if( !p_jwt || !p_in || !p_sign )
	{
		ret = EINVAL;
		goto end;
	}
	
	ret = cjwt_sign(p_jwt, &signed_out,p_in, &sz_signed);
	
	if(ret)
	{
		ret = EINVAL;
		goto end;
	}

	size_t sz_encoded = b64_get_encoded_buffer_size(sz_signed);

	uint8_t *signed_enc = malloc(sz_encoded);
	if(!signed_enc)
	{
		ret = ENOMEM;
		goto err_encode;
	}

	b64_encode( (uint8_t *)signed_out, sz_signed, signed_enc);

	sz_encoded = cjwt_base64uri_encode((char*)signed_enc);
	
	cjwt_info("signed encoded : %s\n",signed_enc);
	cjwt_info("expected token signature  %s\n",p_sign);
	
	size_t sz_p_sign = strlen(p_sign);
	if (sz_encoded != sz_p_sign) {
		cjwt_info ("Signature length mismatch: enc %d, signature %d\n", 
			(int)sz_encoded, (int)sz_p_sign);
		ret = -1;
		goto err_mismatch;
	}

	ret = CRYPTO_memcmp(
		  (unsigned char*)signed_enc, (unsigned char*)p_sign, sz_p_sign); 
		  
err_mismatch:	
	free(signed_enc);
	
err_encode:
	free(signed_out);
end:
	return ret;
}

static int cjwt_update_payload(cjwt_t *p_cjwt, char *p_decpl)
{
	if( !p_cjwt || !p_decpl )
		return EINVAL;
	
	//create cJSON object
	cJSON *j_payload = cJSON_Parse((char*)p_decpl);
	if( !j_payload)
		return ENOMEM;
	
	//extract data
	cjwt_info("Json  = %s\n",cJSON_Print(j_payload));
	cjwt_info("--------------------------------------------- \n");
	
	//iss
	cJSON* j_val = cJSON_GetObjectItem(j_payload,"iss");
	if( j_val )
	{
		if( p_cjwt->iss )
			free(p_cjwt->iss);
		p_cjwt->iss = malloc(strlen(j_val->valuestring));
		strcpy(p_cjwt->iss, j_val->valuestring);
	}
	
	//sub
	j_val = cJSON_GetObjectItem(j_payload,"sub");
	if( j_val )
	{
		if( p_cjwt->sub )
			free(p_cjwt->sub);
		p_cjwt->sub = malloc(strlen(j_val->valuestring));
		strcpy(p_cjwt->sub, j_val->valuestring);
	}
	
	//aud
	j_val = cJSON_GetObjectItem(j_payload,"aud");
	if( j_val )
	{
		if( p_cjwt->aud )
			free(p_cjwt->aud);
		p_cjwt->aud = malloc(strlen(j_val->valuestring));
		strcpy(p_cjwt->aud, j_val->valuestring);
	}
	
	//jti
	j_val = cJSON_GetObjectItem(j_payload,"jti");
	if( j_val )
	{
		if( p_cjwt->jti )
			free(p_cjwt->jti);
		p_cjwt->jti = malloc(strlen(j_val->valuestring));
		strcpy(p_cjwt->jti, j_val->valuestring);
	}
	
	//private_claims
	cJSON* j_new = cJSON_Duplicate(j_payload,1);
	if( j_new )
	{
	
		cjwt_delete_public_claims(j_new);
		
		cjwt_info("private claims count = %d\n",cJSON_GetArraySize(j_new));
		if( cJSON_GetArraySize(j_new) )
		{
			cjwt_info("private claims  = %s\n",cJSON_Print(j_new));
			if( p_cjwt->private_claims )
				cJSON_Delete(p_cjwt->private_claims);
			
			p_cjwt->private_claims = j_new;
		}
	}
	//destroy cJSON object
	cJSON_Delete(j_payload);
	
	return 0;
}

static int cjwt_update_header(cjwt_t *p_cjwt, char *p_dechead)
{
	if( !p_cjwt || !p_dechead )
		return EINVAL;
	
	//create cJSON object
	cJSON *j_header = cJSON_Parse((char*)p_dechead);
	if( !j_header)
		return ENOMEM;
	
	cjwt_info("Json  = %s\n",cJSON_Print(j_header));
	cjwt_info("--------------------------------------------- \n");
	
	//extract data
	cJSON* j_typ = cJSON_GetObjectItem(j_header,"typ");

	if(!j_typ || strcmp(j_typ->valuestring,"JWT"))
		return EINVAL;
		
	cJSON* j_alg = cJSON_GetObjectItem(j_header,"alg");
	if(j_alg)
		p_cjwt->header.alg = cjwt_alg_str_to_enum(j_alg->valuestring);
	
	//destroy cJSON object
	cJSON_Delete(j_header);
	
	return 0;
}

static int cjwt_parse_payload(cjwt_t *p_cjwt, char *p_payload)
{
	if(!p_cjwt || !p_payload)
		return EINVAL;
	
	int sz_payload = strlen((char *)p_payload);
	size_t pl_desize = b64_get_decoded_buffer_size(sz_payload);
	
	cjwt_info("Payload Size = %d , Decoded size = %d\n",sz_payload,(int)pl_desize);

	uint8_t *decoded_pl = malloc(pl_desize);
	if(!decoded_pl)
		return ENOMEM;
	
	memset(decoded_pl,0,pl_desize);
	size_t out_size = 0;
	
	//decode body
	out_size = b64_decode( (uint8_t *)p_payload, sz_payload, decoded_pl );

	cjwt_info("----------------- payload ------------------- \n");
	cjwt_info("Bytes = %d\n",(int)out_size);
	cjwt_info("Raw data  = %*s\n",(int)out_size,decoded_pl);
	
	if(!out_size)
		return EINVAL;
	
	return cjwt_update_payload(p_cjwt, (char*)decoded_pl );
}

static int cjwt_parse_header(cjwt_t *p_cjwt, char *p_head)
{
	if(!p_cjwt || !p_head)
		return EINVAL;

	int sz_head = strlen((char *)p_head);
	size_t head_desize = b64_get_decoded_buffer_size(sz_head);
	
	cjwt_info("Header Size = %d , Decoded size = %d\n",sz_head,(int)head_desize);

	uint8_t *decoded_head = malloc(head_desize);
	if(!decoded_head)
		return ENOMEM;
	
	memset(decoded_head,0,head_desize);

	size_t out_size = 0;
	
	//decode header
	out_size = b64_decode( (uint8_t *)p_head, sz_head,decoded_head );

	cjwt_info("----------------- header -------------------- \n");
	cjwt_info("Bytes = %d\n",(int)out_size);
	cjwt_info("Raw data  = %*s\n",(int)out_size,decoded_head);
	cjwt_info("--------------------------------------------- \n");
	
	if(!out_size)
		return EINVAL;
	
	return cjwt_update_header(p_cjwt, (char*)decoded_head);
}

static int cjwt_update_key(cjwt_t *p_cjwt, const uint8_t *key, size_t key_len )
{
	int ret = 0;
	
	if ((NULL != key) && (key_len > 0)) 
	{
		p_cjwt->header.key = malloc(key_len);
		if (!p_cjwt->header.key) {
			ret = ENOMEM;
			return ret;
		}
		memcpy(p_cjwt->header.key, key, key_len);
		p_cjwt->header.key_len = key_len;
	}
	else
		ret = EINVAL;
	
	return ret;
}

static cjwt_t* cjwt_create()
{
	cjwt_t *init = malloc(sizeof(cjwt_t));
	if( !init )
	{
		return NULL;
	}
	
	init->iss = NULL;
	init->sub = NULL;
	init->aud = NULL;
	init->jti = NULL;
	
	init->private_claims = NULL;
	
	/* TBD */
	//struct timespec exp;
    //struct timespec nbf;
    //struct timespec iat;
	
	return init;
}
 
/**
 * validates jwt token and extracts data
 */
int cjwt_decode(const char *encoded, unsigned int options, cjwt_t **jwt,
                 const uint8_t *key, size_t key_len )
{
	int ret = 0;
	//char *enc_token; 
	char *payload, *signature;
	
	//validate inputs
	if(!encoded || !jwt)
	{
		cjwt_error("null parameter\n");
		ret = EINVAL;
		goto error;
	}
	
	cjwt_info("decoding cjwt\n -> encoded : %s\n -> options : %d\n",encoded,options);
	
	//create copy
	char *enc_token = malloc(strlen(encoded) + 1);
	
	if(!enc_token)
	{
		cjwt_error("memory alloc failed\n");
		ret = ENOMEM;
		goto error;
	}
	strcpy(enc_token, encoded);
	
	//tokenize the jwt token
	for (payload = enc_token; payload[0] != '.'; payload++) {
		if (payload[0] == '\0') {
			cjwt_error ("Invalid jwt token,has only header\n");
			ret = EINVAL;
			goto end;
		}
	}

	payload[0] = '\0';
	payload++;

	for (signature = payload; signature[0] != '.'; signature++) {
		if (signature[0] == '\0') {
			cjwt_error ("Invalid jwt token,missing signature\n");
			ret = EINVAL;
			goto end;
		}
	}

	signature[0] = '\0';
	signature++;
	
	//create cjson 
	cjwt_t *out = cjwt_create(&out);
	if(!out)
	{
		cjwt_error("cjwt memory alloc failed\n");
		ret = ENOMEM;
		goto end;
	}
	
	//populate key 
	ret = cjwt_update_key(out, key, key_len);
	if( ret )
	{
		cjwt_error("Failed to update key\n");
		goto invalid;
	}
	
	//parse header
	ret = cjwt_parse_header(out, enc_token );
	if( ret )
	{
		cjwt_error("Invalid header\n");
		goto invalid;
	}
	
	//parse payload
	ret = cjwt_parse_payload(out, payload);
	if( ret )
	{
		cjwt_error("Invalid payload\n");
		goto invalid;
	}
	
	enc_token[strlen(enc_token)] = '.';
	
	//verify
	ret = cjwt_verify_signature(out, enc_token, signature);
	if( ret )
	{
		cjwt_error("Signature authentication failed\n");
		goto invalid;
	}
	
	cjwt_info("Signature authentication passed\n");

invalid:
	if( ret )
		cjwt_destroy(&out);
	else
		*jwt = out;
end:
	free(enc_token);
error:
	return ret;
}

/**
 * cleanup jwt object
 */
int cjwt_destroy( cjwt_t **jwt )
{
	cjwt_t *del = *jwt;
	jwt = NULL;
	
	if( !del )
	{
		return 0;
	}
	if( del->iss )
		free(del->iss);
	del->iss = NULL;
	
	if( del->sub )
		free(del->sub);
	del->sub = NULL;
	
	if( del->aud )
		free(del->aud);
	del->aud = NULL;
	
	if( del->jti )
		free(del->jti);
	del->jti = NULL;
	
	if( del->private_claims )
		cJSON_Delete(del->private_claims);
	del->private_claims = NULL;
	
	/* TBD */
	//struct timespec exp;
    //struct timespec nbf;
    //struct timespec iat;
	return 0;
}
//end of file