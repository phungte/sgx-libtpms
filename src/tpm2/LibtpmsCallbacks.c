/********************************************************************************/
/*										*/
/*				Libtpms Callbacks				*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2018.						*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

#include <stdint.h>
#include <string.h>

#include "Platform.h"
#include "LibtpmsCallbacks.h"
#include "NVMarshal.h"

#define TPM_HAVE_TPM2_DECLARATIONS
#include "tpm_library_intern.h"
#include "tpm_error.h"
#include "tpm_nvfilename.h"

#ifdef SGX_ENCLAVE
#include "sgx_trts.h"
#include "sgx_tseal.h"

// the struct is taken from swtpm_nvstore.c
typedef struct {
    uint8_t  version;
    uint8_t  min_version; /* min. required version */
    uint16_t hdrsize;
    uint16_t flags;
    uint32_t totlen; /* length of the header and following data */
} __attribute__((packed)) blobheader;
#if !defined(ntohs)
#define ntohs(u16)                                      \
  ((uint16_t)(((((unsigned char*)&(u16))[0]) << 8)        \
            + (((unsigned char*)&(u16))[1])))
#endif
#endif

int
libtpms_plat__NVEnable(void)
{
    unsigned char *data = NULL;
    uint32_t length = 0;
#ifndef SGX_ENCLAVE
    struct libtpms_callbacks *cbs = TPMLIB_GetCallbacks();
#else
    struct libtpms_ocallbacks *cbs = TPMLIB_GetCallbacks();
#endif
    TPM_RC rc;
    bool is_empty_state;

    /* try to get state blob set via TPMLIB_SetState() */
    GetCachedState(TPMLIB_STATE_PERMANENT, &data, &length, &is_empty_state);
    if (is_empty_state) {
        memset(s_NV, 0, NV_MEMORY_SIZE);
        return 0;
    }

    if (data == NULL && cbs->tpm_nvram_loaddata) {
        uint32_t tpm_number = 0;
        const char *name = TPM_PERMANENT_ALL_NAME;
        TPM_RESULT ret;
#ifndef SGX_ENCLAVE
        ret = cbs->tpm_nvram_loaddata(&data, &length, tpm_number, name);
#else
	sgx_status_t status;
	status = cbs->tpm_nvram_datasize(&ret, &length, tpm_number, name);
	if (status != SGX_SUCCESS)
	    ret = TPM_FAIL;
	data = malloc(length);
        status = cbs->tpm_nvram_loaddata(&ret, data, length, tpm_number, name);
	if (status != SGX_SUCCESS)
	    ret = TPM_FAIL;
#endif
        switch (ret) {
        case TPM_RETRY:
            if (!cbs->tpm_nvram_storedata) {
                return -1;
            }
            memset(s_NV, 0, NV_MEMORY_SIZE);
            return 0;

        case TPM_SUCCESS:
            /* got the data -- unmarshal them... */
            break;

        case TPM_FAIL:
        default:
            return -1;
        }
    }

    if (data) {
        unsigned char *buffer = data;
        INT32 size = length;

#ifdef SGX_ENCLAVE
	/*
	 * loaddata_ocall returns full data
	 */
	blobheader *hdr = (blobheader*)buffer;
	/* skip the header */
	buffer += ntohs(hdr->hdrsize);
	/* skip encryption header */
	buffer += 6;
	size -= 0x10;
	uint32_t mac_text_len = sgx_get_add_mac_txt_len((const sgx_sealed_data_t *)buffer);
	uint32_t decrypt_data_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)buffer);
	if (mac_text_len == UINT32_MAX || decrypt_data_len == UINT32_MAX) {
	    rc = -1;
	    goto end;
	}
	uint8_t *de_mac_text =(uint8_t *)malloc(mac_text_len);
	if (de_mac_text == NULL) {
	    rc = -1;
	    goto end;
	}
	uint8_t *decrypt_data = (uint8_t *)malloc(decrypt_data_len);
	if(decrypt_data == NULL) {
	    free(de_mac_text);
	    rc = -1;
	    goto end;
	}

	sgx_status_t ret = sgx_unseal_data((const sgx_sealed_data_t *)buffer, de_mac_text\
					   , &mac_text_len, decrypt_data, &decrypt_data_len);
	if (ret != SGX_SUCCESS) {
	    free(de_mac_text);
	    free(decrypt_data);
	    rc = -1;
	    goto end;
	} else {
	    free(data);
	    data = buffer = decrypt_data;
	    size = decrypt_data_len;
	}
#endif	

        rc = PERSISTENT_ALL_Unmarshal(&buffer, &size);
#ifdef SGX_ENCLAVE	
      end:
#endif	
        free(data);

        if (rc != TPM_RC_SUCCESS)
            return -1;
         return 0;
    }
    return LIBTPMS_CALLBACK_FALLTHROUGH; /* -2 */
}

int
libtpms_plat__NVDisable(
		 void
		 )
{
#ifndef SGX_ENCLAVE
    struct libtpms_callbacks *cbs = TPMLIB_GetCallbacks();
#else
    struct libtpms_ocallbacks *cbs = TPMLIB_GetCallbacks();
#endif

    if (cbs->tpm_nvram_loaddata)
        return 0;
    return LIBTPMS_CALLBACK_FALLTHROUGH; /* -2 */
}

int
libtpms_plat__IsNvAvailable(
		     void
		     )
{
#ifndef SGX_ENCLAVE
    struct libtpms_callbacks *cbs = TPMLIB_GetCallbacks();
#else
    struct libtpms_ocallbacks *cbs = TPMLIB_GetCallbacks();
#endif
    if (cbs->tpm_nvram_loaddata &&
        cbs->tpm_nvram_storedata) {
        return 1;
    }
    return LIBTPMS_CALLBACK_FALLTHROUGH; /* -2 */
}

int
libtpms_plat__NvCommit(
		void
		)

{
#ifndef SGX_ENCLAVE
    struct libtpms_callbacks *cbs = TPMLIB_GetCallbacks();
#else
    struct libtpms_ocallbacks *cbs = TPMLIB_GetCallbacks();
#endif
    if (cbs->tpm_nvram_storedata) {
        uint32_t tpm_number = 0;
        const char *name = TPM_PERMANENT_ALL_NAME;
        TPM_RESULT ret;
        BYTE *buf;
        uint32_t buflen;

        ret = TPM2_PersistentAllStore(&buf, &buflen);
        if (ret != TPM_SUCCESS)
            return ret;
#ifndef SGX_ENCLAVE
        ret = cbs->tpm_nvram_storedata(buf, buflen,
                                       tpm_number, name);
#else
	sgx_status_t status;
	uint32_t sealed_data_size = sgx_calc_sealed_data_size(0, (uint32_t)buflen);
	if (sealed_data_size == UINT32_MAX)
	    return TPM_FAIL;
	uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
	if(temp_sealed_buf == NULL) {
	    ret = TPM_FAIL;
	    goto end;
	}
	status = sgx_seal_data(0, (const uint8_t *)NULL, (uint32_t)buflen, (uint8_t *)buf, sealed_data_size, (sgx_sealed_data_t *)temp_sealed_buf);
	if (status == SGX_SUCCESS) {
	    free(buf);
	    buf = temp_sealed_buf;
	    buflen = sealed_data_size;
	} else {
	    free(temp_sealed_buf);
	    goto end;
	}

	status = cbs->tpm_nvram_storedata(&ret, buf, buflen,
                                       tpm_number, name);
	if (status != SGX_SUCCESS)
	    ret = TPM_FAIL;
	
      end:	
#endif
        free(buf);
        if (ret == TPM_SUCCESS)
            return 0;

        return -1;
    }
    return LIBTPMS_CALLBACK_FALLTHROUGH; /* -2 */
}

int
libtpms_plat__PhysicalPresenceAsserted(
				BOOL *pp
				)
{
#ifndef SGX_ENCLAVE
    struct libtpms_callbacks *cbs = TPMLIB_GetCallbacks();
#else
    struct libtpms_ocallbacks *cbs = TPMLIB_GetCallbacks();
#endif

    if (cbs->tpm_io_getphysicalpresence) {
        uint32_t tpm_number = 0;
        TPM_RESULT res;
        unsigned char mypp;

#ifndef SGX_ENCLAVE
        res = cbs->tpm_io_getphysicalpresence(&mypp, tpm_number);
#else
	sgx_status_t status;
        status = cbs->tpm_io_getphysicalpresence(&res, &mypp, tpm_number);
	if (status != SGX_SUCCESS)
	    res = TPM_FAIL;
#endif
        if (res == TPM_SUCCESS) {
            *pp = mypp;
            return 0;
        }
    }
    return LIBTPMS_CALLBACK_FALLTHROUGH;
}
