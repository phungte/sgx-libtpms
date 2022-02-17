#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>

#include "tpm_debug.h"
#include "tpm_error.h"
#include "tpm_memory.h"

#include "tpm_nvfile.h"

#include "tpm_library_intern.h"
#include "tpm_library.h"
#include "Enclave_t.h"

int asprintf(char **sptr, const char *__restrict format, ...)
{
    va_list ap;
    va_start(ap, format);
    int result;
    result = vasprintf(sptr, format, ap);
    va_end(ap);
    return result;
}

static struct libtpms_ocallbacks callbacks = {
    .sizeOfStruct            = sizeof(struct libtpms_ocallbacks),
    .tpm_nvram_init          = ocall_SWTPM_NVRAM_Init,
    .tpm_nvram_loaddata      = ocall_SWTPM_NVRAM_LoadData,
    .tpm_nvram_datasize      = ocall_SWTPM_NVRAM_DataSize,
    .tpm_nvram_storedata     = ocall_SWTPM_NVRAM_StoreData,
    .tpm_nvram_deletename    = ocall_SWTPM_NVRAM_DeleteName,
    .tpm_io_init             = ocall_SWTPM_IO_Init,
    .tpm_io_getlocality      = ocall_mainloop_cb_get_locality,
};
extern struct libtpms_ocallbacks libtpms_cbs;

TPM_RESULT tpmlib_register_callbacks(uint32_t  cbs_unused) {
    return TPMLIB_RegisterCallbacks(&callbacks);
}

TPM_RESULT TPMLIB_RegisterCallbacks(struct libtpms_ocallbacks *callbacks)
{
    int max_size = sizeof(struct libtpms_ocallbacks);

    /* restrict the size of the structure to what we know currently
       future versions may know more callbacks */
    if (callbacks->sizeOfStruct < max_size)
        max_size = callbacks->sizeOfStruct;

    /* clear the internal callback structure and copy the user provided
       callbacks into it */
    memset(&libtpms_cbs, 0x0, sizeof(libtpms_cbs));
    memcpy(&libtpms_cbs, callbacks, max_size);

    return TPM_SUCCESS;
}
