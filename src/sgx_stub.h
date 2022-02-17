#ifndef SGX_STUB_H
#define SGX_STUB_H
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include "sgx_tprotected_fs.h"
#include "sgx_error.h"
#include "sgx_trts.h"
#include "mbusafecrt.h"
#include "time.h"
// #include "Enclave_libtpms_t.h"

#define fprintf(...)
#define dprintf(...)
#define vdprintf(...)
#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1

#define FILE SGX_FILE
#define fread sgx_fread
#define fwrite sgx_fwrite
#define fflush sgx_fflush
#define fclose sgx_fclose
#define fseek sgx_fseek
#define ftell sgx_ftell
#define remove sgx_remove
#define fopen(X, Y) sgx_fopen(X, Y, NULL)

/* ocalls */
typedef uint32_t  TPM_RESULT;
typedef unsigned char  TPM_BOOL;
typedef uint32_t              TPM_MODIFIER_INDICATOR;
int asprintf(char **sptr, const char *__restrict format, ...);

#if 0
typedef enum TPMLIB_TPMVersion {
    TPMLIB_TPM_VERSION_1_2,
    TPMLIB_TPM_VERSION_2,
} TPMLIB_TPMVersion;

enum TPMLIB_InfoFlags {
    TPMLIB_INFO_TPMSPECIFICATION = 1,
    TPMLIB_INFO_TPMATTRIBUTES = 2,
    TPMLIB_INFO_TPMFEATURES = 4,
};

enum TPMLIB_TPMProperty {
    TPMPROP_TPM_RSA_KEY_LENGTH_MAX = 1,
    TPMPROP_TPM_BUFFER_MAX,
    TPMPROP_TPM_KEY_HANDLES,
    TPMPROP_TPM_OWNER_EVICT_KEY_HANDLES,
    TPMPROP_TPM_MIN_AUTH_SESSIONS,
    TPMPROP_TPM_MIN_TRANS_SESSIONS,
    TPMPROP_TPM_MIN_DAA_SESSIONS,
    TPMPROP_TPM_MIN_SESSION_LIST,
    TPMPROP_TPM_MIN_COUNTERS,
    TPMPROP_TPM_NUM_FAMILY_TABLE_ENTRY_MIN,
    TPMPROP_TPM_NUM_DELEGATE_TABLE_ENTRY_MIN,
    TPMPROP_TPM_SPACE_SAFETY_MARGIN,
    TPMPROP_TPM_MAX_NV_SPACE,
    TPMPROP_TPM_MAX_SAVESTATE_SPACE,
    TPMPROP_TPM_MAX_VOLATILESTATE_SPACE,
};

enum TPMLIB_StateType {
    TPMLIB_STATE_PERMANENT  = (1 << 0),
    TPMLIB_STATE_VOLATILE   = (1 << 1),
    TPMLIB_STATE_SAVE_STATE = (1 << 2),
};
#endif


#define clock_gettime ocall_clock_gettime

/* ecalls */
#define tpmlib_register_callbacks ecall_tpmlib_register_callbacks
#define TPMLIB_ChooseTPMVersion ecall_TPMLIB_ChooseTPMVersion
#define TPMLIB_Terminate ecall_TPMLIB_Terminate

#define TPMLIB_Process ecall_TPMLIB_Process
#define TPMLIB_SetBufferSize ecall_TPMLIB_SetBufferSize
#define TPM_IO_TpmEstablished_Get ecall_TPM_IO_TpmEstablished_Get
#define TPM_IO_Hash_Start ecall_TPM_IO_Hash_Start
#define TPM_IO_Hash_End ecall_TPM_IO_Hash_End
#define TPMLIB_CancelCommand ecall_TPMLIB_CancelCommand
#define TPMLIB_GetInfo ecall_TPMLIB_GetInfo
#define TPM_IO_Hash_Data ecall_TPM_IO_Hash_Data
#define TPM_IO_TpmEstablished_Reset ecall_TPM_IO_TpmEstablished_Reset
#define TPMLIB_SetDebugFD ecall_TPMLIB_SetDebugFD
#define TPMLIB_SetDebugLevel ecall_TPMLIB_SetDebugLevel
#define TPMLIB_SetDebugPrefix ecall_TPMLIB_SetDebugPrefix
// #define TPMLIB_RegisterCallbacks ecall_TPMLIB_RegisterCallbacks
#define TPMLIB_GetTPMProperty ecall_TPMLIB_GetTPMProperty
#define TPMLIB_MainInit ecall_TPMLIB_MainInit
#define TPMLIB_VolatileAll_Store_ecall ecall_TPMLIB_VolatileAll_Store_ecall
#define TPMLIB_VolatileAll_Store_Size ecall_TPMLIB_VolatileAll_Store_Size
#define TPMLIB_SetState ecall_TPMLIB_SetState

typedef int clockid_t;

struct timespec {
	time_t   tv_sec;        /* seconds */
	long     tv_nsec;       /* nanoseconds */
};

static inline
int vasprintf(char **strp, const char *fmt, va_list ap)
{
  const int buff_size = 256;
  int str_size;
  if ((*strp = (char *)malloc(buff_size)) == NULL)
  {
    return -1;
  }
  if ((str_size = vsnprintf(*strp, buff_size, fmt,  ap)) >= buff_size)
  {
    if ((*strp = (char *)realloc(*strp, str_size + 1)) == NULL)
    {
      return -1;
    }
    str_size = vsnprintf(*strp, str_size + 1, fmt,  ap);
  }
  return str_size;
}



static inline int rand ( void ) {
    int retval = 0;
    sgx_read_rand((unsigned char*)&retval, sizeof(int));
    return retval;
}

static inline void srand ( unsigned int seed ) {
}

#endif
