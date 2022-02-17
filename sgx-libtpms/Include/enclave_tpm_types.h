#ifndef ENCLAVE_TPM_TYPES_H
#define ENCLAVE_TPM_TYPES_H
/*
 * some headers like tpm_library.h if brought in, 
 * would be too much, difficult to separate enclave from non-enclave declarations.
 * Copy here some needed declarations.
 */
#ifndef TPM_LIBRARY_H
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
#endif
