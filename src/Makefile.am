#
# src/Makefile.am
#
# For the license, see the LICENSE file in the root directory.
#

AM_CFLAGS = @AM_CFLAGS@
AM_LDFLAGS = @AM_LDFLAGS@ $(HARDENING_LDFLAGS) $(SANITIZERS) $(FUZZER) 
noinst_LTLIBRARIES =
noinst_HEADERS =

lib_LTLIBRARIES = libtpms.la
libtpms_la_LIBADD =


SGX_SDK := /opt/intel/sgxsdk
Enclave_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I../ -I/opt/intel/sgxssl/include -I/opt/intel/sgxssl/include/openssl   -include sgx_stub.h  -I../sgx-libtpms/Enclave -I../sgx-libtpms/Include/
SGX_COMMON_CFLAGS := -m64 -DSGX_ENCLAVE
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -DALG_CAMELLIA=0 -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)

SGXSSL_Link_Flags := -Wl,--whole-archive -lsgx_tsgxssl -Wl,--no-whole-archive -lsgx_tsgxssl_crypto
SGX_SSL = /opt/intel/sgxssl
SGXSSL_TRUSTED_LIB_PATH := $(SGX_SSL)/lib64
SGX_TPROTECTED_FS := sgx_tprotected_fs
Crypto_Library_Name := sgx_tcrypto
Trts_Library_Name := sgx_trts
Service_Library_Name := sgx_tservice

Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx  -l$(Crypto_Library_Name) -l$(Service_Library_Name) -lsgx_urts -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=../sgx-libtpms/Enclave.lds

common_CFLAGS = -include tpm_library_conf.h \
                -I$(top_srcdir)/include/libtpms \
		-I$(top_builddir)/include/libtpms \
		$(AM_CFLAGS) \
                $(HARDENING_CFLAGS) \
               $(SANITIZERS) \
               $(FUZZER) \
               $(LIBCRYPTO_EXTRA_CFLAGS) \
		$(Enclave_C_Flags)

# build with libtpms callback support
common_CFLAGS += -DTPM_LIBTPMS_CALLBACKS
# let the default NVRAM write to disk
common_CFLAGS += -DTPM_NV_DISK

# TPM2
#

noinst_LTLIBRARIES += libtpms_tpm2.la

libtpms_la_LIBADD += libtpms_tpm2.la

libtpms_tpm2_la_LIBADD = $(LIBRT_LIBS)

libtpms_tpm2_la_CFLAGS = $(common_CFLAGS)

libtpms_tpm2_la_CFLAGS += -D_POSIX_
libtpms_tpm2_la_CFLAGS += -DTPM_POSIX

libtpms_tpm2_la_SOURCES = \
	tpm2/ACT_spt.c \
	tpm2/ACTCommands.c \
	tpm2/AlgorithmCap.c \
	tpm2/AlgorithmTests.c \
	tpm2/AsymmetricCommands.c \
	tpm2/AttestationCommands.c \
	tpm2/Attest_spt.c \
	tpm2/AuditCommands.c \
	tpm2/Bits.c \
	tpm2/BnConvert.c \
	tpm2/BnMath.c \
	tpm2/BnMemory.c \
	tpm2/Cancel.c \
	tpm2/CapabilityCommands.c \
	tpm2/Clock.c \
	tpm2/ClockCommands.c \
	tpm2/CommandAudit.c \
	tpm2/CommandCodeAttributes.c \
	tpm2/CommandDispatcher.c \
	tpm2/ContextCommands.c \
	tpm2/Context_spt.c \
	tpm2/CryptEccData.c \
	tpm2/CryptSelfTest.c \
	tpm2/CryptUtil.c \
	tpm2/DA.c \
	tpm2/DebugHelpers.c \
	tpm2/DictionaryCommands.c \
	tpm2/DuplicationCommands.c \
	tpm2/EACommands.c \
	tpm2/EncryptDecrypt_spt.c \
	tpm2/Entity.c \
	tpm2/Entropy.c \
	tpm2/EphemeralCommands.c \
	tpm2/ExecCommand.c \
	tpm2/Global.c \
	tpm2/Handle.c \
	tpm2/HashCommands.c \
	tpm2/Hierarchy.c \
	tpm2/HierarchyCommands.c \
	tpm2/IntegrityCommands.c \
	tpm2/IoBuffers.c \
	tpm2/Locality.c \
	tpm2/LocalityPlat.c \
	tpm2/ManagementCommands.c \
	tpm2/Manufacture.c \
	tpm2/Marshal.c \
	tpm2/MathOnByteBuffers.c \
	tpm2/Memory.c \
	tpm2/NVCommands.c \
	tpm2/NVDynamic.c \
	tpm2/NVMem.c \
	tpm2/NVReserved.c \
	tpm2/NV_spt.c \
	tpm2/Object.c \
	tpm2/ObjectCommands.c \
	tpm2/Object_spt.c \
	tpm2/PCR.c \
	tpm2/PlatformACT.c \
	tpm2/PlatformData.c \
	tpm2/Policy_spt.c \
	tpm2/Power.c \
	tpm2/PowerPlat.c \
	tpm2/PP.c \
	tpm2/PPPlat.c \
	tpm2/PrimeData.c \
	tpm2/PropertyCap.c \
	tpm2/RandomCommands.c \
	tpm2/Response.c \
	tpm2/ResponseCodeProcessing.c \
	tpm2/RunCommand.c \
	tpm2/Session.c \
	tpm2/SessionCommands.c \
	tpm2/SessionProcess.c \
	tpm2/SigningCommands.c \
	tpm2/StartupCommands.c \
	tpm2/SymmetricCommands.c \
	tpm2/TestingCommands.c \
	tpm2/Ticket.c \
	tpm2/Time.c \
	tpm2/TpmAsn1.c \
	tpm2/TpmSizeChecks.c \
	tpm2/TPMCmdp.c \
	tpm2/TpmFail.c \
	tpm2/Unique.c \
	tpm2/Unmarshal.c \
	tpm2/Vendor_TCG_Test.c \
	tpm2/X509_ECC.c \
	tpm2/X509_RSA.c \
	tpm2/X509_spt.c \
	tpm_tpm2_interface.c \
	tpm_tpm2_tis.c \
	\
	tpm2/BackwardsCompatibilityObject.c \
	tpm2/LibtpmsCallbacks.c \
	tpm2/NVMarshal.c \
	tpm2/StateMarshal.c \
	tpm2/Volatile.c

noinst_HEADERS += \
	compiler.h \
	tpm2/crypto/CryptCmac_fp.h \
	tpm2/crypto/CryptDes_fp.h \
	tpm2/crypto/CryptEcc.h \
	tpm2/crypto/CryptEccCrypt_fp.h \
	tpm2/crypto/CryptEccKeyExchange_fp.h \
	tpm2/crypto/CryptEccMain_fp.h \
	tpm2/crypto/CryptEccSignature_fp.h \
	tpm2/crypto/CryptHash_fp.h \
	tpm2/crypto/CryptHash.h \
	tpm2/crypto/CryptPrime_fp.h \
	tpm2/crypto/CryptPrimeSieve_fp.h \
	tpm2/crypto/CryptRand_fp.h \
	tpm2/crypto/CryptRand.h \
	tpm2/crypto/CryptRsa_fp.h \
	tpm2/crypto/CryptRsa.h \
	tpm2/crypto/CryptSelfTest_fp.h \
	tpm2/crypto/CryptSmac_fp.h \
	tpm2/crypto/CryptSym.h \
	tpm2/crypto/CryptSym_fp.h \
	tpm2/crypto/CryptTest.h \
	tpm2/crypto/CryptUtil_fp.h \
	tpm2/ACT.h \
	tpm2/ACT_spt_fp.h \
	tpm2/ACT_SetTimeout_fp.h \
	tpm2/ActivateCredential_fp.h \
	tpm2/AlgorithmCap_fp.h \
	tpm2/AlgorithmTests_fp.h \
	tpm2/Attest_spt_fp.h \
	tpm2/BaseTypes.h \
	tpm2/Bits_fp.h \
	tpm2/Capabilities.h \
	tpm2/CertifyCreation_fp.h \
	tpm2/CertifyX509_fp.h \
	tpm2/Certify_fp.h \
	tpm2/ChangeEPS_fp.h \
	tpm2/ChangePPS_fp.h \
	tpm2/ClearControl_fp.h \
	tpm2/Clear_fp.h \
	tpm2/ClockRateAdjust_fp.h \
	tpm2/ClockSet_fp.h \
	tpm2/CommandAttributeData.h \
	tpm2/CommandAttributes.h \
	tpm2/CommandAudit_fp.h \
	tpm2/CommandCodeAttributes_fp.h \
	tpm2/CommandDispatchData.h \
	tpm2/CommandDispatcher_fp.h \
	tpm2/Commit_fp.h \
	tpm2/CompilerDependencies.h \
	tpm2/ContextLoad_fp.h \
	tpm2/ContextSave_fp.h \
	tpm2/Context_spt_fp.h \
	tpm2/Create_fp.h \
	tpm2/CreateLoaded_fp.h \
	tpm2/CreatePrimary_fp.h \
	tpm2/CryptSelfTest_fp.h \
	tpm2/DA_fp.h \
	tpm2/DebugHelpers_fp.h \
	tpm2/DictionaryAttackLockReset_fp.h \
	tpm2/DictionaryAttackParameters_fp.h \
	tpm2/Duplicate_fp.h \
	tpm2/EccTestData.h \
	tpm2/ECC_Parameters_fp.h \
	tpm2/ECDH_KeyGen_fp.h \
	tpm2/ECDH_ZGen_fp.h \
	tpm2/EC_Ephemeral_fp.h \
	tpm2/EncryptDecrypt2_fp.h \
	tpm2/EncryptDecrypt_fp.h \
	tpm2/EncryptDecrypt_spt_fp.h \
	tpm2/Entity_fp.h \
	tpm2/EventSequenceComplete_fp.h \
	tpm2/EvictControl_fp.h \
	tpm2/ExecCommand_fp.h \
	tpm2/FlushContext_fp.h \
	tpm2/GetCapability_fp.h \
	tpm2/GetCommandAuditDigest_fp.h \
	tpm2/GetRandom_fp.h \
	tpm2/GetSessionAuditDigest_fp.h \
	tpm2/GetTestResult_fp.h \
	tpm2/GetTime_fp.h \
	tpm2/Global.h \
	tpm2/GpMacros.h \
	tpm2/Handle_fp.h \
	tpm2/Hash_fp.h \
	tpm2/HashSequenceStart_fp.h \
	tpm2/HashTestData.h \
	tpm2/HierarchyChangeAuth_fp.h \
	tpm2/HierarchyControl_fp.h \
	tpm2/Hierarchy_fp.h \
	tpm2/HMAC_fp.h \
	tpm2/HMAC_Start_fp.h \
	tpm2/Import_fp.h \
	tpm2/IncrementalSelfTest_fp.h \
	tpm2/InternalRoutines.h \
	tpm2/IoBuffers_fp.h \
	tpm2/KdfTestData.h \
	tpm2/LoadExternal_fp.h \
	tpm2/Load_fp.h \
	tpm2/Locality_fp.h \
	tpm2/MAC_fp.h \
	tpm2/MAC_Start_fp.h \
	tpm2/MakeCredential_fp.h \
	tpm2/Manufacture_fp.h \
	tpm2/Marshal_fp.h \
	tpm2/MathOnByteBuffers_fp.h \
	tpm2/Memory_fp.h \
	tpm2/MinMax.h \
	tpm2/NV_Certify_fp.h \
	tpm2/NV_ChangeAuth_fp.h \
	tpm2/NV_DefineSpace_fp.h \
	tpm2/NVDynamic_fp.h \
	tpm2/NV_Extend_fp.h \
	tpm2/NV_GlobalWriteLock_fp.h \
	tpm2/NV.h \
	tpm2/NV_Increment_fp.h \
	tpm2/NV_Read_fp.h \
	tpm2/NV_ReadLock_fp.h \
	tpm2/NV_ReadPublic_fp.h \
	tpm2/NVReserved_fp.h \
	tpm2/NV_SetBits_fp.h \
	tpm2/NV_spt_fp.h \
	tpm2/NV_UndefineSpace_fp.h \
	tpm2/NV_UndefineSpaceSpecial_fp.h \
	tpm2/NV_Write_fp.h \
	tpm2/NV_WriteLock_fp.h \
	tpm2/OIDs.h \
	tpm2/ObjectChangeAuth_fp.h \
	tpm2/Object_fp.h \
	tpm2/Object_spt_fp.h \
	tpm2/PCR_Allocate_fp.h \
	tpm2/PCR_Event_fp.h \
	tpm2/PCR_Extend_fp.h \
	tpm2/PCR_fp.h \
	tpm2/PCR_Read_fp.h \
	tpm2/PCR_Reset_fp.h \
	tpm2/PCR_SetAuthPolicy_fp.h \
	tpm2/PCR_SetAuthValue_fp.h \
	tpm2/Platform.h \
	tpm2/PlatformACT.h \
	tpm2/PlatformACT_fp.h \
	tpm2/PlatformClock.h \
	tpm2/PlatformData.h \
	tpm2/Platform_fp.h \
	tpm2/PolicyAuthorize_fp.h \
	tpm2/PolicyAuthorizeNV_fp.h \
	tpm2/PolicyAuthValue_fp.h \
	tpm2/PolicyCommandCode_fp.h \
	tpm2/PolicyCounterTimer_fp.h \
	tpm2/PolicyCpHash_fp.h \
	tpm2/PolicyDuplicationSelect_fp.h \
	tpm2/PolicyGetDigest_fp.h \
	tpm2/PolicyLocality_fp.h \
	tpm2/PolicyNameHash_fp.h \
	tpm2/PolicyNV_fp.h \
	tpm2/PolicyNvWritten_fp.h \
	tpm2/PolicyOR_fp.h \
	tpm2/PolicyPassword_fp.h \
	tpm2/PolicyPCR_fp.h \
	tpm2/PolicyPhysicalPresence_fp.h \
	tpm2/PolicyRestart_fp.h \
	tpm2/PolicySecret_fp.h \
	tpm2/PolicySigned_fp.h \
	tpm2/Policy_spt_fp.h \
	tpm2/PolicyTemplate_fp.h \
	tpm2/PolicyTicket_fp.h \
	tpm2/Power_fp.h \
	tpm2/PP_Commands_fp.h \
	tpm2/PP_fp.h \
	tpm2/PRNG_TestVectors.h \
	tpm2/PropertyCap_fp.h \
	tpm2/Quote_fp.h \
	tpm2/ReadClock_fp.h \
	tpm2/ReadPublic_fp.h \
	tpm2/ResponseCodeProcessing_fp.h \
	tpm2/Response_fp.h \
	tpm2/Rewrap_fp.h \
	tpm2/RsaTestData.h \
	tpm2/RSA_Decrypt_fp.h \
	tpm2/RSA_Encrypt_fp.h \
	tpm2/SelfTest.h \
	tpm2/SelfTest_fp.h \
	tpm2/SequenceComplete_fp.h \
	tpm2/SequenceUpdate_fp.h \
	tpm2/Session_fp.h \
	tpm2/SessionProcess_fp.h \
	tpm2/SetAlgorithmSet_fp.h \
	tpm2/SetCommandCodeAuditStatus_fp.h \
	tpm2/SetPrimaryPolicy_fp.h \
	tpm2/Shutdown_fp.h \
	tpm2/Sign_fp.h \
	tpm2/Simulator_fp.h \
	tpm2/StartAuthSession_fp.h \
	tpm2/Startup_fp.h \
	tpm2/StirRandom_fp.h \
	tpm2/SupportLibraryFunctionPrototypes_fp.h \
	tpm2/SymmetricTest.h \
	tpm2/SymmetricTestData.h \
	tpm2/swap.h \
	tpm2/TcpServerPosix_fp.h \
	tpm2/TestParms_fp.h \
	tpm2/Ticket_fp.h \
	tpm2/Time_fp.h \
	tpm2/TPMB.h \
	tpm2/TpmAlgorithmDefines.h \
	tpm2/TpmAsn1.h \
	tpm2/TpmAsn1_fp.h \
	tpm2/TpmBuildSwitches.h \
	tpm2/TpmError.h \
	tpm2/TpmFail_fp.h \
	tpm2/TpmProfile.h \
	tpm2/Tpm.h \
	tpm2/_TPM_Hash_Data_fp.h \
	tpm2/_TPM_Hash_End_fp.h \
	tpm2/_TPM_Hash_Start_fp.h \
	tpm2/_TPM_Init_fp.h \
	tpm2/TpmSizeChecks_fp.h \
	tpm2/TpmTcpProtocol.h \
	tpm2/TpmTypes.h \
	tpm2/Unmarshal_fp.h \
	tpm2/Unseal_fp.h \
	tpm2/VendorString.h \
	tpm2/Vendor_TCG_Test_fp.h \
	tpm2/VerifySignature_fp.h \
	tpm2/X509.h \
	tpm2/X509_ECC_fp.h \
	tpm2/X509_RSA_fp.h \
	tpm2/X509_spt_fp.h \
	tpm2/ZGen_2Phase_fp.h \
	\
	tpm2/BackwardsCompatibility.h \
	tpm2/BackwardsCompatibilityObject.h \
	tpm2/LibtpmsCallbacks.h \
	tpm2/NVMarshal.h \
	tpm2/StateMarshal.h \
	tpm2/Utils.h \
	tpm2/Volatile.h

if LIBTPMS_USE_OPENSSL

libtpms_tpm2_la_SOURCES += \
	tpm2/crypto/openssl/CryptCmac.c \
	tpm2/crypto/openssl/CryptDes.c \
	tpm2/crypto/openssl/CryptEccKeyExchange.c \
	tpm2/crypto/openssl/CryptEccMain.c \
	tpm2/crypto/openssl/CryptEccSignature.c \
	tpm2/crypto/openssl/CryptHash.c \
	tpm2/crypto/openssl/CryptPrime.c \
	tpm2/crypto/openssl/CryptPrimeSieve.c \
	tpm2/crypto/openssl/CryptRand.c \
	tpm2/crypto/openssl/CryptRsa.c \
	tpm2/crypto/openssl/CryptSmac.c \
	tpm2/crypto/openssl/CryptSym.c \
	tpm2/crypto/openssl/ExpDCache.c \
	tpm2/crypto/openssl/Helpers.c \
	tpm2/crypto/openssl/TpmToOsslDesSupport.c \
	tpm2/crypto/openssl/TpmToOsslMath.c \
	tpm2/crypto/openssl/TpmToOsslSupport.c

noinst_HEADERS += \
	tpm2/crypto/openssl/ConsttimeUtils.h \
	tpm2/crypto/openssl/BnConvert_fp.h \
	tpm2/crypto/openssl/BnMath_fp.h \
	tpm2/crypto/openssl/BnMemory_fp.h \
	tpm2/crypto/openssl/BnValues.h \
	tpm2/crypto/openssl/ExpDCache_fp.h \
	tpm2/crypto/openssl/Helpers_fp.h \
	tpm2/crypto/openssl/LibSupport.h \
	tpm2/crypto/openssl/TpmToOsslDesSupport_fp.h \
	tpm2/crypto/openssl/TpmToOsslHash.h \
	tpm2/crypto/openssl/TpmToOsslMath_fp.h \
	tpm2/crypto/openssl/TpmToOsslMath.h \
	tpm2/crypto/openssl/TpmToOsslSupport_fp.h \
	tpm2/crypto/openssl/TpmToOsslSym.h

libtpms_tpm2_la_CFLAGS += \
	-I $(srcdir)/tpm2 \
	-I $(srcdir)/tpm2/crypto \
	-I $(srcdir)/tpm2/crypto/openssl


libtpms_tpm2_la_LIBADD += -lcrypto

endif # LIBTPMS_USE_OPENSSL

#
# Library API layer
#

libtpms_la_SOURCES = \
	sgx_stub.c \
	disabled_interface.c \
	tpm_debug.c \
	tpm_library.c \
	tpm_memory.c \
	tpm_nvfile.c

libtpms_la_CFLAGS = $(common_CFLAGS)

libtpms_la_LDFLAGS = -version-info $(LIBTPMS_VERSION_INFO) \
                     -no-undefined $(AM_LDFLAGS)

if HAVE_VERSION_SCRIPT
libtpms_la_LDFLAGS += -Wl,--version-script=$(srcdir)/libtpms.syms
endif

LDFLAGS_ARCH  = $(findstring -m32, $(AM_CFLAGS))
LDFLAGS_ARCH += $(findstring -m64, $(AM_CFLAGS))
LDFLAGS_ARCH += $(findstring -m32, $(AM_LDFLAGS))
LDFLAGS_ARCH += $(findstring -m64, $(AM_LDFLAGS))

check-local: SHELL?="/usr/bin/env bash"
check-local:
	@case $(host_os) in \
	  openbsd*) ADDLIBS="-lc" ;; \
	  darwin*|freebsd*) LDFLAGS_OS="-shared" ;; \
	  *) ADDLIBS="" ;; \
	esac; \
	 ($(CC) $$LDFLAGS_OS $(LDFLAGS_ARCH) -nostdlib -L./.libs -ltpms $$ADDLIBS 2>/dev/null || \
	 (echo "There are undefined symbols in libtpms ($$LDFLAGS_OS $(LDFLAGS_ARCH))";\
	  $(CC) $$LDFLAGS_OS $(LDFLAGS_ARCH) -nostdlib -L./.libs -ltpms $$ADDLIBS 2>&1 | grep libtpms))
	@case $(host_os) in \
	  openbsd*) ADDLIBS="-lc" ;; \
	  darwin*|freebsd*) LDFLAGS_OS="-shared" ;; \
	  *) ADDLIBS="" ;; \
	esac; \
	$(CC) $$LDFLAGS_OS $(LDFLAGS_ARCH) -nostdlib -L./.libs -ltpms $$ADDLIBS 2>/dev/null
	rm a.out || true

EXTRA_DIST = \
	tpm12/tpm_crypto_freebl.c \
	tpm12/tpm_crypto.c \
	libtpms.syms \
	test.syms

CLEANFILES = \
	a.out \
	*.gcov \
	*.gcda \
	*.gcno \
	tpm12/*.gcov \
	tpm12/*.gcda \
	tpm12/*.gcno \
	tpm2/*.gcov \
	tpm2/*.gcda \
	tpm2/*.gcno \
	tpm2/crypto/openssl/*.gcov \
	tpm2/crypto/openssl/*.gcda \
	tpm2/crypto/openssl/*.gcno
