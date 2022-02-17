#ifndef _SSL_ENCLAVE_TYPES_
#define _SSL_ENCLAVE_TYPES_

#if defined(__cplusplus)
extern "C" {
#endif


/*typedef void FILE*/

    typedef uint32_t  TPM_RESULT;
    typedef unsigned short int sa_family_t;

#define	__SOCKADDR_COMMON(sa_prefix)		\
    sa_family_t sa_prefix##family

#ifndef ENCLAVE_UNTRUSTED
    struct sockaddr
    {
	__SOCKADDR_COMMON (sa_);	/* Common data: address family and length.  */
	char sa_data[14];		/* Address data.  */
    };

    typedef unsigned int uid_t;

    typedef long int __suseconds_t;
    typedef int clockid_t;

#if !(defined(ENCLAVE_UNTRUSTED) || defined(SGX_STUB_H))
    struct timespec {
	time_t   tv_sec;        /* seconds */
	long     tv_nsec;       /* nanoseconds */
    };

    struct timeval
    {
	__time_t tv_sec;		/* Seconds.  */
	__suseconds_t tv_usec;	/* Microseconds.  */
    };
#endif
    
    struct timezone
    {
	int tz_minuteswest;     /* Minutes west of GMT.  */
	int tz_dsttime;     /* Nonzero if DST is ever in effect.  */
    };

#define	AF_INET	2

#define htons(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))
#define ntohs(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))
#define htonl(n) (((((unsigned long)(n) & 0xFF)) << 24) |	\
                  ((((unsigned long)(n) & 0xFF00)) << 8) |	\
                  ((((unsigned long)(n) & 0xFF0000)) >> 8) |	\
                  ((((unsigned long)(n) & 0xFF000000)) >> 24))
#define ntohl(n) (((((unsigned long)(n) & 0xFF)) << 24) |	\
                  ((((unsigned long)(n) & 0xFF00)) << 8) |	\
                  ((((unsigned long)(n) & 0xFF0000)) >> 8) |	\
                  ((((unsigned long)(n) & 0xFF000000)) >> 24))

    typedef uint32_t in_addr_t;
#define	INADDR_ANY		((in_addr_t) 0x00000000)


typedef uint16_t in_port_t;
typedef uint32_t in_addr_t;

struct in_addr
{
    in_addr_t s_addr;
};
#define __SOCKADDR_COMMON_SIZE	(sizeof (unsigned short int))

typedef struct sockaddr_in
{
    __SOCKADDR_COMMON (sin_);
    in_port_t sin_port;			/* Port number.  */
    struct in_addr sin_addr;		/* Internet address.  */

    /* Pad to size of `struct sockaddr'.  */
    unsigned char sin_zero[sizeof (struct sockaddr) -
			   __SOCKADDR_COMMON_SIZE -
			   sizeof (in_port_t) -
			   sizeof (struct in_addr)];
} sockaddr_in;

#define SOCK_STREAM 1
#define SOL_SOCKET	1
#define SO_REUSEADDR 2

// typedef int FILE;
#endif /* ENCLAVE_LIBTPMS_U_H__ */

#ifdef ENCLAVE_UNTRUSTED
struct libtpms_callbacks {
    int sizeOfStruct;
    TPM_RESULT (*tpm_nvram_init)(void);
    TPM_RESULT (*tpm_nvram_loaddata)(unsigned char **data,
                                     uint32_t *length,
                                     uint32_t tpm_number,
                                     const char *name);
    TPM_RESULT (*tpm_nvram_storedata)(const unsigned char *data,
                                      uint32_t length,
                                      uint32_t tpm_number,
                                      const char *name);
    TPM_RESULT (*tpm_nvram_deletename)(uint32_t tpm_number,
                                       const char *name,
                                       TPM_BOOL mustExist);
    TPM_RESULT (*tpm_io_init)(void);
    TPM_RESULT (*tpm_io_getlocality)(TPM_MODIFIER_INDICATOR *localityModifer,
				     uint32_t tpm_number);
    TPM_RESULT (*tpm_io_getphysicalpresence)(TPM_BOOL *physicalPresence,
					     uint32_t tpm_number);
};
#endif
    
#if defined(__cplusplus)
}
#endif

#endif /* !_SSL_ENCLAVE_TYPES_ */
