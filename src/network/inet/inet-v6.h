#ifndef _NETWORK_INET_INET_V6_H
#define _NETWORK_INET_INET_V6_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define INETV6_ILOOPBACK   { { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } } }
#define INETV6_ILOCALHOST  INETV6_ILOOPBACK
#define INETV6_IALL        { { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } }
#define INETV6_IANY        INETV6_IALL
#define INETV6_IALLNODES   { { { 0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } } }
#define INETV6_IALLROUTERS { { { 0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 } } }

#define INETV6_LOOPBACK    inetv6_loopback
#define INETV6_LOCALHOST   INETV6_LOOPBACK
#define INETV6_ALL         inetv6_all
#define INETV6_ANY         INETV6_ALL
#define INETV6_ALLNODES    inetv6_allnodes
#define INETV6_ALLROUTERS  inetv6_allrouters

#define INETV6_SIZE        0x10 // 16 bytes
#define INETV6_STRLENGTH   0x2E // 46 bytes

#define INETV6_ADDRESS     0x06


typedef struct inetv6 {
  union {
    uint8_t u8[INETV6_SIZE];
    uint16_t u16[8];
    uint32_t u32[4];
  };
} inetv6_t;


extern const struct inetv6 inetv6_loopback;
extern const struct inetv6 inetv6_all;
extern const struct inetv6 inetv6_allnodes;
extern const struct inetv6 inetv6_allrouters;


extern char *inetv6_u8tostr(const struct inetv6 *, char *, size_t);
extern int inetv6_strtou8(const char *, struct inetv6 *);
extern char *inetv6_u8instr(const struct inetv6 *);

extern bool inetv6_isunspecified(const struct inetv6 *);
extern bool inetv6_isloopback(const struct inetv6 *);
extern bool inetv6_ismulticast(const struct inetv6 *);
extern bool inetv6_islinklocal(const struct inetv6 *);
extern bool inetv6_issitelocal(const struct inetv6 *);
extern bool inetv6_isglobal(const struct inetv6 *);
extern bool inetv6_isv4mapped(const struct inetv6 *);

extern int inetv6_compare(const struct inetv6 *, const struct inetv6 *);

extern int inetv6_cidr(const char *, struct inetv6 *, struct inetv6 *);

#ifdef __cplusplus
}
#endif

#endif
