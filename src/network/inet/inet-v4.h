#ifndef _NETWORK_INET_INET_V4_H
#define _NETWORK_INET_INET_V4_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define INETV4_IBROADCAST  { { { 0xFF, 0xFF, 0xFF, 0xFF } } }
#define INETV4_ILOOPBACK   { { { 0x7F, 0x00, 0x00, 0x01 } } }
#define INETV4_ILOCALHOST  INETV4_ILOOPBACK
#define INETV4_IALL        { { { 0x00, 0x00, 0x00, 0x00 } } }
#define INETV4_IANY        INETV4_IALL
#define INETV4_IALLNODES   { { { 0xE0, 0x00, 0x00, 0x01 } } }
#define INETV4_IALLROUTERS { { { 0xE0, 0x00, 0x00, 0x02 } } }

#define INETV4_UBROADCAST  0xFFFFFFFF
#define INETV4_ULOOPBACK   0x7F000001
#define INETV4_ULOCALHOST  INETV4_ULOOPBACK
#define INETV4_UALL        0x00000000
#define INETV4_UANY        INETV4_UALL
#define INETV4_UALLNODES   0xE0000001
#define INETV4_UALLROUTERS 0xE0000002

#define INETV4_BROADCAST   inetv4_broadcast
#define INETV4_LOOPBACK    inetv4_loopback
#define INETV4_LOCALHOST   INETV4_LOOPBACK
#define INETV4_ALL         inetv4_all
#define INETV4_ANY         INETV4_ALL
#define INETV4_ALLNODES    inetv4_allnodes
#define INETV4_ALLROUTERS  inetv4_allrouters

#define INETV4_SIZE        0x04 // 04 bytes
#define INETV4_STRLENGTH   0x10 // 16 bytes

#define INETV4_ADDRESS     0x04


typedef struct inetv4 {
  union {
    uint8_t u8[INETV4_SIZE];
    uint16_t u16[INETV4_SIZE/2];
    uint32_t u32;
  };
} inetv4_t;


extern const struct inetv4 inetv4_broadcast;
extern const struct inetv4 inetv4_loopback;
extern const struct inetv4 inetv4_all;
extern const struct inetv4 inetv4_allnodes;
extern const struct inetv4 inetv4_allrouters;


extern char *inetv4_u8tostr(const struct inetv4 *, char *, size_t);
extern int inetv4_strtou8(const char *, struct inetv4 *);
extern char *inetv4_u8instr(const struct inetv4 *);

extern bool inetv4_ismulticast(const struct inetv4 *);
extern bool inetv4_isloopback(const struct inetv4 *);
extern bool inetv4_isclassa(const struct inetv4 *);
extern bool inetv4_isclassb(const struct inetv4 *);
extern bool inetv4_isclassc(const struct inetv4 *);

extern int inetv4_compare(const struct inetv4 *, const struct inetv4 *);

extern int inetv4_cidr(const char *, struct inetv4 *, struct inetv4 *, struct inetv4 *);

#ifdef __cplusplus
}
#endif

#endif
