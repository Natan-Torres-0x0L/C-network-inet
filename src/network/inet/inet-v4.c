#include "inet-v4.h"

#include <strings/strings.h>
#include <string.h>

#include <stdio.h>


const struct inetv4 inetv4_broadcast  = INETV4_IBROADCAST;

const struct inetv4 inetv4_loopback   = INETV4_ILOOPBACK;

const struct inetv4 inetv4_all        = INETV4_IALL;

const struct inetv4 inetv4_allnodes   = INETV4_IALLNODES;
const struct inetv4 inetv4_allrouters = INETV4_IALLROUTERS; 


int
inetv4_strtou8(const char *string, struct inetv4 *network) {
  uint8_t bytes[INETV4_SIZE] = {0};
  uint16_t x11, x22 = 0, chars;

  if (!string || !*string)
    return -1;

  for (;;) {
#define decimal(char) ((char >= '0' && char <= '9') ? (char-'0') : (-1))
    for (x11 = chars = 0; chars < 3 && *string && decimal(*string) >= 0; string++, chars++)
      x11 = (uint16_t)(10*x11+decimal(*string));

    if ((*string && *string != '.') || (*string && !*(string+1) && *string == '.'))
      return -1;
    if (chars == 0 || x22 > 3 || x11 > 0xFF)
      return -1;

    bytes[(x22++) & 3] = (uint8_t)x11;

    if (!*string) {
      if (x22 != INETV4_SIZE /* 255.255.255.255 */)
        return -1;

      break;
    }

    string++;
  }

  if (network)
    memcpy(network, bytes, INETV4_SIZE);

  return 1;
}

char *
inetv4_u8tostr(const struct inetv4 *network, char *string, size_t length) {
  char source[INETV4_STRLENGTH] = {0};

  string_zero(source, sizeof(source));

  snprintf(source, sizeof(source), "%u.%u.%u.%u", network->u8[0], network->u8[1], network->u8[2], network->u8[3]);

  if (string)
    return (char *)memcpy(string, source, length);

  return string_new(source);
}

char *
inetv4_u8instr(const struct inetv4 *network) {
  return inetv4_u8tostr(network, NULL, 0);
}

bool
inetv4_ismulticast(const struct inetv4 *network) {
  return ((network->u32 & 0xF0000000) == 0xE0000000);
}

bool
inetv4_isloopback(const struct inetv4 *network) {
  return !memcmp(network, &INETV4_LOOPBACK, INETV4_SIZE);
}

bool
inetv4_isclassa(const struct inetv4 *network) {
  return ((network->u32 & 0x80000000) == 0);
}

bool
inetv4_isclassb(const struct inetv4 *network) {
  return ((network->u32 & 0xC0000000) == 0x80000000);
}

bool
inetv4_isclassc(const struct inetv4 *network) {
  return ((network->u32 & 0xE0000000) == 0xC0000000);
}

int
inetv4_compare(const struct inetv4 *network1, const struct inetv4 *network2) {
  uint8_t x11;

  for (x11 = 0; x11 < INETV4_SIZE; x11++)
    if (network1->u8[x11] < network2->u8[x11])
      return -1;
    else if (network1->u8[x11] > network2->u8[x11])
      return 1;

  return 0;
}

int
inetv4_cidr(const char *cidr, struct inetv4 *network, struct inetv4 *broadcast, struct inetv4 *netmask) {
  struct inetv4 addr = {0};
  uint32_t netmasku32;

  uint8_t prefix;

  if (sscanf(cidr, "%u.%u.%u.%u/%u", (uint32_t *)&addr.u8[0], (uint32_t *)&addr.u8[1], (uint32_t *)&addr.u8[2], (uint32_t *)&addr.u8[3], (uint32_t *)&prefix) != 5)
    return -1;

  netmasku32 = (0xFFFFFFFF << (32-prefix)) & 0xFFFFFFFF;
  if (netmask)
    netmask->u32 = netmasku32;

  if (broadcast)
    broadcast->u32 = (addr.u32 | (netmasku32 ^ 0xFFFFFFFF));

  if (network)
    network->u32 = (addr.u32 & netmasku32);

  return 0;
}
