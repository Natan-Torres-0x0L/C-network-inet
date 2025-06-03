#include "inet-v6.h"
#include "inet-v4.h"

#include <strings/strings.h>
#include <string.h>

#include <stdio.h>


const struct inetv6 inetv6_loopback   = INETV6_ILOOPBACK;

const struct inetv6 inetv6_all        = INETV6_IALL;

const struct inetv6 inetv6_allnodes   = INETV6_IALLNODES;
const struct inetv6 inetv6_allrouters = INETV6_IALLROUTERS;


int
inetv6_strtou8(const char *string, struct inetv6 *network) {
  uint16_t bytes[8] = {0}, *rbytes = &bytes[8];
  uint16_t x11;

  uint8_t x22 = 0, octets = 0, chars;
  int8_t range = -1;

  bool breaked = false, inetv4 = false;

  if (!string || !*string)
    return -1;
  if (*string == ':' && *++string != ':')
    return -1;

  for (;;) {
    if ((*(string-1) == ':' && *(string) == ':' && !*(string+1) && !breaked) || (*string == ':' && !breaked)) {
      string++, range = 0, breaked = true;
      continue;
    }

#define hexadecimal(char) ((char-'0' < 10) ? (char-'0') : ((char|32)-'a' < 6) ? ((char|32)-'a'+10) : (-1))
    for (chars = 0, x11 = 0; chars < 4 && *string && hexadecimal(*string) >= 0; string++, chars++)
      x11 = (uint16_t)(16*x11+hexadecimal(*string));

    if (*string && *string == '.') {
      string -= chars, inetv4 = true, rbytes -= 2, octets = (uint8_t)(octets+2u);
      break;
    }

    if ((*string && *string != ':') || (*string && !*(string+1) && *string == ':'))
      return -1;
    if (octets > 8 || chars > 4)
      return -1;

    bytes[(x22++) & 7] = (uint16_t)x11;
    range = (int8_t)(range != -1 ? range+1 : -1), octets++;

    if (!*string)
      break;

    string++;
  }

  if (breaked && octets < 8) {
    for (x11 = 1; x11 <= range; x11++) {
      rbytes[-x11] = bytes[x22-x11];
      bytes[x22-x11] = 0;
    }

    breaked = false;
    octets = 8;
  }

  if (octets != 8 || (breaked && octets == 8))
    return -1;

  if (network)
    for (x11 = 0, x22 = 0; x11 < (inetv4 ? 6 : 8); x11++) {
      network->u8[x22++] = (uint8_t)((bytes[x11] >> 0x08) & 0xFF);
      network->u8[x22++] = (uint8_t)((bytes[x11]) & 0xFF);
    }

  if (inetv4)
    return inetv4_strtou8(string, (struct inetv4 *)&network->u8[x22]);

  return 1;
}

char *
inetv6_u8tostr(const struct inetv6 *network, char *string, size_t length) {
  static const char *const hexadecimal = "0123456789abcdef";

  char source[INETV6_STRLENGTH] = {0};
  char *format = (char *)source;

  int start = -1, end = -1, zeros = 0;
  int x11, x22;

  bool skip;

  string_zero(source, sizeof(source));

  if (!memcmp(network, "\0\0\0\0\0\0\0\0\0\0\0\0", 12) && (network->u8[12] || network->u8[13])) { 
    string_write(format, "::", sizeof(source));
    format += 2;

    inetv4_u8tostr((struct inetv4 *)&network->u8[12], format, sizeof(source)-2);
  } else {
    for (x11 = 0; x11 < INETV6_SIZE; x11++) {
      for (x22 = x11; x22 < 16 && network->u8[x22] == 0; x22++);

      if (zeros < x22-x11)
        start = x11, end = x22, zeros = x22-x11;
    }

    if (start != -1 && !(start % 2 == 0))
      start++;
    if (end != -1)
      end--;

    for (x11 = 0; x11 < INETV6_SIZE; x11 += 2) {
      if (zeros >= 4 && x11 == (uint8_t)start) {
        if (start == 0)
          *format++ = ':';

        while (x11 != (uint8_t)end)
          x11++;
        *format++ = ':';

        if (x11 == 15)
          break;
        if (!(x11 % 2 == 0))
          x11++;
      }

      skip = true;

      if ((x22 = network->u8[x11] >> 4) != 0) {
        *format++ = hexadecimal[x22];
        skip = false;
      }

      if (((x22 = network->u8[x11] & 0x0F) != 0 && skip) || !skip) {
        *format++ = hexadecimal[x22];
        skip = false;
      }

      if (((x22 = network->u8[x11+1] >> 4) != 0 && skip) || !skip)
        *format++ = hexadecimal[x22];

      x22 = network->u8[x11+1] & 0x0F;
      *format++ = hexadecimal[x22];

      if (x11 != 14)
        *format++ = ':';
    }
  }

  if (string)
    return (char *)memcpy(string, source, length);

  return string_new(source);
}

char *
inetv6_u8instr(const struct inetv6 *network) {
  return inetv6_u8tostr(network, NULL, 0);
}

bool
inetv6_isunspecified(const struct inetv6 *network) {
  return !memcmp(network, &INETV6_ALL, INETV6_SIZE);
}

bool
inetv6_isloopback(const struct inetv6 *network) {
  return !memcmp(network, &INETV6_LOOPBACK, INETV6_SIZE);
}

bool
inetv6_ismulticast(const struct inetv6 *network) {
  return (network->u8[0] == 0xFF);
}

bool
inetv6_islinklocal(const struct inetv6 *network) {
  return (network->u8[0] == 0xFE && ((network->u8[1] & 0xC0) == 0x80));
}

bool
inetv6_issitelocal(const struct inetv6 *network) {
  return network->u8[0] == 0xFE && ((network->u8[1] & 0xC0) == 0xC0);
}

bool
inetv6_isglobal(const struct inetv6 *network) {
  return (network->u8[0] & 0xE0) == 0x20;
// return !inetv6_isunspecified(network) && !inetv6_isloopback(network) && !inetv6_islinklocal(network) && !inetv6_issitelocal(network) && !inetv6_ismulticast(network);
}

bool
inetv6_isv4mapped(const struct inetv6 *network) {
  return (network->u32[0] == 0x00 && network->u32[1] == 0x00 && network->u16[4] == 0x00 && network->u16[5] == 0xFFFF);
}

int
inetv6_compare(const struct inetv6 *network1, const struct inetv6 *network2) {
  uint8_t x11;

  for (x11 = 0; x11 < INETV6_SIZE/sizeof(uint16_t); x11++)
    if (network1->u16[x11] < network2->u16[x11])
      return -1;
    else if (network1->u16[x11] > network2->u16[x11])
      return 1;

  return 0;
}

int
inetv6_cidr(const char *cidr, struct inetv6 *network, struct inetv6 *netmask) {
  char string[INETV6_STRLENGTH+1] = {0};

  uint8_t netmasku8[INETV6_SIZE] = {0};
  struct inetv6 addr = {0};

  uint8_t prefix;
  uint8_t x11;

  if (sscanf(cidr, "%46[0-9a-fA-F:]/%d", string, (uint32_t *)&prefix) != 2)
    return -1;

  if (inetv6_strtou8(string, &addr) == -1)
    return -1;

  for (x11 = 0; x11 < INETV6_SIZE; x11++)
    if (prefix >= 8)
      netmasku8[x11] = 0xFF, prefix -= 8;
    else if (prefix > 0)
      netmasku8[x11] = (uint8_t)(0xFF << (8 - prefix)), prefix = 0;

  if (netmask)
    memcpy(netmask, netmasku8, INETV6_SIZE);

  if (network)
    for (x11 = 0; x11 < INETV6_SIZE; x11++)
      network->u8[x11] = addr.u8[x11] & netmasku8[x11];

  return 1;
}
