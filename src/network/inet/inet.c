#include "inet.h"


int
inet_strisaddr(const char *string) {
  return ((!string || !*string) ? -1 : ((inetv4_strtou8(string, NULL) != -1) ? INETV4_ADDRESS : ((inetv6_strtou8(string, NULL) != -1) ? INETV6_ADDRESS : -1)));
}
