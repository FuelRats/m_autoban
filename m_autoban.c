#include <stdio.h>
#include <stdlib.h>
#include "unrealircd.h"

#if __APPLE__
#define s6_addr16		__u6_addr.__u6_addr16
#endif

int subnet = 56;
char* defaultReason = "No reason";

struct IPUserInfo {
    char* username;
    char* ipAddress;
};

char* irccloudIPv4List[] = {
  "192.184.9.108",
  "192.184.9.110",
  "192.184.9.112",
  "192.184.10.118",
  "192.184.10.9",
  "192.184.8.73",
  "192.184.8.103"
};

char* irccloudIPv6Subnet = "2001:67c:2f08";

/**
 * Module information
 */
ModuleHeader MOD_HEADER(m_autoban) = {
"autoban",
"$Id: v1.0",
"Module that automatically retrieves user IP and performs a GZLine",
"3.2-b8-1",
NULL
};

MOD_TEST(m_autoban) {
  return MOD_SUCCESS;
}

CMD_FUNC(autoban_func);

/**
 * Called when the module is initialised by UnrealIRCD
 */
MOD_INIT(m_autoban) {
  CommandAdd(modinfo->handle, "AUTOBAN", autoban_func, 3, M_USER);
  return MOD_SUCCESS;
}

/**
 * Called when the module is loaded by UnrealIRCD
 */
MOD_LOAD(m_autoban) {
  return MOD_SUCCESS;
}

MOD_UNLOAD(m_tkl) {
  return MOD_SUCCESS;
}

/**
 * Check whether a string is a valid IPv4 address
 * @param ipAddress a string possibly containing an IPv4 address
 * @return  whether the string is a valid IPv4 address
 */
bool isValidIpv4Address (char *ipAddress) {
  struct sockaddr_in sa;
  int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
  return result != 0;
}

/**
 * Check whether a string is a valid IPv6 address
 * @param ipAddress a string possibly containing an IPv6 address
 * @return whether the string is a valid IPv6 address
 */
bool isValidIpv6Address (char *ipAddress) {
  struct sockaddr_in6 sa;
  int result = inet_pton(AF_INET6, ipAddress, &(sa.sin6_addr));
  return result != 0;
}

char* zeroPad (char* input, int size) {
  char* pad = "0";
  char* str = (char*) malloc(size * sizeof(char) + 1);
  strcpy(str, input);

  while (strlen(str) < size) {
    strcat(str, pad);
  }
  return str;
}

void substr (char* str, char* sub , int start, int len){
  memcpy(sub, &str[start], len);
  sub[len] = '\0';
}

/**
 * Get an IPV6 ban mask wildcarded for the configured subnet
 * @param ipAddress an IPv6 address
 * @return A wildcarded IPV6 ban mask
 */
char* getIPv6BanRange (char *ipAddress) {
  char* padded = NULL;

  struct sockaddr_in6 result;
  int success = inet_pton(AF_INET6, ipAddress, &(result.sin6_addr));
  if (success != 1) {
    return NULL;
  }

  uint16_t address[8];
  memcpy(address, result.sin6_addr.s6_addr16, sizeof address);

  // Switch byte order, UnrealIRCD expects network order
  int i = 0;
  while (i < 8) {
    address[i] = htons(address[i]);
    i += 1;
  }

  //
  int range = subnet / 4;
  int index = 0;
  char* ipRange = malloc(sizeof (char) * 64);
  ipRange[0] = '\0';
  while (index < range) {
    uint16_t group = address[(index / 4)];
    int remainder = range - index;
    char output[8];

    // Our subnet division is inside the current group, calculate where and cut if off
    if (remainder < 4) {
      sprintf(output, "%x", group);
      padded = zeroPad(output, 4);
      substr(padded, output, 0, remainder);
      sprintf(output, "%s*", output);
      // Our subnet division is exactly at the end of the current group, cut it off
    } else if (remainder == 4) {
      sprintf(output, "%x:*", group);
    }
      // Our subnet is further along, add this group and move on to the next
    else {
      sprintf(output, "%x:", group);
    }

    strcat(ipRange, output);
    index += 4;
  }

  if (padded != NULL) {
    free(padded);
  }

  return ipRange;
}

/**
 * Check whether an IP belongs to IRCCloud
 * @param address the IP address to check
 * @return whether the IP address belongs to IRCCloud
 */
bool isIRCCloudAddress (const char *address) {
  int index = 0;
  int listLength = sizeof(irccloudIPv4List) / sizeof(irccloudIPv4List[0]);
  while (index < listLength) {
    if (strncmp(irccloudIPv4List[index], address, strlen(address)) == 0) {
      return true;
    }
    index += 1;
  }

  return strncmp(address, irccloudIPv6Subnet, strlen(irccloudIPv6Subnet)) == 0;
}

/**
 * Get IP information for an active user by their nickname
 * @param nickname the user's nickname
 * @return struct containing username (if defined) and ip address
 */
struct IPUserInfo getIPForNickname (char* nickname) {
  struct IPUserInfo noInfo = { NULL, NULL };
  struct Client* user = find_person(nickname, NULL);
  char* username = NULL;
  if (!user) {
    return noInfo;
  }

  char* ipAddress = GetIP(user);
  if (!ipAddress) {
    return noInfo;
  }

  if (isIRCCloudAddress(ipAddress)) {
    username = user->user->username;
  }

  struct IPUserInfo userInfo = { username, ipAddress };
  return userInfo;
}

/**
 * The function containing the actual logic for the /autoban command
 */
CMD_FUNC(autoban_func) {
  if ((parc < 2) || BadPtr(parv[1]))  {
    sendnotice(sptr, "Error: Nick/IP required");
    return 0;
  }

  if (IsServer(sptr)) {
    return 0;
  }

  if (!ValidatePermissionsForPath("server-ban:zline:global", sptr, NULL, NULL, NULL)) {
    sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, sptr->name);
    return 0;
  }

  // Allow the user to pass an IP address, if input is not recognised as one assume it's a nickname
  char* banTarget = parv[1];
  char* username = "*";
  if (!isValidIpv4Address(banTarget) && !isValidIpv6Address(banTarget)) {
    struct IPUserInfo userInfo = getIPForNickname(banTarget);
    banTarget = userInfo.ipAddress;
    username = userInfo.username;
  }

  if (!banTarget) {
    sendnotice(sptr, "Error: No valid ban target found, need an IP or an active user");
    return 0;
  }

  char* ipRange = NULL;

  // Get a correct ban mask for IPv6 address according to configured subnet
  if (isValidIpv6Address(banTarget)) {
    ipRange = getIPv6BanRange(banTarget);
    banTarget = ipRange;
  }

  parv[1] = banTarget;

  TS secs = 0;
  char expireAt[1024], setAt[1024];

  secs = atime(parv[2]);
  if (secs < 0) {
    sendnotice(sptr, "*** [error] The time you specified is out of range!");
    return 0;
  }

  if (secs == 0) {
    if (DEFAULT_BANTIME && (parc <= 3))
      ircsnprintf(expireAt, sizeof(expireAt), "%li", DEFAULT_BANTIME + TStime());
    else
      ircsnprintf(expireAt, sizeof(expireAt), "%li", secs);
  } else {
    ircsnprintf(expireAt, sizeof(expireAt), "%li", secs + TStime());
  }

  ircsnprintf(setAt, sizeof(expireAt), "%li", TStime());

  char *tkllayer[9] = {
    me.name,
      "+",
      "Z",
      username,
      banTarget,
      make_nick_user_host(sptr->name, sptr->user->username, GetHost(sptr)),
      expireAt,
      setAt,
      defaultReason
  };

  if (parc > 3) {
    tkllayer[8] = parv[3];
  } else if (parc > 2) {
    tkllayer[8] = parv[2];
  }

  TS i = atol(expireAt);
  struct tm *t = gmtime(&i);

  if (!t) {
    sendto_one(sptr,
               ":%s NOTICE %s :*** [error] The time you specified is out of range",
               me.name, sptr->name);
    return 0;
  }

  m_tkl(&me, &me, 9, tkllayer);

  if (ipRange != NULL) {
    free(ipRange);
  }
  return 0;
}

