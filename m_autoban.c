#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "unrealircd.h"

#if __APPLE__
#define s6_addr16		__u6_addr.__u6_addr16
#endif

#if UnrealProtocol < 4200
#define BANPERMISSION "tkl:zline:global"
#else
#define BANPERMISSION "server-ban:zline:global"
#endif

CMD_FUNC(autoban_func);
int autoban_config_run (ConfigFile *cf, ConfigEntry *ce, int type);
int autoban_config_test (ConfigFile *cf, ConfigEntry *ce, int type, int *errs);

int subnet = 56;
char* defaultReason = "You have been banned for a terms of service violation.";

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
  HookAdd(modinfo->handle, HOOKTYPE_CONFIGTEST, 0, autoban_config_test);
  return MOD_SUCCESS;
}

/**
 * Called when the module is initialised by UnrealIRCD
 */
MOD_INIT(m_autoban) {
  HookAdd(modinfo->handle, HOOKTYPE_CONFIGRUN, 0, autoban_config_run);
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
  free(defaultReason);
  return MOD_SUCCESS;
}

int autoban_config_test (ConfigFile *cf, ConfigEntry *ce, int type, int *errs) {
  int errors = 0;
  ConfigEntry *cep, *cep2;

  if (type != CONFIG_SET) {
    return 0;
  }

  if (!ce || !ce->ce_varname || strcmp(ce->ce_varname, "autoban")) {
    return 0;
  }

  for (cep = ce->ce_entries; cep; cep = cep->ce_next) {
    if (!cep->ce_varname) {
      config_error("%s:%i: blank set::autoban item",
                   cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
      errors += 1;
      continue;
    } else if (!strcmp(cep->ce_varname, "subnet")) {
      if (cep->ce_vardata == NULL || atoi(cep->ce_vardata) == 0) {
        config_error("%s:%i: expected a valid IPv6 subnet as integer set::autoban::%s",
                     cep->ce_fileptr->cf_filename, cep->ce_varlinenum, cep->ce_varname);
        errors += 1;
      }
    } else if (!strcmp(cep->ce_varname, "message")) {
      if (cep->ce_vardata == NULL || strlen(cep->ce_vardata) < 1) {
        config_error("%s:%i: default ban message required set::autoban::%s",
                     cep->ce_fileptr->cf_filename, cep->ce_varlinenum, cep->ce_varname);
        errors += 1;
      }
    } else {
      config_error("%s:%i: unknown directive set::autoban::%s",
                   cep->ce_fileptr->cf_filename, cep->ce_varlinenum, cep->ce_varname);
      errors += 1;
    }
  }
  *errs = errors;
  return errors ? -1 : 1;
}

int autoban_config_run (ConfigFile *cf, ConfigEntry *ce, int type) {
  ConfigEntry *cep;

  if (type != CONFIG_SET) {
    return 0;
  }

  if (!ce || !ce->ce_varname || strcmp(ce->ce_varname, "autoban")) {
    return 0;
  }

  for (cep = ce->ce_entries; cep; cep = cep->ce_next) {
    if (!strcmp(cep->ce_varname, "subnet")) {
      subnet = atoi(cep->ce_vardata);
    } else if (!strcmp(cep->ce_varname, "message")) {
      defaultReason = strdup(cep->ce_vardata);
    }
  }
  return 1;
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
      if (group == 0) {
        sprintf(output, "*");
      } else {
        sprintf(output, "%x", group);
        char delimitedOutput[8];
        substr(output, delimitedOutput, 0, remainder);
        sprintf(output, "%s*", delimitedOutput);
      }
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

  if (!ValidatePermissionsForPath(BANPERMISSION, sptr, NULL, NULL, NULL)) {
    sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, sptr->name);
    return 0;
  }

  // Allow the user to pass an IP address, if input is not recognised as one assume it's a nickname
  char* banTarget = parv[1];
  char* username = "*";
  if (!isValidIpv4Address(banTarget) && !isValidIpv6Address(banTarget)) {
    struct IPUserInfo userInfo = getIPForNickname(banTarget);
    banTarget = userInfo.ipAddress;
    if (userInfo.username != NULL) {
      username = userInfo.username;
    }
  } else if (isIRCCloudAddress(banTarget)) {
    sendnotice(sptr, "Error: Do not directly ban IRCCloud IP addresses, use /autoban user");
    return 0;
  }

  if (!banTarget) {
    sendnotice(sptr, "Error: No valid ban target found, need an IP or an active user");
    return 0;
  }

  char* ipRange = NULL;

  // Get a correct ban mask for IPv6 address according to configured subnet
  if (isValidIpv6Address(banTarget)) {
    ipRange = getIPv6BanRange(banTarget);
    if (!ipRange) {
      sendnotice(sptr, "Error: Failed to create ban mask for IPv6 address");
      return 0;
    }
    banTarget = ipRange;
  }

  TS secs = 0;
  char expireAt[1024], setAt[1024];

  if (parc > 2) {
    secs = atime(parv[2]);
    if (secs < 0) {
      sendnotice(sptr, "*** [error] The time you specified is out of range!");
      return 0;
    }
  } else {
    secs = 604800;
  }

  if (secs == 0) {
    if (DEFAULT_BANTIME && (parc <= 3)) {
      ircsnprintf(expireAt, sizeof(expireAt), "%li", DEFAULT_BANTIME + TStime());
    } else {
      ircsnprintf(expireAt, sizeof(expireAt), "%li", secs);
    }
  } else {
    ircsnprintf(expireAt, sizeof(expireAt), "%li", secs + TStime());
  }

  ircsnprintf(setAt, sizeof(setAt), "%li", TStime());

  char* banReason = defaultReason;
  if (parc > 3) {
    banReason = parv[3];
  }

  char *tkllayer[9] = {
    me.name,
      "+",
      "G",
      username,
      banTarget,
      make_nick_user_host(sptr->name, sptr->user->username, GetHost(sptr)),
      expireAt,
      setAt,
      banReason
  };

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

