#include <stdio.h>
#include <stdlib.h>
#include "unrealircd.h"
#include <arpa/inet.h>

ModuleHeader MOD_HEADER(autoban) = {
    "autoban",
    "$Id$",
    "Module that automatically retrieves user IP and performs a GZLine",
    "4.0",
    NULL
};

MOD_INIT(autoban) = {
        CommandAdd(modinfo->handle, "AUTOBAN", auto_func, 3, M_USER)
}

MOD_LOAD(autoban) = {
        return MOD_SUCCESS;
}

CMD_FUNC(autoban_func) {
        if ((parc < 2) || BadPtr(parv[1]))  {
            sendnotice(sptr, "Error: Nick/IP required");
            return 0;
        }

        if (IsServer(sptr)) {
            return 0;
        }

        if (!ValidatePermissionsForPath("server-ban:zline:global",sptr,NULL,NULL,NULL)) {
            sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, sptr->name);
            return 0;
        }

        char* banTarget = parv[0];
        if (!isValidIpv4Address(banTarget) && !isValidIpv6Address(banTarget)) {
            banTarget = getIPForNickname(banTarget)
        }

        if (!banTarget) {
            sendnotice(sptr, "Error: No valid ban target found, need an IP or an active user");
            return;
        }

        if (isValidIpv6Address(banTarget)) {
            banTarget = getIpv6BanRange(banTarget);
        }

        parv[0] = banTarget;
        return m_tkl_line(cptr, sptr, parc, parv, "G");
};

bool isValidIpv4Address (char *ipAddress) {
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
    return result != 0;
}

bool isValidIpv6Address (char *ipAddress) {
    struct sockaddr_in6 sa;
    int result = inet_pton(AF_INET6, ipAddress, &(sa.sin6_addr));
    return result != 0;
}


char* getIpv6BanRange (char *ipAddress) {
    struct sockaddr_in6 result;
    int success = inet_pton(AF_INET6, ipAddress, &(result.sin6_addr));
    if (success != 1) {
        return NULL;
    }

    uint16_t address[8];
    memcpy(address, result.sin6_addr.__u6_addr.__u6_addr16, sizeof address);
    int i = 0;
    while (i < 8) {
        address[i] = htons(address[i]);
        i += 1;
    }

    address[4] = address[4] / 256;

    char *ipRange = malloc(32);
    sprintf(ipRange, "%x:%x:%x:%x:%x*", address[0], address[1], address[2], address[3], address[4]);
    return ipRange;
}

char* getIPForNickname (char* nickname) {
    struct Client* user = find_person(nickname, NULL);
    if (!user) {
        return NULL;
    }

    return GetIP(user);
}
