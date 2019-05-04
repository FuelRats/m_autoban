#include <stdio.h>
#include <stdlib.h>
#include "unrealircd.h"
#include <arpa/inet.h>

int subnet = 56;

/**
 * Module information
 */
ModuleHeader MOD_HEADER(autoban) = {
    "autoban",
    "$Id$",
    "Module that automatically retrieves user IP and performs a GZLine",
    "4.0",
    NULL
};

/**
 * Called when the module is initialised by UnrealIRCD
 */
MOD_INIT(autoban) = {
        CommandAdd(modinfo->handle, "AUTOBAN", auto_func, 3, M_USER)
}

/**
 * Called when the module is loaded by UnrealIRCD
 */
MOD_LOAD(autoban) = {
        return MOD_SUCCESS;
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

        if (!ValidatePermissionsForPath("server-ban:zline:global",sptr,NULL,NULL,NULL)) {
            sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, sptr->name);
            return 0;
        }

        // Allow the user to pass an IP address, if input is not recognised as one assume it's a nickname
        char* banTarget = parv[0];
        if (!isValidIpv4Address(banTarget) && !isValidIpv6Address(banTarget)) {
            banTarget = getIPForNickname(banTarget)
        }

        if (!banTarget) {
            sendnotice(sptr, "Error: No valid ban target found, need an IP or an active user");
            return;
        }

        // Get a correct ban mask for IPv6 address according to configured subnet
        if (isValidIpv6Address(banTarget)) {
            banTarget = getIpv6BanRange(banTarget);
        }

        parv[0] = banTarget;
        m_tkl_line(cptr, sptr, parc, parv, "G");
        free(banTarget);
        return 0;
};

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

/**
 * Get an IPV6 ban mask wildcarded for the configured subnet
 * @param ipAddress an IPv6 address
 * @return A wildcarded IPV6 ban mask
 */
char* getIpv6BanRange (char *ipAddress) {
    struct sockaddr_in6 result;
    int success = inet_pton(AF_INET6, ipAddress, &(result.sin6_addr));
    if (success != 1) {
        return NULL;
    }

    uint16_t address[8];
    memcpy(address, result.sin6_addr.__u6_addr.__u6_addr16, sizeof address);

    // Switch byte order, UnrealIRCD expects network order
    int i = 0;
    while (i < 8) {
        address[i] = htons(address[i]);
        i += 1;
    }

    //
    int range = subnet / 4;
    int index = 0;
    char *ipRange = malloc(40);
    while (index < range) {
        uint16_t group = address[(index / 4)];
        int remainder = range - index;
        char output[8];

        // Our subnet division is inside the current group, calculate where and cut if off
        if (remainder < 4) {
            group = group / pow(16, 4 - remainder);
            /* For the subnet mask to work correctly we need leading zeroes inside the group,
             * calculate the number of leading zeroes required and format the output */
            char format[6];
            sprintf(format, "%%0%dx*", remainder);
            sprintf(output, format, group);
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
 * Retrieve the IP of an inline user by their nickname
 * @param nickname the nickname of the online user
 * @return the IP address
 */
char* getIPForNickname (char* nickname) {
    struct Client* user = find_person(nickname, NULL);
    if (!user) {
        return NULL;
    }

    return GetIP(user);
}
