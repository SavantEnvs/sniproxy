/*
 * fuzz_address — sniproxy's address parser, new_address(), which reads every
 * address in the config file (listen, fallback, source, table targets,
 * nameservers) and, for a wildcard table entry, the hostname a client sent
 * (listener_lookup_server_address). Accepts hostnames, IPv4, [IPv6]:port and
 * unix: socket paths.
 *
 * Input: "<address>" or "<address>\n<port string>". The parsed address is then
 * formatted, copied, compared and has its port reset, through the public API in
 * address.h. new_address() takes a C string, so the copy is NUL-terminated.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "address.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *str = malloc(size + 1);
    if (str == NULL)
        return 0;
    if (size > 0)
        memcpy(str, data, size);
    str[size] = '\0';

    char *port = strchr(str, '\n');
    if (port != NULL)
        *port++ = '\0';

    struct Address *addr = new_address(str);
    if (addr != NULL) {
        char buf[ADDRESS_BUFFER_SIZE];
        display_address(addr, buf, sizeof(buf));

        volatile int flags = address_is_hostname(addr) +
                             address_is_sockaddr(addr) +
                             address_is_wildcard(addr);
        (void)flags;
        if (address_is_hostname(addr))
            (void)strlen(address_hostname(addr));
        if (address_is_sockaddr(addr)) {
            char sbuf[ADDRESS_BUFFER_SIZE];
            display_sockaddr(address_sa(addr), sbuf, sizeof(sbuf));
        }

        struct Address *copy = copy_address(addr);
        if (copy != NULL) {
            if (port != NULL && address_set_port_str(copy, port))
                display_address(copy, buf, sizeof(buf));
            else
                address_set_port(copy, (uint16_t)(address_port(addr) + 1));
            (void)address_compare(addr, copy);
            (void)address_compare(copy, addr);
            free(copy);
        }
        free(addr);
    }

    free(str);
    return 0;
}
