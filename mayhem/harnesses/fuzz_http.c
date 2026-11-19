/*
 * fuzz_http — the first bytes a client sends to an HTTP listener, as sniproxy's
 * connection.c hands them to http_protocol->parse_packet() to find the
 * Host header (request line, header scanning in next_header, get_header).
 *
 * The packet is passed as an exact-size heap copy with no trailing NUL, like
 * the connection buffer, so ASan sees any read past the end (size 0 included).
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "http.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *packet = malloc(size);
    if (packet == NULL)
        return 0;
    if (size > 0)
        memcpy(packet, data, size);

    char *hostname = NULL;
    int result = http_protocol->parse_packet(packet, size, &hostname);
    if (result >= 0 && hostname != NULL) {
        /* The contract: hostname is a NUL-terminated string of length result. */
        volatile size_t len = strlen(hostname);
        (void)len;
    }

    free(hostname);
    free(packet);
    return 0;
}
