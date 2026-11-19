/*
 * fuzz_tls — the first bytes a client sends to a TLS listener, as sniproxy's
 * connection.c hands them to tls_protocol->parse_packet() to find the SNI
 * hostname (TLS record -> ClientHello -> extensions -> server_name).
 *
 * The packet is passed as an exact-size heap copy with no trailing NUL, like
 * the connection buffer, so ASan sees any read past the end (size 0 included).
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tls.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *packet = malloc(size);
    if (packet == NULL)
        return 0;
    if (size > 0)
        memcpy(packet, data, size);

    char *hostname = NULL;
    int result = tls_protocol->parse_packet(packet, size, &hostname);
    if (result >= 0 && hostname != NULL) {
        /* The contract: hostname is a NUL-terminated string of length result. */
        volatile size_t len = strlen(hostname);
        (void)len;
    }

    free(hostname);
    free(packet);
    return 0;
}
