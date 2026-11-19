/*
 * fuzz_lookup — a client's first bytes through sniproxy's routing decision:
 * the listener's protocol parser extracts the hostname (as connection.c's
 * parse_client_request does), then listener_lookup_server_address() matches it
 * against the listener's table (PCRE2 backend patterns) and, for a wildcard
 * `*` target, builds a new address from the client's hostname (new_address).
 *
 * Input: byte 0 selects the listener (even: TLS on :443, odd: HTTP on :80);
 * the rest is the packet, as an exact-size heap copy with no trailing NUL.
 *
 * Kept across inputs on purpose: the configuration below, loaded once with
 * init_config() and wired as init_listener() does (table lookup, init_table,
 * table reference, fallback port) minus the socket bind. A lookup only reads
 * it; addresses it allocates for the caller are freed per input.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ev.h>

#include "address.h"
#include "config.h"
#include "listener.h"
#include "protocol.h"
#include "table.h"

static const char config_text[] =
    "listener 127.0.0.1:443 {\n"
    "    protocol tls\n"
    "    table routes\n"
    "    fallback 127.0.0.1:8443\n"
    "}\n"
    "listener 127.0.0.1:80 {\n"
    "    protocol http\n"
    "    table routes\n"
    "}\n"
    "table routes {\n"
    "    ^example\\.com$ 192.0.2.10:8001\n"
    "    ^www\\.example\\.(com|net|org)$ 192.0.2.11\n"
    "    ^v6\\.example\\.com$ [2001:db8::1]:443\n"
    "    ^local\\.example\\.com$ unix:/tmp/sniproxy-fuzz.sock\n"
    "    ^backend\\.example\\.com$ backend.internal.test:8080 proxy_protocol\n"
    "    \\.wild\\.test$ *:4443\n"
    "    .* *\n"
    "}\n";

static struct Config *config;
static struct Listener *listeners[2];
static size_t nlisteners;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    char path[4096];
    const char *tmp = getenv("TMPDIR");
    if (tmp == NULL || *tmp == '\0')
        tmp = "/tmp";
    snprintf(path, sizeof(path), "%s/sniproxy-fuzz-lookup-XXXXXX", tmp);
    int fd = mkstemp(path);
    if (fd < 0 || write(fd, config_text, sizeof(config_text) - 1) !=
                      (ssize_t)(sizeof(config_text) - 1)) {
        perror("fuzz_lookup: config");
        abort();
    }
    close(fd);

    config = init_config(path, EV_DEFAULT);
    unlink(path);
    if (config == NULL) {
        fprintf(stderr, "fuzz_lookup: embedded config failed to parse\n");
        abort();
    }

    struct Listener *l;
    SLIST_FOREACH(l, &config->listeners, entries) {
        struct Table *table = table_lookup(&config->tables, l->table_name);
        if (table == NULL || nlisteners >= 2)
            abort();
        init_table(table);
        l->table = table_ref_get(table);
        if (l->fallback_address && address_port(l->fallback_address) == 0)
            address_set_port(l->fallback_address, address_port(l->address));
        listeners[nlisteners++] = l;
    }
    if (nlisteners != 2)
        abort();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1)
        return 0;
    /* Listener order follows the config's sorted listener list; pick by protocol. */
    const char *want = (data[0] & 1) ? "http" : "tls";
    struct Listener *listener = strcmp(listeners[0]->protocol->name, want) == 0 ?
                                listeners[0] : listeners[1];
    data++;
    size--;

    char *packet = malloc(size);
    if (packet == NULL)
        return 0;
    if (size > 0)
        memcpy(packet, data, size);

    char *hostname = NULL;
    int len = listener->protocol->parse_packet(packet, size, &hostname);
    if (len >= 0 && hostname != NULL) {
        struct LookupResult result =
            listener_lookup_server_address(listener, hostname, (size_t)len);
        if (result.address != NULL) {
            char buf[ADDRESS_BUFFER_SIZE];
            display_address(result.address, buf, sizeof(buf));
            if (result.caller_free_address)
                free((void *)result.address);
        }
    }

    free(hostname);
    free(packet);
    return 0;
}
