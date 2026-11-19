/*
 * fuzz_config — the configuration file, exactly as `sniproxy -c <file>` loads
 * it: init_config() (cfg_tokenizer + cfg_parser + config/listener/table/
 * backend/address/logger builders), then print_config() and free_config(), as
 * upstream's tests/config_test does. init_config() only parses; it binds no
 * socket.
 *
 * Log files stay in the scratch dir: a `filename` in an error_log/access_log
 * stanza makes logger.c's obtain_file_sink() fopen(<input path>, "a"). The
 * harness is linked with -Wl,--wrap=fopen (build.sh) and, while an input runs,
 * __wrap_fopen sends every append-mode open to one log file inside the
 * harness's own mkdtemp scratch dir, which is truncated before each input. The
 * logger code still runs unchanged (sink lookup, setvbuf, writes, refcounts);
 * only the environment's file system is confined. Read/write opens (the config
 * scratch file, /dev/null) pass through untouched.
 *
 * Kept across inputs on purpose: the scratch dir and file paths, a /dev/null
 * FILE and a baseline stderr logger. Reset per input: the scratch log file is
 * truncated, and since an `error_log` stanza replaces the process-wide default
 * logger (set_default_logger), the baseline logger is made the default again
 * after each input (set_default_logger asserts on NULL, so it cannot simply be
 * cleared).
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ev.h>

#include "config.h"
#include "logger.h"

static char scratch_dir[4096];
static char path[4096];
static char log_path[4096];
static FILE *devnull;
static struct Logger *baseline_logger;
static int confine_logs;

FILE *__real_fopen(const char *, const char *);

/* Every fopen() in this binary (harness and project objects) lands here. */
FILE *__wrap_fopen(const char *filename, const char *mode) {
    if (confine_logs && mode != NULL && mode[0] == 'a')
        return __real_fopen(log_path, mode);
    return __real_fopen(filename, mode);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    const char *tmp = getenv("TMPDIR");
    if (tmp == NULL || *tmp == '\0')
        tmp = "/tmp";
    snprintf(scratch_dir, sizeof(scratch_dir), "%s/sniproxy-fuzz-config-XXXXXX", tmp);
    if (mkdtemp(scratch_dir) == NULL) {
        perror("mkdtemp");
        abort();
    }
    snprintf(path, sizeof(path), "%s/input.conf", scratch_dir);
    snprintf(log_path, sizeof(log_path), "%s/log", scratch_dir);
    devnull = fopen("/dev/null", "w");
    if (devnull == NULL) {
        perror("/dev/null");
        abort();
    }
    baseline_logger = logger_ref_get(new_file_logger("/dev/stderr"));
    if (baseline_logger == NULL)
        abort();
    set_logger_priority(baseline_logger, LOG_NOTICE);
    set_default_logger(baseline_logger);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FILE *f = fopen(path, "w");
    if (f == NULL)
        abort();
    if (size > 0 && fwrite(data, 1, size, f) != size)
        abort();
    fclose(f);
    /* Start each input with an empty scratch log. */
    f = __real_fopen(log_path, "w");
    if (f == NULL)
        abort();
    fclose(f);

    confine_logs = 1;
    struct Config *config = init_config(path, EV_DEFAULT);
    if (config != NULL) {
        print_config(devnull, config);
        free_config(config, EV_DEFAULT);
    }
    fflush(devnull);

    set_default_logger(baseline_logger);
    confine_logs = 0;
    return 0;
}
