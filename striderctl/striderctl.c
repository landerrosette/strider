// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2025-2026 landerrosette
 */

#include <ctype.h>
#include <getopt.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netlink/netlink.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <strider/uapi/limits.h>
#include <strider/uapi/netlink.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

static const char *program_name;
static const char version[] = VERSION;


struct striderctl_command {
    const char *name;
    const char *description;
    int (*handler)(int argc, char *argv[]);
};

static int do_create(int argc, char *argv[]);
static int do_destroy(int argc, char *argv[]);
static int do_add(int argc, char *argv[]);
static int do_del(int argc, char *argv[]);

static const struct striderctl_command all_commands[] = {
    {
        .name = "create",
        .description = "Create a new pattern set",
        .handler = do_create,
    },
    {
        .name = "destroy",
        .description = "Destroy an existing pattern set",
        .handler = do_destroy,
    },
    {
        .name = "add",
        .description = "Add a pattern to a set",
        .handler = do_add,
    },
    {
        .name = "del",
        .description = "Delete a pattern from a set",
        .handler = do_del,
    },
};

static const size_t num_commands = sizeof(all_commands) / sizeof(all_commands[0]);

static void print_opt_err(char *argv[]) {
    if (optopt)
        fprintf(stderr, "%s: invalid option -- '%c'\n", program_name, optopt);
    else
        fprintf(stderr, "%s: unrecognized option '%s'\n", program_name, argv[optind - 1]);
}


struct strider_pattern {
    uint8_t data[STRIDER_MAX_PATTERN_SIZE];
    size_t len;
};

static int validate_set_name(const char *set_name) {
    size_t len = strlen(set_name);
    if (len > STRIDER_MAX_SET_NAME_SIZE - 1) {
        fprintf(stderr, "%s: SET_NAME too long\n", program_name);
        return -1;
    }
    if (len == 0) {
        fprintf(stderr, "%s: SET_NAME cannot be empty\n", program_name);
        return -1;
    }
    return 0;
}

static int parse_hex_string(const char *s, struct strider_pattern *pattern) {
    size_t pos = 0;
    bool hex_flag = false, literal_flag = false;
    size_t len = strlen(s);
    if (len == 0) {
        fprintf(stderr, "%s: PATTERN cannot be empty\n", program_name);
        return -1;
    }
    for (size_t i = 0; i < len; ++pos) {
        if (pos >= STRIDER_MAX_PATTERN_SIZE) {
            fprintf(stderr, "%s: PATTERN too long\n", program_name);
            return -1;
        }
        if (s[i] == '\\' && !hex_flag) {
            literal_flag = true;
        } else if (s[i] == '\\') {
            fprintf(stderr, "%s: cannot include literals in hex data\n", program_name);
            return -1;
        } else if (s[i] == '|') {
            hex_flag = !hex_flag;
            if (hex_flag) {
                while (s[i + 1] == ' ')
                    ++i; // get past any initial whitespace just after the '|'
            }
            if (i + 1 >= len)
                break;
            else
                ++i;
        }

        if (literal_flag) {
            if (i + 1 >= len) {
                fprintf(stderr, "%s: bad literal placement at end of string\n", program_name);
                return -1;
            }
            pattern->data[pos] = s[i + 1];
            i += 2;
            literal_flag = false;
        } else if (hex_flag) {
            if (i + 1 >= len) {
                fprintf(stderr, "%s: odd number of hex digits\n", program_name);
                return -1;
            }
            if (i + 2 >= len) {
                fprintf(stderr, "%s: invalid hex block\n", program_name);
                return -1;
            }
            if (!isxdigit((unsigned char)s[i])) {
                fprintf(stderr, "%s: invalid hex digit '%c'\n", program_name, s[i]);
                return -1;
            }
            if (!isxdigit((unsigned char)s[i + 1])) {
                fprintf(stderr, "%s: invalid hex digit '%c'\n", program_name, s[i + 1]);
                return -1;
            }
            sscanf(&s[i], "%2hhx", &pattern->data[pos]);
            if (s[i + 2] == ' ') // space included in the hex block
                i += 3;
            else
                i += 2;
        } else
            pattern->data[pos] = s[i++]; // the char is not part of hex data, so just copy
    }
    pattern->len = pos;
    return 0;
}


struct strider_nl_connection {
    struct nl_sock *sock;
    int family_id;
};

static int strider_nl_connect(struct strider_nl_connection *conn) {
    int ret = 0;
    conn->sock = nl_socket_alloc();
    if (!conn->sock) {
        ret = -NLE_NOMEM;
        goto fail;
    }
    ret = genl_connect(conn->sock);
    if (ret < 0)
        goto fail_sk_free;
    ret = genl_ctrl_resolve(conn->sock, STRIDER_GENL_FAMILY_NAME);
    if (ret < 0)
        goto fail_sk_free;
    conn->family_id = ret;
    return 0;
fail_sk_free:
    nl_socket_free(conn->sock);
fail:
    return ret;
}

static void strider_nl_disconnect(struct strider_nl_connection *conn) {
    nl_socket_free(conn->sock);
}

static int get_kernel_err(struct sockaddr_nl *nla, struct nlmsgerr *nlerr, void *arg) {
    *(int *) arg = nlerr->error;
    return NL_STOP;
}

static int strider_nl_exch_msg(struct strider_nl_connection *conn, struct nl_msg *msg, int *kernel_err) {
    struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb)
        return -NLE_NOMEM;
    nl_cb_err(cb, NL_CB_CUSTOM, get_kernel_err, kernel_err);
    int ret = nl_send_auto(conn->sock, msg);
    if (ret < 0)
        goto out;
    ret = nl_recvmsgs(conn->sock, cb);
out:
    nl_cb_put(cb);
    return ret;
}

static int strider_nl_do_cmd(enum strider_cmd nl_cmd, int (*cb_add_attrs[])(struct nl_msg *msg, const void *data),
                             const void *cb_data[]) {
    struct strider_nl_connection conn;
    int ret = strider_nl_connect(&conn);
    if (ret < 0) {
        fprintf(stderr, "%s: netlink error: %s\n", program_name, nl_geterror(ret));
        return ret;
    }
    struct nl_msg *msg = nlmsg_alloc();
    if (!msg) {
        ret = -NLE_NOMEM;
        fprintf(stderr, "%s: netlink error: %s\n", program_name, nl_geterror(ret));
        goto out;
    }
    if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, conn.family_id, 0, 0, nl_cmd, STRIDER_GENL_VERSION)) {
        ret = -NLE_NOMEM;
        fprintf(stderr, "%s: netlink error: %s\n", program_name, nl_geterror(ret));
        goto out_msg_free;
    }
    for (int i = 0; cb_add_attrs[i]; ++i) {
        ret = cb_add_attrs[i](msg, cb_data[i]);
        if (ret < 0) {
            fprintf(stderr, "%s: netlink error: %s\n", program_name, nl_geterror(ret));
            goto out_msg_free;
        }
    }
    int kernel_err = 0;
    ret = strider_nl_exch_msg(&conn, msg, &kernel_err);
    if (ret < 0)
        fprintf(stderr, "%s: %s: %s\n", program_name, kernel_err == 0 ? "netlink error" : "operation failed",
                nl_geterror(ret));
out_msg_free:
    nlmsg_free(msg);
out:
    strider_nl_disconnect(&conn);
    return ret;
}


static int add_attr_set_name(struct nl_msg *msg, const void *data) {
    const char *set_name = data;
    return nla_put_string(msg, STRIDER_ATTR_SET_NAME, set_name);
}

static int do_create_destroy(int argc, char *argv[], enum strider_cmd nl_cmd) {
    struct option options[] = {
        {"help", no_argument, NULL, 'h'},
        {}
    };
    while (1) {
        int c = getopt_long(argc, argv, ":h", options, NULL);
        if (c == -1)
            break;
        switch (c) {
            case 'h':
                goto print_help;
            case '?':
                print_opt_err(argv);
                return -1;
            default:
                abort();
        }
    }
    if (optind + 1 != argc) {
        fprintf(stderr, "%s: too %s arguments\n", program_name, optind + 1 < argc ? "many" : "few");
        return -1;
    }
    const char *set_name = argv[optind];

    int ret = validate_set_name(set_name);
    if (ret < 0)
        return ret;
    int (*cbs[])(struct nl_msg *msg, const void *) = {add_attr_set_name, NULL};
    const void *attrs[] = {set_name, NULL};
    return strider_nl_do_cmd(nl_cmd, cbs, attrs);

print_help:
    printf("%s %s [OPTIONS...] SET_NAME\n", program_name, argv[0]);

    printf("\n");
    printf("Options:\n");
    printf("  -h, --help    Print this help information\n");

    printf("\n");
    printf("Arguments:\n");
    printf("  SET_NAME    The unique name of the pattern set\n");

    return 0;
}

static int do_create(int argc, char *argv[]) {
    return do_create_destroy(argc, argv, STRIDER_CMD_CREATE_SET);
}

static int do_destroy(int argc, char *argv[]) {
    return do_create_destroy(argc, argv, STRIDER_CMD_DESTROY_SET);
}

static int add_attr_pattern(struct nl_msg *msg, const void *data) {
    const struct strider_pattern *pattern = data;
    return nla_put(msg, STRIDER_ATTR_PATTERN, (int) pattern->len, pattern->data);
}

static int do_add_del(int argc, char *argv[], enum strider_cmd nl_cmd) {
    int use_hex = false;

    struct option options[] = {
        {"help", no_argument, NULL, 'h'},
        {"hex", no_argument, &use_hex, true},
        {}
    };
    while (1) {
        int c = getopt_long(argc, argv, ":h", options, NULL);
        if (c == -1)
            break;
        switch (c) {
            case 'h':
                goto print_help;
            case 0:
                break;
            case '?':
                print_opt_err(argv);
                return -1;
            default:
                abort();
        }
    }
    if (optind + 2 != argc) {
        fprintf(stderr, "%s: too %s arguments\n", program_name, optind + 2 < argc ? "many" : "few");
        return -1;
    }
    const char *set_name = argv[optind];
    const char *pattern_str = argv[optind + 1];

    int ret = validate_set_name(set_name);
    if (ret < 0)
        return ret;
    struct strider_pattern pattern = {};
    if (use_hex) {
        ret = parse_hex_string(pattern_str, &pattern);
        if (ret < 0)
            return ret;
    } else {
        size_t len = strlen(pattern_str);
        if (len > STRIDER_MAX_PATTERN_SIZE) {
            fprintf(stderr, "%s: PATTERN too long\n", program_name);
            return -1;
        }
        if (len == 0) {
            fprintf(stderr, "%s: PATTERN cannot be empty\n", program_name);
            return -1;
        }
        memcpy(pattern.data, pattern_str, len);
        pattern.len = len;
    }
    int (*cbs[])(struct nl_msg *msg, const void *) = {add_attr_set_name, add_attr_pattern, NULL};
    const void *attrs[] = {set_name, &pattern, NULL};
    return strider_nl_do_cmd(nl_cmd, cbs, attrs);

print_help:
    printf("%s %s [OPTIONS...] SET_NAME PATTERN\n", program_name, argv[0]);

    printf("\n");
    printf("Options:\n");
    printf(
        "  -h, --help    Print this help information\n");
    printf(
        "      --hex     Enable hexadecimal parsing mode for PATTERN\n"
        "                (e.g., 'foo|42 41 52|' -> 'fooBAR')\n");

    printf("\n");
    printf("Arguments:\n");
    printf("  SET_NAME    The name of the pattern set\n");
    printf("  PATTERN     The pattern string\n");

    return 0;
}

static int do_add(int argc, char *argv[]) {
    return do_add_del(argc, argv, STRIDER_CMD_ADD_PATTERN);
}

static int do_del(int argc, char *argv[]) {
    return do_add_del(argc, argv, STRIDER_CMD_DEL_PATTERN);
}


int main(int argc, char *argv[]) {
    char *argv0_copy = strdup(argv[0]);
    program_name = basename(argv0_copy);

    struct option options[] = {
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'v'},
        {}
    };
    while (1) {
        int c = getopt_long(argc, argv, "+:hv", options, NULL);
        if (c == -1)
            break;
        switch (c) {
            case 'h':
                goto print_help;
            case 'v':
                goto print_version;
            case '?':
                print_opt_err(argv);
                return EXIT_FAILURE;
            default:
                abort();
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "%s: no command specified\n", program_name);
        return EXIT_FAILURE;
    }
    const char *command_name = argv[optind];
    const struct striderctl_command *command = NULL;
    for (int i = 0; i < num_commands; ++i) {
        if (strcmp(command_name, all_commands[i].name) == 0) {
            command = &all_commands[i];
            break;
        }
    }
    if (!command) {
        fprintf(stderr, "%s: unknown command '%s'\n", program_name, command_name);
        return EXIT_FAILURE;
    }

    argc -= optind;
    argv += optind;
    optind = 0; // reset
    int ret = command->handler(argc, argv);
    if (ret < 0)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;

print_help:
    printf("%s [OPTIONS...] COMMAND ...\n", program_name);

    printf("\n");
    printf("Commands:\n");
    size_t max_name_len = 0;
    for (int i = 0; i < num_commands; ++i) {
        size_t len = strlen(all_commands[i].name);
        if (len > max_name_len)
            max_name_len = len;
    }
    for (int i = 0; i < num_commands; ++i)
        printf("  %-*s    %s\n", (int) max_name_len, all_commands[i].name, all_commands[i].description);

    printf("\n");
    printf("Options:\n");
    printf("  -h, --help       Print this help information\n");
    printf("  -v, --version    Print version information\n");

    printf("\n");
    printf("Run '%s COMMAND --help' for more information on a command.\n", program_name);

    return EXIT_SUCCESS;
print_version:
    printf("%s v%s\n", program_name, version);
    return EXIT_SUCCESS;
}
