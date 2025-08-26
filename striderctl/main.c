#include <ctype.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netlink/netlink.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <strider/protocol.h>

static const char program_name[] = PROGRAM;
static const char version[] = VERSION;

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
    ret = 0;
    return ret;
fail_sk_free:
    nl_socket_free(conn->sock);
fail:
    fprintf(stderr, "%s: netlink error: %s\n", program_name, nl_geterror(ret));
    return ret;
}

static void strider_nl_disconnect(struct strider_nl_connection *conn) {
    nl_socket_free(conn->sock);
}

static int get_kernel_err(struct sockaddr_nl *nla, struct nlmsgerr *nlerr, void *arg) {
    (void) nla;
    *(int *) arg = nlerr->error;
    return NL_STOP;
}

static int strider_nl_send_cmd_msg(struct strider_nl_connection *conn, struct nl_msg *msg, int *kernel_err) {
    struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb)
        return -NLE_NOMEM;
    nl_cb_err(cb, NL_CB_CUSTOM, get_kernel_err, kernel_err);
    int ret = nl_send_auto(conn->sock, msg);
    if (ret < 0)
        goto out;
    ret = nl_recvmsgs(conn->sock, cb);
    if (ret < 0)
        goto out;
out:
    nl_cb_put(cb);
    return ret;
}

struct strider_pattern {
    uint8_t data[STRIDER_MAX_PATTERN_SIZE];
    size_t len;
};

static int parse_hex_pattern(const char *s, struct strider_pattern *pattern) {
    size_t idx = 0;
    bool hex = false, literal = false;
    for (size_t i = 0; i < strlen(s); ++idx) {
        if (idx >= STRIDER_MAX_PATTERN_SIZE)
            return -NLE_INVAL;

        if (s[i] == '\\' && !hex)
            literal = true;
        else if (s[i] == '\\')
            return -NLE_INVAL;
        else if (s[i] == '|') {
            hex = !hex;
            if (i + 1 >= strlen(s))
                break;
            else
                ++i;
        }

        if (literal) {
            if (i + 1 >= strlen(s))
                return -NLE_INVAL;
            pattern->data[idx] = s[i + 1];
            i += 2;
            literal = false;
        } else if (hex) {
            if (isspace(s[i])) {
                ++i;
                continue;
            }
            if (s[i] == '|') {
                hex = false;
                ++i;
                continue;
            }
            if (i + 1 >= strlen(s) || !isxdigit(s[i]) || !isxdigit(s[i + 1]))
                return -NLE_INVAL;

            char hextmp[3] = {s[i], s[i + 1], '\0'};
            unsigned int schar;
            if (sscanf(hextmp, "%x", &schar) != 1)
                return -NLE_INVAL;
            pattern->data[idx] = schar;
            i += 2;
        } else
            pattern->data[idx] = s[i++];
    }
    pattern->len = idx;
    return 0;
}

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

#define NUM_COMMANDS (sizeof(all_commands) / sizeof(all_commands[0]))

static int do_create_destroy(int argc, char *argv[], enum strider_cmd cmd) {
    struct option options[] = {
        {"help", no_argument, NULL, 'h'},
        {}
    };
    while (1) {
        int c = getopt_long(argc, argv, "+h", options, NULL);
        if (c == -1)
            break;
        switch (c) {
            case 'h':
                goto print_help;
            case '?':
                goto prompt_help;
            default:
                abort();
        }
    }
    if (optind + 1 != argc) {
        fprintf(stderr, "%s: too %s arguments for '%s'\n", program_name, optind + 1 < argc ? "many" : "few", argv[0]);
        goto prompt_help;
    }
    const char *set_name = argv[optind];

    struct strider_nl_connection conn;
    int kernel_err = 0;
    int ret = strider_nl_connect(&conn);
    if (ret < 0)
        goto out;
    struct nl_msg *msg = nlmsg_alloc();
    if (!msg) {
        ret = -NLE_NOMEM;
        goto out_disconnect;
    }
    if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, conn.family_id, 0, 0, cmd, STRIDER_GENL_VERSION)) {
        ret = -NLE_NOMEM;
        goto out_msg_free;
    }
    ret = nla_put_string(msg, STRIDER_ATTR_SET_NAME, set_name);
    if (ret < 0)
        goto out_msg_free;
    ret = strider_nl_send_cmd_msg(&conn, msg, &kernel_err);
    if (ret < 0)
        goto out_msg_free;

out_msg_free:
    nlmsg_free(msg);
out_disconnect:
    strider_nl_disconnect(&conn);
out:
    if (ret < 0)
        fprintf(stderr, "%s: %s: %s\n", program_name, kernel_err == 0 ? "netlink error" : "operation failed",
                nl_geterror(ret));
    return ret;

print_help:
    printf("%s %s [OPTIONS...] SET_NAME\n", program_name, argv[0]);

    printf("\n");
    printf("Options:\n");
    printf("  -h, --help    Print this help information\n");

    printf("\n");
    printf("Arguments:\n");
    printf("  SET_NAME    Pattern set name\n");

    return 0;
prompt_help:
    fprintf(stderr, "Try '%s %s --help' for more information.\n", program_name, argv[0]);
    return -1;
}

static int do_create(int argc, char *argv[]) {
    return do_create_destroy(argc, argv, STRIDER_CMD_CREATE_SET);
}

static int do_destroy(int argc, char *argv[]) {
    return do_create_destroy(argc, argv, STRIDER_CMD_DESTROY_SET);
}

static int do_add(int argc, char *argv[]) {}

static int do_del(int argc, char *argv[]) {}

int main(int argc, char *argv[]) {
    struct option options[] = {
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'v'},
        {}
    };
    while (1) {
        int c = getopt_long(argc, argv, "+hv", options, NULL);
        if (c == -1)
            break;
        switch (c) {
            case 'h':
                goto print_help;
            case 'v':
                goto print_version;
            case '?':
                goto prompt_help;
            default:
                abort();
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "%s: no command specified\n", program_name);
        goto prompt_help;
    }
    const char *command_name = argv[optind];
    const struct striderctl_command *command = NULL;
    for (size_t i = 0; i < NUM_COMMANDS; ++i) {
        if (strcmp(command_name, all_commands[i].name) == 0) {
            command = &all_commands[i];
            break;
        }
    }
    if (!command) {
        fprintf(stderr, "%s: unknown command '%s'\n", program_name, command_name);
        goto prompt_help;
    }

    argc -= optind;
    argv += optind;
    optind = 1; // reset
    int ret = command->handler(argc, argv);
    if (ret < 0)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;

print_help:
    printf("%s [OPTIONS...] COMMAND ...\n", program_name);

    printf("\n");
    printf("Commands:\n");
    size_t max_name_len = 0;
    for (size_t i = 0; i < NUM_COMMANDS; ++i) {
        size_t len = strlen(all_commands[i].name);
        if (len > max_name_len)
            max_name_len = len;
    }
    for (size_t i = 0; i < NUM_COMMANDS; ++i)
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
prompt_help:
    fprintf(stderr, "Try '%s --help' for more information.\n", program_name);
    return EXIT_FAILURE;
}
