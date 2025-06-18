#include <errno.h>
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
#include <strider/protocol.h>

static const char *program_name = "striderctl";
static char *argv0_alloc_copy = NULL;

struct strider_nl_connection {
    struct nl_sock *sock;
    int family_id;
};

struct command {
    const char *name;

    int (*handler)(struct strider_nl_connection *conn, int argc, char *argv[]);

    int min_argc;
    const char *usage_args;
    const char *description;
};

static int handle_add(struct strider_nl_connection *conn, int argc, char *argv[]);

static int handle_del(struct strider_nl_connection *conn, int argc, char *argv[]);

static struct command commands[] = {
    {
        .name = "add",
        .handler = handle_add,
        .min_argc = 2,
        .usage_args = "<pattern> <action>",
        .description = "Add a new matching rule",
    },
    {
        .name = "del",
        .handler = handle_del,
        .min_argc = 2,
        .usage_args = "<pattern> <action>",
        .description = "Delete an existing matching rule",
    },
    {NULL, NULL, 0, NULL, NULL},
};

static struct option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0},
};

static int get_error_in_response(struct sockaddr_nl *nla, struct nlmsgerr *nlerr, void *arg) {
    *(int *) arg = nlerr->error;
    return NL_STOP;
}

static int strider_nl_connect(struct strider_nl_connection *conn) {
    int ret;

    conn->sock = nl_socket_alloc();
    if (!conn->sock) {
        fprintf(stderr, "%s: system resource error\n", program_name);
        ret = -ENOMEM;
        goto out;
    }

    ret = genl_connect(conn->sock);
    if (ret < 0) {
        fprintf(stderr, "%s: kernel communication error: %s\n", program_name, nl_geterror(ret));
        goto out_sock_free;
    }

    ret = genl_ctrl_resolve(conn->sock, STRIDER_GENL_FAMILY_NAME);
    if (ret < 0) {
        fprintf(stderr, "%s: kernel communication error: %s\n", program_name, nl_geterror(ret));
        goto out_sock_free;
    }
    conn->family_id = ret;

    return 0;

out_sock_free:
    nl_socket_free(conn->sock);
out:
    return ret;
}

static void strider_nl_disconnect(struct strider_nl_connection *conn) {
    nl_socket_free(conn->sock);
}

static int strider_send_rule_request(struct strider_nl_connection *conn, uint8_t cmd, const char *pattern,
                                     const char *action_str) {
    int ret;

    uint8_t action;
    if (strcmp(action_str, "drop") == 0) {
        action = STRIDER_ACTION_DROP;
    } else if (strcmp(action_str, "accept") == 0) {
        action = STRIDER_ACTION_ACCEPT;
    } else {
        fprintf(stderr, "%s: invalid action '%s'\n", program_name, action_str);
        ret = -EINVAL;
        goto out;
    }

    struct nl_msg *msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "%s: system resource error\n", program_name);
        ret = -ENOMEM;
        goto out;
    }

    if (!genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, conn->family_id, 0, NLM_F_REQUEST | NLM_F_ACK, cmd,
                     STRIDER_GENL_VERSION)) {
        fprintf(stderr, "%s: failed to prepare kernel request message\n", program_name);
        ret = -ENOMEM;
        goto out_msg_free;
    }

    ret = nla_put_string(msg, STRIDER_NLA_PATTERN, pattern);
    if (ret < 0) {
        fprintf(stderr, "%s: failed to prepare kernel request message: %s\n", program_name, nl_geterror(ret));
        goto out_msg_free;
    }

    ret = nla_put_u8(msg, STRIDER_NLA_ACTION, action);
    if (ret < 0) {
        fprintf(stderr, "%s: failed to prepare kernel request message: %s\n", program_name, nl_geterror(ret));
        goto out_msg_free;
    }

    struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        fprintf(stderr, "%s: system resource error\n", program_name);
        ret = -ENOMEM;
        goto out_msg_free;
    }
    int kernel_err = 0;
    nl_cb_err(cb, NL_CB_CUSTOM, get_error_in_response, &kernel_err);

    ret = nl_send_auto(conn->sock, msg);
    if (ret < 0) {
        fprintf(stderr, "%s: kernel communication error: %s\n", program_name, nl_geterror(ret));
        goto out_msg_free;
    }

    ret = nl_recvmsgs(conn->sock, cb);
    if (ret < 0) {
        if (kernel_err < 0) {
            const char *detail;
            switch (kernel_err) {
                case -EEXIST:
                    detail = "Rule exists";
                    break;
                case -ENOENT:
                    detail = "Rule not found";
                    break;
                default:
                    detail = nl_geterror(nl_syserr2nlerr(kernel_err));
            }
            fprintf(stderr, "%s: operation failed: %s\n", program_name, detail);
        } else
            fprintf(stderr, "%s: kernel communication error: %s\n", program_name, nl_geterror(ret));
        goto out_cb_put;
    }

    ret = 0;

out_cb_put:
    nl_cb_put(cb);
out_msg_free:
    nlmsg_free(msg);
out:
    return ret;
}

static int handle_add(struct strider_nl_connection *conn, int argc, char *argv[]) {
    const char *pattern = argv[0], *action = argv[1];
    return strider_send_rule_request(conn, STRIDER_CMD_ADD_RULE, pattern, action);
}

static int handle_del(struct strider_nl_connection *conn, int argc, char *argv[]) {
    const char *pattern = argv[0], *action = argv[1];
    return strider_send_rule_request(conn, STRIDER_CMD_DEL_RULE, pattern, action);
}

static void show_help(FILE *stream) {
    fprintf(stream, "Usage: striderctl [OPTION]... COMMAND [ARG]...\n");
    fprintf(stream, "\n");

    fprintf(stream, "Options:\n");
    fprintf(stream, "  -h, --help      Show this help message and exit\n");
    fprintf(stream, "\n");

    fprintf(stream, "Commands:\n");
    for (int i = 0; commands[i].name; ++i) {
        char command_usage[128];
        snprintf(command_usage, sizeof(command_usage), "%s %s", commands[i].name, commands[i].usage_args);
        fprintf(stream, "  %-25s %s\n", command_usage, commands[i].description);
    }
}

int main(int argc, char *argv[]) {
    int ret;

    if (argc > 0) {
        argv0_alloc_copy = strdup(argv[0]);
        if (argv0_alloc_copy)
            program_name = basename(argv0_alloc_copy);
    }

    while (true) {
        int opt_idx = 0;
        int c = getopt_long(argc, argv, ":h", long_options, &opt_idx);
        if (c == -1) break;
        switch (c) {
            case 'h':
                show_help(stdout);
                ret = EXIT_SUCCESS;
                goto out_free;
            case '?':
                if (optopt) {
                    fprintf(stderr, "%s: invalid option -- '%c'\n", program_name, optopt);
                } else {
                    fprintf(stderr, "%s: unrecognized option '%s'\n", program_name, argv[optind - 1]);
                }
                fprintf(stderr, "Try '%s --help' for more information.\n", program_name);
                ret = EXIT_FAILURE;
                goto out_free;
            default:
                abort(); // Should not happen
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "%s: missing command\n", program_name);
        fprintf(stderr, "Try '%s --help' for more information.\n", program_name);
        ret = EXIT_FAILURE;
        goto out_free;
    }

    struct strider_nl_connection conn = {0};
    if (strider_nl_connect(&conn) < 0) {
        ret = EXIT_FAILURE;
        goto out_free;
    }

    const char *command_name = argv[optind];
    for (int i = 0; commands[i].name; ++i) {
        if (strcmp(command_name, commands[i].name) == 0) {
            int remaining_argc = argc - optind - 1;
            char **remaining_argv = &argv[optind + 1];

            if (remaining_argc < commands[i].min_argc) {
                fprintf(stderr, "%s: command '%s' requires at least %d arguments\n", program_name, command_name,
                        commands[i].min_argc);
                fprintf(stderr, "Usage: %s %s %s\n", program_name, command_name, commands[i].usage_args);
                ret = EXIT_FAILURE;
                goto out_disconnect;
            }

            ret = commands[i].handler(&conn, remaining_argc, remaining_argv) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
            goto out_disconnect;
        }
    }
    fprintf(stderr, "%s: unknown command '%s'\n", program_name, command_name);
    fprintf(stderr, "Try '%s --help' for more information.\n", program_name);
    ret = EXIT_FAILURE;

out_disconnect:
    strider_nl_disconnect(&conn);
out_free:
    free(argv0_alloc_copy);
    return ret;
}
