#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
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

out:
    return ret;

fail_sk_free:
    nl_socket_free(conn->sock);
fail:
    fprintf(stderr, "%s: netlink error: %s\n", program_name, nl_geterror(-ret));
    goto out;
}

static void strider_nl_disconnect(struct strider_nl_connection *conn) {
    nl_socket_free(conn->sock);
}

static int get_error_in_response(struct sockaddr_nl *nla, struct nlmsgerr *nlerr, void *arg) {
    *(int *) arg = nl_syserr2nlerr(nlerr->error);
    return NL_STOP;
}

static int strider_nl_send_cmd(struct strider_nl_connection *conn, uint8_t cmd,
                               int (*add_attrs_cb)(struct nl_msg *msg, void *data), void *cb_data) {
    int ret = 0;

    struct nl_msg *msg = nlmsg_alloc();
    if (!msg) {
        ret = -ENOMEM;
        goto fail;
    }

    if (!genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, conn->family_id, 0, NLM_F_REQUEST | NLM_F_ACK, cmd,
                     STRIDER_GENL_VERSION)) {
        ret = -ENOMEM;
        goto fail_msg_free;
    }

    if (add_attrs_cb) {
        ret = add_attrs_cb(msg, cb_data);
        if (ret < 0)
            goto fail_msg_free_nlerr;
    }

    struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        ret = -ENOMEM;
        goto fail_msg_free;
    }
    int kernel_err = 0;
    nl_cb_err(cb, NL_CB_CUSTOM, get_error_in_response, &kernel_err);

    ret = nl_send_auto(conn->sock, msg);
    if (ret < 0)
        goto fail_cb_put;

    ret = nl_recvmsgs(conn->sock, cb);
    if (kernel_err < 0) {
        fprintf(stderr, "%s: operation failed: %s\n", program_name, nl_geterror(-kernel_err));
        ret = kernel_err;
    } else if (ret < 0)
        goto fail_cb_put;

out_cb_put:
    nl_cb_put(cb);
out_msg_free:
    nlmsg_free(msg);
out:
    return ret;

fail_cb_put:
    fprintf(stderr, "%s: netlink error: %s\n", program_name, nl_geterror(-ret));
    goto out_cb_put;
fail_msg_free_nlerr:
    fprintf(stderr, "%s: netlink error: %s\n", program_name, nl_geterror(-ret));
    goto out_msg_free;
fail_msg_free:
    nlmsg_free(msg);
fail:
    fprintf(stderr, "%s: netlink error: %s\n", program_name, nl_geterror(nl_syserr2nlerr(-ret)));
    goto out;
}

struct set_args {
    const char *name;
};

static int add_attrs_set(struct nl_msg *msg, void *data) {
    return nla_put_string(msg, STRIDER_ATTR_SET_NAME, ((struct set_args *) data)->name);
}

static int handle_create(struct strider_nl_connection *conn, int argc, char *argv[]) {
    struct set_args args = {.name = argv[0]};
    return strider_nl_send_cmd(conn, STRIDER_CMD_CREATE_SET, add_attrs_set, &args);
}

static int handle_destroy(struct strider_nl_connection *conn, int argc, char *argv[]) {
    struct set_args args = {.name = argv[0]};
    return strider_nl_send_cmd(conn, STRIDER_CMD_DESTROY_SET, add_attrs_set, &args);
}

static int handle_add(struct strider_nl_connection *conn, int argc, char *argv[]);

static int handle_del(struct strider_nl_connection *conn, int argc, char *argv[]);

struct striderctl_command {
    const char *name;
    int (*handler)(struct strider_nl_connection *conn, int argc, char *argv[]);
    int min_argc;
    const char *usage_args;
    const char *description;
};

static const struct striderctl_command striderctl_commands[] = {
    {
        .name = "create",
        .handler = handle_create,
        .min_argc = 1,
        .usage_args = "<name>",
        .description = "Create a new pattern set",
    },
    {
        .name = "destroy",
        .handler = handle_destroy,
        .min_argc = 1,
        .usage_args = "<name>",
        .description = "Destroy an existing pattern set",
    },
    {
        .name = "add",
        // .handler = handle_add,
        .min_argc = 2,
        .usage_args = "<set_name> <pattern>",
        .description = "Add a pattern to a set",
    },
    {
        .name = "del",
        // .handler = handle_del,
        .min_argc = 2,
        .usage_args = "<set_name> <pattern>",
        .description = "Delete a pattern from a set",
    },
    {}
};

static void print_version(FILE *stream) {
    fprintf(stream, "%s v%s\n", program_name, version);
}

static void print_help(FILE *stream) {
    fprintf(stream, "Usage: %s [OPTION]... COMMAND [ARG]...\n", program_name);
    fprintf(stream, "\n");

    fprintf(stream, "Options:\n");
    fprintf(stream, "  -h, --help       Print this help information\n");
    fprintf(stream, "  -v, --version    Print version information\n");
    fprintf(stream, "\n");

    fprintf(stream, "Commands:\n");
    for (int i = 0; striderctl_commands[i].name; ++i) {
        char command_usage[128];
        snprintf(command_usage, sizeof(command_usage), "%s %s", striderctl_commands[i].name,
                 striderctl_commands[i].usage_args);
        fprintf(stream, "  %-27s %s\n", command_usage, striderctl_commands[i].description);
    }
}

int main(int argc, char *argv[]) {
    int ret = 0;

    struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'v'},
        {}
    };
    int c = getopt_long(argc, argv, "hv", long_options, NULL);
    if (c != -1) {
        switch (c) {
            case 'h':
                print_help(stdout);
                goto out;
            case 'v':
                print_version(stdout);
                goto out;
            case '?':
            default:
                ret = -EINVAL;
                goto out_print;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "%s: missing command\n", program_name);
        ret = -EINVAL;
        goto out_print;
    }
    const char *command_name = argv[optind];
    for (int i = 0; striderctl_commands[i].name; ++i) {
        if (strcmp(command_name, striderctl_commands[i].name) == 0) {
            int remaining_argc = argc - optind - 1;
            char **remaining_argv = &argv[optind + 1];
            if (remaining_argc < striderctl_commands[i].min_argc) {
                fprintf(stderr, "%s: command '%s' requires at least %d argument(s)\n", program_name, command_name,
                        striderctl_commands[i].min_argc);
                ret = -EINVAL;
                goto out_print;
            }

            struct strider_nl_connection conn = {};
            ret = strider_nl_connect(&conn);
            if (ret < 0)
                goto out;
            ret = striderctl_commands[i].handler(&conn, remaining_argc, remaining_argv);
            strider_nl_disconnect(&conn);
            goto out;
        }
    }
    // loop did not end early
    fprintf(stderr, "%s: unknown command '%s'\n", program_name, command_name);
    ret = -EINVAL;

out_print:
    fprintf(stderr, "Try '%s --help' for more information.\n", program_name);
out:
    return ret < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
