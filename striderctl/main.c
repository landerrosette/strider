#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netlink/netlink.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <strider/protocol.h>

struct strider_nl_connection {
    struct nl_sock *sock;
    int family_id;
};

static int strider_connect(struct strider_nl_connection *conn) {
    int ret;

    conn->sock = nl_socket_alloc();
    if (!conn->sock) {
        fprintf(stderr, "Error: Could not allocate netlink socket\n");
        ret = -ENOMEM;
        goto out;
    }

    ret = genl_connect(conn->sock);
    if (ret < 0) {
        nl_perror(ret, "Error: Could not connect to generic netlink");
        goto out_sock_free;
    }

    ret = genl_ctrl_resolve(conn->sock, STRIDER_GENL_FAMILY_NAME);
    if (ret < 0) {
        nl_perror(ret, "Error: Could not resolve family name \"" STRIDER_GENL_FAMILY_NAME "\"");
        goto out_sock_free;
    }
    conn->family_id = ret;

    printf("Successfully connected to \"%s\" family with ID %d.\n", STRIDER_GENL_FAMILY_NAME, conn->family_id);

    return 0;

out_sock_free:
    nl_socket_free(conn->sock);
out:
    return ret;
}

static void strider_disconnect(struct strider_nl_connection *conn) {
    nl_socket_free(conn->sock);
}

static int do_add_rule(struct strider_nl_connection *conn, const char *pattern, const char *action_str) {
    int ret;

    uint8_t action;
    if (strcmp(action_str, "drop") == 0) {
        action = STRIDER_ACTION_DROP;
    } else {
        fprintf(stderr, "Error: Invalid action \"%s\"\n", action_str);
        ret = -EINVAL;
        goto out;
    }

    struct nl_msg *msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "Error: Could not allocate netlink message\n");
        ret = -ENOMEM;
        goto out;
    }

    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, conn->family_id, 0, NLM_F_REQUEST | NLM_F_ACK, STRIDER_CMD_ADD_RULE,
                STRIDER_GENL_VERSION);

    ret = nla_put_string(msg, STRIDER_NLA_PATTERN, pattern);
    if (ret < 0) {
        fprintf(stderr, "Error: Could not add pattern attribute: %s\n", nl_geterror(ret));
        goto out_msg_free;
    }

    ret = nla_put_u8(msg, STRIDER_NLA_ACTION, action);
    if (ret < 0) {
        fprintf(stderr, "Error: Could not add action attribute: %s\n", nl_geterror(ret));
        goto out_msg_free;
    }

    printf("Sending add rule request for pattern \"%s\" with action \"%s\"...\n", pattern, action_str);
    ret = nl_send_auto(conn->sock, msg);
    if (ret < 0) {
        nl_perror(ret, "Error: Could not send add rule request");
        goto out_msg_free;
    }

    ret = nl_recvmsgs_default(conn->sock);
    if (ret < 0) {
        nl_perror(ret, "Error receiving response");
    } else {
        printf("Received response for pattern \"%s\" with action \"%s\".\n", pattern, action_str);
    }

    return 0;

out_msg_free:
    nlmsg_free(msg);
out:
    return ret;
}

int main(int argc, char *argv[]) {
    struct strider_nl_connection conn = {0};

    if (strider_connect(&conn) < 0)
        goto out;

    const char *command = argv[1];
    if (strcmp(command, "add") == 0) {
        const char *pattern = argv[2];
        const char *action = argv[3];
        if (do_add_rule(&conn, pattern, action))
            goto out_disconnect;
    } else {
        fprintf(stderr, "Error: Unknown command \"%s\"\n", command);
        goto out_disconnect;
    }

    return EXIT_SUCCESS;

out_disconnect:
    strider_disconnect(&conn);
out:
    return EXIT_FAILURE;
}
