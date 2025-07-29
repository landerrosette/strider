#ifndef STRIDER_PROTOCOL_H
#define STRIDER_PROTOCOL_H


#define STRIDER_GENL_FAMILY_NAME "strider"
#define STRIDER_GENL_VERSION 2

// commands that can be sent over netlink
enum {
    STRIDER_CMD_UNSPEC,
    STRIDER_CMD_ADD_PATTERN,
    STRIDER_CMD_DEL_PATTERN,
    __STRIDER_CMD_MAX,
};

#define STRIDER_CMD_MAX (__STRIDER_CMD_MAX - 1)

// netlink attributes used in the messages
enum {
    STRIDER_NLA_UNSPEC,
    STRIDER_NLA_PATTERN, // type: NLA_NUL_STRING
    __STRIDER_NLA_MAX,
};

#define STRIDER_NLA_MAX (__STRIDER_NLA_MAX - 1)


#endif //STRIDER_PROTOCOL_H
