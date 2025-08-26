#ifndef STRIDER_PROTOCOL_H
#define STRIDER_PROTOCOL_H


#include "limits.h"

#define STRIDER_GENL_FAMILY_NAME "strider"
#define STRIDER_GENL_VERSION 2

// commands that can be sent over netlink
enum strider_cmd {
    STRIDER_CMD_UNSPEC,
    STRIDER_CMD_CREATE_SET,
    STRIDER_CMD_DESTROY_SET,
    STRIDER_CMD_ADD_PATTERN,
    STRIDER_CMD_DEL_PATTERN,
    __STRIDER_CMD_MAX,
};

#define STRIDER_CMD_MAX (__STRIDER_CMD_MAX - 1)

// netlink attributes used in the messages
enum {
    STRIDER_ATTR_UNSPEC,
    STRIDER_ATTR_SET_NAME, // type: NLA_NUL_STRING
    STRIDER_ATTR_PATTERN, // type: NLA_BINARY
    __STRIDER_ATTR_MAX,
};

#define STRIDER_ATTR_MAX (__STRIDER_ATTR_MAX - 1)


#endif //STRIDER_PROTOCOL_H
