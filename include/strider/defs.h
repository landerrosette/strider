#ifndef STRIDER_DEFS_H
#define STRIDER_DEFS_H


#define STRIDER_PATTERN_MAX_LEN 256 // maximum length of a pattern in bytes

// actions that can be taken on a matched packet
enum strider_action {
    STRIDER_ACTION_UNSPEC,
    STRIDER_ACTION_DROP,
    STRIDER_ACTION_ACCEPT,
};


#endif //STRIDER_DEFS_H
