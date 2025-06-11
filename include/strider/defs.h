#ifndef STRIDER_DEFS_H
#define STRIDER_DEFS_H


#define STRIDER_PATTERN_MAX_LEN 256 // maximum length of a pattern in bytes

enum {
    STRIDER_ACTION_UNSPEC,
    STRIDER_ACTION_DROP,
    STRIDER_ACTION_ACCEPT,
}; // actions that can be taken on a matched packet


#endif //STRIDER_DEFS_H
