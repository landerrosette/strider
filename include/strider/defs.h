#ifndef STRIDER_DEFS_H
#define STRIDER_DEFS_H


#define STRIDER_PATTERN_MAX_LEN 256 // maximum length of a pattern in bytes

enum {
    STRIDER_ACTION_DROP,
    STRIDER_ACTION_ACCEPT,
    __STRIDER_ACTION_MAX,
}; // actions that can be taken on a matched packet

#define STRIDER_ACTION_MAX (__STRIDER_ACTION_MAX - 1)


#endif //STRIDER_DEFS_H
