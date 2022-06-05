#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>
#include "modules/user_comm.h"

void wrong_usage(void) {
    fprintf(stderr, "Error: Invalid syntax\n");
    printf("Usage: wdum [COMMAND] [OPTION]...\n\n\
Commands:\n add PATTERN                        add rule with PATTERN\n\
 delete PATTERN                     delete rule with PATTERN\n\
 update OLD_PATTERN NEW_PATTERN     substitute OLD_PATTERN with NEW_PATTERN\n\n\
Options:\n -e, --regex                        regex matching\n\
 -p, --proto=http|dns               app-level filtering\n");

    exit(EPERM);
}

int main(int argc, char *argv[]) {
    int fd;
    char *pattern;
    char *old_pattern;
    char *new_pattern;

    fd = open("/dev/wdumdev", O_WRONLY);

    if (argc < 3)
        wrong_usage();

    if (strcmp(argv[1], "add") == 0) {
        pattern = argv[2];
        switch (argc) {
            case 3:
                ioctl(fd, WDUM_ADD_SM_GEN_RULE, pattern);
                break;
            case 4:
                if (strcmp(argv[3], "-e") == 0 || strcmp(argv[3], "--regex") == 0) {
                    ioctl(fd, WDUM_ADD_RE_GEN_RULE, pattern);
                } else if (strcmp(argv[3], "-phttp") == 0 || strcmp(argv[3], "--proto=http") == 0) {
                    ioctl(fd, WDUM_ADD_SM_HTTP_RULE, pattern);
                } else if (strcmp(argv[3], "-pdns") == 0 || strcmp(argv[3], "--proto=dns") == 0) {
                    ioctl(fd, WDUM_ADD_SM_DNS_RULE, pattern);
                } else {
                    wrong_usage();
                }
                break;
            case 5:
                if (((strcmp(argv[3], "-e") == 0 || strcmp(argv[3], "--regex") == 0) &&
                     (strcmp(argv[4], "-phttp") == 0 || strcmp(argv[4], "--proto=http") == 0)) ||
                    ((strcmp(argv[4], "-e") == 0 || strcmp(argv[4], "--regex") == 0) &&
                     (strcmp(argv[3], "-phttp") == 0 || strcmp(argv[3], "--proto=http") == 0))) {
                    ioctl(fd, WDUM_ADD_RE_HTTP_RULE, pattern);
                } else if (((strcmp(argv[3], "-e") == 0 || strcmp(argv[3], "--regex") == 0) &&
                            (strcmp(argv[4], "-pdns") == 0 || strcmp(argv[4], "--proto=dns") == 0)) ||
                           ((strcmp(argv[4], "-e") == 0 || strcmp(argv[4], "--regex") == 0) &&
                            (strcmp(argv[3], "-pdns") == 0 || strcmp(argv[3], "--proto=dns") == 0))) {
                    ioctl(fd, WDUM_ADD_RE_DNS_RULE, pattern);
                } else if ((strcmp(argv[3], "-p") == 0 || strcmp(argv[3], "--proto") == 0) &&
                           strcmp(argv[4], "http") == 0) {
                    ioctl(fd, WDUM_ADD_SM_HTTP_RULE, pattern);
                } else if ((strcmp(argv[3], "-p") == 0 || strcmp(argv[3], "--proto") == 0) &&
                           strcmp(argv[4], "dns") == 0) {
                    ioctl(fd, WDUM_ADD_SM_DNS_RULE, pattern);
                } else {
                    wrong_usage();
                }
                break;
            case 6:
                if (((strcmp(argv[3], "-e") == 0 || strcmp(argv[3], "--regex") == 0) &&
                      strcmp(argv[4], "--proto") == 0 &&
                      strcmp(argv[5], "http") == 0) ||
                    ((strcmp(argv[5], "-e") == 0 || strcmp(argv[5], "--regex") == 0) &&
                      strcmp(argv[3], "--proto") == 0 &&
                      strcmp(argv[4], "http") == 0)) {
                    ioctl(fd, WDUM_ADD_RE_HTTP_RULE, pattern);
                } else if (((strcmp(argv[3], "-e") == 0 || strcmp(argv[3], "--regex") == 0) &&
                             strcmp(argv[4], "--proto") == 0 &&
                             strcmp(argv[5], "dns") == 0) ||
                           ((strcmp(argv[5], "-e") == 0 || strcmp(argv[5], "--regex") == 0) &&
                             strcmp(argv[3], "--proto") == 0 &&
                             strcmp(argv[4], "dns") == 0)) {
                    ioctl(fd, WDUM_ADD_RE_DNS_RULE, pattern);
                } else {
                    wrong_usage();
                }
                break;
            default:
                wrong_usage();
                break;
        }
    } else if (strcmp(argv[1], "delete") == 0) {
        pattern = argv[2];
        switch (argc) {
            case 3:
                ioctl(fd, WDUM_DEL_SM_GEN_RULE, pattern);
                break;
            case 4:
                if (strcmp(argv[3], "-e") == 0 || strcmp(argv[3], "--regex") == 0) {
                    ioctl(fd, WDUM_DEL_RE_GEN_RULE, pattern);
                } else if (strcmp(argv[3], "-phttp") == 0 || strcmp(argv[3], "--proto=http") == 0) {
                    ioctl(fd, WDUM_DEL_SM_HTTP_RULE, pattern);
                } else if (strcmp(argv[3], "-pdns") == 0 || strcmp(argv[3], "--proto=dns") == 0) {
                    ioctl(fd, WDUM_DEL_SM_DNS_RULE, pattern);
                } else {
                    wrong_usage();
                }
                break;
            case 5:
                if (((strcmp(argv[3], "-e") == 0 || strcmp(argv[3], "--regex") == 0) &&
                     (strcmp(argv[4], "-phttp") == 0 || strcmp(argv[4], "--proto=http") == 0)) ||
                    ((strcmp(argv[4], "-e") == 0 || strcmp(argv[4], "--regex") == 0) &&
                     (strcmp(argv[3], "-phttp") == 0 || strcmp(argv[3], "--proto=http") == 0))) {
                    ioctl(fd, WDUM_DEL_RE_HTTP_RULE, pattern);
                } else if (((strcmp(argv[3], "-e") == 0 || strcmp(argv[3], "--regex") == 0) &&
                            (strcmp(argv[4], "-pdns") == 0 || strcmp(argv[4], "--proto=dns") == 0)) ||
                           ((strcmp(argv[4], "-e") == 0 || strcmp(argv[4], "--regex") == 0) &&
                            (strcmp(argv[3], "-pdns") == 0 || strcmp(argv[3], "--proto=dns") == 0))) {
                    ioctl(fd, WDUM_DEL_RE_DNS_RULE, pattern);
                } else if ((strcmp(argv[3], "-p") == 0 || strcmp(argv[3], "--proto") == 0) &&
                           strcmp(argv[4], "http") == 0) {
                    ioctl(fd, WDUM_DEL_SM_HTTP_RULE, pattern);
                } else if ((strcmp(argv[3], "-p") == 0 || strcmp(argv[3], "--proto") == 0) &&
                           strcmp(argv[4], "dns") == 0) {
                    ioctl(fd, WDUM_DEL_SM_DNS_RULE, pattern);
                } else {
                    wrong_usage();
                }
                break;
            case 6:
                if (((strcmp(argv[3], "-e") == 0 || strcmp(argv[3], "--regex") == 0) &&
                      strcmp(argv[4], "--proto") == 0 &&
                      strcmp(argv[5], "http") == 0) ||
                    ((strcmp(argv[5], "-e") == 0 || strcmp(argv[5], "--regex") == 0) &&
                      strcmp(argv[3], "--proto") == 0 &&
                      strcmp(argv[4], "http") == 0)) {
                    ioctl(fd, WDUM_DEL_RE_HTTP_RULE, pattern);
                } else if (((strcmp(argv[3], "-e") == 0 || strcmp(argv[3], "--regex") == 0) &&
                             strcmp(argv[4], "--proto") == 0 &&
                             strcmp(argv[5], "dns") == 0) ||
                           ((strcmp(argv[5], "-e") == 0 || strcmp(argv[5], "--regex") == 0) &&
                             strcmp(argv[3], "--proto") == 0 &&
                             strcmp(argv[4], "dns") == 0)) {
                    ioctl(fd, WDUM_DEL_RE_DNS_RULE, pattern);
                } else {
                    wrong_usage();
                }
                break;
            default:
                wrong_usage();
                break;
        }
    } else if (strcmp(argv[1], "update") == 0) {
        if (argc != 4)
            wrong_usage();
        old_pattern = argv[2];
        new_pattern = argv[3];
        ioctl(fd, WDUM_UPD_RULE_OLD, old_pattern);
        ioctl(fd, WDUM_UPD_RULE_NEW, new_pattern);
    } else {
        wrong_usage();
    }

    return 0;
}
