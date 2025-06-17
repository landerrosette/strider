#ifndef STRIDER_KMOD_CONTROL_H
#define STRIDER_KMOD_CONTROL_H


#include <linux/init.h>

int __init strider_control_init(void);

void strider_control_cleanup(void);


#endif //STRIDER_KMOD_CONTROL_H
