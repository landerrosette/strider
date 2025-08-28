#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>

#include "core.h"
#include "netlink.h"

static int __init strider_module_init(void) {
    int ret = strider_core_init();
    if (ret < 0)
        goto out;
    ret = strider_netlink_init();
    if (ret < 0)
        goto fail;
    pr_debug("module loaded\n");
out:
    return ret;
fail:
    strider_core_exit();
    return ret;
}

static void __exit strider_module_exit(void) {
    strider_netlink_exit();
    strider_core_exit();
    pr_debug("module unloaded\n");
}

module_init(strider_module_init);
module_exit(strider_module_exit);

MODULE_LICENSE("GPL");
