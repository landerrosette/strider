#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/limits.h>
#include <asm/uaccess.h>
#include "user_comm.h"
#include "rule.h"
#include "rule_base.h"
#include "logging.h"

#define WDUMDEV_MAJOR 0

static int wdumdev_major = WDUMDEV_MAJOR;
static struct class *wdumdev_class;

static struct wdumdev {
    /* temp storage of old_pattern */
    char *rule_optn;
    struct cdev cdev;
} *device;

long wdum_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    int err, retval = 0;
    char *rule_ptn;
    size_t rule_ptn_len;
    unsigned int rule_ptn_type;
    unsigned int rule_ftr_type;
    
	if (_IOC_TYPE(cmd) != WDUM_IOC_MAGIC)
        return -ENOTTY;
	if (_IOC_NR(cmd) > WDUM_IOC_MAXNR)
        return -ENOTTY;
	err = !access_ok((void __user *)arg, _IOC_SIZE(cmd));
	if (err)
        return -EFAULT;

    switch (_IOC_NR(cmd) % 3) {
        case 0:
            rule_ftr_type = WDUM_GENERAL;
            break;
        case 1:
            rule_ftr_type = WDUM_HTTP;
            break;
        case 2:
            rule_ftr_type = WDUM_DNS;
            break;
        default:
            break;
    }
    
    rule_ptn_len = strnlen_user((char __user *)arg, LONG_MAX);
    /* WDUM_ADD_ */
    if (_IOC_NR(cmd) < 6) {
        rule_ptn = (char *)kmalloc(sizeof(char) * rule_ptn_len, GFP_KERNEL);
        if (rule_ptn == NULL)
            return -ENOMEM;
        retval = strncpy_from_user(rule_ptn, (char __user *)arg, rule_ptn_len);
        if (_IOC_NR(cmd) < 3) {
            rule_ptn_type = WDUM_SIMPLE;
        } else {
            rule_ptn_type = WDUM_REGEX;
        }
        wdum_add_rule(rule_ptn, rule_ptn_type, rule_ftr_type);
        kfree(rule_ptn);
    }
    /* WDUM_DEL_ */
    else if (_IOC_NR(cmd) < 12) {
        rule_ptn = (char *)kmalloc(sizeof(char) * rule_ptn_len, GFP_KERNEL);
        if (rule_ptn == NULL)
            return -ENOMEM;
        retval = strncpy_from_user(rule_ptn, (char __user *)arg, rule_ptn_len);
        if (_IOC_NR(cmd) < 9) {
            rule_ptn_type = WDUM_SIMPLE;
        } else {
            rule_ptn_type = WDUM_REGEX;
        }
        wdum_delete_rule(rule_ptn, rule_ptn_type, rule_ftr_type);
        kfree(rule_ptn);
    }
    /* WDUM_UPD_RULE_OLD */
    else if (_IOC_NR(cmd) == 12) {
        device->rule_optn = (char *)kmalloc(sizeof(char) * rule_ptn_len, GFP_KERNEL);
        if (device->rule_optn == NULL)
            return -ENOMEM;
        retval = strncpy_from_user(device->rule_optn, (char __user *)arg, rule_ptn_len);
    }
    /* WDUM_UPD_RULE_NEW */
    else if (_IOC_NR(cmd) == 13) {
        rule_ptn = (char *)kmalloc(sizeof(char) * rule_ptn_len, GFP_KERNEL);
        if (rule_ptn == NULL) {
            kfree(device->rule_optn);
            return -ENOMEM;
        }
        retval = strncpy_from_user(rule_ptn, (char __user *)arg, rule_ptn_len);
        wdum_update_rule(device->rule_optn, rule_ptn);
        kfree(device->rule_optn);
        kfree(rule_ptn);
    } else {
        retval = -EINVAL;
    }

    return retval;
}

static struct file_operations wdum_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = wdum_ioctl,
};

static int wdum_user_comm_init(void) {
    int retval;
    dev_t dev = 0;
    struct device *wdumdev_device;

    if (wdumdev_major) {
        dev = MKDEV(wdumdev_major, 0);
        retval = register_chrdev_region(dev, 1, "wdumdev");
    } else {
        retval = alloc_chrdev_region(&dev, 0, 1, "wdumdev");
        wdumdev_major = MAJOR(dev);
    }
    if (retval < 0)
        goto err_chrdev;
    wdumdev_class = class_create(THIS_MODULE, "wdumdev");
    if (IS_ERR(wdumdev_class)) {
        retval = PTR_ERR(wdumdev_class);
        goto err_class_create;
    }
    wdumdev_device = device_create(wdumdev_class, NULL, dev, NULL, "wdumdev");
    if (IS_ERR(wdumdev_device)) {
        retval = PTR_ERR(wdumdev_device);
        goto err_device_create;
    }

    device = (struct wdumdev *)kmalloc(sizeof(struct wdumdev), GFP_KERNEL);
    if (device == NULL) {
        retval = -ENOMEM;
        goto err_device;
    }
    memset(device, 0, sizeof(struct wdumdev));

    cdev_init(&device->cdev, &wdum_fops);
    device->cdev.owner = THIS_MODULE;
    device->cdev.ops = &wdum_fops;
    retval = cdev_add(&device->cdev, dev, 1);
    if (retval < 0)
        goto err_cdev_add;

    return 0;

err_cdev_add:
    kfree(device);
err_device:
    device_destroy(wdumdev_class, dev);
err_device_create:
    class_destroy(wdumdev_class);
err_class_create:
    unregister_chrdev_region(dev, 1);
err_chrdev:
    return retval;
}

static void wdum_user_comm_exit(void) {
    dev_t dev = MKDEV(wdumdev_major, 0);

    cdev_del(&device->cdev);
    kfree(device);
    device_destroy(wdumdev_class, dev);
    class_destroy(wdumdev_class);
    unregister_chrdev_region(dev, 1);
}

static int __init wdum_rules_init(void) {
    int retval;

    wdum_rule_base_init();
    retval = wdum_user_comm_init();
    if (retval < 0)
        wdum_log_error("initiating user_comm");
    
    return retval;
}

static void __exit wdum_rules_exit(void) {
    wdum_user_comm_exit();
    wdum_rule_base_dest();
}

MODULE_LICENSE("Dual BSD/GPL");

module_init(wdum_rules_init);
module_exit(wdum_rules_exit);
