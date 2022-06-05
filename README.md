# wdum
A keyword filter (umbrella) based on Netfilter.

## Install
To build the kernel modules of wdum, `cd` into `modules`, and type
```
$ make modules
```
Then, to load the modules into kernel, type as root
```
# insmod wdum_rules.ko; insmod wdum_filter.ko
```

## Usage
To interact with the kernel modules of wdum, use the CLI program built from `wdum.c`.

## Uninstall
To remove the kernel modules of wdum, type as root
```
# rmmod wdum_filter; rmmod wdum_rules
```
