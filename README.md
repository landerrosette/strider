# wdum
A keyword filter (umbrella) based on Netfilter.

## Install
To build the kernel modules of wdum, `cd` into `modules`, and type
```
$ make modules
```
Then, to load the modules into kernel, as root type
```
# insmod wdum_rules.ko; insmod wdum_filter.ko
```

## Usage
To interact with the kernel modules of wdum, use the CLI program built from `wdum.c`.

## Uninstall
To remove the kernel modules of wdum, as root type
```
# rmmod wdum_filter; rmmod wdum_rules
```
