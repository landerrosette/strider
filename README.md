# Strider

Strider is a Linux kernel module and Xtables extension for fast multi-pattern string matching on network packets. It provides a more scalable and dynamic alternative to the string match extension, capable of handling thousands of runtime-updatable patterns with minimal performance impact using the [Aho-Corasick algorithm](https://cr.yp.to/bib/1975/aho.pdf).

## Installation

Strider uses a combination of Autotools and Kbuild for its build system.

### Dependencies

Ensure your system has the necessary kernel headers and build tools for building kernel modules. Additionally, you will need the following development packages:

- GNU Autotools (Autoconf, Automake, and Libtool)
- Generic Netlink library (libnl-genl)
- Xtables development files

On Debian/Ubuntu, these can be installed using

```shell
sudo apt install build-essential pkg-config linux-headers-$(uname -r) autoconf automake libtool libnl-3-dev libnl-genl-3-dev libxtables-dev
```

### Build and Install

Use the following commands to build and install Strider, including kernel modules `strider` and `xt_strider`, an utility program `striderctl`, and a shared library `libxt_strider.so`.

```shell
autoreconf -i
./configure
mkdir build && cd build
make
sudo make install
```

Now update the kernel's module dependency map:

```shell
sudo depmod -a
```

## Usage
