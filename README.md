# Strider

Strider accelerates multi-pattern string matching in Linux Netfilter using
the [Aho-Corasick algorithm](https://cr.yp.to/bib/1975/aho.pdf). It provides a scalable, dynamic alternative to the
string match extension `xt_string`, capable of handling thousands of runtime-updatable patterns with minimal overhead.

## Installation

### Dependencies

- Kernel headers and build tools
- GNU Autotools (Autoconf, Automake, Libtool)
- Generic Netlink library (libnl-genl)
- Xtables development files

On a Debian-based system, these can be installed with:

```shell
sudo apt update
sudo apt install build-essential pkg-config \
    linux-headers-$(uname -r) \
    autoconf automake libtool \
    libnl-3-dev libnl-genl-3-dev \
    libxtables-dev
```

### Build and Install

1. Generate the `configure` script:
    ```shell
    autoreconf -i
    ```
2. Create a `build` directory:
    ```shell
    mkdir build
    cd build
    ```
3. Configure, build, and install:
    ```shell
    ../configure
    make
    sudo make install
    ```
4. Update the kernel's module dependency list:
    ```shell
    sudo depmod -a
    ```

## Example Usage

1. **Create a pattern set**

   Patterns live in named sets. Let's create one called "blocklist":

    ```shell
    sudo striderctl create blocklist
    ```

2. **Add patterns to the set**

   Patterns can be added as simple strings or as hex-encoded bytes:

    ```shell
    # Add a simple string pattern
    sudo striderctl add blocklist "evil-pattern"

    # Add a pattern with mixed hex and ASCII: "GET /malicious"
    sudo striderctl add blocklist --hex "GET /|6d616c6963696f7573|"
    ```

3. **Use the set in an iptables rule**

   Use `-m strider` to block any TCP packets on port 80 containing patterns from "blocklist":

    ```shell
    sudo iptables -A INPUT -p tcp --dport 80 -m strider --match-set blocklist -j DROP
    ```

   Any new patterns added to "blocklist" will be enforced by this rule immediately, without needing to reload the
   firewall.

4. **Cleanup**

   To remove the rule and the pattern set:

    ```shell
    # Remove the iptables rule
    sudo iptables -D INPUT -p tcp --dport 80 -m strider --match-set blocklist -j DROP

    # Destroy the set
    sudo striderctl destroy blocklist
    ```
