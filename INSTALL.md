This file contains instructions to build and install Clevis from source

# Dependencies
To build and install the Clevis software the following software packages
are required. In many cases dependencies are platform specific and so the
following sections describe them for the supported platforms.

## Linux
Autoconf, Autoconf archive, Automake, Libtool, C compiler, 
C Library Development Libraries and Header Files

* [José](https://github.com/latchset/jose) (JSON Web Signing and Encryption)
* [LUKSMeta](https://github.com/latchset/luksmeta) (Adds metadata to LUKS volume)
* [linux-audit](https://github.com/linux-audit/audit-userspace) (Userspace lib of Linux Auditing Framework)
* [udisks2](https://github.com/storaged-project/udisks) (Storage management deamon, tools and libs)
* [desktop-file-utils](https://cgit.freedesktop.org/xdg/desktop-file-utils) (Linux .desktop files / autostart)
* [pkg-config](https://cgit.freedesktop.org/pkg-config) (Dependency discovery with Autotools)
* [systemd](https://github.com/systemd) (Control clevis akspass service)

PIN specific dependencies
* [tang](https://github.com/latchset/tang) (required for pin **Tang**)
* [curl](https://github.com/curl/curl) (required for pin **Tang** and pin **HTTP**)
* [tpm2-tools](https://github.com/tpm2-software/tpm2-tools) (required for pin **TPM2**)
* [OpenSSL](https://github.com/openssl/openssl) (required for pin **Shamir Secret Sharing**)

To automatically decrypt rootfs, initramfs needs to be updated.
* [dracut](https://github.com/dracutdevs/dracut) (default on Fedora)
* initramfs-tools not yet supported (PR https://github.com/latchset/clevis/pull/35)

Without updating initramfs, you need to trigger decryption manually.

### Fedora

There is a package already, so the package build dependencies information can be
used to make sure that the needed packages to compile from source are installed:

```
$ sudo dnf builddep clevis
```

### Debian

Dependencies can be checked on Debian bases distributions, too.
```
apt build-dep clevis
```
Caution: Think twice about replacing initramfs-tools!

# Building From Source

## Bootstrapping the Build
To configure the Clevis source code first run autoreconf to generate
the configure script and Makefile.in configuration files:

```
$ autoreconf -si
```

## Configuring the Build
Then run the configure script, which generates the Makefiles:

```
$ ./configure
```

## Compiling
Then compile the code using make:

```
$ make -j$(nproc)
```

## Installing
Once you've built the Clevis software it can be installed with:

```
$ sudo make install
```

This will install Clevis to a location determined at configure time.

See the output of ./configure --help for the available options. Typically
much won't be needed besides providing an alternative --prefix option at
configure time, and maybe DESTDIR at install time if you're packaging for
a distro.

## Updating initramfs
After clevis is installed, the dracut and systemd hooks can be added to the
initramfs with:

```
$ sudo dracut -f
```
