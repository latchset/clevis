This file contains instructions to build and install Clevis from source

# Dependencies
To build and install the Clevis software the following software packages
are required. In many cases dependencies are platform specific and so the
following sections describe them for the supported platforms.

## Linux:
* Autoconf
* Autoconf archive
* Automake
* Libtool
* C compiler
* C Library Development Libraries and Header Files
* [jose](https://github.com/latchset/jose)
* [luksmeta](https://github.com/latchset/luksmeta)
* [audit-libs](https://github.com/linux-audit/audit-userspace)
* [udisks2](https://github.com/storaged-project/udisks)
* [OpenSSL](https://github.com/openssl/openssl)
* [desktop-file-utils](https://cgit.freedesktop.org/xdg/desktop-file-utils)
* [pkg-config](https://cgit.freedesktop.org/pkg-config)
* [systemd](https://github.com/systemd)
* [dracut](https://github.com/dracutdevs/dracut)
* [tang](https://github.com/latchset/tang)
* [curl](https://github.com/curl/curl)
* [tpm2-tools](https://github.com/tpm2-software/tpm2-tools)

### Fedora

There is a package already, so the package build dependencies information can be
used to make sure that the needed packages to compile from source are installed:

```
$ sudo dnf builddep clevis
```

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

After is installed, the dracut and systemd hooks can be added to the
initramfs with:

```
$ sudo dracut -f
```
