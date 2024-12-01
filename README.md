[![build](https://github.com/latchset/clevis/workflows/build/badge.svg)](https://github.com/latchset/clevis/actions)

# Clevis

## Welcome to Clevis!
Clevis is a pluggable framework for automated decryption. It can be used to
provide automated decryption of data or even automated unlocking of LUKS
volumes.

### Encrypting Data

What does this look like? Well, the first step is encrypting some data. We do
this with a simple command:

```bash
$ clevis encrypt PIN CONFIG < PLAINTEXT > CIPHERTEXT.jwe
```

This command takes plaintext on standard input and produces an encrypted JWE
object on standard output. Besides the plaintext, we need to specify two
additional input parameters.

First, is the pin. In clevis terminology, a pin is a plugin which implements
automated decryption. We simply pass the name of a pin here.

Second, is the config. The config is a JSON object which will be passed
directly to the pin. It contains all the necessary configuration to perform
encryption and setup automated decryption.

To decrypt our JWE, we simply perform the following:

```bash
$ clevis decrypt < CIPHERTEXT.jwe > PLAINTEXT
```

Notice that no additional input or interaction is required for the decrypt
command. Let's look at some more concrete examples.

#### PIN: Tang

[Tang](http://github.com/latchset/tang) is a server implementation which
provides cryptographic binding services without the need for an escrow.
Clevis has full support for Tang. Here is an example of how to use Clevis with
Tang:

```bash
$ echo hi | clevis encrypt tang '{"url": "http://tang.local"}' > hi.jwe
The advertisement is signed with the following keys:
        kWwirxc5PhkFIH0yE28nc-EvjDY

Do you wish to trust the advertisement? [yN] y
```

In this example, we encrypt the message "hi" using the Tang pin. The only
parameter needed in this case is the URL of the Tang server. During the
encryption process, the Tang pin requests the key advertisement from the
server and asks you to trust the keys. This works similarly to SSH.

Alternatively, you can manually load the advertisement using the `adv`
parameter. This parameter takes either a string referencing the file where the
advertisement is stored, or the JSON contents of the advertisement itself. When
the advertisement is specified manually like this, Clevis presumes that the
advertisement is trusted.

#### PIN: TPM2

Clevis provides support to encrypt a key in a Trusted Platform Module 2.0 (TPM2)
chip. The cryptographically-strong, random key used for encryption is encrypted
using the TPM2 chip, and is decrypted using TPM2 at the time of decryption to allow clevis to decrypt the secret stored in the JWE.

For example:

```bash
$ echo hi | clevis encrypt tpm2 '{}' > hi.jwe
```

Clevis store the public and private keys of the encrypted key in the JWE object,
so those can be fetched on decryption to unseal the key encrypted using the TPM2.

#### PIN: PKCS#11

Clevis can perform the role of a PKCS#11 application, as described in the [RFC 7512: The PKCS#11 URI Scheme](https://www.rfc-editor.org/rfc/rfc7512.html).

PKCS#11 protocol determines that a PIN (Personal Identity Number) must be configured into the hardware device so that the unlocking process is successful. Clevis will allow users to unlock a particular encrypted disk, and will provide a way to get the PIN. There will be two possibilities:

1 - Provide the PIN at boot time: In this first case, Clevis will detect PKCS#11 device and will prompt for its PIN.
In case PIN is wrong, Clevis will prompt for the PIN again. It is the user's responsibility to be aware of the possible lock / brick of the device in case PIN is unknown.

2 - Provide the PIN at Clevis configuration time: In this second case, Clevis will be configured with the PIN value.

Initially, RFC7512 defines a mechanism to specify a special kind of URI (the `pkcs11` URI), that allows identifying both a device and also the information required for it to be unlocked. Special attention deserves the parameters `pin-value`, which allow specifying the value of the PIN or the location of the PIN respectively. Clevis will understand, initially, the 'pin-value' parameter. Below you can find and example of PKCS#11 URIs using previous parameter:

* PKCS#11 URI with `pin-value` defined:

```
pkcs11:token=Software%20PKCS%2311%20softtoken;manufacturer=Snake%20Oil,%20Inc.?pin-value=the-pin
```

In the next section, Clevis configuration examples are provided, so that it is clarified what are the different options for a PKCS#11 device to be bound to an encrypted disk.

##### Clevis configuration

Clevis will provide a mechanism for the user to bind a particular PKCS#11 device to an encrypted device. The name of the new pin for Clevis will be `pkcs11`, and the way to configure it will be the same that is currently used:

```
$ clevis luks bind -h
```

```
Usage: clevis luks bind [-y] [-f] [-s SLT] [-k KEY] [-t TOKEN_ID] [-e EXISTING_TOKEN_ID] -d DEV PIN CFG
```

##### Configuration to provide a PKCS#11 URI to Clevis
As first example, a user can provide the information of the device by specifying its URI to Clevis:

```
$ clevis luks bind -d /dev/sda1 pkcs11 '{"uri": "pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;
serial=0a35ba26b062b9c5;token=clevis;id=%02;object=Encryption%20Key"}'
```

##### Configuration to bind Clevis to the first PKCS#11 device found
An additional option is to provide Clevis a configuration so that the first PKCS#11 device found by Clevis is bound. To do so, an empty URI can be provided as shown below:

```
$ clevis luks bind -d /dev/sda1 pkcs11 '{"uri": "pkcs11:"}'
```

An even shorter configuration command, equivalent to the previous one, is shown below:

```
$ clevis luks bind -d /dev/sda1 pkcs11 '{}'
```

In this case, Clevis will be responsible for the detection of the device and, if no device is found, responsible for dumping the corresponding error.

It must be clarified that providing an empty URI will make Clevis to prompt also to select one of the available keys matched on the token to avoid accidentally encryption with unwanted keys.

##### Configuration to provide a module path to Clevis PKCS#11 pin:
A module path can be provided to Clevis, so that it uses that module to access a device. This is only required in case the card is not supported by underlying Clevis software (OpenSC). For this reason, the module path field is completely optional. To provide the module location the user can provide the "module-path" to the "uri" Clevis configuration:

```
$ clevis-luks-bind -d /dev/sda1 pkcs11 '{"uri": "pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;
serial=0a35ba26b062b9c5;token=clevis;id=%02;object=Encryption%20Key?
module-path=/usr/local/lib64/libmypkcs11.so"}'
```

As it happens with the rest of devices, encrypted disks that have been bound to a PKCS#11 device can be checked with `clevis luks list` command:

```
$ clevis luks list -d /dev/sda1
```

```
1: pkcs11 '{"uri": "pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;
serial=0a35ba26b062b9c5;token=clevis;id=%02;object=Encryption%20Key?
module-path=/usr/local/lib64/libmypkcs11.so"}'
```

##### Configuration to provide PKCS#11 tool a different mechanism

In the first phase of development, Clevis will be used in top of OpenSC to provide PKCS#11 functionality.
OpenSC, and, in particular, `pkcs11-tool`, provides an option to indicate the mechanism to use for decryption.
For testing purposes, some libraries, such as [SoftHSM](https://www.opendnssec.org/softhsm)), don't work with default `pkcs11-tool` mechanism,
so it is  required to provide a particular mechanism to use. For this reason, Clevis can be provided with
the mechanism to use, in case the default one, `RSA-PKCS-OAEP`, is not valid:

```
$ clevis luks bind -d /dev/sda1 pkcs11 '{"uri": "pkcs11:", "mechanism":"RSA-PKCS"}'
```

In order to check available mechanisms for a specific token, command `pkcs11-tool -M` can be used:


```
$ pkcs11-tool -M
Using slot 0 with a present token (0x0)
Supported mechanisms:
  SHA-1, digest
...
  SHA512, digest
  MD5, digest
...
  RSA-PKCS-KEY-PAIR-GEN, keySize={2048,4096}, generate_key_pair
```

At this time, only RSA mechanisms are supported by Clevis. Due to a limitation of the rest of the algorithms, no other asymmetric cryptographic algorithm can do encryption easily.  The ECC supports only signatures and key derivation, but not encryption. The encryption operation can be somehow constructed from the key derivation, but it is not a straightforward operation.

It must be highlighted that the RSA-PKCS mechanism (PKCS#1.5 padding for encryption) is [considered to be not secure](https://people.redhat.com/~hkario/marvin/) and it is mostly provided for compatibility, but it is not recommended using it in production.

##### Multi-device configuration
Clevis will allow specifying the slot where a PKCS#11 device is located through the parameters provided to the URI:

```
$ clevis luks bind -d /dev/sda1 pkcs11 '{"uri": "pkcs11:slot-id=0"}'
```

It must be clarified that providing just the slot information will make Clevis to guess one of the available keys matched on the token in the selected slot, which could cause accidentally encryption with unwanted keys. **It is not recommended to use slot as device selector, as slot id is a number that is not guaranteed to be stable across PKCS#11 module initializations**. However, there are certain libraries and modules that provide stable slot identifiers, so it can be used for these particular cases.

There are two better options to distinguish between different PKCS#11 devices:

1 - Multi-device configuration with public key object (**recommended**):

With recent versions of `OpenSC` (from OpenSC 0.26.0 release) onwards, `pkcs11-tool`, which is used by Clevis to handle most of the PKCS#11 commands, the PKCS#11 URI is dumped for both the tokens and the objects of a particular token:

```
$ pkcs11-tool -L | grep uri
  uri                : pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=42facd1f749ece7f;token=clevis
  uri                : pkcs11:model=PKCS%2315%20emulated;manufacturer=OpenPGP%20project;serial=000f06080f4f;token=OpenPGP%20card%20%28User%20PIN%29
$ pkcs11-tool -O --slot-index 1 --type pubkey | grep uri
ising slot 0 with a present token (0x0)
  uri:        pkcs11:model=PKCS%2315%20emulated;manufacturer=OpenPGP%20project;serial=000f06080f4f;token=OpenPGP%20card%20%28User%20PIN%29;id=%03;object=Authentication%20key;type=public
```

In this particular cases, when multiple PKCS#11 devices exist, select the public key of the particular device and bind it to Clevis:

```
$ clevis luks bind -d /dev/sda pkcs11 '{"uri":"pkcs11:model=PKCS%2315%20emulated;manufacturer=OpenPGP%20project;serial=000f06080f4f;token=OpenPGP%20card%20%28User%20PIN%29;id=%03;object=Authentication%20key;type=public"}'
```
**In case you are using module-path, you will have to use the one returned when providing --module option:**

```
$ pkcs11-tool --module /usr/lib64/libykcs11.so -O --type pubkey | grep uri
 /usr/local/bin/pkcs11-tool.manual --module /usr/lib64/libykcs11.so -O --type pubkey | grep uri
Using slot 0 with a present token (0x0)
  uri:        pkcs11:model=YubiKey%20YK5;manufacturer=Yubico%20%28www.yubico.com%29;serial=28083311;token=YubiKey%20PIV%20%2328083311;id=%03;object=Public%20key%20for%20Key%20Management;type=public
  uri:        pkcs11:model=YubiKey%20YK5;manufacturer=Yubico%20%28www.yubico.com%29;serial=28083311;token=YubiKey%20PIV%20%2328083311;id=%19;object=Public%20key%20for%20PIV%20Attestation;type=public
$ clevis luks bind -d /dev/sda pkcs11 '{"uri":"pkcs11:model=YubiKey%20YK5;manufacturer=Yubico%20%28www.yubico.com%29;serial=28083311;token=YubiKey%20PIV%20%2328083311;id=%03;object=Public%20key%20for%20Key%20Management;type=public;module-path=/usr/lib64/libykcs11.so"}'
```

2 - Multi-device configuration with serial + token specification:

**For versions where `pkcs11-tool` does not dump the URI for the tokens/objects**, specific identification will be "tried" by Clevis by using the device `serial` + `token label` pair.
In this type of scenarios, identification can be performed with these two parameters, although `model` should be provided also to ease Clevis informing about the device when asking for the PIN:

```
# pkcs11-tool -L | grep "token label\|serial"
  token label        : OpenPGP card (User PIN)
  serial num         : 42facd1f749ece7f
$ clevis luks bind -d /dev/sda pkcs11 '{"uri":"pkcs11:model=PKCS%2315%20emulated;serial=000f06080f4f;token=OpenPGP%20card%20%28User%20PIN%29"}'
```

Remember that special characters must be defined in percent mode, as defined in [RFC 7512: The PKCS#11 URI Scheme](https://www.rfc-editor.org/rfc/rfc7512.html).

##### Clevis PKCS#11 installation and configuration

For installation and configuration of the clevis PKCS#11 feature, next steps must be followed:

1 - Install Clevis required dependencies, including PKCS#11 dependencies:

```
$ sudo dnf install -y openssl socat clevis-pin-pkcs11
```

2 - The PKCS11 device must be accessible by “pkcs11-tool”:

```
$ pkcs11-tool -L
pkcs11-tool -L
Available slots:
Slot 0 (0x0): Yubico YubiKey OTP+CCID 00 00
  token label        : clevis
  ...
  uri                : pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=42facd1f749ece7f;token=clevis
```

3 - Configure device to bind with clevis:

```
$ sudo clevis luks bind -d /dev/sda5 pkcs11 '{"uri":"pkcs11:"}'
```

In case it is required to provide the module to use, it can be done through `module-path` URI parameter:

```
$ sudo clevis luks bind -d /dev/sda5 pkcs11 '{"uri":"pkcs11:module-path=/usr/lib64/libykcs11.so.2"}'
```

4 - Enable clevis-luks-pkcs11-askpass.socket unit:

```
$ sudo systemctl enable --now clevis-luks-pkcs11-askpass.socket
```

5 - /etc/crypttab configuration:

For PKCS#11 feature to work appropriately, `/etc/crypttab` file must be configured so that systemd uses an AF\_UNIX socket to wait for the keyphrase that will unlock the disk and not to prompt it through the console.

Clevis PKCS#11 unit file will configure a socket in path `/run/systemd/clevis-pkcs11.sock` to send and receive information about disk unlocking. For disks that will be unlocked through PKCS#11 Clevis pin, that socket file must be configured as key file. So, next change must be introduced in `/etc/crypttab` for unlocking to take place:

```
$ sudo diff -Nuar /etc/crypttab.ori /etc/crypttab
--- /etc/crypttab.ori   2024-07-04 10:46:16.295073739 +0200
+++ /etc/crypttab       2024-07-03 17:14:27.764743860 +0200
@@ -1 +1,2 @@
-luks-6e38d5e1-7f83-43cc-819a-7416bcbf9f84 UUID=6e38d5e1-7f83-43cc-819a-7416bcbf9f84 - -
+luks-6e38d5e1-7f83-43cc-819a-7416bcbf9f84 UUID=6e38d5e1-7f83-43cc-819a-7416bcbf9f84 /run/systemd/clevis-pkcs11.sock keyfile-timeout=30s
```

It is highly recommended setting a `keyfile-timeout` option to configure a fall-through mechanism in case some unlocking error occurs and passphrase is required to be entered manually through console.

6 - Reboot and test:

System should boot and ask for the PKCS#11 device PIN, and decrypt the corresponding configured encrypted disk only in case PIN is correct.

7 - In case no boot process needs to be tested, encrypt and decrypt with next command (note it is necessary to provide the PIN value for it to work appropriately) and check encryption/decryption of a string can be performed with this one-liner, and no error takes place:

```
$ echo "top secret" | clevis encrypt pkcs11 '{"uri":"pkcs11:module-path=/usr/lib64/libykcs11.so.2?pin-value=123456"}' | clevis decrypt
```

The `top secret` string should be returned

#### PIN: Shamir Secret Sharing

Clevis provides a way to mix pins together to provide sophisticated unlocking
policies. This is accomplished by using an algorithm called Shamir Secret
Sharing (SSS).

SSS is a thresholding scheme. It creates a key and divides it into a number of
pieces. Each piece is encrypted using another pin (possibly even SSS
recursively). Additionally, you define the threshold `t`. If at least `t`
pieces can be decrypted, then the encryption key can be recovered and
decryption can succeed.

Here is an example where we use the SSS pin with both the Tang and TPM2 pins:

```bash
$ echo hi | clevis encrypt sss \
'{"t": 2, "pins": {"tpm2": {"pcr_ids": "0"}, "tang": {"url": "http://tang.local"}}}' \
> hi.jwe
```

In the above example, we define two child pins and have a threshold of 2.
This means that during decryption **both** child pins must succeed in order for
SSS itself to succeed.

Here is another example where we use just the Tang pin:

```bash
$ echo hi | clevis encrypt sss \
'{"t": 1, "pins": {"tang": [{"url": "http://server1.local/key"}, {"url": "http://server2.local/key"}]}}' \
> hi.jwe
```

In this example, we define two child instances of the Tang pin - each with its
own configuration. Since we have a threshold of 1, if **either** of the Tang
pin instances succeed during decryption, SSS will succeed.

### Binding LUKS Volumes

Clevis can be used to bind a LUKS volume using a pin so that it can be
automatically unlocked.

How this works is rather simple. We generate a new, cryptographically strong
key. This key is added to LUKS as an additional passphrase. We then encrypt
this key using Clevis, and store the output JWE inside the LUKS header using
[LUKSMeta](http://github.com/latchset/luksmeta).

Here is an example where we bind `/dev/sda1` using the Tang pin:

```bash
$ sudo clevis luks bind -d /dev/sda1 tang '{"url": "http://tang.local"}'
The advertisement is signed with the following keys:
        kWwirxc5PhkFIH0yE28nc-EvjDY

Do you wish to trust the advertisement? [yN] y
Enter existing LUKS password:
```

Upon successful completion of this binding process, the disk can be unlocked
using one of the provided unlockers.

#### Network based unlocking
If you want to use network based unlocking you will need to specify `rd.neednet=1` as kernel argument or use `--hostonly-cmdline` when creating with dracut.

If you're using **Tang** with TLS (Example: `'{"url": "https://tang.remote"}'`), the folder `/etc/ssl` should be included in the initramfs image, `--include /etc/ssl /etc/ssl --force` when creating with dracut.

#### Unlocker: Dracut

The Dracut unlocker attempts to automatically unlock volumes during early
boot. This permits automated root volume encryption. Enabling the Dracut
unlocker is easy. Just rebuild your initramfs after installing Clevis:

```bash
$ sudo dracut -f
```

Upon reboot, you will be prompted to unlock the volume using a password. In
the background, Clevis will attempt to unlock the volume automatically. If it
succeeds, the password prompt will be cancelled and boot will continue.

#### Unlocker: Initramfs-tools

When using Clevis with initramfs-tools, in order to rebuild your
initramfs you will need to run:

```bash
sudo update-initramfs -u -k 'all'
```

Upon reboot, it will behave exactly as if using Dracut.

#### Unlocker: UDisks2

Our UDisks2 unlocker runs in your desktop session. You should not need to
manually enable it; just install the Clevis UDisks2 unlocker and restart your
desktop session. The unlocker should be started automatically.

This unlocker works almost exactly the same as the Dracut unlocker. If you
insert a removable storage device that has been bound with Clevis, we will
attempt to unlock it automatically in parallel with a desktop password prompt.
If automatic unlocking succeeds, the password prompt will be dismissed without
user intervention.

#### Unlocker: Clevis command

A LUKS device bound to a Clevis policy can also be unlocked by using the clevis
luks unlock command.

```bash
$ sudo clevis luks unlock -d /dev/sda1
```

#### Unbinding LUKS volumes

LUKS volumes can be unbound using the clevis luks unbind command. For example:

```bash
$ sudo clevis luks unbind -d /dev/sda1 -s 1
```

#### Listing pins bound to LUKS volumes

The pins that are bound to a given LUKS volume can be listed using the clevis
luks list command. For example:

```bash
$ sudo clevis luks list -d /dev/sda1
```

## Installing Clevis

Please don't install Clevis directly. Instead, use your preferred
distribution's packages.

### Fedora 24+

This command installs the core Clevis commands, the Dracut unlocker and the
UDisks2 unlocker, respectively.

```bash
$ sudo dnf install clevis clevis-dracut clevis-udisks2
```

## Manual compilation

As remarked in the previous section, **it is suggested not to install Clevis directly**.
However, in case no Clevis packages exist for your Linux distribution, the steps to
manually compile and install Clevis are next ones:

* Download latest version of the binaries (note that the latest version could change):
```bash
$ wget https://github.com/latchset/clevis/releases/download/v21/clevis-21.tar.xz
```

* Untar the binaries file:
```bash
$ tar Jxvf clevis-21.tar.xz
```

* Create build directory and change path to it:
```bash
$ cd clevis-21
$ mkdir build
$ cd build
```

* Execute `meson` to setup compilation:
```bash
$ meson setup ..
```

* Compile with `ninja` command:
```bash
$ ninja
```

* Install with `ninja install` command (you will need root permissions for it):
```bash
$ sudo ninja install
```
