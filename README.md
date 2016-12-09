# Clevis

## Welcome to Clevis!
Clevis is a plugable framework for automated decryption. It can be used to
provide automated decryption of data or even automated unlocking of LUKS
volumes.

### Encrypting Data

What does this look like? Well, the first step is encrypting some data. We do
this with a simple command:

    $ clevis encrypt PIN CONFIG < PLAINTEXT > CIPHERTEXT.jwe

This command takes plaintext on standard input and produces an encrypted JWE
object on standard output. Besides the plaintext, we need to specify two
additional input parameters.

First, is the pin. In clevis terminology, a pin is a plugin which implements
automated decryption. We simply pass the name of a pin here.

Second, is the config. The config is a JSON object which will be passed
directly to the pin. It contains all the necessary configuration to perform
encryption and setup automated decryption.

To decrypt our JWE, we simply perform the following:

    $ clevis decrypt < CIPHERTEXT.jwe > PLAINTEXT

Notice that no additional input or interaction is required for the decrypt
command.

Let's look at some more concrete examples.

#### PIN: Tang

[Tang](http://github.com/latchset/tang) is a server implementation which
provides cryptographic binding services without the need for an escrow.
Clevis has full support for Tang. Here is an example of how to use Clevis with
Tang:

    $ echo hi | clevis encrypt tang '{"url": "http://tang.local"}' > hi.jwe
    The advertisement is signed with the following keys:
            kWwirxc5PhkFIH0yE28nc-EvjDY

    Do you wish to trust the advertisement? [yN] y

In this example, we encrypt the message "hi" using the Tang pin. The only
parameter needed in this case is the URL of the Tang server. During the
encryption process, the Tang pin requests the key advertisement from the
server and asks you to trust the keys. This works similarly to SSH.

Alternatively, you can manually load the advertisment using the `adv`
parameter. This parameter takes either a string referencing the file where the
advertisement is stored, or the JSON contents of the advertisment itself. When
the advertisment is specified manually like this, Clevis presumes that the
advertisement is trusted.

#### PIN: HTTP

Clevis also ships a pin for performing escrow using HTTP. Please note that,
at this time, this pin does not provide HTTPS support and is suitable only
for use over local sockets. This provides integration with services like
[Custodia](http://github.com/latchset/custodia).

For example:

    $ echo hi | clevis encrypt http '{"url": "http://server.local/key"}' > hi.jwe

The HTTP pin generate a new (cryptographically-strong random) key and performs
encryption using it. It then performs a PUT request to the URL specified. It is
understood that the server will securely store this key for later retrieval.
During decryption, the pin will perform a GET request to retrieve the key and
perform decryption.

Patches to provide support for HTTPS and authentication are welcome.

#### PIN: Shamir Secret Sharing

Clevis provides a way to mix pins together to provide sophisticated unlocking
policies. This is accomplished by using an algorithm called Shamir Secret
Sharing (SSS).

SSS is a thresholding scheme. It creates a key and divides it into a number of
pieces. Each piece is encrypted using another pin (possibly even SSS
recursively). Additionally, you define the threshold `t`. If at least `t`
pieces can be decrypted, then the encryption key can be recovered and
decryption can succeed.

Here is an example where we use the SSS pin with both the Tang and HTTP pins:

    $ echo hi | clevis encrypt sss '{"t": 2, "pins": {"http": {"url": ...}, "tang": {"url": ...}}}' > hi.jwe

In the above example, we define two child pins and have a threshold of 2.
This means that during decryption **both** child pins must succeed in order for
SSS itself to succeed.

Here is another example where we use just the HTTP pin:

    $ echo hi | clevis encrypt sss '{"t": 1, "pins": {"http": [{"url": ...}, {"url": ...}]}}' > hi.jwe

In this example, we define two child instances of the HTTP pin - each with its
own configuration. Since we have a threshold of 1, if either of the HTTP pin
instances succeed during decryption, SSS will succeed.

### Binding LUKS Volumes

Clevis can be used to bind a LUKS volume using a pin so that it can be
automatically unlocked.

How this works is rather simple. We generate a new, cryptographically strong
key. This key is added to LUKS as an additional passphrase. We then encrypt
this key using Clevis, and store the output JWE inside the LUKS header using
[LUKSMeta](http://github.com/latchset/luksmeta).

Here is an example where we bind `/dev/sda1` using the Tang ping:

    $ sudo clevis bind-luks /dev/sda1 tang '{"url": "http://tang.local"}'
    The advertisement is signed with the following keys:
            kWwirxc5PhkFIH0yE28nc-EvjDY

    Do you wish to trust the advertisement? [yN] y
    Enter existing LUKS password:

Upon successful completion of this binding process, the disk can be unlocked
using one of the provided unlockers.

#### Unlocker: Dracut

The Dracut unlocker attempts to automatically unlock volumes during early
boot. This permits automated root volume encryption. Enabling the Dracut
unlocker is easy. Just rebuild your initramfs after installing Clevis:

    $ sudo dracut -f

Upon reboot, you will be prompted to unlock the volume using a password. In
the background, Clevis will attempt to unlock the volume automatically. If it
succeeds, the password prompt will be cancelled and boot will continue.

#### Unlocker: UDisks2

Our UDisks2 unlocker runs in your desktop session. You should not need to
manually enable it; just install the Clevis UDisks2 unlocker and restart your
desktop session. The unlocker should be started automatically.

This unlocker works almost exactly the same as the Dracut unlocker. If you
insert a removable storage device that has been bound with Clevis, we will
attempt to unlock it automatically in parallel with a desktop password prompt.
If automatic unlocking succeeds, the password prompt will be dissmissed without
user intervention.

## Installing Clevis

Please don't install Clevis directly. Use your preferred distribution's packages.

### Fedora 24+

    $ sudo dnf install clevis clevis-dracut clevis-udisks2
