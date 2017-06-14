clevis-bind-luks(1) -- Bind a LUKSv1 device using the specified policy
======================================================================

## SYNOPSIS

`clevis bind luks` [-f] -d DEV [-s SLT] [-k KEY] PIN CFG

## OVERVIEW

The `clevis bind luks` command binds a LUKSv1 device using the specified
policy. This is accomplished with a simple command:

    $ clevis bind luks -d /dev/sda tang '{"url":...}'

This command performs four steps:

1. Creates a new key with the same entropy as the LUKS master key.
2. Encrypts the new key with Clevis.
3. Stores the Clevis JWE in the LUKS header with LUKSMeta.
4. Enables the new key for use with LUKS.

This disk can now be unlocked with your existing password as well as with
the Clevis policy. Clevis provides two unlockers for LUKS volumes. First,
we provide integration with Dracut to automatically unlock your root volume
during early boot. Second, we provide integration with UDisks2 to
automatically unlock your removable media in your desktop session.

## OPTIONS

* `-f` :
  Do not prompt for LUKSMeta initialization

* `-d` _DEV_ :
  The LUKS device on which to perform binding

* `-s` _SLT_ :
  The LUKSMeta slot to use for metadata storage

* `-k` _KEY_ :
  Non-interactively read LUKS password from KEY file

* `-k` - :
  Non-interactively read LUKS password from standard input

## CAVEATS

This command does not change the LUKS master key. This implies that if you
create a LUKS-encrypted image for use in a Virtual Machine or Cloud
environment, all the instances that run this image will share a master key.
This is extremely dangerous and should be avoided at all cost.

This is not a limitation of Clevis but a design principle of LUKS. If you wish
to have encrypted root volumes in the cloud, you will need to make sure that
you perform the OS install method for each instance in the cloud as well.
The images cannot be shared without also sharing a master key.

## AUTHOR

Nathaniel McCallum &lt;npmccallum@redhat.com&gt;

## SEE ALSO

`clevis-encrypt-http`(1),
`clevis-encrypt-tang`(1),
`clevis-encrypt-sss`(1),
`clevis-decrypt`(1)
