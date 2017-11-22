% CLEVIS-LUKS-UNLOCK(1)
% Nathaniel McCallum <npmccallum@redhat.com>
% September 2017

# NAME

clevis-luks-unlock -- Unlocks a LUKSv1 device bound with a Clevis policy

# SYNOPSIS

`clevis luks unlock` -d DEV [-n NAME]

# OVERVIEW

The `clevis luks unlock` command unlocks a LUKSv1 device using its already
provisioned Clevis policy. For example:

    $ clevis luks unlock -d /dev/sda

# OPTIONS

* `-d` _DEV_ :
  The LUKS device to unlock

* `-n` _NAME_ :
  The name to give the unlocked device node

# SEE ALSO

`clevis-luks-bind`(1)
