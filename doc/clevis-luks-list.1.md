% CLEVIS-LUKS-LIST(1)
% Javier Martinez Canillas <javierm@redhat.com>
% November 2017

# NAME

clevis-luks-list -- Lists pins bound to a LUKSv1 device

# SYNOPSIS

`clevis luks list` -d DEV [-s SLT]

# OVERVIEW

The `clevis luks list` command lists the pins bound to a LUKSv1 device.
For example:

    $ clevis luks list -d /dev/sda

# OPTIONS

* `-d` _DEV_ :
  The LUKS device to list bound pins

* `-s` _SLT_ :
  The LUKSMeta slot number to list the pin from

# SEE ALSO

`clevis-luks-bind`(1)
