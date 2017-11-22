% CLEVIS-LUKS-UNBIND(1)
% Javier Martinez Canillas <javierm@redhat.com>
% February 2018

# NAME

clevis-luks-unbind -- Unbinds a pin bound to a LUKSv1 volume

# SYNOPSIS

`clevis luks unbind` -d DEV -s SLT

# OVERVIEW

The `clevis luks unbind` command unbinds a pin bound to a LUKSv1 volume.
For example:

    $ clevis luks unbind -d /dev/sda -s 1

# OPTIONS

* `-d` _DEV_ :
  The bound LUKS device

* `-s` _SLT_ :
  The LUKSMeta slot number for the pin to unbind

* `-f` :
  Do not ask for confirmation and wipe slot in batch-mode

# SEE ALSO

`clevis-luks-bind`(1)
