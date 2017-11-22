% CLEVIS-DECRYPT(1)
% Nathaniel McCallum <npmccallum@redhat.com>
% September 2017

# NAME

clevis-decrypt -- Decrypts using the policy defined at encryption time

# SYNOPSIS

`clevis decrypt` CONFIG < JWE > PT

# OVERVIEW

The `clevis decrypt` command decrypts data using the policy defined at
encryption time. The specific decryption pin is inferred during decryption.
There are no parameters.

# SEE ALSO

`clevis-decrypt`(1)
