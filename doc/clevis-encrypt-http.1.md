% CLEVIS-ENCRYPT-HTTP(1)
% Nathaniel McCallum <npmccallum@redhat.com>
% September 2017

# NAME

clevis-encrypt-http -- Encrypts using a REST HTTP escrow server policy

# SYNOPSIS

`clevis encrypt http` CONFIG < PT > JWE

# OVERVIEW

The `clevis encrypt http` command encrypts using a REST HTTP escrow server
policy. Its only argument is the JSON configuration object.

When using the HTTP pin, we create a new, cryptographically-strong, random key.
This key is stored in a remote HTTP escrow server (using a simple PUT or POST).
Then at decryption time, we attempt to fetch the key back again in order to
decrypt our data. So, for our configuration we need to pass the URL to the key
location:

    $ clevis encrypt http '{"url":"https://escrow.srv/1234"}' < PT > JWE

To decrypt the data, simply provide the ciphertext (JWE):

    $ clevis decrypt < JWE > PT

Notice that we did not pass any configuration during decryption. The decrypt
command extracted the URL (and possibly other configuration) from the JWE
object, fetched the encryption key from the escrow and performed decryption.

# CONFIG

This command uses the following configuration properties:

* `url`  (string) :
  The URL where the key is stored (REQUIRED)

* `http` (boolean) :
  Allow or disallow non-TLS HTTP (default: false)

* `type` (string) :
  The type of key to store (default: octet-stream)

* `method` (string) :
  The HTTP method to use (default: PUT)

# SEE ALSO

`clevis-decrypt`(1)
