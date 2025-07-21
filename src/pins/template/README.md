
# Writing your own pin

The files here should give you an introduction into writing your own pin.

## Overall workflow

The `encrypt` script reads a plain text from stdin, encrypts it using
`jose jwe enc` which writes the result to stdout, together with some
information how to re-create the plain text later. The encryption key
itself *must* *not* be included here.

The encryption key is provided or created by the pin and stashed away
in some way. That is the core logic of a pin.

A configuration in the JSON format is provided as the first parameter,
it controls the pin's operation.

The `decrypt` script reads the encrypted information from stdin,
decrypts it using `ose jwe dec` which again writes the result to
stdout. The information provided by `encrypt` above is available, this
must be sufficient to restore the encryption key.

## How to use this template

Copy all the files here (except for this one) into a new subdirectory
of `src/pins/`, named as your pin.

Replace @pin@ with the name of your pin everywhere, including file names.

The `clevis-{en,de}crypt-@pin@` scripts require the most attention.

Have a man page in `clevis-encrypt-@pin@.1.adoc`.

Adjust `meson.build`.

Provide a test in `pin-@pin@`.

Adjust dracut configuration in `dracut.module-setup.sh.in`.

Adjust initramfs configuration in `initramfs.in`.

Optionally add something to `clevis-luks-list`.

Finally, add your pin in `../meson.build`.

## Comments

An extra form of comments is used to explain concepts. They all should
be removed before sending out patches/merge requests.

    #%# some generic information
    #!# things worth to know, gotchas
    #?# some bits that require more understanding

## Nameing your pin and configuration variables

The pin name should be short and reflect the purpose. To avoid trouble
or extra work, the name should start with a letter, followed by letters,
digits, or underscore.

Parameter names for the pin configuration should follow the same
syntax. These templates assume they can be used as a shell variable.

## Templates variables

The templates use `@...@` to mark places that can semi-automatically
be adjusted to your needs. Variables are

* `@pin@`: The name of this pin, see above
* `@PIN@`: The name of this pin, uppercase
* `@year@`: Current year
* `@name@`: Your name
* `@email@`: Your e-mail address
* `@mand1@`: The name of a mandatory parameter
* `@mand2@`: The name of another mandatory parameter
* `@opt1@`: The name of an optional parameter
* `@param1@`: The name of a parameter needed for decryption
* `@param2@`: Another name

If you have more parameters, extend accordingly

Any `@@` requires attention in wording.

Make sure you've replaced *all* occurances of template variables.
Else the build will probably fail.
