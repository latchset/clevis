SUBDIRS=dracut systemd udisks2 .

AM_CFLAGS = \
    @CLEVIS_CFLAGS@ \
    @jansson_CFLAGS@ \
    @libcrypto_CFLAGS@ \
    @jose_CFLAGS@

dist_check_SCRIPTS = \
    clevis-encrypt-test \
    clevis-decrypt-test

bin_PROGRAMS = \
    clevis-encrypt-sss \
    clevis-decrypt-sss

dist_bin_SCRIPTS = \
    clevis-encrypt-http \
    clevis-encrypt-tang \
    clevis-decrypt-http \
    clevis-decrypt-tang \
    clevis-bind-luks \
    clevis-luks-unlock \
    clevis-luks-bind \
    clevis-decrypt \
    clevis

if HAVE_TPM2_TOOLS
    dist_bin_SCRIPTS += \
    clevis-encrypt-tpm2 \
    clevis-decrypt-tpm2
endif

clevis_encrypt_sss_SOURCES = clevis-encrypt-sss.c sss.c sss.h
clevis_decrypt_sss_SOURCES = clevis-decrypt-sss.c sss.c sss.h
clevis_encrypt_sss_LDADD = @jose_LIBS@ @libcrypto_LIBS@
clevis_decrypt_sss_LDADD = @jose_LIBS@ @libcrypto_LIBS@
