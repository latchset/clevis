.PHONY: all core luks encrypt decrypt

all: core luks encrypt decrypt
core: clevis.1
luks: clevis-luks-unlockers.7 clevis-luks-unlock.1 clevis-luks-bind.1
encrypt: clevis-encrypt-http.1 clevis-encrypt-tang.1 clevis-encrypt-sss.1
decrypt: clevis-decrypt.1

%: %.md
	pandoc -s -t man $< -o $@
