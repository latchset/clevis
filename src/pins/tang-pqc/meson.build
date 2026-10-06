libcrypto = dependency('libcrypto', required: get_option('tang-pqc'))
libcurl = dependency('libcurl', required: get_option('tang-pqc'))

if jansson.found() and libcrypto.found() and libcurl.found() and jose.found()
  cc = meson.get_compiler('c')
  has_kem_api = cc.links('''
#include <jose/jose.h>
int main(void) {
    json_auto_t *j = json_pack("{s:s}", "alg", "ML-KEM-768");
    if (!jose_jwk_gen(NULL, j))
        return 1;
    json_auto_t *enc = jose_jwk_kem_enc(NULL, j);
    return enc ? 0 : 1;
}
''', dependencies: [jose, jansson], name: 'ML-KEM KEM API support in jose')

  if not has_kem_api
    warning('Will not install tang-pqc pin: jose lacks ML-KEM KEM API support!')
  else
    tang_pqc_common = [
      'jose_wrapper.cpp',
      'key_deriver.cpp',
      'tang_client.cpp',
      'ecmr_ops.cpp',
    ]

    tang_pqc_deps = [jansson, jose, libcrypto, libcurl]

    executable('clevis-encrypt-tang-pqc',
      tang_pqc_common + ['encrypt_main.cpp'],
      dependencies: tang_pqc_deps,
      install_dir: bindir,
      install: true,
      override_options: ['cpp_std=c++17'],
    )

    executable('clevis-decrypt-tang-pqc',
      tang_pqc_common + ['decrypt_main.cpp'],
      dependencies: tang_pqc_deps,
      install_dir: bindir,
      install: true,
      override_options: ['cpp_std=c++17'],
    )

    tang_pqc_test_deps = [jansson, jose, libcrypto]

    test_jose_wrapper = executable('test-tang-pqc-jose-wrapper',
      ['jose_wrapper.cpp', 'test_jose_wrapper.cpp'],
      dependencies: tang_pqc_test_deps,
      override_options: ['cpp_std=c++17'],
      install: false,
    )

    test_key_deriver = executable('test-tang-pqc-key-deriver',
      ['jose_wrapper.cpp', 'key_deriver.cpp', 'test_key_deriver.cpp'],
      dependencies: tang_pqc_test_deps,
      override_options: ['cpp_std=c++17'],
      install: false,
    )

    test_ecmr_ops = executable('test-tang-pqc-ecmr-ops',
      ['jose_wrapper.cpp', 'ecmr_ops.cpp', 'test_ecmr_ops.cpp'],
      dependencies: tang_pqc_test_deps,
      override_options: ['cpp_std=c++17'],
      install: false,
    )

    test('tang-pqc-jose-wrapper', test_jose_wrapper)
    test('tang-pqc-key-deriver', test_key_deriver)
    test('tang-pqc-ecmr-ops', test_ecmr_ops)

    subdir('tests')
  endif
else
  warning('Will not install tang-pqc pin due to missing dependencies!')
endif
