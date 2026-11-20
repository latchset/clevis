if build_tang_pqc
  tang_pqc_common = [
    'jose_wrapper.cpp',
    'key_deriver.cpp',
    'tang_client.cpp',
    'ecmr_ops.cpp',
    'response_validator.cpp',
  ]

  tang_pqc_deps = [jansson, jose, libcrypto, libcurl]

  # jose's public headers declare both the struct tag jose_cfg and the
  # function jose_cfg(); in C++, gcc's -Wshadow reports the function as
  # hiding the struct's constructor. Headers from a prefix-installed
  # jose are reached through -I instead of a system include directory,
  # so the warning is not suppressed there and -Werror fails the build.
  # The collision is long-standing jose API shape and cannot be fixed
  # without a jose API break, so keep -Wshadow but stop treating it as
  # an error for this pin's C++ targets only.
  tang_pqc_cpp_args = ['-Wno-error=shadow']

  executable('clevis-encrypt-tang-pqc',
    tang_pqc_common + ['encrypt_main.cpp'],
    dependencies: tang_pqc_deps,
    cpp_args: tang_pqc_cpp_args,
    install_dir: bindir,
    install: true,
    override_options: ['cpp_std=c++17'],
  )

  mans += join_paths(meson.current_source_dir(), 'clevis-encrypt-tang-pqc.1')

  executable('clevis-decrypt-tang-pqc',
    tang_pqc_common + ['decrypt_main.cpp'],
    dependencies: tang_pqc_deps,
    cpp_args: tang_pqc_cpp_args,
    install_dir: bindir,
    install: true,
    override_options: ['cpp_std=c++17'],
  )

  tang_pqc_test_deps = [jansson, jose, libcrypto]

  test_jose_wrapper = executable('test-tang-pqc-jose-wrapper',
    ['jose_wrapper.cpp', 'test_jose_wrapper.cpp'],
    dependencies: tang_pqc_test_deps,
    cpp_args: tang_pqc_cpp_args,
    override_options: ['cpp_std=c++17'],
    install: false,
  )

  test_key_deriver = executable('test-tang-pqc-key-deriver',
    ['jose_wrapper.cpp', 'key_deriver.cpp', 'test_key_deriver.cpp'],
    dependencies: tang_pqc_test_deps,
    cpp_args: tang_pqc_cpp_args,
    override_options: ['cpp_std=c++17'],
    install: false,
  )

  test_ecmr_ops = executable('test-tang-pqc-ecmr-ops',
    ['jose_wrapper.cpp', 'ecmr_ops.cpp', 'test_ecmr_ops.cpp'],
    dependencies: tang_pqc_test_deps,
    cpp_args: tang_pqc_cpp_args,
    override_options: ['cpp_std=c++17'],
    install: false,
  )

  test_response_validator = executable('test-tang-pqc-response-validator',
    ['jose_wrapper.cpp', 'response_validator.cpp', 'test_response_validator.cpp'],
    dependencies: tang_pqc_test_deps,
    cpp_args: tang_pqc_cpp_args,
    override_options: ['cpp_std=c++17'],
    install: false,
  )

  test('tang-pqc-jose-wrapper', test_jose_wrapper)
  test('tang-pqc-key-deriver', test_key_deriver)
  test('tang-pqc-ecmr-ops', test_ecmr_ops)
  test('tang-pqc-response-validator', test_response_validator)

  subdir('tests')
else
  warning('Will not install tang-pqc pin due to missing dependencies!')
endif
