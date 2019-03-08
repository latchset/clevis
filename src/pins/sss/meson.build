libcrypto = dependency('libcrypto', required: false)

if jansson.found() and libcrypto.found()
  executable('clevis-decrypt-sss', ['clevis-decrypt-sss.c', 'sss.c', 'sss.h'],
    dependencies: [jansson, libcrypto, jose],
    install_dir: bindir,
    install: true,
  )

  executable('clevis-encrypt-sss', ['clevis-encrypt-sss.c', 'sss.c', 'sss.h'],
    dependencies: [jansson, libcrypto, jose],
    install_dir: bindir,
    install: true,
  )

  src = meson.current_source_dir()

  mans += join_paths(src, 'clevis-encrypt-sss.1')

  env = environment()
  env.append('PATH',
    join_paths(meson.source_root(), 'src'),
    meson.current_build_dir(),
    '/usr/libexec',
    libexecdir,
    src,
    separator: ':'
  )

  test('pin-sss', find_program(join_paths(src, 'pin-sss')), env: env)
  test('pin-test', find_program(join_paths(src, 'pin-test')), env: env)
else
  warning('Will not install sss pin due to missing dependencies!')
endif
