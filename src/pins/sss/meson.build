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
  env.prepend('PATH',
    join_paths(meson.source_root(), 'src'),
    join_paths(meson.source_root(), 'src', 'pins', 'tang'),
    meson.current_build_dir(),
    '/usr/libexec',
    libexecdir,
    src,
    separator: ':'
  )

  bins += join_paths(meson.current_source_dir(), 'clevis-encrypt-null')
  bins += join_paths(meson.current_source_dir(), 'clevis-decrypt-null')

  test('pin-sss', find_program(join_paths(src, 'pin-sss')), env: env)
  test('pin-null', find_program(join_paths(src, 'pin-null')), env: env)
else
  warning('Will not install sss pin due to missing dependencies!')
endif
