pcscd = find_program('pcscd', required: false)
pkcs11tool = find_program('pkcs11-tool', required: false)
pcscd_disable_polkit = false
git = find_program('git', required: false)

if git.found()
  git_version_cmd = run_command('git', 'rev-parse', '--short', 'HEAD', check: false)
  git_version = 'release-v' + meson.project_version() + '-' + git_version_cmd.stdout().strip()
else
  git_version = 'release-v' + meson.project_version() + '-' + 'UNKNOWN_GIT_VERSION'
endif
GIT_VERSION_FLAG = '-DGIT_VERSION="' + git_version + '"'

if pcscd.found()
  pcscd_options = run_command('pcscd', '--help', check: false)
  pcscd_disable_polkit = pcscd_options.stdout().strip().contains('disable-polkit')
  if not pcscd_disable_polkit
    warning('pcscd does not have --disable-polkit option')
  endif
endif

if pcscd.found() and pkcs11tool.found()
  bins += join_paths(meson.current_source_dir(), 'clevis-decrypt-pkcs11')
  bins += join_paths(meson.current_source_dir(), 'clevis-encrypt-pkcs11')
  bins += join_paths(meson.current_source_dir(), 'clevis-pkcs11-common')
  mans += join_paths(meson.current_source_dir(), 'clevis-encrypt-pkcs11.1')
  ### TODO: Include man pages
  # mans += join_paths(meson.current_source_dir(), 'clevis-decrypt-pkcs11.1')
  if not meson.is_cross_build()
    subdir('tests')
  endif

  threads_dep = dependency('threads', required: true)
  executable('clevis-pkcs11-afunix-socket-unlock', ['clevis-pkcs11-afunix-socket-unlock.c'],
    dependencies: threads_dep,
    install_dir: bindir,
    install: true,
    c_args: GIT_VERSION_FLAG
  )
else
  warning('Will not install pkcs11 pin due to missing dependencies!')
  if not pcscd.found()
    warning('pcscd not found')
  endif
  if not pkcs11tool.found()
    warning('pkcs11-tool not found')
  endif
endif
