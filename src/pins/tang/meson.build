actv = find_program(
  'systemd-socket-activate',
  'systemd-activate',
  join_paths('/', 'usr', 'lib', 'systemd', 'systemd-activate'),
  required: false
)
kgen = find_program(
  join_paths(libexecdir, 'tangd-keygen'),
  join_paths(get_option('prefix'), get_option('libdir'), 'tangd-keygen'),
  join_paths(get_option('prefix'), get_option('libexecdir'), 'tangd-keygen'),
  join_paths('/', 'usr', get_option('libdir'), 'tangd-keygen'),
  join_paths('/', 'usr', get_option('libexecdir'), 'tangd-keygen'),
  required: false
)
updt = find_program(
  join_paths(libexecdir, 'tangd-update'),
  join_paths(get_option('prefix'), get_option('libdir'), 'tangd-update'),
  join_paths(get_option('prefix'), get_option('libexecdir'), 'tangd-update'),
  join_paths('/', 'usr', get_option('libdir'), 'tangd-update'),
  join_paths('/', 'usr', get_option('libexecdir'), 'tangd-update'),
  required: false
)
tang = find_program(
  join_paths(libexecdir, 'tangd'),
  join_paths(get_option('prefix'), get_option('libdir'), 'tangd'),
  join_paths(get_option('prefix'), get_option('libexecdir'), 'tangd'),
  join_paths('/', 'usr', get_option('libdir'), 'tangd'),
  join_paths('/', 'usr', get_option('libexecdir'), 'tangd'),
  required: false
)
curl = find_program('curl', required: false)

if curl.found()
  bins += join_paths(meson.current_source_dir(), 'clevis-decrypt-tang')
  bins += join_paths(meson.current_source_dir(), 'clevis-encrypt-tang')
  mans += join_paths(meson.current_source_dir(), 'clevis-encrypt-tang.1')

  if actv.found() and kgen.found() and updt.found() and tang.found()
    env = environment()
    env.set('SD_ACTIVATE', actv.path())
    env.set('TANGD_KEYGEN', kgen.path())
    env.set('TANGD_UPDATE', updt.path())
    env.set('TANGD', tang.path())
    env.prepend('PATH',
      join_paths(meson.source_root(), 'src'),
      meson.current_source_dir(),
      separator: ':'
    )

    test('pin-tang', find_program('./pin-tang'), env: env)
  else
    warning('Will not run tang tests due to missing dependencies!')
  endif
else
  warning('Will not install tang pin due to missing dependencies!')
endif
