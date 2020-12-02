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

socat = find_program('socat', required: false)

tang_data = configuration_data()
tang_data.set('SOCAT', '')
tang_data.set('TANGD_KEYGEN', '')
tang_data.set('TANGD_UPDATE', '')
tang_data.set('TANGD', '')

if socat.found()
  tang_data.set('SOCAT', socat.path())
endif

if kgen.found()
  tang_data.set('TANGD_KEYGEN', kgen.path())
endif

if tang.found()
  tang_data.set('TANGD', tang.path())
endif

if updt.found()
  tang_data.set('TANGD_UPDATE', updt.path())
endif

tang_tests_common = configure_file(
  input: 'tang-common-test-functions.in',
  output: 'tang-common-test-functions',
  configuration: tang_data
)

env = environment()
env.prepend('PATH',
  join_paths(meson.source_root(), 'src'),
  join_paths(meson.source_root(), 'src', 'pins', 'tang'),
  join_paths(meson.build_root(), 'src', 'pins', 'tang', 'tests'),
  separator: ':'
)

test('pin-tang', find_program('pin-tang'), env: env)
test('tang-validate-adv', find_program('tang-validate-adv'), env: env)
