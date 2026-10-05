tang_pqc_tests_common = configure_file(
  input: 'tang-pqc-common-test-functions.in',
  output: 'tang-pqc-common-test-functions',
  configuration: configuration_data()
)

tang_pqc_test_env = environment()
tang_pqc_test_env.prepend('PATH',
  join_paths(meson.source_root(), 'src'),
  join_paths(meson.source_root(), 'src', 'pins', 'tang'),
  join_paths(meson.source_root(), 'src', 'pins', 'tang-pqc'),
  join_paths(meson.build_root(), 'src', 'pins', 'tang', 'tests'),
  join_paths(meson.build_root(), 'src', 'pins', 'tang-pqc'),
  join_paths(meson.build_root(), 'src', 'pins', 'tang-pqc', 'tests'),
  join_paths(meson.build_root(), 'src', 'luks', 'tests'),
  separator: ':'
)

test('pin-tang-pqc', find_program('pin-tang-pqc'), env: tang_pqc_test_env)
test('pin-tang-pqc-version', find_program('pin-tang-pqc-version'), env: tang_pqc_test_env)
test('pin-tang-pqc-offline', find_program('pin-tang-pqc-offline'), env: tang_pqc_test_env)
test('pin-tang-pqc-sss', find_program('pin-tang-pqc-sss'), env: tang_pqc_test_env)
test('pin-tang-pqc-errors', find_program('pin-tang-pqc-errors'), env: tang_pqc_test_env)
