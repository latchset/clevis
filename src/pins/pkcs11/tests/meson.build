env = environment()
env.prepend('PATH',
  join_paths(meson.source_root(), 'src'),
  join_paths(meson.source_root(), 'src', 'pins', 'pkcs11'),
  join_paths(meson.source_root(), 'src', 'pins', 'pkcs11', 'tests'),
  join_paths(meson.build_root(), 'src'),
  join_paths(meson.build_root(), 'src', 'pins'),
  join_paths(meson.build_root(), 'src', 'pins', 'pkcs11'),
  join_paths(meson.build_root(), 'src', 'pins', 'pkcs11', 'tests'),
  join_paths(meson.source_root(), 'src'),
  join_paths(meson.source_root(), 'src', 'luks'),
  join_paths(meson.source_root(), 'src', 'luks', 'tests'),
  join_paths(meson.build_root(), 'src'),
  join_paths(meson.build_root(), 'src', 'luks'),
  join_paths(meson.build_root(), 'src', 'luks', 'tests'),
  join_paths(meson.source_root(), 'src', 'pins', 'tang'),
  join_paths(meson.source_root(), 'src', 'pins', 'tang', 'tests'),
  join_paths(meson.build_root(), 'src', 'pins', 'tang'),
  join_paths(meson.build_root(), 'src', 'pins', 'tang', 'tests'),
  separator: ':'
)

test('pin-pkcs11', find_program('pin-pkcs11'), env: env)
