env = environment()
env.prepend('PATH',
  join_paths(meson.source_root(), 'src'),
  join_paths(meson.source_root(), 'src', 'pins', 'sss'),
  join_paths(meson.source_root(), 'src', 'zfs'),
  join_paths(meson.source_root(), 'src', 'zfs', 'tests'),
  join_paths(meson.build_root(), 'src'),
  join_paths(meson.build_root(), 'src', 'pins', 'sss'),
  separator: ':'
)

test('bind-unbind-zfs', find_program('bind-unbind-zfs'), env: env)
test('unlock-zfs', find_program('unlock-zfs'), env: env)
test('bind-chunked-zfs', find_program('bind-chunked-zfs'), env: env)
test('bind-raw-zfs', find_program('bind-raw-zfs'), env: env)
