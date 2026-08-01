install_data(
  [join_paths(meson.current_source_dir(), 'clevis-zfs-common')],
  install_dir: libexecdir
)

zfs_bins = [
  'clevis-zfs-bind',
  'clevis-zfs-list',
  'clevis-zfs-unbind',
  'clevis-zfs-unlock',
]
foreach b : zfs_bins
  configure_file(
    input: b,
    output: b,
    install_dir: bindir,
    configuration: data
  )
endforeach

test('clevis-zfs-test', find_program(join_paths(meson.current_source_dir(), 'clevis-zfs-test')))
