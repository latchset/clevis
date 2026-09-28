bins += join_paths(meson.current_source_dir(), 'clevis-zfs-common-functions')
bins += join_paths(meson.current_source_dir(), 'clevis-zfs-bind')
bins += join_paths(meson.current_source_dir(), 'clevis-zfs-list')
bins += join_paths(meson.current_source_dir(), 'clevis-zfs-unbind')
bins += join_paths(meson.current_source_dir(), 'clevis-zfs-unlock')

mans += join_paths(meson.current_source_dir(), 'clevis-zfs-bind.1')
mans += join_paths(meson.current_source_dir(), 'clevis-zfs-list.1')
mans += join_paths(meson.current_source_dir(), 'clevis-zfs-unbind.1')
mans += join_paths(meson.current_source_dir(), 'clevis-zfs-unlock.1')
mans += join_paths(meson.current_source_dir(), 'clevis-zfs-unlockers.7')

subdir('dracut')
subdir('initramfs-tools')

if not meson.is_cross_build()
  subdir('tests')
endif
