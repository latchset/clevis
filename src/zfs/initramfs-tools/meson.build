if initramfs_tools.found()
  configure_file(
    input: 'clevis-zfs-hook.in',
    output: 'clevis-zfs',
    install_dir: initramfs_hooks_dir,
    configuration: initramfs_data,
  )

  configure_file(
    input: 'clevis-zfs-load-key.in',
    output: 'clevis-zfs-load-key',
    install_dir: libexecdir,
    configuration: initramfs_data,
  )

  configure_file(
    input: 'load-key.in',
    output: 'clevis',
    install_dir: join_paths(sysconfdir, 'zfs', 'initramfs-tools-load-key.d'),
    configuration: initramfs_data,
  )
endif
