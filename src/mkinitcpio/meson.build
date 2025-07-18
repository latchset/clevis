mkinitcpio = find_program('mkinitcpio', required: false)

if mkinitcpio.found()
  install_data(['clevis.install', 'clevis.hooks'],
               rename: ['install/clevis', 'hooks/clevis'],
               install_dir: get_option('mkinitcpiodir') != '' ?
                            get_option('mkinitcpiodir') :
                            join_paths(get_option('sysconfdir'), 'initcpio'))
else
  warning('Will not install mkinitcpio hooks due to missing dependencies!')
endif
