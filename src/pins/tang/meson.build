curl = find_program('curl', required: false)

if curl.found() or meson.is_cross_build()
  bins += join_paths(meson.current_source_dir(), 'clevis-decrypt-tang')
  bins += join_paths(meson.current_source_dir(), 'clevis-encrypt-tang')
  mans += join_paths(meson.current_source_dir(), 'clevis-encrypt-tang.1')

if not meson.is_cross_build()
  subdir('tests')
endif
else
  warning('Will not install tang pin due to missing dependencies!')
endif
