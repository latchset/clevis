curl = find_program('curl', required: false)

if curl.found()
  bins += join_paths(meson.current_source_dir(), 'clevis-decrypt-tang')
  bins += join_paths(meson.current_source_dir(), 'clevis-encrypt-tang')
  mans += join_paths(meson.current_source_dir(), 'clevis-encrypt-tang.1')

  subdir('tests')
else
  warning('Will not install tang pin due to missing dependencies!')
endif
