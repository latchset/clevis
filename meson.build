project('clevis', 'c', license: 'GPL3+', version: '11',
        default_options: 'c_std=c99')

libexecdir = join_paths(get_option('prefix'), get_option('libexecdir'))
sysconfdir = join_paths(get_option('prefix'), get_option('sysconfdir'))
bindir = join_paths(get_option('prefix'), get_option('bindir'))

data = configuration_data()
data.set('libexecdir', libexecdir)
data.set('sysconfdir', sysconfdir)
data.set('bindir', bindir)

add_project_arguments(
  '-Wall',
  '-Wextra',
  '-Werror',
  '-Wstrict-aliasing',
  '-Wchar-subscripts',
  '-Wformat-security',
  '-Wmissing-declarations',
  '-Wmissing-prototypes',
  '-Wnested-externs',
  '-Wpointer-arith',
  '-Wshadow',
  '-Wsign-compare',
  '-Wstrict-prototypes',
  '-Wtype-limits',
  '-Wunused-function',
  '-Wno-missing-field-initializers',
  '-Wno-unused-parameter',
  '-Wno-unknown-pragmas',
  '-D_DEFAULT_SOURCE',
  '-D_POSIX_C_SOURCE=200112L',
  '-DBINDIR="' + bindir + '"',
  '-DCLEVIS_USER="' + get_option('user') + '"',
  '-DCLEVIS_GROUP="' + get_option('group') + '"',
  language: 'c'
)

jansson = dependency('jansson', version: '>=2.10', required: false)
jose = dependency('jose', version: '>=8')
a2x = find_program('a2x', required: false)

bins = []
mans = []

subdir('src')

install_data(bins, install_dir: bindir)

if a2x.found()
  foreach m : mans
    custom_target(m.split('/')[-1], input: m + '.adoc', output: m.split('/')[-1],
      command: [a2x, '-f', 'manpage', '-D', meson.current_build_dir(), '@INPUT@'],
      install_dir: join_paths(get_option('mandir'), 'man' + m.split('.')[-1]),
      install: true
    )
  endforeach
else
  warning('Will not build man pages due to missing dependencies!')
endif
