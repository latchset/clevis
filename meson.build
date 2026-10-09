project('clevis', 'c', license: 'GPL3+',
  version: '23',
  default_options: ['c_std=c99']
)

libexecdir = join_paths(get_option('prefix'), get_option('libexecdir'))
sysconfdir = join_paths(get_option('prefix'), get_option('sysconfdir'))
bindir = join_paths(get_option('prefix'), get_option('bindir'))
libdir = join_paths(get_option('prefix'), get_option('libdir'))

data = configuration_data()
data.set('libexecdir', libexecdir)
data.set('sysconfdir', sysconfdir)
data.set('bindir', bindir)
data.set('libdir', libdir)

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

has_kem_api = false
if not get_option('tang-pqc').disabled() and jansson.found()
  cc = meson.get_compiler('c')
  has_kem_api = cc.links('''
#include <jose/jose.h>
int main(void) {
    json_auto_t *j = json_pack("{s:s}", "alg", "ML-KEM-768");
    if (!jose_jwk_gen(NULL, j))
        return 1;
    json_auto_t *enc = jose_jwk_kem_enc(NULL, j);
    return enc ? 0 : 1;
}
''', dependencies: [jose, jansson], name: 'ML-KEM KEM API support in jose')
endif

have_cpp = false
if has_kem_api
  have_cpp = add_languages('cpp', required: get_option('tang-pqc'))
  if have_cpp
    add_project_arguments(
      '-Wall',
      '-Wextra',
      '-Werror',
      '-Wchar-subscripts',
      '-Wformat-security',
      '-Wpointer-arith',
      '-Wshadow',
      '-Wsign-compare',
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
      language: 'cpp'
    )
  endif
elif get_option('tang-pqc').enabled()
  error('tang-pqc pin is enabled but jose lacks ML-KEM KEM API support')
endif

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

summary('TPM 1.2 pin', get_option('tpm1'), section: 'Features')
summary('Tang PQC pin', get_option('tang-pqc'), section: 'Features')
