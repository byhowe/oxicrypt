project(
  'oxicrypt',
  'c',
  version : '0.1',
  license : 'MIT',
)

cargo_args = ['rustc', '--package=oxicrypt_c', '--target-dir=builddir']

if get_option('debug')
  message('Debug mode is enabled')
  target = 'debug'
else
  message('Release mode is enabled')
  target = 'release'
  cargo_args += ['--release']
endif

system = build_machine.system()
if system == 'windows'
  ext_dynamic = 'dll'
  ext_static = 'lib'
elif system == 'darwin'
  ext_dynamic = 'dylib'
  ext_static = 'a'
else
  ext_dynamic = 'so'
  ext_static = 'a'
endif

cargo = find_program('cargo', required : true)
message('Running `', cargo.full_path(), cargo_args, '`')
run_command(cargo, cargo_args, check : true)

libraries = []
if get_option('default_library') == 'shared' or get_option('default_library') == 'both'
  libraries += [join_paths('builddir', target, 'liboxicrypt.' + ext_dynamic)]
endif

if get_option('default_library') == 'static' or get_option('default_library') == 'both'
  libraries += [join_paths('builddir', target, 'liboxicrypt.' + ext_static)]
endif

install_data(libraries, install_dir : get_option('libdir'))

headers = [
  join_paths('include', 'oxicrypt', 'oxicrypt.h'),
  join_paths('include', 'oxicrypt', 'digest.h'),
  join_paths('include', 'oxicrypt', 'aes.h'),
  join_paths('include', 'oxicrypt', 'hmac.h'),
  join_paths('include', 'oxicrypt', 'core', 'aes_arm.h'),
  join_paths('include', 'oxicrypt', 'core', 'aes_lut.h'),
  join_paths('include', 'oxicrypt', 'core', 'aesni.h'),
  join_paths('include', 'oxicrypt', 'core', 'md_compress.h'),
]

install_headers(headers, subdir : 'oxicrypt')

pkgconf = import('pkgconfig')
pkgconf.generate(
  name : 'oxicrypt',
  filebase : 'oxicrypt',
  description : 'C/C++ interface for OxiCrypt library.',
  libraries : [ library('oxicrypt') ],
  version : '0.1',
)
