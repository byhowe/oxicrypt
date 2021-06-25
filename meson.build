project(
  'oxicrypt',
  'c',
  version : '0.1',
  license : 'MIT',
)

cargo_args = ['build', '--package=oxicrypt-sys']

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
message('Running cargo')
run_command(cargo, cargo_args, check : true)

libraries = {}
if get_option('default_library') == 'shared' or get_option('default_library') == 'both'
  libraries += { join_paths('target', target, 'liboxicrypt_sys.' + ext_dynamic) : 'liboxicrypt.' + ext_dynamic }
endif

if get_option('default_library') == 'static' or get_option('default_library') == 'both'
  libraries += { join_paths('target', target, 'liboxicrypt_sys.' + ext_static) : 'liboxicrypt.' + ext_static }
endif

foreach path, name : libraries
  install_data(path, install_dir : get_option('libdir'), rename : name)
endforeach

headers = [
  join_paths('oxicrypt-sys', 'include', 'oxicrypt', 'aes.h'),
  join_paths('oxicrypt-sys', 'include', 'oxicrypt', 'sha.h'),
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
