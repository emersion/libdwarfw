project(
	'dwarfw',
	'c',
	version: '0.0.1',
	license: 'MIT',
	meson_version: '>=0.43.0',
	default_options: [
		'c_std=c11',
		'warning_level=2',
		'werror=true',
	],
)

add_project_arguments('-Wno-unused-parameter', language: 'c')

dwarfw_inc = include_directories('include')

elf = dependency('libelf')

install_headers('include/dwarfw.h')

lib_dwarfw = library(
	meson.project_name(),
	files(
		'dwarfw.c',
		'instructions.c',
		'leb128.c',
		'pointer.c',
	),
	include_directories: dwarfw_inc,
	dependencies: [elf],
	version: meson.project_version(),
	install: true,
)

dwarfw = declare_dependency(
	link_with: lib_dwarfw,
	include_directories: dwarfw_inc,
)

subdir('examples')

pkgconfig = import('pkgconfig')
pkgconfig.generate(
	libraries: lib_dwarfw,
	version: meson.project_version(),
	filebase: meson.project_name(),
	name: meson.project_name(),
	description: 'DWARF writer library',
)
