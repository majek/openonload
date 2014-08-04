from distutils.core import setup, Extension
import os, sys


onload_tree = os.getenv('ONLOAD_TREE')
onload_build = os.getenv('ONLOAD_BUILD')
if not onload_tree or not onload_build:
    sys.stderr.write('ONLOAD_TREE and ONLOAD_BUILD must be set to use this ' +
                     'script\n')
    sys.exit(1)


ext = Extension(
    'solar_clusterd.cluster_protocol',
    ['cluster_protocol.c', 'filter_string.c'],
    include_dirs = [
        os.path.join(onload_tree, 'src', 'include'),
        os.path.join(onload_tree, 'src', 'tools', 'solar_clusterd')],
    extra_objects = [os.path.join(onload_build, 'lib', 'ciul', 'libciul1.a')],
    )


setup(name='solar_clusterd',
      version = '1.0',
      author = 'Solarflare Communications',
      author_email = 'support@solarflare.com',
      url = 'http://www.openonload.org/',
      package_dir = {'solar_clusterd': '.'},
      packages = ['solar_clusterd'],
      ext_modules = [ext],
      scripts = ['solar_clusterd']
      )
