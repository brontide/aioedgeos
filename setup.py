from setuptools import setup

def readme():
    with open('README.rst') as f:
        return f.read()


setup(name='aioedgeos',
      version='0.3',
      description='Interact with EdgeOS web ui by async http and websockets',
      long_description=readme(),
      classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
      ],
      keywords='UBNT edgerouter edgeos',
      url='http://github.com/brontide/aiodgeos',
      author='Eric Warnke',
      author_email='ericew@gmail.com',
      license='MIT',
      packages=['aioedgeos'],
      install_requires=[
          'aiohttp',
          'aiodns',
          'PyYAML',
      ],
#      entry_points={
#          'console_scripts': ['unificmd=unifiapi.cmd:main'],
#      },
      include_package_data=True,
      zip_safe=False)
