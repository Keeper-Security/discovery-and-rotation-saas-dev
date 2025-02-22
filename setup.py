#!/usr/bin/env python

from plugin_dev.__version__ import __version__
from setuptools import setup, find_packages
from setuptools.command.install import install as install_command
import subprocess
import re


with open('requirements.txt') as f:
    required = []
    prog = re.compile("^[^-.]")
    for row in f.read().splitlines():
        if prog.match(row) is None:
            continue
        required.append(row)


class Install(install_command):
    """ Customized setuptools install command which uses pip. """

    def run(self):
        subprocess.call(['pip3', 'install', '-r', 'requirements.txt'])
        install_command.run(self)


packages = find_packages(where='plugin_dev') + find_packages(where='kdnrm')

setup(
    version=__version__,
    name='plugin_dev',
    description='PAM SaaS Plugin Dev',
    packages=packages,
    install_requires=required,
    include_package_data=True,
    cmdclass={
        'install': Install,
    },
    python_requires='>=3.8',
    entry_points={
        "console_scripts": [
            "plugin_dev_cli=plugin_dev.cli",
        ]
    }
)
