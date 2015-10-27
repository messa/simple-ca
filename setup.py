#!/usr/bin/env python3

from pathlib import Path
from setuptools import setup, find_packages


here = Path(__file__).resolve().parent

setup(
    name='simple_ca',
    version='0.0.1',
    description='OpenSSL wrapper to create your own CA',
    long_description=(here / 'README.md').open().read(),
    url='https://github.com/messa/simple-ca',
    author='Petr Messner',
    author_email='petr.messner@gmail.com',
    license='MIT',
    classifiers=[
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
    ],
    keywords='openssl ssl ca certificate',
    packages=find_packages(exclude=['tests']),
    entry_points={
    })
