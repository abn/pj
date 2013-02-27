#!/usr/bin/env python
from setuptools import setup, find_packages

setup(
	name='pj',
	version='0.0.1',
	description='Python package to interpret java byte code',
	long_description='',
	author='Grant C Murphy',
	url="https://github.com/gcmurphy/pj",
	download_url="https://github.com/gcmurphy/pj",
	packages=find_packages(),
	include_package_data=True,
	classifiers=[
		'Intended Audience :: Developers',
		'Programming Language :: Python',
		'Topic :: Software Development :: Libraries :: Python Modules',
	],
)
