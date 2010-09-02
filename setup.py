#!/usr/bin/env python
import ez_setup
ez_setup.use_setuptools()

from setuptools import setup, find_packages

setup(
    name = 'asyncdns',
    version = '0.3',
    packages = find_packages(exclude=['ez_setup', 'tests']),
    author = 'Flier Lu',
    author_email = 'flier.lu@gmail.com',
    description = 'Asynchronous DNS query pipeline for Python',
    long_description = open('README.txt').read(),
    license = 'Apache License 2.0',
    keywords = 'asynchronous DNS python',
    url = 'http://code.google.com/p/asyncdns/',
    download_url = 'http://code.google.com/p/asyncdns/downloads/list',
    install_requires = [
        'dnspython >= 1.8.0',
    ],
    classifiers = [
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Software Development',
    ]
)
