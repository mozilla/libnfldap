#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2014 Mozilla Corporation
# Author: gdestuynder@mozilla.com

import os
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "libnfldap",
    py_modules=['libnfldap'],
    version = "1.0.7",
    author = "Julien Vehent",
    author_email = "jvehent@mozilla.com",
    description = ("A client library to generate ipset and iptables rules from LDAP records."),
    license = "MPL",
    keywords = "libnfldap client library",
    url = "https://github.com/mozilla/libnfldap",
    long_description=read('README.rst'),
    install_requires=['ldap'],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
    ],
)

