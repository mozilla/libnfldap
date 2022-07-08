# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2014 Mozilla Corporation
# Author: gdestuynder@mozilla.com

all:
	./setup.py build

install:
	./setup.py install

rpm:
	fpm -s python -t rpm --python-bin python3 -d python3-ldap --no-python-fix-name ./setup.py

deb:
	fpm -s python -t deb ./setup.py

clean:
	rm -rf *pyc
	rm -rf build
	rm -rf __pycache__
	rm -rf libnfldap.egg-info
