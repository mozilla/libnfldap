#!/usr/bin/env python
# Requires:
# python-ldap
#
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Initial Developer of the Original Code is
# Mozilla Corporation
# Portions created by the Initial Developer are Copyright (C) 2012
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
# jvehent@mozilla.com
# gdestuynder@mozilla.com
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.

import ldap
from string import Template
from datetime import datetime

IP_REGEXP = "((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}" \
            "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))"

class IPTables(object):
	def __init__(self):
		self.filters=[]
		self.raw=[]
		self.mangle=[]
		self.nat=[]

	def insertSaneDefaults(self):
		""" Add sane defaults rules to the raw and filter tables """
		self.raw.insert(0, '-A OUTPUT -o lo -j NOTRACK')
		self.raw.insert(1, '-A PREROUTING -i lo -j NOTRACK')
		self.filters.insert(0, '-A INPUT -i lo -j ACCEPT')
		self.filters.insert(1, '-A OUTPUT -o lo -j ACCEPT')
		self.filters.insert(2, '-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT')
		self.filters.insert(3, '-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT')
		return self

	def appendDefaultDrop(self):
		""" Add a DROP policy at the end of the rules """
		self.filters.append('-A INPUT -j DROP')
		self.filters.append('-A OUTPUT -j DROP')
		self.filters.append('-A FILTER -j DROP')
		return self

	def appendFilterRule(self, rule):
		self.filters.append(rule)
		return self

	def newFilterChain(self, name):
		self.filters.insert(0, ":" + name + " - [0:0]")
		return self

	def appendRawRule(self, rule):
		self.raw.append(rule)
		return self

	def newRawChain(self, name):
		self.raw.insert(0, ":" + name + " - [0:0]")
		return self

	def appendMangleRule(self, rule):
		self.mangle.append(rule)
		return self

	def newMangleChain(self, name):
		self.mangle.insert(0, ":" + name + " - [0:0]")
		return self

	def appendNatRule(self, rule):
		self.nat.append(rule)
		return self

	def newNATChain(self, name):
		self.nat.insert(0, ":" + name + " - [0:0]")
		return self

	def template(self):
		"""
			Create a rules file in iptables-restore format
		"""
		s = Template(self._IPTABLES_TEMPLATE)
		return s.substitute(filtertable='\n'.join(self.filters),
							rawtable='\n'.join(self.raw),
							mangletable='\n'.join(self.mangle),
							nattable='\n'.join(self.nat),
							date=datetime.today())

	_IPTABLES_TEMPLATE = '''# Generated by libnfldap on $date
*raw
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
$rawtable

*mangle
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
$mangletable

*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
$nattable

*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
$filtertable

COMMIT'''

class IPset(object):
	def __init__(self):
		self.sets=[]

	def newHashNet(self, name):
		self.sets.insert(0, "create " + name + " hash:net family inet hashsize 1024 maxelem 65536")

	def addCIDRToHashNet(self, setname, cidr):
		self.sets.append("add "+ setname + " " + cidr)

	def template(self):
		"""
			Create a rules file in ipset --restore format
		"""
		s = Template(self._IPSET_TEMPLATE)
		return s.substitute(sets='\n'.join(self.sets),
							date=datetime.today())

	_IPSET_TEMPLATE = '''# Generated by libnfldap on $date
$sets
COMMIT'''