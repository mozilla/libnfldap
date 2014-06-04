#!/usr/bin/env python
# Requires:
# libnfldap

import libnfldap
import os
import pwd
import sys
from tempfile import mkstemp

LDAP_URL='ldap://<%= ldap_server %>'
LDAP_BIND_DN='uid=<%= bind_user %>,ou=logins,dc=mozilla'
LDAP_BIND_PASSWD='<%= bind_password %>'

def main():
	# declare a new iptables ruleset
	ipt = libnfldap.IPTables()

	# insert sane default at the top of the ruleset
	ipt.insertSaneDefaults()

	# declare a new ipset ruleset
	ipset = libnfldap.IPset()

	# find all LDAP users
	ldap = libnfldap.LDAP(LDAP_URL, LDAP_BIND_DN, LDAP_BIND_PASSWD)
	query = '(&(objectClass=mozComPerson)(objectClass=posixAccount))'
	res = ldap.query('dc=mozilla', query, ['uid', 'uidNumber'])
	users = {}

	# get users from the system, the find the corresponding ldap record
	for p in pwd.getpwall():
		if p.pw_uid > 500:
			# iterate over the ldap records
			for dn, attr in res:
				uid = attr['uid'][0]
				uidNumber = attr['uidNumber'][0]
				if uidNumber == str(p.pw_uid) and uid == p.pw_name:
					# store the user
					users[uidNumber] = {'dn': dn, 'uid': uid}

	# iterate over the users and create the rules
	for uidNumber,attr in users.iteritems():
		dn = attr['dn']
		uid = attr['uid']

		# create a custom chain and sets for the user
		ipt.newFilterChain(uid)

		# add rules to forward this user's packets to the custom chain and the ipset
		r = "-A OUTPUT -m owner --uid-owner " +  uidNumber + " -m state --state NEW -j " + uid
		ipt.appendFilterRule(r)

		# find ACLs of a given user
		acls = ldap.getACLs('ou=groups,dc=mozilla',
							"(&(member="+dn+")(cn=vpn_*))")

		# iterate through the ACLs and create iptables or ipset rules
		for group,dests in acls.iteritems():
			for dest,desc in dests.iteritems():
				# if the destination is a CIDR (IP or subnet), add it to ipset
				if libnfldap.is_cidr(dest):
					ipt.acceptIP(uid, dest, desc)
				else:
					# if the destination has ports, add one rule per port
					ip = dest.split(":", 1)[0]
					ports = dest.split(":", 1)[1]
					if len(ports) > 0:
						ipt.acceptIPPortProto(uid, ip, ports, "tcp", desc)
						ipt.acceptIPPortProto(uid, ip, ports, "udp", desc)
					else:
						ipt.acceptIP(uid, ip, desc)

		# add a DROP at the end of the user rules
		ipt.appendFilterRule("-A " + uid + " -j DROP")

	# set a default drop policy at the end of the ruleset
	#ipt.appendDefaultDrop()

	# template and print the iptables rules
	tmpfd, tmppath = mkstemp()
	f = open(tmppath, 'w')
	f.write(ipt.template())
	f.close()
	os.close(tmpfd)
	print("IPTables rules written in %s" % tmppath)

if __name__ == "__main__":
	main()
