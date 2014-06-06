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

# This script generates a tree of rules that efficiently looks up packets
# belonging to a given user. The tree is composed of one chain for each
# VPN group. Then each user has a custom chain that point to the
# proper VPN chains based on the user's group membership.
#
# --- PSEUDO CODE
# For each VPN group:
#	create iptables chain `vpngroupname`
#	for each iphostnumber in vpn group:
#		insert iptables rule in chain `vpngroupname`
#
# For each local user:
#	create iptables chain `username`
#	insert jump rule from OUTPUT & FORWARD to chain `username`
#	obtain list of vpn groups user belong to
#	for each vpn group:
#		create jump rule from user chain to `vpngroupname` chain
#	append DROP rule to user chain
#
def main():
	ipt = libnfldap.IPTables()
	ldap = libnfldap.LDAP(LDAP_URL, LDAP_BIND_DN, LDAP_BIND_PASSWD)
	ipset = libnfldap.IPset()

	# find all vpn groups and create chains
	acls = ldap.getACLs('ou=groups,dc=mozilla',"(cn=vpn_*)")
	for group,dests in acls.iteritems():
		ipt.newFilterChain(group)
		for dest,desc in dests.iteritems():
			if libnfldap.is_cidr(dest):
				ipt.acceptIP(group, dest, desc)
			else:
				ip = dest.split(":", 1)[0]
				ports = dest.split(":", 1)[1]
				if len(ports) > 0:
					ipt.acceptIPPortProto(group, ip, ports, "tcp", desc)
					ipt.acceptIPPortProto(group, ip, ports, "udp", desc)
				else:
					ipt.acceptIP(group, ip, desc)

	# get a list of all LDAP users
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

	## iterate over the users and create the rules
	for uidNumber,attr in users.iteritems():
		dn = attr['dn']
		uid = attr['uid']
		# create a custom chain for the user
		ipt.newFilterChain(uid)
		# add rules to forward this user's packets to the custom chain
		r = "-A OUTPUT -m owner --uid-owner " +  uidNumber + " -m state --state NEW -j " + uid
		ipt.appendFilterRule(r)

		# find groups memberships of the user
		acls = ldap.getACLs('ou=groups,dc=mozilla',
							"(&(member="+dn+")(cn=vpn_*))")

		# iterate through the ACLs and send the user to the group chains
		for group,dests in acls.iteritems():
			ipt.appendFilterRule("-A " + uid + " -j " + group)

		# add a DROP at the end of the user rules
		ipt.appendFilterRule("-A " + uid + " -j DROP")

	# set a default drop policy at the end of the ruleset
	ipt.insertSaneDefaults()
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
