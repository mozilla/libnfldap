#!/usr/bin/env python
# Requires:
# libnfldap

import libnfldap
import sys

LDAP_URL='ldap://<%= ldap_server %>'
LDAP_BIND_DN='uid=<%= bind_user %>,ou=logins,dc=mozilla'
LDAP_BIND_PASSWD='<%= bind_password %>'

def main():
	uidnum = sys.argv[1]
	print("#Generating rules for user ID %s" % uidnum)

	# declare a new iptables ruleset
	ipt = libnfldap.IPTables()

	# insert sane default at the top of the ruleset
	ipt.insertSaneDefaults()

	# declare a new ipset ruleset
	ips = libnfldap.IPset()

	# find a user in ldap
	ldap = libnfldap.LDAP(LDAP_URL, LDAP_BIND_DN, LDAP_BIND_PASSWD)
	userdn,userid = ldap.getUserByNumber('o=com,dc=mozilla', uidnum)

	# create a custom chain and sets for the user
	ipt.newFilterChain(userid)
	r = "-A FORWARD -m owner --uid-owner " +  uidnum + " -m state --state NEW -j " + userid
	ipt.appendFilterRule(r)
	ips.newHashNet(userid)

	# find groups of an ldap user
	acls = ldap.getACLs('ou=groups,dc=mozilla',
						"(&(member="+userdn+")(cn=vpn_*))")

	# iterate through the ACLs
	print("#====== ACL details ======")
	for group,dests in acls.iteritems():
		for dest,desc in dests.iteritems():
			print("%s has access to %s aka '%s'" % (userid, dest, desc))
			if libnfldap.is_cidr(dest):
				ips.addCIDRToHashNet(userid, dest)
			else:
				ipt.appendFilterRule("-A " + userid + " -d " + dest + " -j ACCEPT")

	# set a default drop policy at the end of the ruleset
	ipt.appendDefaultDrop()

	# template and print the iptables rules
	print("#====== IPTABLES RULES ======\n")
	print("%s\n\n" % ipt.template())

	# template and print the ipset rules
	print("#====== IPSET RULES ======\n")
	print("%s" % ips.template())

if __name__ == "__main__":
	main()
