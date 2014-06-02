#!/usr/bin/env python
# Requires:
# libnfldap

import libnfldap

def main():

	print("====== IPTABLES RULES ======")
	# declare a new iptables ruleset
	ipt = libnfldap.IPTables()

	# insert sane default at the top of the ruleset
	ipt.insertSaneDefaults()

	# append a rule in the filter table
	ipt.appendFilterRule('-A OUTPUT -p tcp --dport 80 -j ACCEPT')

	# create a custom chain in the filter table
	ipt.newFilterChain('someuser')
	ipt.appendFilterRule('-A someuser -p tcp --dport 443 -d 10.0.0.2 -j ACCEPT')

	# set a default drop policy at the end of the ruleset
	ipt.appendDefaultDrop()

	# template the ruleset
	print(ipt.template())

	print("\n\n====== IPSET RULES ======")
	# declare a new ipset ruleset
	ips = libnfldap.IPset()

	# create a set of type hash:net
	ips.newHashNet('customset')

	# add an cidr to the hash:net
	ips.addCIDRToHashNet('customset', '10.0.2.0/16')

	# template the ruleset
	print(ips.template())

if __name__ == "__main__":
	main()
