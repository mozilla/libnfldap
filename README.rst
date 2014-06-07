=========
libnfldap
=========

A Python module to generate IPTables and IPSet rules from LDAP records.
See example.py for a demo.

Example
-------

The script at `example_allusers.py` will build iptables and ipset rules for all
users in LDAP. You can provide the script an ldap filter as argv[1] to limit the
scope.

.. code:: bash

	$ time python example_allusers.py '(uid=jvehent)'
	IPTables rules written in /tmp/tmpT7JgOW
	IPSet rules written in /tmp/tmpJYtWM5

	real    0m0.605s
	user    0m0.061s
	sys     0m0.014s

`example.py` does something similar but for a single user identified by its
uidNumber (unix user ID).

.. code:: bash

	$ python example.py 2297
	#Generating rules for user ID 1664
	#====== ACL details ======
	jvehent has access to .....

Authors
-------
Julien Vehent & Guillaume Destuynder (@ mozilla)
