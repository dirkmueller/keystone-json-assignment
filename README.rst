Keystone JSON Assignment Driver Backend
=======================================

This assignment backend inherits from the standard SQL backend and adds
user-project assignments for LDAP users using a JSON mapping found at
/etc/keystone/user-project-map.json. This is based on the
`hybrid_json_assignment driver for SUSE OpenStack Cloud 6
<https://github.com/SUSE-Cloud/keystone-hybrid-backend/blob/liberty/hybrid_json_assignment.py>`_.

Installation
------------

::

    git clone https://github.com/cmurphy/keystone-json-assignment
    pip install keystone-json-assignment/

Usage
-----

In the ``[assignment]`` section of keystone.conf, set ``driver = json``.

Add a ``[json_assignment]`` section and set ``ldap_domain_name`` to the name of
the domain that contains your LDAP users. Defaults to `ldap_users`.

The format of user-project-map.json will look something like::

  {
    "comurphy" : [
       "cloud",
       "appliances",
       "suse"
    ],
    ...
  }
