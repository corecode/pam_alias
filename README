pam_alias - map user names using an arbitrary file
==================================================

pam_alias is a PAM module which provides a way to map user names using
an arbitrary file.

For example, it can rewrite mail address- or jid-style user names to
local user names.

      foo@sub.example.org	loclfoo

will map the user name `foo@sub.example.org` to `loclfoo`, which will
then be used in turn by the following PAM modules.


Installation
------------

make install


Usage
-----

Add something like this to the beginning of select PAM configs:

    auth required pam_alias.so file=/etc/security/useralias

For more details, see the pam_alias(8) manual page.


Author
------

Simon Schubert <2@0x2c.org>
