Simple CA
=========

__Python OpenSSL wrapper__ that can create __your own certificate authority (CA)__ and create server certficates with it.

Use cases:

- enable SSL communication in your private MongoDB cluster
- easy setup your SSL infrastructure for any services that need it, for example VPN

Usage
-----

```python
from simple_ca import SimpleCA
s = SimpleCA()
ca = s.init_ca(org='ACME')
# now you have created your own CA
# ca.cert is the CA certificate (pass it to all clients)
# ca.key is needed to create (and sign) certificates
# ca.key_password is password to the key, keep this private

sc = s.create_server_cert(
    ca_cert=ca.cert, ca_key=ca.key, ca_key_password=ca.key_password,
    cn='localhost', org='ACME', dc='example')
# now you have created your own server certificate
# sc.cert is the SSL certficate
# sc.key is key to that certificate (needed on the server)
# sc.key_password is password to the key, keep this private
```

I recommend to store the `cert` and `key` in plain text files and `key_password` in GPG-encrypted file.
