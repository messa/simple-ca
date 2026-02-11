Simple CA
=========

__Python OpenSSL wrapper__ that can create __your own certificate authority (CA)__ and create server certficates with it.

Use cases:

- Enable SSL communication in your private MongoDB cluster
- Easy setup your SSL infrastructure for any services that need it, for example VPN


Installation
------------

```console
python3 -m pip install https://github.com/messa/simple-ca/archive/v0.0.2.zip
```


Usage
-----

```python
from simple_ca import CA

ca = CA.init_ca(org='ACME')
# now you have created your own CA
# ca.cert is the CA certificate (pass it to all clients)
# ca.key is needed to create (and sign) certificates
# ca.key_password is password to the key, keep this private

sc = ca.create_server_cert(cn='localhost', org='ACME', dc='example')
# now you have created your own server certificate
# sc.cert is the SSL certficate
# sc.key is key to that certificate (needed on the server)
# sc.key_password is password to the key, keep this private
```

You can also reconstruct a `CA` object from previously saved PEM data:

```python
ca = CA(cert=saved_cert, key=saved_key, key_password=saved_key_password)
sc = ca.create_server_cert(cn='localhost', org='ACME')
```

I recommend to store the `cert` and `key` in plain text files and `key_password` in encrypted file (using GPG, [AGE](https://age-encryption.org) etc.).


### Legacy API

```python
from simple_ca import SimpleCA
s = SimpleCA()
ca = s.init_ca(org='ACME')
sc = s.create_server_cert(
    ca_cert=ca.cert, ca_key=ca.key, ca_key_password=ca.key_password,
    cn='localhost', org='ACME', dc='example')
```


Similar projects
----------------

- [github.com/rocaccion/quick-ca](https://github.com/rocaccion/quick-ca)

- [cryptography.x509](https://cryptography.io/en/latest/x509/), [example](https://gist.github.com/major/8ac9f98ae8b07f46b208)
