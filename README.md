ct_helper
=========

Helper modules for common_test suites.

Generating SSL certificates
---------------------------

This library includes a function that allows you to generate SSL
certificates for testing purposes. The following snippet can be
used to generate certificates and a private key.

``` erlang
{CaCert, Cert, Key} = ct_helper:make_certs().
```

The resulting `CaCert`, `Cert` and `Key` can be used directly with
Erlang functions like `ssl:connect/3`.

``` erlang
ssl:connect("example.com", 443, [binary, {cert, Cert}, {key, Key}]).
```

Support
-------

 *  Official IRC Channel: #ninenines on irc.freenode.net
 *  [Mailing Lists](http://lists.ninenines.eu)
