ct_helper
=========

Helper modules for common_test suites.

Creating temporary static files
-------------------------------

This library includes a function that will generate files tailored
for testing web servers. The following snippet will create a
directory containing all the files and subsequently delete it all.

``` erlang
ct_helper:create_static_dir(Path),
%% do things!
ct_helper:delete_static_dir(Path).
```

The following files are created. Replace `./` with the `Path` passed
as argument to find the real path of the files.

 *  ./
 *  ./directory/
 *  ./unknown
 *  ./style.css
 *  ./index.html
 *  ./unreadable (mode 0333)

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
