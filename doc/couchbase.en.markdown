# Nginx Couchbase Module (0.3.0)

[Couchbase][1] client for [nginx][2].

## Description

This module translates requests to Couchbase cluster, specified with
directive [couchbase_pass][3], and returns result back to the client.

By default, the module can use information, accessible in the request,
to construct data packet. As a key it use part of the request URI,
which remains after stripping the name of the matching location.

    location /cache/ {
        couchbase_pass;
    }

In example above, if address `/cache/example.html` will be requested
from the server, then the key will be `example.html`.

To choose command, which will be sent to Couchbase Server, it use HTTP
method. The table below shows correspondence commands to the methods.

<table>
  <tr><th>HTTP</th><th>Couchbase</th></tr>
  <tr><td>GET, HEAD</td><td>get</td></tr>
  <tr><td>POST</td><td>add</td></tr>
  <tr><td>PUT</td><td>set</td></tr>
  <tr><td>DELETE</td><td>delete</td></tr>
</table>

And, eventually, to pick the value (for mutation operations) it uses
body of the HTTP request.

Information, about how to override aforementioned behaviour using
variables, can be found below: [set $couchbase_cmd][4], [set
$couchbase_key][5], [set $couchbase_val][6].

## Configuration Directives

<a name="couchbase_pass"></a>
<table>
  <tr>
    <td><strong>syntax:</strong></td>
    <td><code><strong>couchbase_pass</strong> <i>address</i> bucket=<i>value</i> username=<i>value</i> password=<i>value</i>;</code></td>
  </tr>
  <tr>
    <td><strong>default:</strong></td>
    <td><code><strong>couchbase_pass</strong> <i>localhost:8091</i> bucket=<i>default</i>;</code></td>
  </tr>
  <tr>
    <td><strong>severity:</strong></td>
    <td>mandatory</td>
  </tr>
  <tr>
    <td><strong>context:</strong></td>
    <td><code>location</code>, <code>if in location</code>, <code>limit_except</code></td>
  </tr>
</table>

Specifies connection parameters for the cluster. Parameter `address` represents comma-separated pairs `host:port`, where `:port` might be omitted in which case default port (8091) will be used:

    location /cache/ {
        couchbase_pass example.com:8091,example.org bucket=app;
    }

* * *

<a name="couchbase_connect_timeout"></a>
<table>
  <tr>
    <td><strong>syntax:</strong></td>
    <td><code><strong>couchbase_connect_timeout</strong> <i>time</i>;</code></td>
  </tr>
  <tr>
    <td><strong>default:</strong></td>
    <td><code><strong>couchbase_connect_timeout</strong> <i>2.5s</i>;</code></td>
  </tr>
  <tr>
    <td><strong>severity:</strong></td>
    <td>optional</td>
  </tr>
  <tr>
    <td><strong>context:</strong></td>
    <td><code>location</code></td>
  </tr>
</table>

Sets timeout for establishing connection to Couchbase Server.

* * *

<a name="couchbase_timeout"></a>
<table>
  <tr>
    <td><strong>syntax:</strong></td>
    <td><code><strong>couchbase_timeout</strong> <i>time</i>;</code></td>
  </tr>
  <tr>
    <td><strong>default:</strong></td>
    <td><code><strong>couchbase_timeout</strong> <i>2.5s</i>;</code></td>
  </tr>
  <tr>
    <td><strong>severity:</strong></td>
    <td>optional</td>
  </tr>
  <tr>
    <td><strong>context:</strong></td>
    <td><code>location</code></td>
  </tr>
</table>

Sets timeout for data communication with Couchbase Server.

## Variables

<a name="set-couchbase_cmd"></a>
<table>
  <tr>
    <td><strong>syntax:</strong></td>
    <td><code><strong>set $couchbase_cmd</strong> <i>command</i>;</code></td>
  </tr>
  <tr>
    <td><strong>default:</strong></td>
    <td>-</td>
  </tr>
  <tr>
    <td><strong>severity:</strong></td>
    <td>optional</td>
  </tr>
</table>

Sets command type, executed for this location. For example, command
can be taken from query string (`/cache/?cmd=append`):

    location /cache/ {
        set $couchbase_cmd $arg_cmd;
        couchbase_pass;
    }

Or command can be fixed string:

    location /cache/ {
        set $couchbase_cmd 'append';
        couchbase_pass;
    }

As for version 0.2.0 supported the following commands: `get`, `set`,
`add`, `replace`, `append`, `prepend`, `delete`. About corresponding
HTTP methods to commands, read section "Description".

* * *

<a name="set-couchbase_key"></a>
<table>
  <tr>
    <td><strong>syntax:</strong></td>
    <td><code><strong>set $couchbase_key</strong> <i>value</i>;</code></td>
  </tr>
  <tr>
    <td><strong>default:</strong></td>
    <td>-</td>
  </tr>
  <tr>
    <td><strong>severity:</strong></td>
    <td>optional</td>
  </tr>
</table>

Sets key for the document in this location. For example, key can be
taken from query string (`/cache/?key=foo`):

    location /cache/ {
        set $couchbase_key $arg_key;
        couchbase_pass;
    }

Or key can be fixed string:

    location /cache/ {
        set $couchbase_key 'foo';
        couchbase_pass;
    }

* * *

<a name="set-couchbase_val"></a>
<table>
  <tr>
    <td><strong>syntax:</strong></td>
    <td><code><strong>set $couchbase_val</strong> <i>value</i>;</code></td>
  </tr>
  <tr>
    <td><strong>default:</strong></td>
    <td>-</td>
  </tr>
  <tr>
    <td><strong>severity:</strong></td>
    <td>optional</td>
  </tr>
</table>

Picks the value for the document in this location. For example, value
might be taken from query string (`/cache/?value=foo%0a`):

    location /cache/ {
        set $couchbase_val $arg_val;
        couchbase_pass;
    }

Or value can be fixed string:

    location /cache/ {
        set $couchbase_val 'foo%a';
        couchbase_pass;
    }

Note, that if the value specified by `$couchbase_key`, then it will be
considered URL-encoded, and will be decoded back.

* * *

<a name="set-couchbase_cas"></a>
<table>
  <tr>
    <td><strong>syntax:</strong></td>
    <td><code><strong>set $couchbase_cas</strong> <i>value</i>;</code></td>
  </tr>
  <tr>
    <td><strong>default:</strong></td>
    <td>-</td>
  </tr>
  <tr>
    <td><strong>severity:</strong></td>
    <td>optional</td>
  </tr>
</table>

This variable stores CAS value of the document. This value changes on
each mutation of the document. Therefore it can be used for optimistic
locking.

    location /cache/ {
        set $couchbase_key $arg_key;
        set $couchbase_val $arg_val;
        set $couchbase_cmd $arg_cmd;
        set $couchbase_cas $arg_cas;
        couchbase_pass;
        add_header X-CAS $couchbase_cas;
    }

With configuration above, the server will set header
<code>X-CAS</code> with actual CAS value. This value can be used for
subsequent updates, and if someone managed to changed it before, the
server will respond with code <code>409 Conflict</code>, so that the
client have to update local document and try again with new CAS.

## System Requirements

This module has been tested with nginx 1.3.7.

## Download

Last version is 0.2.0: [nginx-couchbase-module-0.2.0.tar.gz][7].

Project repository: [https://github.com/couchbaselabs/couchbase-nginx-module][8]

## Usage

Create build directory, download and unpack all dependencies there:

    mkdir nginx-couchbase
    cd nginx-couchbase
    wget http://nginx.org/download/nginx-1.3.7.tar.gz
    wget http://packages.couchbase.com/clients/c/libcouchbase-2.0.3nginx2.tar.gz
    wget http://packages.couchbase.com/clients/c/nginx-couchbase-module-0.2.0.tar.gz
    for i in *.tar.gz; do tar xvf $i; done

The following steps describe how to install nginx with module into the
directory `/opt/nginx-couchbase`:

    export PREFIX=/opt/nginx-couchbase

    cd libcouchbase-2.0.3nginx2
    ./configure --prefix=$PREFIX --enable-debug --disable-plugins --disable-tests --disable-couchbasemock
    make && sudo make install
    cd ..

    cd nginx-1.3.7
    export LIBCOUCHBASE_INCLUDE=$PREFIX/include
    export LIBCOUCHBASE_LIB=$PREFIX/lib
    ./configure --prefix=$PREFIX --with-debug --add-module=../nginx-couchbase-module-0.2.0
    make && sudo make install


[1]: http://couchbase.com/download
[2]: http://www.nginx.ru/
[3]: #couchbase_pass
[4]: #set-couchbase_cmd
[5]: #set-couchbase_key
[6]: #set-couchbase_val
[7]: http://packages.couchbase.com/clients/c/nginx-couchbase-module-0.2.0.tar.gz
[8]: https://github.com/couchbaselabs/couchbase-nginx-module
