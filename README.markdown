# nginx-couchbase-module

Hi, this is couchbase module for nginx. Here is short build
instructions. More docs are coming.

Your test machine should have C compiler installed, as well as
autotools.

    mkdir couchbase-nginx-module
    cd couchbase-nginx-module
    repo init -u git://github.com/avsej/manifests.git -b nginx -m nginx.xml
    repo sync
    make


The repo represents squashed commit for now, which probably will be
fixed later. Keep tuned.
