# vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

repeat_each(1);

plan tests => 2 * repeat_each() * blocks();

$ENV{TEST_NGINX_COUCHBASE_HOST} ||= '127.0.0.1:8091';

#no_shuffle();

run_tests();

__DATA__

=== TEST 1: set only
--- config
    location /cb {
        set $couchbase_cmd $arg_cmd;
        set $couchbase_key $arg_key;
        set $couchbase_value $arg_val;
        couchbase_pass $TEST_NGINX_COUCHBASE_HOST;
    }
--- request
GET /cb?key=foo&cmd=set&val=blah
--- response_body eval
"STORED\r\n"
--- error_code: 201
