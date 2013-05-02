# vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

$ENV{TEST_NGINX_COUCHBASE_HOST} ||= '127.0.0.1:8091';

plan tests => 62;
run_tests();

__DATA__

=== TEST 1: set only
--- config
    location /cb {
        set $couchbase_cmd $arg_cmd;
        set $couchbase_key $arg_key;
        set $couchbase_val $arg_val;
        couchbase_pass $TEST_NGINX_COUCHBASE_HOST;
    }
--- request eval
my $key = "test1_" . time();
"GET /cb?cmd=set&key=$key&val=blah"
--- error_code: 201
--- response_body

=== TEST 2: add only
--- config
    location /cb {
        set $couchbase_cmd $arg_cmd;
        set $couchbase_key $arg_key;
        set $couchbase_val $arg_val;
        couchbase_pass $TEST_NGINX_COUCHBASE_HOST;
    }
--- request eval
my $key = "test2_" . time();
"GET /cb?cmd=add&key=$key&val=blah"
--- error_code: 201
--- response_body

=== TEST 3: set and get
--- config
    location /cb {
        set $couchbase_cmd $arg_cmd;
        set $couchbase_key $arg_key;
        set $couchbase_val $arg_val;
        couchbase_pass $TEST_NGINX_COUCHBASE_HOST;
    }
--- request eval
my $key = "test3_" . time();
[
    "GET /cb?cmd=set&key=$key&val=blah",
    "GET /cb?cmd=get&key=$key"
]
--- error_code eval
[
    201,
    200
]
--- response_body eval
[
    "",
    "blah"
]

=== TEST 4: set and delete
--- config
    location /cb {
        set $couchbase_cmd $arg_cmd;
        set $couchbase_key $arg_key;
        set $couchbase_val $arg_val;
        couchbase_pass $TEST_NGINX_COUCHBASE_HOST;
    }
--- request eval
my $key = "test4_" . time();
[
    "GET /cb?cmd=set&key=$key&val=blah",
    "GET /cb?cmd=delete&key=$key"
]
--- error_code eval
[
    201,
    200
]
--- response_body eval
[
    "",
    ""
]

=== TEST 5: add after set
--- config
    location /cb {
        set $couchbase_cmd $arg_cmd;
        set $couchbase_key $arg_key;
        set $couchbase_val $arg_val;
        couchbase_pass $TEST_NGINX_COUCHBASE_HOST;
    }
--- request eval
my $key = "test5_" . time();
[
    "GET /cb?cmd=set&key=$key&val=blah",
    "GET /cb?cmd=add&key=$key&val=blah2",
    "GET /cb?cmd=get&key=$key",
]
--- error_code eval
[
    201,
    409,
    200
]
--- response_body eval
[
    "",
    '{"error":"key_eexists","reason":"Key exists (with a different CAS value)"}',
    "blah"
]

=== TEST 6: handle URL encoding properly
--- config
    location /cb {
        set $couchbase_cmd $arg_cmd;
        set $couchbase_key $arg_key;
        set $couchbase_val $arg_val;
        couchbase_pass $TEST_NGINX_COUCHBASE_HOST;
    }
--- request eval
my $key = "test6_" . time();
[
    "GET /cb?cmd=set&key=$key&val=foo%20bar",
    "GET /cb?cmd=get&key=$key"
]
--- error_code eval
[
    201,
    200
]
--- response_body eval
[
    "",
    "foo bar"
]

=== TEST 7: use REST-like interface
--- config
    location /cb {
        couchbase_pass $TEST_NGINX_COUCHBASE_HOST;
    }
--- request eval
my $key = "test7_" . time();
[
    "POST /cb/$key\n\r\n\rhello world",
    "GET /cb/$key",
    "PUT /cb/$key\n\r\n\rHello, world!",
    "GET /cb/$key",
    "DELETE /cb/$key",
]
--- error_code eval
[
    201,
    200,
    201,
    200,
    200
]
--- response_body eval
[
    "",
    "hello world",
    "",
    "Hello, world!",
    ""
]

=== TEST 8: returns 404 for unexisting keys
--- config
    location /cb {
        set $couchbase_cmd $arg_cmd;
        set $couchbase_key $arg_key;
        set $couchbase_val $arg_val;
        couchbase_pass $TEST_NGINX_COUCHBASE_HOST;
    }
--- request eval
my $key = "test8_" . time();
[
    "GET /cb/$key",
    "GET /cb/cmd=get&key=$key"
]
--- error_code eval
[
    404,
    404
]
--- response_body eval
[
    '{"error":"key_enoent","reason":"No such key"}',
    '{"error":"key_enoent","reason":"No such key"}'
]

=== TEST 9: strip location name in the URI key
--- config
    location /cb/ {
        set $couchbase_cmd $arg_cmd;
        set $couchbase_key $arg_key;
        set $couchbase_val $arg_val;
        couchbase_pass $TEST_NGINX_COUCHBASE_HOST;
    }
--- request eval
my $key = "test9_" . time();
[
    "GET /cb/?cmd=set&key=$key&val=value",
    "GET /cb/$key"
]
--- error_code eval
[
    201,
    200
]
--- response_body eval
[
    "",
    "value"
]

=== TEST 10: replace only
--- config
    location /cb {
        set $couchbase_cmd $arg_cmd;
        set $couchbase_key $arg_key;
        set $couchbase_val $arg_val;
        couchbase_pass $TEST_NGINX_COUCHBASE_HOST;
    }
--- request eval
my $key = "test10_" . time();
"GET /cb?cmd=replace&key=$key&val=blah"
--- error_code: 404
--- response_body eval
'{"error":"key_enoent","reason":"No such key"}'

=== TEST 11: replace after set
--- config
    location /cb {
        set $couchbase_cmd $arg_cmd;
        set $couchbase_key $arg_key;
        set $couchbase_val $arg_val;
        couchbase_pass $TEST_NGINX_COUCHBASE_HOST;
    }
--- request eval
my $key = "test11_" . time();
[
    "GET /cb?cmd=set&key=$key&val=blah",
    "GET /cb?cmd=replace&key=$key&val=blah2",
    "GET /cb?cmd=get&key=$key",
]
--- error_code eval
[
    201,
    201,
    200
]
--- response_body eval
[
    "",
    "",
    "blah2"
]

=== TEST 12: append
--- config
    location /cb {
        set $couchbase_cmd $arg_cmd;
        set $couchbase_key $arg_key;
        set $couchbase_val $arg_val;
        couchbase_pass $TEST_NGINX_COUCHBASE_HOST;
    }
--- request eval
my $key = "test12_" . time();
[
    "GET /cb?cmd=set&key=$key&val=aaa",
    "GET /cb?cmd=append&key=$key&val=bbb",
    "GET /cb?cmd=get&key=$key",
]
--- error_code eval
[
    201,
    201,
    200
]
--- response_body eval
[
    "",
    "",
    "aaabbb"
]

=== TEST 13: prepend
--- config
    location /cb {
        set $couchbase_cmd $arg_cmd;
        set $couchbase_key $arg_key;
        set $couchbase_val $arg_val;
        couchbase_pass $TEST_NGINX_COUCHBASE_HOST;
    }
--- request eval
my $key = "test5_" . time();
[
    "GET /cb?cmd=set&key=$key&val=aaa",
    "GET /cb?cmd=prepend&key=$key&val=bbb",
    "GET /cb?cmd=get&key=$key",
]
--- error_code eval
[
    201,
    201,
    200
]
--- response_body eval
[
    "",
    "",
    "bbbaaa"
]

=== TEST 14: it sets header with CAS
--- config
    location /cb {
        set $couchbase_cmd $arg_cmd;
        set $couchbase_key $arg_key;
        set $couchbase_val $arg_val;
        couchbase_pass $TEST_NGINX_COUCHBASE_HOST;
        add_header X-CAS $couchbase_cas;
    }
--- request eval
my $key = "test14_" . time();
"GET /cb?cmd=set&key=$key&val=blah"
--- error_code: 201
--- response_headers_like
X-CAS: \d+

