# vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

repeat_each(1);

plan tests => 2 * repeat_each() * blocks();
run_tests();

__DATA__

=== TEST 1: version
--- config
    location /version {
        couchbase;
    }
--- request
GET /version
--- error_code: 200
--- response_body_like: \d\.\d\.\d
--- timeout: 10
