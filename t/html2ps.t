# vi:ft=

# Coverage for the html2ps/html2pdf handler mode (directive given one
# or more literal string arguments), which had no dedicated test at
# all despite being the module's simplest and most common form.

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each() * 11;

no_long_string();

run_tests();

__DATA__

=== TEST 1: html2ps with a single document
--- main_config
    load_module /etc/nginx/modules/ngx_http_htmldoc_module.so;
--- config
    location /html2ps {
        html2ps "hello world";
    }
--- request
GET /html2ps
--- response_headers
Content-Type: application/ps


=== TEST 2: html2pdf with a single document
--- main_config
    load_module /etc/nginx/modules/ngx_http_htmldoc_module.so;
--- config
    location /html2pdf {
        html2pdf "hello world";
    }
--- request
GET /html2pdf
--- response_headers
Content-Type: application/pdf


=== TEST 3: html2pdf with several documents (multi-append path)
--- main_config
    load_module /etc/nginx/modules/ngx_http_htmldoc_module.so;
--- config
    location /html2pdf {
        html2pdf "one" "two" "three" "four";
    }
--- request
GET /html2pdf
--- response_headers
Content-Type: application/pdf


=== TEST 4: HEAD request returns headers only, no body
--- main_config
    load_module /etc/nginx/modules/ngx_http_htmldoc_module.so;
--- config
    location /html2ps {
        html2ps "hello world";
    }
--- request
HEAD /html2ps
--- response_headers
Content-Type: application/ps
--- response_body:


=== TEST 5: Content-Length reflects the generated body length
--- main_config
    load_module /etc/nginx/modules/ngx_http_htmldoc_module.so;
--- config
    location /html2ps {
        html2ps "hello world";
    }
--- request
GET /html2ps
--- response_headers_like
Content-Length: \d+
