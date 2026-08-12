# vi:ft=

# Coverage for config-time behavior: rejecting a duplicate directive in
# the same location, and merge_loc_conf inheritance into nested
# locations that don't repeat the directive themselves.
#
# Inheritance behaves differently depending on which of the module's
# two modes is in play, which is worth locking in explicitly:
#
#  - Handler mode (the directive given literal arguments, e.g.
#    html2ps "text";) dispatches via ngx_http_core_loc_conf_t's own
#    "handler" field, which nginx sets per location block and does
#    NOT propagate to nested locations that don't set it themselves -
#    so a nested location gets nginx's normal (non-htmldoc) handling.
#  - Filter mode (the bare directive, e.g. html2ps;, auto-converting
#    whatever the location would otherwise have served) hooks the
#    global header/body filter chain and reads the merged location
#    config at request time via ngx_http_get_module_loc_conf(), which
#    genuinely does inherit into nested locations via
#    ngx_http_htmldoc_merge_loc_conf.

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each() * 5;

no_long_string();

run_tests();

__DATA__

=== TEST 1: a second htmldoc directive in the same location is rejected as a duplicate
--- main_config
    load_module /etc/nginx/modules/ngx_http_htmldoc_module.so;
--- config
    location /dup {
        file2pdf "a";
        file2ps "b";
    }
--- request
GET /dup
--- must_die
--- error_log
is duplicate


=== TEST 2: handler mode does NOT propagate to a nested location (nginx's own per-location handler dispatch, not this module's doing)
--- main_config
    load_module /etc/nginx/modules/ngx_http_htmldoc_module.so;
--- config
    location /outer {
        html2ps "hello world";
        location /outer/inner {
        }
    }
--- request
GET /outer/inner
--- error_code: 404


=== TEST 3: filter mode DOES propagate to a nested location via merge_loc_conf
--- main_config
    load_module /etc/nginx/modules/ngx_http_htmldoc_module.so;
--- config
    location /outer {
        html2ps;
        location /outer/inner {
            default_type text/html;
            return 200 "hello world";
        }
    }
--- request
GET /outer/inner
--- response_headers
Content-Type: application/ps
