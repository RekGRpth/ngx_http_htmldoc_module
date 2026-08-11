# vi:ft=

# Regression test for the file2ps/file2pdf path-traversal guard added to
# read_fileurl(): the guard resolves both the target file and the
# configured search root (the global `Path`, from libhtmldoc) via
# realpath() and rejects the request unless the target stays inside
# that root. But this module has no directive that ever sets `Path`,
# so in practice it is always empty - and realpath("") fails. The guard
# is therefore only applied when Path is non-empty, precisely so an
# empty (unconfigured) Path keeps behaving exactly as it did before the
# guard was added: file2ps/file2pdf given an absolute path must still
# work. That is what this test locks in - it was an actual regression
# caught by hand while writing the guard (an absolute path started
# failing with "!realpath(\"\")" until the path[0] check was added).
#
# The traversal-blocking behavior itself is not exercised here: it only
# activates once Path is non-empty, and there is no config directive to
# set it, so it is not reachable through an nginx-level test at all.

use lib 'lib';
use Test::Nginx::Socket;
use FindBin;

$ENV{TEST_NGINX_HTML_DIR} = "$FindBin::Bin/html";

plan tests => repeat_each() * 6;

no_long_string();

run_tests();

__DATA__

=== TEST 1: file2ps with an absolute path still works with an empty (unconfigured) Path
--- main_config
    load_module /var/cache/nginx/src/nginx/objs/ngx_http_htmldoc_module.so;
--- config
    location /file2ps {
        file2ps "$TEST_NGINX_HTML_DIR/plain.html";
    }
--- request
GET /file2ps
--- response_headers
Content-Type: application/ps


=== TEST 2: file2pdf with an absolute path still works with an empty (unconfigured) Path
--- main_config
    load_module /var/cache/nginx/src/nginx/objs/ngx_http_htmldoc_module.so;
--- config
    location /file2pdf {
        file2pdf "$TEST_NGINX_HTML_DIR/plain.html";
    }
--- request
GET /file2pdf
--- response_headers
Content-Type: application/pdf


=== TEST 3: file2ps against a nonexistent file fails gracefully with 500, not a crash
--- main_config
    load_module /var/cache/nginx/src/nginx/objs/ngx_http_htmldoc_module.so;
--- config
    location /file2ps {
        file2ps "$TEST_NGINX_HTML_DIR/does-not-exist.html";
    }
--- request
GET /file2ps
--- error_code: 500
--- error_log
read_fileurl != NGX_OK
