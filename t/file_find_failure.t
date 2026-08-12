# vi:ft=

# Regression test for read_fileurl()'s "!file_find" error log call.
#
# It used to always print the global `Path`, even though the value
# actually passed to file_find() as `path` is NULL for url2pdf/url2ps
# (only file2pdf/file2ps pass Path). Fixing that naively to log `path`
# directly introduced a real crash: nginx's own "%s" formatter
# (ngx_sprintf_str in src/core/ngx_string.c) dereferences the pointer
# unconditionally, with no NULL check, so logging a NULL path segfaults
# the worker. The actual fix guards it with `path ? path : ""`.
#
# This sends the same request twice (repeat_each) against a url2ps
# target that always fails file_find() (path is NULL there), on
# separate connections but the same long-lived nginx-under-test
# process. In single-process test mode a crashed worker takes the
# whole process (and its listening socket) down with it, so the second
# request would fail with connection refused rather than getting a
# clean 500 - that's what would have caught the segfault this guards
# against.

use lib 'lib';
use Test::Nginx::Socket;

repeat_each(2);

plan tests => repeat_each() * 2 * blocks();

no_long_string();

run_tests();

__DATA__

=== TEST 1: url2ps against a target that fails file_find() does not crash the worker
--- main_config
    load_module /etc/nginx/modules/ngx_http_htmldoc_module.so;
--- config
    location /url2ps {
        url2ps "not-a-valid-url-at-all";
    }
--- request
GET /url2ps
--- error_code: 500
--- error_log
!file_find("", "not-a-valid-url-at-all")
