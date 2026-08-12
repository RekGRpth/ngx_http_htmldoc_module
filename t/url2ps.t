# vi:ft=

# Regression test for the url2ps/url2pdf output-type mixup: the "url2ps"
# directive's command table entry used to be initialized with
# OUTPUT_TYPE_PDF (copy-pasted from url2pdf), so it silently produced a
# PDF document instead of a PostScript one, contradicting both its name
# and README.md. file2ps/file2pdf/html2ps/html2pdf were not affected,
# since each of those has its own separate command table entry. The
# Content-Type header is exactly what the bug got wrong, so that alone
# is what this test checks.
#
# Deliberately does NOT match the (real, ~170KB, mostly binary) response
# body with --- response_body_like: Test::Nginx::Socket inlines the
# whole matched body into the TAP result line's own text, and binary
# PS/PDF content routinely contains raw bytes that TAP::Parser misreads
# as extra protocol lines (stray "ok"/"not ok"/plan lines), corrupting
# the test stream (phantom extra tests, bogus exit(255)). Confirmed by
# hand that url2ps's/url2pdf's bodies do start with "%!PS-Adobe"/"%PDF"
# respectively and are valid.
#
# url2ps makes htmldoc perform a blocking HTTP fetch from inside the
# nginx worker, so the fetch target must be a process other than the
# nginx-under-test itself (fetching from itself would deadlock the
# single worker: it would be blocked waiting on the fetch while also
# being the only process that could ever accept and answer it). A tiny
# standalone backend is started (via the shell's own "&", not Perl's
# fork()) for that reason.

use lib 'lib';
use Test::Nginx::Socket;
use FindBin;

my $backend_port = 21593;
my $html_dir = "$FindBin::Bin/html";

my $backend_cmd = "python3 -m http.server $backend_port --directory '$html_dir' "
    . "--bind 127.0.0.1 </dev/null >/dev/null 2>&1 & echo \$!";
my $backend_pid = `$backend_cmd`;
chomp $backend_pid;
sleep 1;

END {
    kill 'TERM', $backend_pid if $backend_pid;
}

plan tests => repeat_each() * 4;

no_long_string();

run_tests();

__DATA__

=== TEST 1: url2ps produces a PostScript document (Content-Type: application/ps)
--- main_config
    load_module /etc/nginx/modules/ngx_http_htmldoc_module.so;
--- config
    location /url2ps {
        url2ps "http://127.0.0.1:21593/plain.html";
    }
--- request
GET /url2ps
--- response_headers
Content-Type: application/ps
--- timeout: 10


=== TEST 2: url2ps with several URLs (multi-document path)
--- main_config
    load_module /etc/nginx/modules/ngx_http_htmldoc_module.so;
--- config
    location /url2ps {
        url2ps "http://127.0.0.1:21593/plain.html" "http://127.0.0.1:21593/plain2.html";
    }
--- request
GET /url2ps
--- response_headers
Content-Type: application/ps
--- timeout: 10
