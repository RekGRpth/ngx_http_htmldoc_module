# vi:ft=

# Companion to url2ps.t: makes sure the url2ps fix (see url2ps.t for the
# bug it regresses against) did not accidentally break url2pdf, which
# was already correct before the fix.
#
# See url2ps.t for why the response body is not matched with
# --- response_body_like here (it corrupts the TAP stream for large
# binary bodies), and why the backend is a real, separate process
# started via the shell rather than Perl's fork().

use lib 'lib';
use Test::Nginx::Socket;
use FindBin;

my $backend_port = 21594;
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

=== TEST 1: url2pdf still produces a PDF document (Content-Type: application/pdf)
--- main_config
    load_module /etc/nginx/modules/ngx_http_htmldoc_module.so;
--- config
    location /url2pdf {
        url2pdf "http://127.0.0.1:21594/plain.html";
    }
--- request
GET /url2pdf
--- response_headers
Content-Type: application/pdf
--- timeout: 10


=== TEST 2: url2pdf with several URLs (multi-document path)
--- main_config
    load_module /etc/nginx/modules/ngx_http_htmldoc_module.so;
--- config
    location /url2pdf {
        url2pdf "http://127.0.0.1:21594/plain.html" "http://127.0.0.1:21594/plain2.html";
    }
--- request
GET /url2pdf
--- response_headers
Content-Type: application/pdf
--- timeout: 10
