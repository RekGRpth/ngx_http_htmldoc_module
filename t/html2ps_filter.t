# vi:ft=

# Coverage for the html2ps;/html2pdf; auto-filter mode (bare
# directive, no arguments, converting whatever the location would
# otherwise have served): the multi-buffer body corruption regression,
# that non-HTML responses are passed through untouched, and the
# simple single-buffer happy path.
#
# TEST 1 is a regression test for ngx_chain_add_copy_buf(), the only
# path that ever buffers a body this way. It used to alias the source
# buffer's memory instead of actually copying it; once the proxy
# module recycled an early buffer to receive more upstream data -
# forced here with a proxy_buffers pool smaller than the body, fed
# through small upstream reads via output_buffers - the accumulated
# body silently dropped and reordered chunks.
#
# Its body is checked with a custom callback (add_response_body_check),
# gated on the custom --- check_letters section so it only runs for
# blocks that want it, instead of --- response_body_like: Test::Nginx::
# Socket inlines the whole matched body into the TAP result line's own
# text, and this body is large/binary PS content that reliably
# corrupts the TAP stream if embedded that way (see t/url2ps.t for the
# same lesson learned there).

use lib 'lib';
use Test::Nginx::Socket;

my $expected_letters = join('', map { chr(65 + $_ % 26) x 32 } (0 .. 79));

add_response_body_check(sub {
    my ($block, $body, $req_idx, $repeated_req_idx, $dry_run) = @_;
    return if $dry_run;
    return if !defined $block->check_letters;
    my $name = $block->name;
    my ($letters) = $body =~ /\(([A-Z]{500,})\)/;
    $letters = '' if !defined $letters;
    Test::More::is(length($letters), length($expected_letters),
        "$name - body letters length matches (req $repeated_req_idx)");
    Test::More::ok($letters eq $expected_letters,
        "$name - body letters uncorrupted (req $repeated_req_idx)");
});

plan tests => repeat_each() * 9;

no_long_string();

run_tests();

__DATA__

=== TEST 1: html2ps auto-filter mode reassembles a fragmented proxied body without corruption
--- main_config
    load_module /var/cache/nginx/src/nginx/objs/ngx_http_htmldoc_module.so;
--- config eval
my $body = '<html><head><title>t</title></head><body>'
    . join('', map { chr(65 + $_ % 26) x 32 } (0 .. 79))
    . '</body></html>';
<<"END";
    location /origin.html {
        output_buffers 1 16;
        sendfile off;
        default_type text/html;
        return 200 '$body';
    }
    location /filtered {
        html2ps;
        proxy_buffering on;
        proxy_buffer_size 1024;
        proxy_buffers 12 128;
        proxy_busy_buffers_size 1024;
        proxy_pass http://127.0.0.1:\$TEST_NGINX_SERVER_PORT/origin.html;
    }
END
--- request
GET /filtered
--- response_headers
Content-Type: application/ps
--- check_letters: 1
--- timeout: 10


=== TEST 2: html2ps; leaves a non-text/html response untouched
--- main_config
    load_module /var/cache/nginx/src/nginx/objs/ngx_http_htmldoc_module.so;
--- config
    location /plain {
        html2ps;
        default_type text/plain;
        return 200 "just plain text, not HTML";
    }
--- request
GET /plain
--- response_headers
Content-Type: text/plain
--- response_body: just plain text, not HTML


=== TEST 3: html2ps; converts a simple, non-fragmented text/html response (single-buffer happy path)
--- main_config
    load_module /var/cache/nginx/src/nginx/objs/ngx_http_htmldoc_module.so;
--- config
    location /simple {
        html2ps;
        default_type text/html;
        return 200 "<html><head><title>t</title></head><body>hello world</body></html>";
    }
--- request
GET /simple
--- response_headers
Content-Type: application/ps
