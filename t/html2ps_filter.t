# vi:ft=

# Regression test for the multi-buffer body corruption bug in
# ngx_chain_add_copy_buf() (used only by the html2ps;/html2pdf;
# auto-filter mode - bare directive, no arguments - to buffer a
# proxied response body until last_buf arrives). It used to alias the
# source buffer's memory instead of actually copying it; once the
# proxy module recycled an early buffer to receive more upstream data
# - forced here with a proxy_buffers pool smaller than the body,
# fed through small upstream reads via output_buffers - the
# accumulated body silently dropped and reordered chunks.
#
# The body is checked with a custom callback (add_response_body_check)
# instead of --- response_body_like: Test::Nginx::Socket inlines the
# whole matched body into the TAP result line's own text, and this
# body is large/binary PS content that reliably corrupts the TAP
# stream if embedded that way (see t/url2ps.t for the same lesson
# learned there).

use lib 'lib';
use Test::Nginx::Socket;

my $expected_letters = join('', map { chr(65 + $_ % 26) x 32 } (0 .. 79));

add_response_body_check(sub {
    my ($block, $body, $req_idx, $repeated_req_idx, $dry_run) = @_;
    return if $dry_run;
    my $name = $block->name;
    my ($letters) = $body =~ /\(([A-Z]{500,})\)/;
    $letters = '' if !defined $letters;
    Test::More::is(length($letters), length($expected_letters),
        "$name - body letters length matches (req $repeated_req_idx)");
    Test::More::ok($letters eq $expected_letters,
        "$name - body letters uncorrupted (req $repeated_req_idx)");
});

plan tests => repeat_each() * 4 * blocks();

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
--- timeout: 10
