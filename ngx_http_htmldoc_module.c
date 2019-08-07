#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "htmldoc.h"

typedef struct {
    ngx_http_complex_value_t *input_data;
} ngx_http_htmldoc_loc_conf_t;

ngx_module_t ngx_http_htmldoc_module;

static ngx_int_t ngx_http_htmldoc_handler(ngx_http_request_t *r) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_htmldoc_handler");
    if (!(r->method & NGX_HTTP_GET)) return NGX_HTTP_NOT_ALLOWED;
    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK && rc != NGX_AGAIN) return rc;
    ngx_http_htmldoc_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_htmldoc_module);
    rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
    ngx_str_t input_data;
    char *output_data = NULL;
    if (ngx_http_complex_value(r, conf->input_data, &input_data) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); goto ret; }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "input_data = %V", &input_data);
    FILE *in = fmemopen(input_data.data, input_data.len, "rb");
    if (!in) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!in"); goto ret; }
    size_t output_len = 0;
    FILE *out = open_memstream(&output_data, &output_len);
    if (!out) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!out"); goto fclose; }
    set_out(out);
    htmlSetCharSet("utf-8");
    tree_t *document = htmlAddTree(NULL, MARKUP_FILE, NULL);
    if (!document) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!document"); goto fclose; }
    htmlSetVariable(document, (uchar *)"_HD_FILENAME", (uchar *)"");
    htmlSetVariable(document, (uchar *)"_HD_BASE", (uchar *)".");
    htmlReadFile(document, in, ".");
    htmlFixLinks(document, document, 0);
    pspdf_export(document, NULL);
    htmlDeleteTree(document);
    file_cleanup();
    image_flush_cache();
fclose:
    fclose(in);
//    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "output_data = %s", output_data);
    if (output_len) {
//        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "output_len = %li", output_len);
        ngx_buf_t *buf = ngx_create_temp_buf(r->pool, output_len);
        if (!buf) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!buf"); goto ret; }
        buf->last = ngx_cpymem(buf->last, output_data, output_len);
        buf->last_buf = (r == r->main) ? 1 : 0;
        buf->last_in_chain = 1;
        ngx_chain_t ch = {.buf = buf, .next = NULL};
        ngx_str_set(&r->headers_out.content_type, "application/pdf");
        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = output_len;
        rc = ngx_http_send_header(r);
        ngx_http_weak_etag(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only); else rc = ngx_http_output_filter(r, &ch);
    }
ret:
    if (output_data) free(output_data);
    return rc;
}

static char *ngx_http_htmldoc_convert_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_htmldoc_handler;
    return ngx_http_set_complex_value_slot(cf, cmd, conf);
}

static ngx_command_t ngx_http_htmldoc_commands[] = {
  { .name = ngx_string("htmldoc"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_http_htmldoc_convert_set,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_htmldoc_loc_conf_t, input_data),
    .post = NULL },
    ngx_null_command
};

static void *ngx_http_htmldoc_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_htmldoc_loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_htmldoc_loc_conf_t));
    if (!conf) return NGX_CONF_ERROR;
    return conf;
}

static char *ngx_http_htmldoc_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_htmldoc_loc_conf_t *prev = parent;
    ngx_http_htmldoc_loc_conf_t *conf = child;
    if (!conf->input_data) conf->input_data = prev->input_data;
    return NGX_CONF_OK;
}

static ngx_http_module_t ngx_http_htmldoc_module_ctx = {
    .preconfiguration = NULL,
    .postconfiguration = NULL,
    .create_main_conf = NULL,
    .init_main_conf = NULL,
    .create_srv_conf = NULL,
    .merge_srv_conf = NULL,
    .create_loc_conf = ngx_http_htmldoc_create_loc_conf,
    .merge_loc_conf = ngx_http_htmldoc_merge_loc_conf
};

ngx_module_t ngx_http_htmldoc_module = {
    NGX_MODULE_V1,
    .ctx = &ngx_http_htmldoc_module_ctx,
    .commands = ngx_http_htmldoc_commands,
    .type = NGX_HTTP_MODULE,
    .init_master = NULL,
    .init_module = NULL,
    .init_process = NULL,
    .init_thread = NULL,
    .exit_thread = NULL,
    .exit_process = NULL,
    .exit_master = NULL,
    NGX_MODULE_V1_PADDING
};
