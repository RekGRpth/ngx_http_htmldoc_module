#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "htmldoc.h"

enum {
    INPUT_TYPE_HTML = 0,
    INPUT_TYPE_URL
};

enum {
    OUTPUT_TYPE_PDF = 0,
    OUTPUT_TYPE_PS
};

typedef struct {
    ngx_http_complex_value_t *input_data;
    ngx_uint_t input_type;
    ngx_uint_t output_type;
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
//    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "input_data = %V", &input_data);
    _htmlPPI = 72.0f * _htmlBrowserWidth / (PageWidth - PageLeft - PageRight);
    htmlSetCharSet("utf-8");
    tree_t *document = htmlAddTree(NULL, MARKUP_FILE, NULL);
    if (!document) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!document"); goto ret; }
    if (conf->input_type == INPUT_TYPE_HTML) {
        FILE *in = fmemopen(input_data.data, input_data.len, "rb");
        if (!in) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!in"); goto htmlDeleteTree; }
        htmlSetVariable(document, (uchar *)"_HD_FILENAME", (uchar *)"");
        htmlSetVariable(document, (uchar *)"_HD_BASE", (uchar *)".");
        htmlReadFile2(document, in, ".");
        fclose(in);
    } else if (conf->input_type == INPUT_TYPE_URL) {
        char *url = ngx_pcalloc(r->pool, (input_data.len + 1));
        if (!url) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!url"); goto htmlDeleteTree; }
        ngx_memcpy(url, input_data.data, input_data.len);
        const char *realname = file_find(NULL, url);
        if (!realname) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!realname"); goto htmlDeleteTree; }
        FILE *in = fopen(realname, "rb");
        if (!in) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!in"); goto htmlDeleteTree; }
        const char *base = file_directory(url);
        if (!base) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!base"); fclose(in); goto htmlDeleteTree; }
        htmlSetVariable(document, (uchar *)"_HD_URL", (uchar *)url);
        htmlSetVariable(document, (uchar *)"_HD_FILENAME", (uchar *)file_basename(url));
        htmlSetVariable(document, (uchar *)"_HD_BASE", (uchar *)base);
        htmlReadFile2(document, in, base);
        fclose(in);
    }
    htmlFixLinks(document, document, 0);
    if (conf->output_type == OUTPUT_TYPE_PDF) {
        PSLevel = 0;
    } else if (conf->output_type == OUTPUT_TYPE_PS) {
        PSLevel = 3;
    }
    size_t output_len = 0;
    FILE *out = open_memstream(&output_data, &output_len);
    if (!out) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!out"); goto htmlDeleteTree; }
    pspdf_export_out(document, NULL, out);
    ngx_buf_t *buf = ngx_create_temp_buf(r->pool, output_len);
    if (!buf) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!buf"); goto free; }
    buf->last = ngx_cpymem(buf->last, output_data, output_len);
    buf->last_buf = (r == r->main) ? 1 : 0;
    buf->last_in_chain = 1;
    ngx_chain_t ch = {.buf = buf, .next = NULL};
    if (conf->output_type == OUTPUT_TYPE_PDF) {
        ngx_str_set(&r->headers_out.content_type, "application/pdf");
    } else if (conf->output_type == OUTPUT_TYPE_PS) {
        ngx_str_set(&r->headers_out.content_type, "application/ps");
    }
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = output_len;
    rc = ngx_http_send_header(r);
    ngx_http_weak_etag(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only); else rc = ngx_http_output_filter(r, &ch);
free:
    free(output_data);
htmlDeleteTree:
    htmlDeleteTree(document);
    file_cleanup();
    image_flush_cache();
ret:
    return rc;
}

static char *ngx_http_htmldoc_convert_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    char *p = conf;
    ngx_uint_t *input_type = (ngx_uint_t *) (p + offsetof(ngx_http_htmldoc_loc_conf_t, input_type));
    ngx_uint_t *output_type = (ngx_uint_t *) (p + offsetof(ngx_http_htmldoc_loc_conf_t, output_type));
    if (*output_type != NGX_CONF_UNSET_UINT) return "is duplicate";
    ngx_str_t *value = cf->args->elts;
    if (!ngx_strncasecmp(value[0].data, (u_char *)"html2pdf", sizeof("html2pdf") - 1)) {
        *input_type = INPUT_TYPE_HTML;
        *output_type = OUTPUT_TYPE_PDF;
    } else if (!ngx_strncasecmp(value[0].data, (u_char *)"html2ps", sizeof("html2ps") - 1)) {
        *input_type = INPUT_TYPE_HTML;
        *output_type = OUTPUT_TYPE_PS;
    } else if (!ngx_strncasecmp(value[0].data, (u_char *)"url2pdf", sizeof("url2pdf") - 1)) {
        *input_type = INPUT_TYPE_URL;
        *output_type = OUTPUT_TYPE_PDF;
    } else if (!ngx_strncasecmp(value[0].data, (u_char *)"url2ps", sizeof("url2ps") - 1)) {
        *input_type = INPUT_TYPE_URL;
        *output_type = OUTPUT_TYPE_PS;
    }
    ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_htmldoc_handler;
    return ngx_http_set_complex_value_slot(cf, cmd, conf);
}

static ngx_command_t ngx_http_htmldoc_commands[] = {
  { .name = ngx_string("html2pdf"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_http_htmldoc_convert_set,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_htmldoc_loc_conf_t, input_data),
    .post = NULL },
  { .name = ngx_string("html2ps"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_http_htmldoc_convert_set,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_htmldoc_loc_conf_t, input_data),
    .post = NULL },
  { .name = ngx_string("url2pdf"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_http_htmldoc_convert_set,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_htmldoc_loc_conf_t, input_data),
    .post = NULL },
  { .name = ngx_string("url2ps"),
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
    conf->input_type = NGX_CONF_UNSET_UINT;
    conf->output_type = NGX_CONF_UNSET_UINT;
    return conf;
}

static char *ngx_http_htmldoc_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_htmldoc_loc_conf_t *prev = parent;
    ngx_http_htmldoc_loc_conf_t *conf = child;
    if (!conf->input_data) conf->input_data = prev->input_data;
    ngx_conf_merge_uint_value(conf->input_type, prev->input_type, NGX_CONF_UNSET_UINT);
    ngx_conf_merge_uint_value(conf->output_type, prev->output_type, NGX_CONF_UNSET_UINT);
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
