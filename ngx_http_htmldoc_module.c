#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "htmldoc.h"

enum {
    DATA_TYPE_TEXT = 0,
    DATA_TYPE_ARRAY
};

enum {
    INPUT_TYPE_FILE = 0,
    INPUT_TYPE_HTML,
    INPUT_TYPE_URL
};

enum {
    OUTPUT_TYPE_PDF = 0,
    OUTPUT_TYPE_PS
};

typedef struct {
    ngx_uint_t input;
    ngx_uint_t output;
} ngx_http_htmldoc_type_t;

typedef struct {
    ngx_array_t *data;
    ngx_http_htmldoc_type_t type;
} ngx_http_htmldoc_location_conf_t;

ngx_module_t ngx_http_htmldoc_module;

static ngx_int_t read_fileurl(const u_char *fileurl, tree_t **document, const char *path, ngx_log_t *log) {
    _htmlPPI = 72.0f * _htmlBrowserWidth / (PageWidth - PageLeft - PageRight);
    tree_t *file = htmlAddTree(NULL, MARKUP_FILE, NULL);
    if (!file) { ngx_log_error(NGX_LOG_ERR, log, 0, "!htmlAddTree"); return NGX_ERROR; }
    htmlSetVariable(file, (uchar *)"_HD_URL", (uchar *)fileurl);
    htmlSetVariable(file, (uchar *)"_HD_FILENAME", (uchar *)file_basename((const char *)fileurl));
    const char *realname = file_find(path, (const char *)fileurl);
    if (!realname) { ngx_log_error(NGX_LOG_ERR, log, 0, "!file_find"); return NGX_ERROR; }
    const char *base = file_directory((const char *)fileurl);
    if (!base) { ngx_log_error(NGX_LOG_ERR, log, 0, "!file_directory"); return NGX_ERROR; }
    htmlSetVariable(file, (uchar *)"_HD_BASE", (uchar *)base);
    FILE *in = fopen(realname, "rb");
    if (!in) { ngx_log_error(NGX_LOG_ERR, log, 0, "!fopen"); return NGX_ERROR; }
    htmlReadFile2(file, in, base);
    fclose(in);
    if (!*document) *document = file; else {
        while ((*document)->next) *document = (*document)->next;
        (*document)->next = file;
        file->prev = *document;
    }
    return NGX_OK;
}

static ngx_int_t read_html(u_char *html, size_t len, tree_t **document, ngx_log_t *log) {
    _htmlPPI = 72.0f * _htmlBrowserWidth / (PageWidth - PageLeft - PageRight);
    tree_t *file = htmlAddTree(NULL, MARKUP_FILE, NULL);
    if (!file) { ngx_log_error(NGX_LOG_ERR, log, 0, "!htmlAddTree"); return NGX_ERROR; }
    htmlSetVariable(file, (uchar *)"_HD_FILENAME", (uchar *)"");
    htmlSetVariable(file, (uchar *)"_HD_BASE", (uchar *)".");
    FILE *in = fmemopen(html, len, "rb");
    if (!in) { ngx_log_error(NGX_LOG_ERR, log, 0, "!fmemopen"); return NGX_ERROR; }
    htmlReadFile2(file, in, ".");
    fclose(in);
    if (!*document) *document = file; else {
        while ((*document)->next) *document = (*document)->next;
        (*document)->next = file;
        file->prev = *document;
    }
    return NGX_OK;
}

static ngx_int_t ngx_http_htmldoc_handler(ngx_http_request_t *r) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_htmldoc_handler");
    if (!(r->method & NGX_HTTP_GET)) return NGX_HTTP_NOT_ALLOWED;
    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK && rc != NGX_AGAIN) return rc;
    ngx_http_htmldoc_location_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_htmldoc_module);
    rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
    ngx_str_t output = ngx_null_string;
    tree_t *document = NULL;
    ngx_http_complex_value_t *elts = conf->data->elts;
    for (ngx_uint_t i = 0; i < conf->data->nelts; i++) {
        ngx_str_t data;
        if (ngx_http_complex_value(r, &elts[i], &data) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); goto htmlDeleteTree; }
        switch (conf->type.input) {
            case INPUT_TYPE_FILE: {
                u_char *fileurl = ngx_pnalloc(r->pool, (data.len + 1));
                if (!fileurl) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); goto htmlDeleteTree; }
                (void) ngx_cpystrn(fileurl, data.data, data.len + 1);
                if (read_fileurl(fileurl, &document, Path, r->connection->log) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!read_fileurl"); goto htmlDeleteTree; }
            } break;
            case INPUT_TYPE_HTML: {
                if (read_html(data.data, data.len, &document, r->connection->log) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!read_fileurl"); goto htmlDeleteTree; }
            } break;
            case INPUT_TYPE_URL: {
                u_char *fileurl = ngx_pnalloc(r->pool, (data.len + 1));
                if (!fileurl) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); goto htmlDeleteTree; }
                (void) ngx_cpystrn(fileurl, data.data, data.len + 1);
                if (read_fileurl(fileurl, &document, NULL, r->connection->log) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!read_fileurl"); goto htmlDeleteTree; }
            } break;
        }
    }
    while (document && document->prev) document = document->prev;
    htmlFixLinks(document, document, 0);
    switch (conf->type.output) {
        case OUTPUT_TYPE_PDF: PSLevel = 0; break;
        case OUTPUT_TYPE_PS: PSLevel = 3; break;
    }
    FILE *out = open_memstream((char **)&output.data, &output.len);
    if (!out) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!open_memstream"); goto htmlDeleteTree; }
    pspdf_export_out(document, NULL, out);
    ngx_buf_t *buf = ngx_create_temp_buf(r->pool, output.len);
    if (!buf) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_create_temp_buf"); goto free; }
    ngx_chain_t *chain = ngx_alloc_chain_link(r->pool);
    if (!chain) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_alloc_chain_link"); goto free; }
    chain->buf = buf;
    buf->memory = 1;
    buf->last = ngx_copy(buf->last, output.data, output.len);
    if (buf->last != buf->end) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "buf->last != buf->end"); goto free; }
    chain->next = NULL;
    switch (conf->type.output) {
        case OUTPUT_TYPE_PDF: ngx_str_set(&r->headers_out.content_type, "application/pdf"); break;
        case OUTPUT_TYPE_PS: ngx_str_set(&r->headers_out.content_type, "application/ps"); break;
    }
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = output.len;
    rc = ngx_http_send_header(r);
    ngx_http_weak_etag(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only); else rc = ngx_http_output_filter(r, chain);
free:
    free(output.data);
htmlDeleteTree:
    if (document) htmlDeleteTree(document);
    file_cleanup();
    image_flush_cache();
    return rc;
}

static char *ngx_http_htmldoc_convert_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_htmldoc_location_conf_t *location_conf = conf;
    if (location_conf->data != NGX_CONF_UNSET_PTR) return "is duplicate";
    if (!(location_conf->data = ngx_array_create(cf->pool, 4, sizeof(ngx_http_complex_value_t)))) return "!ngx_array_create";
    ngx_str_t *elts = cf->args->elts;
    for (ngx_uint_t i = 1; i < cf->args->nelts; i++) {
        ngx_http_complex_value_t *cv = ngx_array_push(location_conf->data);
        if (!cv) return "!ngx_array_push";
        ngx_http_compile_complex_value_t ccv = {cf, &elts[i], cv, 0, 0, 0};
        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) return "ngx_http_compile_complex_value != NGX_OK";
    }
    location_conf->type = *(ngx_http_htmldoc_type_t *)cmd->post;
    ngx_http_core_loc_conf_t *core_loc_conf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    core_loc_conf->handler = ngx_http_htmldoc_handler;
    return NGX_CONF_OK;
}

static ngx_command_t ngx_http_htmldoc_commands[] = {
  { .name = ngx_string("file2pdf"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
    .set = ngx_http_htmldoc_convert_set,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_htmldoc_location_conf_t, data),
    .post = &(ngx_http_htmldoc_type_t){ INPUT_TYPE_FILE, OUTPUT_TYPE_PDF } },
  { .name = ngx_string("file2ps"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
    .set = ngx_http_htmldoc_convert_set,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_htmldoc_location_conf_t, data),
    .post = &(ngx_http_htmldoc_type_t){ INPUT_TYPE_FILE, OUTPUT_TYPE_PS } },
  { .name = ngx_string("html2pdf"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
    .set = ngx_http_htmldoc_convert_set,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_htmldoc_location_conf_t, data),
    .post = &(ngx_http_htmldoc_type_t){ INPUT_TYPE_HTML, OUTPUT_TYPE_PDF } },
  { .name = ngx_string("html2ps"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
    .set = ngx_http_htmldoc_convert_set,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_htmldoc_location_conf_t, data),
    .post = &(ngx_http_htmldoc_type_t){ INPUT_TYPE_HTML, OUTPUT_TYPE_PS } },
  { .name = ngx_string("url2pdf"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
    .set = ngx_http_htmldoc_convert_set,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_htmldoc_location_conf_t, data),
    .post = &(ngx_http_htmldoc_type_t){ INPUT_TYPE_URL, OUTPUT_TYPE_PDF } },
  { .name = ngx_string("url2ps"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
    .set = ngx_http_htmldoc_convert_set,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_htmldoc_location_conf_t, data),
    .post = &(ngx_http_htmldoc_type_t){ INPUT_TYPE_URL, OUTPUT_TYPE_PDF } },
    ngx_null_command
};

static void *ngx_http_htmldoc_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_htmldoc_location_conf_t *location_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_htmldoc_location_conf_t));
    if (!location_conf) return NGX_CONF_ERROR;
    location_conf->data = NGX_CONF_UNSET_PTR;
    location_conf->type.input = NGX_CONF_UNSET_UINT;
    location_conf->type.output = NGX_CONF_UNSET_UINT;
    return location_conf;
}

static char *ngx_http_htmldoc_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_htmldoc_location_conf_t *prev = parent;
    ngx_http_htmldoc_location_conf_t *conf = child;
    ngx_conf_merge_ptr_value(conf->data, prev->data, NGX_CONF_UNSET_PTR);
    ngx_conf_merge_uint_value(conf->type.input, prev->type.input, NGX_CONF_UNSET_UINT);
    ngx_conf_merge_uint_value(conf->type.output, prev->type.output, NGX_CONF_UNSET_UINT);
    return NGX_CONF_OK;
}

static ngx_http_module_t ngx_http_htmldoc_ctx = {
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
    .ctx = &ngx_http_htmldoc_ctx,
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
