#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "htmldoc.h"

typedef enum {
    INPUT_TYPE_FILE = 0,
    INPUT_TYPE_HTML,
    INPUT_TYPE_URL
} ngx_http_htmldoc_input_type_t;

typedef enum {
    OUTPUT_TYPE_PDF = 0,
    OUTPUT_TYPE_PS
} ngx_http_htmldoc_output_type_t;

typedef struct {
    ngx_uint_t input;
    ngx_uint_t output;
} ngx_http_htmldoc_type_t;

typedef struct {
    ngx_chain_t *cl;
    ngx_flag_t done;
} ngx_http_htmldoc_context_t;

typedef struct {
    ngx_flag_t enable;
} ngx_http_htmldoc_main_t;

typedef struct {
    ngx_array_t *data;
    ngx_http_htmldoc_type_t type;
} ngx_http_htmldoc_location_t;

ngx_module_t ngx_http_htmldoc_module;

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

static ngx_int_t read_fileurl(ngx_log_t *log, tree_t **document, const u_char *fileurl, const char *path) {
    FILE *in;
    tree_t *file;
    const char *base = file_directory((const char *)fileurl);
    const char *realname = file_find(path, (const char *)fileurl);
    if (!base) { ngx_log_error(NGX_LOG_ERR, log, 0, "!file_directory(\"%s\")", fileurl); return NGX_ERROR; }
    if (!realname) { ngx_log_error(NGX_LOG_ERR, log, 0, "!file_find(\"%s\", \"%s\")", Path, fileurl); return NGX_ERROR; }
    _htmlPPI = 72.0f * _htmlBrowserWidth / (PageWidth - PageLeft - PageRight);
    if (!(file = htmlAddTree(NULL, MARKUP_FILE, NULL))) { ngx_log_error(NGX_LOG_ERR, log, 0, "!htmlAddTree"); return NGX_ERROR; }
    if (!*document) *document = file; else {
        while ((*document)->next) *document = (*document)->next;
        (*document)->next = file;
        file->prev = *document;
    }
    htmlSetVariable(file, (uchar *)"_HD_URL", (uchar *)fileurl);
    htmlSetVariable(file, (uchar *)"_HD_FILENAME", (uchar *)file_basename((const char *)fileurl));
    htmlSetVariable(file, (uchar *)"_HD_BASE", (uchar *)base);
    if (!(in = fopen(realname, "rb"))) { ngx_log_error(NGX_LOG_ERR, log, 0, "!fopen(\"%s\")", realname); return NGX_ERROR; }
    htmlReadFile2(file, in, base);
    fclose(in);
    return NGX_OK;
}

static ngx_int_t read_html(ngx_log_t *log, tree_t **document, u_char *html, size_t len) {
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

static ngx_buf_t *ngx_http_htmldoc_process(ngx_http_request_t *r, tree_t *document) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_htmldoc_location_t *location = ngx_http_get_module_loc_conf(r, ngx_http_htmldoc_module);
    switch (location->type.output) {
        case OUTPUT_TYPE_PDF: PSLevel = 0; ngx_str_set(&r->headers_out.content_type, "application/pdf"); break;
        case OUTPUT_TYPE_PS: PSLevel = 3; ngx_str_set(&r->headers_out.content_type, "application/ps"); break;
    }
    while (document && document->prev) document = document->prev;
    htmlFixLinks(document, document, 0);
    ngx_str_t output = ngx_null_string;
    FILE *out = open_memstream((char **)&output.data, &output.len);
    if (!out) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!open_memstream"); return NULL; }
    ngx_buf_t *b = NULL;
    pspdf_export_out(document, NULL, out);
    if (!output.len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!output.len"); goto free; }
    if (!(b = ngx_create_temp_buf(r->pool, output.len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_create_temp_buf"); goto free; }
    b->last_buf = 1;
    b->last = ngx_copy(b->last, output.data, output.len);
    b->memory = 1;
    if (b->last != b->end) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "b->last != b->end"); goto free; }
    if (r == r->main) {
        r->headers_out.content_length_n = b->last - b->pos;
        if (r->headers_out.content_length) {
            r->headers_out.content_length->hash = 0;
            r->headers_out.content_length = NULL;
        }
        ngx_http_weak_etag(r);
    }
free:
    free(output.data);
    return b;
}

static void ngx_http_htmldoc_cleanup_handler(void *data) {
    tree_t *document = data;
    if (document) htmlDeleteTree(document);
    file_cleanup();
    image_flush_cache();
}

static ngx_int_t ngx_http_htmldoc_handler(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK && rc != NGX_AGAIN) return rc;
    tree_t *document = NULL;
    ngx_http_cleanup_t *cln = ngx_http_cleanup_add(r, 0);
    if (!cln) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_http_cleanup_add"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    cln->handler = ngx_http_htmldoc_cleanup_handler;
    cln->data = document;
    if (!_htmlInitialized) htmlSetCharSet("utf-8");
    ngx_http_htmldoc_location_t *location = ngx_http_get_module_loc_conf(r, ngx_http_htmldoc_module);
    ngx_http_complex_value_t *elts = location->data->elts;
    for (ngx_uint_t i = 0; i < location->data->nelts; i++) {
        ngx_str_t data;
        if (ngx_http_complex_value(r, &elts[i], &data) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
        switch (location->type.input) {
            case INPUT_TYPE_HTML: {
                if (read_html(r->connection->log, &document, data.data, data.len) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "read_html != NGX_OK"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
            } break;
            default: {
                u_char *fileurl = ngx_pnalloc(r->pool, (data.len + 1));
                if (!fileurl) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
                (void) ngx_cpystrn(fileurl, data.data, data.len + 1);
                if (read_fileurl(r->connection->log, &document, fileurl, location->type.input == INPUT_TYPE_FILE ? Path : NULL) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "read_fileurl != NGX_OK"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
            } break;
        }
    }
    ngx_chain_t cl = {.buf = ngx_http_htmldoc_process(r, document), .next = NULL};
    if (!cl.buf) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!cl.buf"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    r->headers_out.status = NGX_HTTP_OK;
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) return rc;
    return ngx_http_output_filter(r, &cl);
}

static char *ngx_http_htmldoc_convert_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_htmldoc_location_t *location = conf;
    if (location->type.input != NGX_CONF_UNSET_UINT || location->type.output != NGX_CONF_UNSET_UINT) return "is duplicate";
    location->type = *(ngx_http_htmldoc_type_t *)cmd->post;
    if (cf->args->nelts > 1) {
        ngx_http_complex_value_t *cv;
        if (!(location->data = ngx_array_create(cf->pool, cf->args->nelts - 1, sizeof(*cv)))) return "!ngx_array_create";
        ngx_str_t *elts = cf->args->elts;
        for (ngx_uint_t i = 1; i < cf->args->nelts; i++) {
            if (!(cv = ngx_array_push(location->data))) return "!ngx_array_push";
            ngx_http_compile_complex_value_t ccv = {cf, &elts[i], cv, 0, 0, 0};
            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) return "ngx_http_compile_complex_value != NGX_OK";
        }
        ngx_http_core_loc_conf_t *core = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
        if (!core->handler) core->handler = ngx_http_htmldoc_handler;
    }
    ngx_http_htmldoc_main_t *main = ngx_http_conf_get_module_main_conf(cf, ngx_http_htmldoc_module);
    main->enable = 1;
    return NGX_CONF_OK;
}

static ngx_command_t ngx_http_htmldoc_commands[] = {
  { .name = ngx_string("file2pdf"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
    .set = ngx_http_htmldoc_convert_set,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_htmldoc_location_t, data),
    .post = &(ngx_http_htmldoc_type_t){INPUT_TYPE_FILE, OUTPUT_TYPE_PDF}},
  { .name = ngx_string("file2ps"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
    .set = ngx_http_htmldoc_convert_set,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_htmldoc_location_t, data),
    .post = &(ngx_http_htmldoc_type_t){INPUT_TYPE_FILE, OUTPUT_TYPE_PS}},
  { .name = ngx_string("html2pdf"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_ANY,
    .set = ngx_http_htmldoc_convert_set,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_htmldoc_location_t, data),
    .post = &(ngx_http_htmldoc_type_t){INPUT_TYPE_HTML, OUTPUT_TYPE_PDF}},
  { .name = ngx_string("html2ps"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_ANY,
    .set = ngx_http_htmldoc_convert_set,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_htmldoc_location_t, data),
    .post = &(ngx_http_htmldoc_type_t){INPUT_TYPE_HTML, OUTPUT_TYPE_PS}},
  { .name = ngx_string("url2pdf"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
    .set = ngx_http_htmldoc_convert_set,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_htmldoc_location_t, data),
    .post = &(ngx_http_htmldoc_type_t){INPUT_TYPE_URL, OUTPUT_TYPE_PDF}},
  { .name = ngx_string("url2ps"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
    .set = ngx_http_htmldoc_convert_set,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_htmldoc_location_t, data),
    .post = &(ngx_http_htmldoc_type_t){INPUT_TYPE_URL, OUTPUT_TYPE_PDF}},
    ngx_null_command
};

static void *ngx_http_htmldoc_create_main_conf(ngx_conf_t *cf) {
    ngx_http_htmldoc_main_t *main = ngx_pcalloc(cf->pool, sizeof(*main));
    if (!main) return NULL;
    return main;
}

static void *ngx_http_htmldoc_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_htmldoc_location_t *location = ngx_pcalloc(cf->pool, sizeof(*location));
    if (!location) return NULL;
    location->data = NGX_CONF_UNSET_PTR;
    location->type.input = NGX_CONF_UNSET_UINT;
    location->type.output = NGX_CONF_UNSET_UINT;
    return location;
}

static char *ngx_http_htmldoc_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_htmldoc_location_t *prev = parent;
    ngx_http_htmldoc_location_t *conf = child;
    ngx_conf_merge_ptr_value(conf->data, prev->data, NGX_CONF_UNSET_PTR);
    ngx_conf_merge_uint_value(conf->type.input, prev->type.input, NGX_CONF_UNSET_UINT);
    ngx_conf_merge_uint_value(conf->type.output, prev->type.output, NGX_CONF_UNSET_UINT);
    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_htmldoc_header_filter(ngx_http_request_t *r) {
    ngx_http_htmldoc_location_t *location = ngx_http_get_module_loc_conf(r, ngx_http_htmldoc_module);
    if (location->type.input == NGX_CONF_UNSET_UINT || location->type.output == NGX_CONF_UNSET_UINT || location->data != NGX_CONF_UNSET_PTR) return ngx_http_next_header_filter(r);
    if (!(location->type.input == INPUT_TYPE_HTML && r->headers_out.content_type.len >= sizeof("text/html") - 1 && !ngx_strncasecmp(r->headers_out.content_type.data, (u_char *)"text/html", sizeof("text/html") - 1))) return ngx_http_next_header_filter(r);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_htmldoc_context_t *context = ngx_pcalloc(r->pool, sizeof(*context));
    if (!context) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
    ngx_http_set_ctx(r, context, ngx_http_htmldoc_module);
    return NGX_OK;
}

static ngx_int_t ngx_http_htmldoc_body_filter(ngx_http_request_t *r, ngx_chain_t *in) {
    if (!in) return ngx_http_next_body_filter(r, in);
    ngx_http_htmldoc_context_t *context = ngx_http_get_module_ctx(r, ngx_http_htmldoc_module);
    ngx_http_htmldoc_location_t *location = ngx_http_get_module_loc_conf(r, ngx_http_htmldoc_module);
    if (location->type.input == NGX_CONF_UNSET_UINT || location->type.output == NGX_CONF_UNSET_UINT || !context || context->done) return ngx_http_next_body_filter(r, in);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (!in->buf->last_buf && !in->buf->last_in_chain) {
        if (ngx_chain_add_copy(r->pool, &context->cl, in) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_chain_add_copy != NGX_OK"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
        return ngx_http_next_body_filter(r, in);
    }
    tree_t *document = NULL;
    ngx_http_cleanup_t *cln = ngx_http_cleanup_add(r, 0);
    if (!cln) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_http_cleanup_add"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    cln->handler = ngx_http_htmldoc_cleanup_handler;
    cln->data = document;
    if (!_htmlInitialized) htmlSetCharSet("utf-8");
    ngx_str_t data = ngx_null_string;
    for (ngx_chain_t *cl = context->cl ? context->cl : in; cl; cl = cl->next) {
        if (!ngx_buf_in_memory(cl->buf)) continue;
        data.len += cl->buf->last - cl->buf->pos;
    }
    if (!data.len) return ngx_http_next_body_filter(r, in);
    if (!(data.data = ngx_pnalloc(r->pool, data.len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    u_char *p = data.data;
    size_t len;
    for (ngx_chain_t *cl = context->cl ? context->cl : in; cl; cl = cl->next) {
        if (!ngx_buf_in_memory(cl->buf)) continue;
        if (!(len = cl->buf->last - cl->buf->pos)) continue;
        p = ngx_copy(p, cl->buf->pos, len);
    }
    if (read_html(r->connection->log, &document, data.data, data.len) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "read_html != NGX_OK"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    ngx_chain_t cl = {.buf = ngx_http_htmldoc_process(r, document), .next = NULL};
    if (!cl.buf) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!cl.buf"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    context->done = 1;
    ngx_int_t rc = ngx_http_next_header_filter(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) return rc;
    return ngx_http_next_body_filter(r, &cl);
}

static ngx_int_t ngx_http_htmldoc_postconfiguration(ngx_conf_t *cf) {
    ngx_http_htmldoc_main_t *main = ngx_http_conf_get_module_main_conf(cf, ngx_http_htmldoc_module);
    if (!main->enable) return NGX_OK;
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_htmldoc_header_filter;
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_htmldoc_body_filter;
    return NGX_OK;
}

static ngx_http_module_t ngx_http_htmldoc_ctx = {
    .preconfiguration = NULL,
    .postconfiguration = ngx_http_htmldoc_postconfiguration,
    .create_main_conf = ngx_http_htmldoc_create_main_conf,
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
