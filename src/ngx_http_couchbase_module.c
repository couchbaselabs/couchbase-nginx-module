/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010, 2011 Couchbase, Inc.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <libcouchbase/couchbase.h>

#include "ddebug.h"
#include "ngx_lcb_plugin.h"

static void* ngx_http_couchbase_create_main_conf(ngx_conf_t *cf);
static char* ngx_http_couchbase_init_main_conf(ngx_conf_t *cf, void *conf);
static void* ngx_http_couchbase_create_loc_conf(ngx_conf_t *cf);
static char* ngx_http_couchbase_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

typedef struct {
    lcb_t lcb;

    unsigned connected:1;
} ngx_http_couchbase_loc_conf_t;

typedef struct {
    lcb_io_opt_t lcb_io;
    ngx_lcb_cookie_t lcb_cookie;
} ngx_http_couchbase_main_conf_t;

static ngx_command_t  ngx_http_couchbase_commands[] = {

    {
        ngx_string("couchbase_pass"),
        NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1234,
        ngx_http_couchbase_pass,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },

    ngx_null_command
};

static ngx_http_module_t  ngx_http_couchbase_module_ctx = {
    NULL,   /* preconfiguration */
    NULL,   /* postconfiguration */

    ngx_http_couchbase_create_main_conf,    /* create main configuration */
    ngx_http_couchbase_init_main_conf,      /* init main configuration */

    NULL,   /* create server configuration */
    NULL,   /* merge server configuration */

    ngx_http_couchbase_create_loc_conf, /* create location configuration */
    NULL                                /* merge location configuration */
};


ngx_module_t  ngx_http_couchbase_module = {
    NGX_MODULE_V1,
    &ngx_http_couchbase_module_ctx, /* module context */
    ngx_http_couchbase_commands,    /* module directives */
    NGX_HTTP_MODULE,                /* module type */
    NULL,                           /* init master */
    NULL,                           /* init module */
    NULL,                           /* init process */
    NULL,                           /* init thread */
    NULL,                           /* exit thread */
    NULL,                           /* exit process */
    NULL,                           /* exit master */
    NGX_MODULE_V1_PADDING
};

struct cb_request_ctx
{
    ngx_err_t err;
    ngx_http_request_t *req;
};

#define cb_string_arg(str) (u_char *)str, sizeof(str) - 1
static ngx_err_t
cb_add_header_uint64_t(ngx_http_request_t *r, u_char *key, size_t nkey, uint64_t val)
{
    ngx_table_elt_t  *h;
    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "couchbase: failed to allocate buffer for \"%s\" header.", key);
        return NGX_ERROR;
    }
    h->key.data = key;
    h->key.len = nkey;
    h->value.data = ngx_pnalloc(r->pool, NGX_UINT64_T_LEN);
    if (h->value.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "couchbase: failed to allocate buffer for \"%s\" header value.", key);
        return NGX_ERROR;
    }
    h->value.len = ngx_sprintf(h->value.data, "%02uL", val) - h->value.data;
    return NGX_OK;
}

#ifndef NGX_HTTP_UNPROCESSABLE_ENTITY
#define NGX_HTTP_UNPROCESSABLE_ENTITY 422
#endif

static ngx_err_t
cb_format_lcb_error(ngx_http_request_t *r, lcb_error_t rc, ngx_str_t *str, ngx_err_t *status)
{
    const u_char *ptr, *reason = (const u_char*)lcb_strerror(NULL, rc);
    const char *error;

    *status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    switch (rc) {
    case LCB_SUCCESS:
        error = "success";
        *status = NGX_HTTP_OK;
        break;
    case LCB_AUTH_CONTINUE:
        error = "auth_continue";
        break;
    case LCB_AUTH_ERROR:
        error = "auth_error";
        break;
    case LCB_DELTA_BADVAL:
        error = "delta_badval";
        *status = NGX_HTTP_UNPROCESSABLE_ENTITY;
        break;
    case LCB_E2BIG:
        error = "e2big";
        break;
    case LCB_EBUSY:
        error = "ebusy";
        break;
    case LCB_EINTERNAL:
        error = "einternal";
        break;
    case LCB_EINVAL:
        error = "einval";
        break;
    case LCB_ENOMEM:
        error = "enomem";
        break;
    case LCB_ERANGE:
        error = "erange";
        break;
    case LCB_ERROR:
        error = "error";
        break;
    case LCB_ETMPFAIL:
        error = "etmp_fail";
        break;
    case LCB_KEY_EEXISTS:
        error = "key_eexists";
        *status = NGX_HTTP_CONFLICT;
        break;
    case LCB_KEY_ENOENT:
        error = "key_enoent";
        *status = NGX_HTTP_NOT_FOUND;
        break;
    case LCB_DLOPEN_FAILED:
        error = "dlopen_failed";
        break;
    case LCB_DLSYM_FAILED:
        error = "dlsym_failed";
        break;
    case LCB_NETWORK_ERROR:
        error = "network_error";
        break;
    case LCB_NOT_MY_VBUCKET:
        error = "not_my_vbucket";
        break;
    case LCB_NOT_STORED:
        error = "not_stored";
        *status = NGX_HTTP_UNPROCESSABLE_ENTITY;
        break;
    case LCB_NOT_SUPPORTED:
        error = "not_supported";
        break;
    case LCB_UNKNOWN_COMMAND:
        error = "unknown_command";
        break;
    case LCB_UNKNOWN_HOST:
        error = "unknown_host";
        break;
    case LCB_PROTOCOL_ERROR:
        error = "protocol_error";
        break;
    case LCB_ETIMEDOUT:
        error = "etimeout";
        *status = NGX_HTTP_REQUEST_TIME_OUT;
        break;
    case LCB_CONNECT_ERROR:
        error = "connect_error";
        break;
    case LCB_BUCKET_ENOENT:
        error = "bucket_enoent";
        *status = NGX_HTTP_NOT_FOUND;
        break;
    case LCB_CLIENT_ENOMEM:
        error = "client_enomem";
        break;
    case LCB_CLIENT_ETMPFAIL:
        error = "client_etmpfail";
        break;
    case LCB_EBADHANDLE:
        error = "ebadhandle";
        break;
    case LCB_SERVER_BUG:
        error = "server_bug";
        break;
    case LCB_PLUGIN_VERSION_MISMATCH:
        error = "plugin_version_mismatch";
        break;
    default:
        error = "unknown_error";
    }

    str->len = ngx_strlen(error) + ngx_strlen(reason) + 24;
    str->data = ngx_pnalloc(r->pool, str->len);
    if (str->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "couchbase: failed to allocate buffer while formatting libcouchbase error");
        return NGX_ERROR;
    }
    ptr = ngx_sprintf(str->data, "{\"error\":\"%s\",\"reason\":\"%s\"}", error, reason);
    if ((size_t)(ptr - str->data) != str->len) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "couchbase: failed to format libcouchbase error");
        return NGX_ERROR;
    }
    return NGX_OK;
}

static void
ngx_lcb_configuration_callback(lcb_t instance, lcb_configuration_t config)
{
    if (config == LCB_CONFIGURATION_NEW) {
        dd("initial configuration has been successed");
    }
}

static void
ngx_lcb_get_callback(lcb_t instance, const void *cookie, lcb_error_t error,
                     const lcb_get_resp_t *item)
{
    struct cb_request_ctx *ctx = (struct cb_request_ctx *)cookie;
    ngx_http_request_t *r = ctx->req;
    ngx_chain_t out;

    cb_add_header_uint64_t(r, cb_string_arg("X-Couchbase-RC"), (uint64_t)error);

    ngx_buf_t *b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "couchbase: failed to allocate response buffer.");
        ctx->err = NGX_ERROR;
        return;
    }
    out.buf = b;
    out.next = NULL;
    b->memory = 1;
    b->last_buf = 1;

    r->headers_out.content_type.len = sizeof("application/json") - 1;
    r->headers_out.content_type.data = (u_char *) "application/json";
    switch (error) {
    case LCB_SUCCESS:
        b->pos = (u_char *)item->v.v0.bytes;
        b->last = (u_char *)item->v.v0.bytes + item->v.v0.nbytes;
        if (ctx->err != NGX_OK) {
            return;
        }
        r->headers_out.content_length_n = item->v.v0.nbytes;
        r->headers_out.status = NGX_HTTP_OK;
        ctx->err = cb_add_header_uint64_t(r, cb_string_arg("X-Couchbase-CAS"),
                                          (uint64_t)item->v.v0.cas);
        if (ctx->err != NGX_OK) {
            return;
        }
        ctx->err = cb_add_header_uint64_t(r, cb_string_arg("X-Couchbase-Flags"),
                                          (uint64_t)item->v.v0.flags);
        if (ctx->err != NGX_OK) {
            return;
        }
        break;
    default:
        {
            ngx_str_t err;
            ngx_err_t status;
            ctx->err = cb_format_lcb_error(r, error, &err, &status);
            if (ctx->err != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "couchbase: failed to format libcouchbase error");
                return;
            }
            b->pos = err.data;
            b->last = err.data + err.len;
            r->headers_out.content_length_n = err.len;
            r->headers_out.status = status;
        }
    }

    ctx->err = ngx_http_send_header(r);
    if (ctx->err != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "couchbase: failed to send headers from libcouchbase get callback.");
    }
    ctx->err = ngx_http_output_filter(r, &out);
    if (ctx->err != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "couchbase: failed to execute output filters from libcouchbase get callback 0x%02x\n", (int)ctx->err);
    }
}

static ngx_int_t
ngx_http_couchbase_create_request(ngx_http_request_t *r)
{
    dd_request(r);
    return NGX_OK;
}

static ngx_int_t
ngx_http_couchbase_reinit_request(ngx_http_request_t *r)
{
    dd_request(r);
    return NGX_OK;
}

static ngx_int_t
ngx_http_couchbase_process_status_line(ngx_http_request_t *r)
{
    dd_request(r);
    return NGX_OK;
}

static void
ngx_http_couchbase_abort_request(ngx_http_request_t *r)
{
    dd_request(r);
    return;
}

static void
ngx_http_couchbase_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    dd_request(r);
    (void)rc;
    return;
}

static ngx_int_t
ngx_http_couchbase_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    ngx_http_upstream_t *u;
    ngx_http_couchbase_loc_conf_t *cblcf;

    dd("enter couchbase handler");
    dd_request(r);
    cblcf = ngx_http_get_module_loc_conf(r, ngx_http_couchbase_module);
    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }
    dd_request(r);
    if (!cblcf->connected) {
        lcb_error_t err;

        dd("connecting lcb handler");
        err = lcb_connect(cblcf->lcb);
        if (err != LCB_SUCCESS) {
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "couchbase: failed to initiate lcb_t(%p) connection: 0x%02x \"%s\"",
                          cblcf->lcb, err, lcb_strerror(NULL, err));
            return NGX_ERROR;
        }
        cblcf->connected = 1;
        dd("connected");
    }

#if 0
    u = r->upstream;
    u->schema.len = sizeof("couchbase://") - 1;
    u->schema.data = (u_char *) "couchbase://";
    u->output.tag = (ngx_buf_tag_t) &ngx_http_couchbase_module;
/*    u->conf = &cblcf->upstream;*/

    /* attach the callback functions */
    u->create_request = ngx_http_couchbase_create_request;
    u->reinit_request = ngx_http_couchbase_reinit_request;
    u->process_header = ngx_http_couchbase_process_status_line;
    u->abort_request = ngx_http_couchbase_abort_request;
    u->finalize_request = ngx_http_couchbase_finalize_request;
#endif

#if 0
    rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }
#endif

    dd("exit couchbase handler");
    return NGX_DONE;
#if 0
    ngx_int_t rc;
    lcb_t lcb;
    lcb_error_t err;
    struct cb_request_ctx ctx;
    ngx_http_core_loc_conf_t  *clcf;

    if (!(r->method & NGX_HTTP_GET)) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK && rc != NGX_AGAIN) {
        return rc;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (r->uri.len - clcf->name.len < 2) {
        return NGX_HTTP_NOT_FOUND;
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "creating the instance");
    err = lcb_create(&lcb, NULL);
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "instance created, connecting");
    /* Initiate the connect sequence in libcouchbase */
    if ((err = lcb_connect(lcb)) != LCB_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "couchbase: failed to initiate connect: %s", lcb_strerror(NULL, err));
        lcb_destroy(lcb);
        return NGX_ERROR;
    }
    (void)lcb_set_get_callback(lcb, cb_get_callback);
    /* FIXME Make it asynchronous */
    err = lcb_wait(lcb);
    if (err != LCB_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "couchbase: failed to connect: %s", lcb_strerror(NULL, err));
        lcb_destroy(lcb);
        return NGX_ERROR;
    }
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "instance connected, connecting");
    ctx.err = NGX_OK;
    ctx.req = r;
    {
        lcb_get_cmd_t cmd;
        const lcb_get_cmd_t *commands[1];
        ngx_str_t str;
        commands[0] = &cmd;
        memset(&cmd, 0, sizeof(cmd));
        cmd.v.v0.key = r->uri.data + clcf->name.len;
        cmd.v.v0.nkey = r->uri.len - clcf->name.len;
        if (clcf->name.data[clcf->name.len - 1] != '/') {
            /* ignore slash between location and key */
            cmd.v.v0.key = (char *)cmd.v.v0.key + 1;
            cmd.v.v0.nkey -= 1;
        }
        str.data = (u_char *)cmd.v.v0.key;
        str.len = cmd.v.v0.nkey;
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Getting \"%V\"", &str);
        err = lcb_get(lcb, &ctx, 1, commands);
        if (err != LCB_SUCCESS) {
            lcb_destroy(lcb);
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "couchbase: failed to schedule get: %s", lcb_strerror(lcb, err));
            return NGX_ERROR;
        }
    }
    lcb_wait(lcb);

    if (ctx.err == NGX_ERROR || ctx.err > NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "couchbase: failed to get \"%V\": %s", &r->uri, lcb_strerror(lcb, err));
    }
    lcb_destroy(lcb);
    return ctx.err;
#endif
}

static void *
ngx_http_couchbase_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_couchbase_loc_conf_t  *conf;

    dd("%s", __func__);
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_couchbase_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    return conf;
}

static void
ngx_http_couchbase_cleanup_peer(void *data)
{
    lcb_t instance = data;
    lcb_destroy(instance);
}

/* parse couchbase_pass arguments.
 * full form is:
 *
 *   couchbase_pass host:port bucket=val user=val password=val
 */
static char *
ngx_http_couchbase_lcb_options(ngx_conf_t *cf, struct lcb_create_st* options)
{
    ngx_str_t *value;
    ngx_url_t u;
    size_t ii, len;
    char *ptr;

    if (cf->args->nelts < 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "couchbase: address argument required for couchbase_pass");
        return NGX_CONF_ERROR;
    }
    value = cf->args->elts;

    /* host:port */
    ngx_memzero(&u, sizeof(ngx_url_t));
    u.url = value[1];
    u.no_resolve = 1;
    u.default_port = 8091;
    u.uri_part = 1;
    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "couchbase: %s in couchbase_pass \"%V\"", u.err, &u.url);
        }
        return NGX_CONF_ERROR;
    }

    /* optional arguments */
    for (ii = 2; ii < cf->args->nelts; ii++) {

        if (ngx_strncmp(value[ii].data, "bucket=", sizeof("bucket=") - 1) == 0) {
            len = value[ii].len - (sizeof("bucket=") - 1);
            ptr = calloc(sizeof(char), len + 1);
            if (ptr == NULL) {
                goto nomem;
            }
            memcpy(ptr, &value[ii].data[sizeof("bucket=") - 1], len);
            options->v.v0.bucket = ptr;
            continue;
        }

        if (ngx_strncmp(value[ii].data, "user=", sizeof("user=") - 1) == 0) {
            len = value[ii].len - (sizeof("user=") - 1);
            ptr = calloc(sizeof(char), len + 1);
            if (ptr == NULL) {
                goto nomem;
            }
            memcpy(ptr, &value[ii].data[sizeof("user=") - 1], len);
            options->v.v0.user = ptr;
            continue;
        }

        if (ngx_strncmp(value[ii].data, "password=", sizeof("password=") - 1) == 0) {
            len = value[ii].len - (sizeof("password=") - 1);
            ptr = calloc(sizeof(char), len + 1);
            if (ptr == NULL) {
                goto nomem;
            }
            memcpy(ptr, &value[ii].data[sizeof("password=") - 1], len);
            options->v.v0.passwd = ptr;
            continue;
        }

        goto invalid;
    }
    len = u.host.len + 7; /* "host:65535\0" */
    ptr = calloc(sizeof(char), len);
    if (ptr == NULL) {
        goto nomem;
    }
    memcpy(ptr, u.host.data, u.host.len);
    ngx_snprintf((u_char *)(ptr + u.host.len), 6, ":%d", (int)u.port);
    options->v.v0.host = ptr;
    return NGX_CONF_OK;

nomem:
    free((void*)options->v.v0.host);
    free((void*)options->v.v0.bucket);
    free((void*)options->v.v0.user);
    free((void*)options->v.v0.passwd);
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "couchbase: failed to allocate memory for \"%V\" in %s:%ui", &value[ii]);
    return NGX_CONF_ERROR;

invalid:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "couchbase: invalid parameter \"%V\"", &value[ii]);
    return NGX_CONF_ERROR;
}


static char *
ngx_http_couchbase_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_couchbase_loc_conf_t *cblcf = conf;
    ngx_http_couchbase_main_conf_t *cbmcf;
    ngx_http_core_loc_conf_t *clcf;
    ngx_pool_cleanup_t *cln;
    struct lcb_create_st options;
    lcb_error_t err;
    char *rc;

    dd("enter couchbase_pass directive");
    if (cblcf->lcb) {
        return "is duplicate";
    }

    cbmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_couchbase_module);
    ngx_memzero(&options, sizeof(options));
    /* options.version = 0; */
    options.v.v0.io = cbmcf->lcb_io;
    rc = ngx_http_couchbase_lcb_options(cf, &options);
    if (rc != NGX_CONF_OK) {
        return rc;
    }
    dd("initializing lcb_t struct for %s", options.v.v0.host);
    err = lcb_create(&cblcf->lcb, &options);
    (void)lcb_set_get_callback(cblcf->lcb, ngx_lcb_get_callback);
    (void)lcb_set_configuration_callback(cblcf->lcb, ngx_lcb_configuration_callback);
    dd("initialized lcb_t, rc = %d", (int)err);
    free((void*)options.v.v0.host);
    free((void*)options.v.v0.bucket);
    free((void*)options.v.v0.user);
    free((void*)options.v.v0.passwd);
    if (err != LCB_SUCCESS) {
        /* You can't initialize the library without a io-handler! */
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                      "couchbase: failed to create IO object for libcouchbase: 0x%02x \"%s\"",
                      err, lcb_strerror(NULL, err));
        return NGX_CONF_ERROR;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_CONF_ERROR;
    }
    cln->handler = ngx_http_couchbase_cleanup_peer;
    cln->data = cblcf->lcb;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_couchbase_handler;
    if (clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }
    dd("exit couchbase_pass directive");

    return NGX_CONF_OK;
}

static void *
ngx_http_couchbase_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_couchbase_main_conf_t *cbmcf;
    struct lcb_create_io_ops_st options;
    lcb_error_t err;

    dd("create main conf");
    cbmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_couchbase_main_conf_t));
    if (cbmcf == NULL) {
        return NULL;
    }
    cbmcf->lcb_cookie = ngx_pcalloc(cf->pool, sizeof(struct ngx_lcb_cookie_s));
    if (cbmcf->lcb_cookie == NULL) {
        ngx_pfree(cf->pool, cbmcf);
        return NULL;
    }
    cbmcf->lcb_cookie->pool = cf->pool;
    cbmcf->lcb_cookie->log = cf->log;

    memset(&options, 0, sizeof(options));
    options.version = 2;
    options.v.v2.create = ngx_lcb_create_io_opts;
    options.v.v2.cookie = cbmcf->lcb_cookie;

    err = lcb_create_io_ops(&cbmcf->lcb_io, &options);
    if (err != LCB_SUCCESS) {
        ngx_pfree(cf->pool, cbmcf->lcb_cookie);
        ngx_pfree(cf->pool, cbmcf);
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "couchbase: failed to create IO object for libcouchbase: 0x%02xd \"%s\"",
                           err, lcb_strerror(NULL, err));
        return NULL;
    }
    dd("main conf created");

    return cbmcf;
}

static void
ngx_http_couchbase_cleanup_io(void *data)
{
    lcb_io_opt_t io = data;
    lcb_destroy_io_ops(io);
}

static char *
ngx_http_couchbase_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_couchbase_main_conf_t *cbmcf = conf;
    ngx_pool_cleanup_t *cln;

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_CONF_ERROR;
    }
    cln->handler = ngx_http_couchbase_cleanup_io;
    cln->data = cbmcf->lcb_io;

    return NGX_CONF_OK;
}
