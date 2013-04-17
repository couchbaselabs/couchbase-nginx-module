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
static ngx_int_t ngx_http_couchbase_postconf(ngx_conf_t *cf);

static ngx_flag_t ngx_http_couchbase_enabled = 0;

static ngx_str_t ngx_http_couchbase_cmd = ngx_string("couchbase_cmd");
static ngx_int_t ngx_http_couchbase_cmd_idx;
static ngx_str_t ngx_http_couchbase_key = ngx_string("couchbase_key");
static ngx_int_t ngx_http_couchbase_key_idx;
static ngx_str_t ngx_http_couchbase_val = ngx_string("couchbase_val");
static ngx_int_t ngx_http_couchbase_val_idx;

enum ngx_http_couchbase_cmd {
    ngx_http_couchbase_cmd_get,
    ngx_http_couchbase_cmd_set,
    ngx_http_couchbase_cmd_add,
    ngx_http_couchbase_cmd_delete
};

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
    ngx_http_couchbase_postconf,    /* postconfiguration */

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

static ngx_int_t
ngx_http_couchbase_process(ngx_http_request_t *r)
{
/*    ngx_http_core_loc_conf_t *clcf;*/
    ngx_http_couchbase_loc_conf_t *cblcf;
    lcb_error_t err = LCB_NOT_SUPPORTED;
    ngx_http_variable_value_t *cmd_vv, *key_vv, *val_vv;
    ngx_str_t key, val;
    enum ngx_http_couchbase_cmd opcode;

/*    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);*/
    cblcf = ngx_http_get_module_loc_conf(r, ngx_http_couchbase_module);

    /* setup command: use variable or fallback to HTTP method */
    cmd_vv = ngx_http_get_indexed_variable(r, ngx_http_couchbase_cmd_idx);
    if (cmd_vv == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (cmd_vv->not_found || cmd_vv->len == 0) {
        if (r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD)) {
            opcode = ngx_http_couchbase_cmd_get;
        } else if (r->method == NGX_HTTP_POST) {
            opcode = ngx_http_couchbase_cmd_add;
        } else if (r->method == NGX_HTTP_PUT) {
            opcode = ngx_http_couchbase_cmd_set;
        } else if (r->method == NGX_HTTP_DELETE) {
            opcode = ngx_http_couchbase_cmd_delete;
        } else {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "ngx_memc: $memc_cmd variable requires explicit "
                          "assignment for HTTP request method %V",
                          &r->method_name);
            ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
            return NGX_HTTP_BAD_REQUEST;
        }
    } else {
        if (ngx_strncmp(cmd_vv->data, "get", 3) == 0) {
            opcode = ngx_http_couchbase_cmd_get;
        } else if (ngx_strncmp(cmd_vv->data, "set", 3) == 0) {
            opcode = ngx_http_couchbase_cmd_set;
        } else if (ngx_strncmp(cmd_vv->data, "add", 3) == 0) {
            opcode = ngx_http_couchbase_cmd_add;
        } else if (ngx_strncmp(cmd_vv->data, "delete", 6) == 0) {
            opcode = ngx_http_couchbase_cmd_delete;
        } else {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "ngx_memc: unknown $couchbase_cmd \"%v\"", cmd_vv);
            ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
            return NGX_HTTP_BAD_REQUEST;
        }
    }

    /* setup key: use variable or fallback to URI */
    key_vv = ngx_http_get_indexed_variable(r, ngx_http_couchbase_key_idx);
    if (key_vv == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (key_vv->not_found || key_vv->len == 0) {
        key.data = r->uri.data;
        key.len = r->uri.len;
    } else {
        key.data = key_vv->data;
        key.len = key_vv->len;
    }

    /* setup value: use variable or fallback to HTTP body */
    if (opcode == ngx_http_couchbase_cmd_set || opcode == ngx_http_couchbase_cmd_add) {
        val_vv = ngx_http_get_indexed_variable(r, ngx_http_couchbase_val_idx);
        if (val_vv == NULL) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        if (val_vv->not_found || val_vv->len == 0) {
            if (r->request_body == NULL || r->request_body->bufs == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "neither the \"$couchbase_value\" variable "
                              "nor the request body is available");
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            } else {
                /* copy body to the buffer */
                ngx_chain_t *cl;
                u_char *p;

                val.len = 0;
                for (cl = r->request_body->bufs; cl; cl = cl->next) {
                    val.len += ngx_buf_size(cl->buf);
                }
                p = val.data = ngx_palloc(r->pool, val.len);
                /* FIXME check return value */
                for (cl = r->request_body->bufs; cl; cl = cl->next) {
                    p = ngx_copy(p, cl->buf->pos, cl->buf->last - cl->buf->pos);
                }
                val_vv = NULL;
            }
        } else {
            val.data = val_vv->data;
            val.len = val_vv->len;
        }
    }

    switch (opcode) {
    case ngx_http_couchbase_cmd_get:
        {
            lcb_get_cmd_t cmd;
            const lcb_get_cmd_t *commands[1];

            commands[0] = &cmd;
            memset(&cmd, 0, sizeof(cmd));
            cmd.v.v0.key = key.data;
            cmd.v.v0.nkey = key.len;
            err = lcb_get(cblcf->lcb, r, 1, commands);
        }
        break;
    case ngx_http_couchbase_cmd_set:
    case ngx_http_couchbase_cmd_add:
        {
            lcb_store_cmd_t cmd;
            const lcb_store_cmd_t *commands[1];

            commands[0] = &cmd;
            memset(&cmd, 0, sizeof(cmd));
            cmd.v.v0.operation =  ngx_http_couchbase_cmd_set ? LCB_SET : LCB_ADD;
            cmd.v.v0.key = key.data;
            cmd.v.v0.nkey = key.len;
            cmd.v.v0.bytes = val.data;
            cmd.v.v0.nbytes = val.len;
            err = lcb_store(cblcf->lcb, r, 1, commands);
        }
        break;
    case ngx_http_couchbase_cmd_delete:
        {
            lcb_remove_cmd_t cmd;
            const lcb_remove_cmd_t *commands[1];

            commands[0] = &cmd;
            memset(&cmd, 0, sizeof(cmd));
            cmd.v.v0.key = key.data;
            cmd.v.v0.nkey = key.len;
            err = lcb_remove(cblcf->lcb, r, 1, commands);
        }
        break;
    }
    if (val_vv == NULL) {
        ngx_pfree(r->pool, val.data);
    }
    if (err != LCB_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "couchbase: failed to schedule get: %s",
                      lcb_strerror(cblcf->lcb, err));
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }
    return NGX_OK;
}

static void
ngx_lcb_configuration_callback(lcb_t instance, lcb_configuration_t config)
{
    if (config == LCB_CONFIGURATION_NEW) {
        ngx_http_couchbase_loc_conf_t *cblcf;
        ngx_http_request_t *r;

        r = (ngx_http_request_t *)lcb_get_cookie(instance);
        cblcf = ngx_http_get_module_loc_conf(r, ngx_http_couchbase_module);
        lcb_set_cookie(instance, NULL);
        cblcf->connected = 1;

        ngx_http_couchbase_process(r);
    }
}

static void
ngx_lcb_store_callback(lcb_t instance, const void *cookie,
                       lcb_storage_t operation, lcb_error_t error,
                       const lcb_store_resp_t *item)
{
    ngx_http_request_t *r = (ngx_http_request_t *)cookie;
    ngx_chain_t out;
    ngx_buf_t *b;
    ngx_int_t err;

    r->main->count--;

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "couchbase: failed to allocate response buffer.");
        err = NGX_ERROR;
        return;
    }
    out.buf = b;
    out.next = NULL;
    b->memory = 1;
    b->last_buf = 1;

    switch (error) {
    case LCB_SUCCESS:
        r->headers_out.status = NGX_HTTP_CREATED;
        r->headers_out.content_length_n = 0;
        r->header_only = 1;
        if (cb_add_header_uint64_t(r, cb_string_arg("X-Couchbase-CAS"),
                                   (uint64_t)item->v.v0.cas) != NGX_OK) {
            return;
        }
        break;
    default:
        {
            ngx_str_t errstr;
            ngx_err_t status;

            err = cb_format_lcb_error(r, error, &errstr, &status);
            if (err != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                              "couchbase: failed to format libcouchbase error 0x%02x", err);
                return;
            }
            b->pos = errstr.data;
            b->last = errstr.data + errstr.len;
            r->headers_out.content_length_n = errstr.len;
            r->headers_out.status = status;
        }
    }

    err = ngx_http_send_header(r);
    if (err != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                      "couchbase: failed to send headers from libcouchbase store callback 0x%02x", (int)err);
    }
    if (!r->header_only) {
        err = ngx_http_output_filter(r, &out);
        if (err != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                          "couchbase: failed to execute output filters from libcouchbase store callback 0x%02x", (int)err);
        }
    }
    (void)instance;
    (void)operation;
}

static void
ngx_lcb_remove_callback(lcb_t instance, const void *cookie,
                        lcb_error_t error, const lcb_remove_resp_t *item)
{
    ngx_http_request_t *r = (ngx_http_request_t *)cookie;
    ngx_chain_t out;
    ngx_buf_t *b;
    ngx_int_t err;

    r->main->count--;

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "couchbase: failed to allocate response buffer.");
        err = NGX_ERROR;
        return;
    }
    out.buf = b;
    out.next = NULL;
    b->memory = 1;
    b->last_buf = 1;

    switch (error) {
    case LCB_SUCCESS:
        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = 0;
        r->header_only = 1;
        if (cb_add_header_uint64_t(r, cb_string_arg("X-Couchbase-CAS"),
                                   (uint64_t)item->v.v0.cas) != NGX_OK) {
            return;
        }
        break;
    default:
        {
            ngx_str_t errstr;
            ngx_err_t status;

            err = cb_format_lcb_error(r, error, &errstr, &status);
            if (err != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                              "couchbase: failed to format libcouchbase error 0x%02x", (int)err);
                return;
            }
            b->pos = errstr.data;
            b->last = errstr.data + errstr.len;
            r->headers_out.content_length_n = errstr.len;
            r->headers_out.status = status;
        }
    }

    err = ngx_http_send_header(r);
    if (err != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                      "couchbase: failed to send headers from libcouchbase remove callback 0x%02x", (int)err);
    }
    if (!r->header_only) {
        err = ngx_http_output_filter(r, &out);
        if (err != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                          "couchbase: failed to execute output filters from libcouchbase remove callback 0x%02x", (int)err);
        }
    }
}

static void
ngx_lcb_get_callback(lcb_t instance, const void *cookie, lcb_error_t error,
                     const lcb_get_resp_t *item)
{
    ngx_http_request_t *r = (ngx_http_request_t *)cookie;
    ngx_chain_t out;
    ngx_buf_t *b;
    ngx_int_t err;

    r->main->count--;

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "couchbase: failed to allocate response buffer.");
        err = NGX_ERROR;
        return;
    }
    out.buf = b;
    out.next = NULL;
    b->memory = 1;
    b->last_buf = 1;

#if 0
    r->headers_out.content_type.len = sizeof("application/json") - 1;
    r->headers_out.content_type.data = (u_char *) "application/json";
#endif
    switch (error) {
    case LCB_SUCCESS:
        b->pos = (u_char *)item->v.v0.bytes;
        b->last = (u_char *)item->v.v0.bytes + item->v.v0.nbytes;
        r->headers_out.content_length_n = item->v.v0.nbytes;
        r->headers_out.status = NGX_HTTP_OK;
        if (cb_add_header_uint64_t(r, cb_string_arg("X-Couchbase-CAS"),
                                   (uint64_t)item->v.v0.cas) != NGX_OK) {
            return;
        }
#if 0
        if (cb_add_header_uint64_t(r, cb_string_arg("X-Couchbase-Flags"),
                                   (uint64_t)item->v.v0.flags) != NGX_OK) {
            return;
        }
#endif
        break;
    default:
        {
            ngx_str_t errstr;
            ngx_err_t status;

            err = cb_format_lcb_error(r, error, &errstr, &status);
            if (err != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                              "couchbase: failed to format libcouchbase error 0x%02x", (int)err);
                return;
            }
            b->pos = errstr.data;
            b->last = errstr.data + errstr.len;
            r->headers_out.content_length_n = errstr.len;
            r->headers_out.status = status;
        }
    }

    err = ngx_http_send_header(r);
    if (err != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                      "couchbase: failed to send headers from libcouchbase get callback 0x%02x", (int)err);
    }
    err = ngx_http_output_filter(r, &out);
    if (err != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                      "couchbase: failed to execute output filters from libcouchbase get callback 0x%02x", (int)err);
    }
}

static ngx_int_t
ngx_http_couchbase_upstream_init(ngx_http_request_t *r)
{
    ngx_http_couchbase_loc_conf_t *cblcf;

    dd("init upstream");
    r->main->count++;
    cblcf = ngx_http_get_module_loc_conf(r, ngx_http_couchbase_module);
    if (cblcf->connected) {
        ngx_http_couchbase_process(r);
    } else {
        lcb_error_t err;

        lcb_set_cookie(cblcf->lcb, r);
        err = lcb_connect(cblcf->lcb);
        if (err != LCB_SUCCESS) {
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "couchbase: failed to initiate lcb_t(%p) connection: 0x%02x \"%s\"",
                          cblcf->lcb, err, lcb_strerror(NULL, err));
            return NGX_ERROR;
        }
    }
    return NGX_DONE;
}

static ngx_int_t
ngx_http_couchbase_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    ngx_http_upstream_t *u;

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_read_client_request_body(r, ngx_http_couchbase_upstream_init);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        return rc;
    }
    return NGX_DONE;
}

static void *
ngx_http_couchbase_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_couchbase_loc_conf_t  *conf;

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

    if (cblcf->lcb) {
        return "is duplicate";
    }
    ngx_http_couchbase_enabled = 1;

    cbmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_couchbase_module);
    ngx_memzero(&options, sizeof(options));
    /* options.version = 0; */
    options.v.v0.io = cbmcf->lcb_io;
    rc = ngx_http_couchbase_lcb_options(cf, &options);
    if (rc != NGX_CONF_OK) {
        return rc;
    }
    err = lcb_create(&cblcf->lcb, &options);
    (void)lcb_set_get_callback(cblcf->lcb, ngx_lcb_get_callback);
    (void)lcb_set_store_callback(cblcf->lcb, ngx_lcb_store_callback);
    (void)lcb_set_remove_callback(cblcf->lcb, ngx_lcb_remove_callback);
    (void)lcb_set_configuration_callback(cblcf->lcb, ngx_lcb_configuration_callback);
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

    return NGX_CONF_OK;
}

static void *
ngx_http_couchbase_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_couchbase_main_conf_t *cbmcf;
    struct lcb_create_io_ops_st options;
    lcb_error_t err;

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

static ngx_int_t
ngx_http_couchbase_variable_not_found(ngx_http_request_t *r,
                                      ngx_http_variable_value_t *v,
                                      uintptr_t data)
{
    v->not_found = 1;
    return NGX_OK;
}

static ngx_int_t
ngx_http_couchbase_add_variable(ngx_conf_t *cf, ngx_str_t *name) {
    ngx_http_variable_t *v;

    v = ngx_http_add_variable(cf, name, NGX_HTTP_VAR_CHANGEABLE);
    if (v == NULL) {
        return NGX_ERROR;
    }

    v->get_handler = ngx_http_couchbase_variable_not_found;

    return ngx_http_get_variable_index(cf, name);
}

static ngx_int_t
ngx_http_couchbase_postconf(ngx_conf_t *cf)
{
    if (!ngx_http_couchbase_enabled) {
        return NGX_OK;
    }

    ngx_http_couchbase_cmd_idx = ngx_http_couchbase_add_variable(cf, &ngx_http_couchbase_cmd);
    if (ngx_http_couchbase_cmd_idx == NGX_ERROR) {
        return NGX_ERROR;
    }
    ngx_http_couchbase_key_idx = ngx_http_couchbase_add_variable(cf, &ngx_http_couchbase_key);
    if (ngx_http_couchbase_key_idx == NGX_ERROR) {
        return NGX_ERROR;
    }
    ngx_http_couchbase_val_idx = ngx_http_couchbase_add_variable(cf, &ngx_http_couchbase_val);
    if (ngx_http_couchbase_val_idx == NGX_ERROR) {
        return NGX_ERROR;
    }
    return NGX_OK;
}
