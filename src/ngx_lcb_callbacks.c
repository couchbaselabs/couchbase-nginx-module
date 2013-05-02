/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2013 Couchbase, Inc.
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

#include "ngx_lcb_module.h"
#include "ddebug.h"

#ifndef NGX_HTTP_UNPROCESSABLE_ENTITY
#define NGX_HTTP_UNPROCESSABLE_ENTITY 422
#endif

typedef struct ngx_lcb_error_s {
    lcb_error_t rc;
    ngx_str_t errmsg;
    ngx_int_t status;
} ngx_lcb_error_t;

static ngx_lcb_error_t ngx_lcb_errors[] = {
    {LCB_SUCCESS,                   ngx_string("success"),                  NGX_HTTP_OK},
    {LCB_AUTH_CONTINUE,             ngx_string("auth_continue"),            NGX_HTTP_INTERNAL_SERVER_ERROR},
    {LCB_AUTH_ERROR,                ngx_string("auth_error"),               NGX_HTTP_INTERNAL_SERVER_ERROR},
    {LCB_DELTA_BADVAL,              ngx_string("delta_badval"),             NGX_HTTP_UNPROCESSABLE_ENTITY},
    {LCB_E2BIG,                     ngx_string("e2big"),                    NGX_HTTP_INTERNAL_SERVER_ERROR},
    {LCB_EBUSY,                     ngx_string("ebusy"),                    NGX_HTTP_INTERNAL_SERVER_ERROR},
    {LCB_EINTERNAL,                 ngx_string("einternal"),                NGX_HTTP_INTERNAL_SERVER_ERROR},
    {LCB_EINVAL,                    ngx_string("einval"),                   NGX_HTTP_INTERNAL_SERVER_ERROR},
    {LCB_ENOMEM,                    ngx_string("enomem"),                   NGX_HTTP_INTERNAL_SERVER_ERROR},
    {LCB_ERANGE,                    ngx_string("erange"),                   NGX_HTTP_INTERNAL_SERVER_ERROR},
    {LCB_ERROR,                     ngx_string("error"),                    NGX_HTTP_INTERNAL_SERVER_ERROR},
    {LCB_ETMPFAIL,                  ngx_string("etmp_fail"),                NGX_HTTP_INTERNAL_SERVER_ERROR},
    {LCB_KEY_EEXISTS,               ngx_string("key_eexists"),              NGX_HTTP_CONFLICT},
    {LCB_KEY_ENOENT,                ngx_string("key_enoent"),               NGX_HTTP_NOT_FOUND},
    {LCB_DLOPEN_FAILED,             ngx_string("dlopen_failed"),            NGX_HTTP_INTERNAL_SERVER_ERROR},
    {LCB_DLSYM_FAILED,              ngx_string("dlsym_failed"),             NGX_HTTP_INTERNAL_SERVER_ERROR},
    {LCB_NETWORK_ERROR,             ngx_string("network_error"),            NGX_HTTP_INTERNAL_SERVER_ERROR},
    {LCB_NOT_MY_VBUCKET,            ngx_string("not_my_vbucket"),           NGX_HTTP_INTERNAL_SERVER_ERROR},
    {LCB_NOT_STORED,                ngx_string("not_stored"),               NGX_HTTP_UNPROCESSABLE_ENTITY},
    {LCB_NOT_SUPPORTED,             ngx_string("not_supported"),            NGX_HTTP_INTERNAL_SERVER_ERROR},
    {LCB_UNKNOWN_COMMAND,           ngx_string("unknown_command"),          NGX_HTTP_INTERNAL_SERVER_ERROR},
    {LCB_UNKNOWN_HOST,              ngx_string("unknown_host"),             NGX_HTTP_INTERNAL_SERVER_ERROR},
    {LCB_PROTOCOL_ERROR,            ngx_string("protocol_error"),           NGX_HTTP_INTERNAL_SERVER_ERROR},
    {LCB_ETIMEDOUT,                 ngx_string("etimeout"),                 NGX_HTTP_REQUEST_TIME_OUT},
    {LCB_CONNECT_ERROR,             ngx_string("connect_error"),            NGX_HTTP_INTERNAL_SERVER_ERROR},
    {LCB_BUCKET_ENOENT,             ngx_string("bucket_enoent"),            NGX_HTTP_NOT_FOUND},
    {LCB_CLIENT_ENOMEM,             ngx_string("client_enomem"),            NGX_HTTP_INTERNAL_SERVER_ERROR},
    {LCB_CLIENT_ETMPFAIL,           ngx_string("client_etmpfail"),          NGX_HTTP_INTERNAL_SERVER_ERROR},
    {LCB_EBADHANDLE,                ngx_string("ebadhandle"),               NGX_HTTP_INTERNAL_SERVER_ERROR},
    {LCB_SERVER_BUG,                ngx_string("server_bug"),               NGX_HTTP_INTERNAL_SERVER_ERROR},
    {LCB_PLUGIN_VERSION_MISMATCH,   ngx_string("plugin_version_mismatch"),  NGX_HTTP_INTERNAL_SERVER_ERROR},

    {0,                             ngx_null_string,                        NGX_HTTP_INTERNAL_SERVER_ERROR}
};


static ngx_err_t
cb_format_lcb_error(lcb_t instance, ngx_http_request_t *r, lcb_error_t rc, ngx_str_t *str)
{
    ngx_lcb_error_t *e;
    const u_char *ptr;
    ngx_str_t error = ngx_string("unknown_error");
    const u_char *reason = (const u_char *)"Unknown error code";


    e = ngx_lcb_errors;
    r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    while (e->errmsg.data != NULL) {
        if (rc == e->rc) {
            error = e->errmsg;
            reason = (const u_char *)lcb_strerror(NULL, rc);
            r->headers_out.status = e->status;
            break;
        }
        e++;
    }

    str->len = error.len + ngx_strlen(reason) + 24;
    str->data = ngx_pnalloc(r->pool, str->len);
    if (str->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "couchbase(%p): failed to allocate buffer while formatting libcouchbase error", instance);
        return NGX_ERROR;
    }
    ptr = ngx_sprintf(str->data, "{\"error\":\"%V\",\"reason\":\"%s\"}", &error, reason);
    if ((size_t)(ptr - str->data) != str->len) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "couchbase(%p): failed to format libcouchbase error", instance);
        return NGX_ERROR;
    }
    return NGX_OK;
}

void
ngx_lcb_null_configuration_callback(lcb_t arg1, lcb_configuration_t arg2)
{
    (void)arg1;
    (void)arg2;
}

void
ngx_lcb_configuration_callback(lcb_t instance, lcb_configuration_t config)
{
    if (config == LCB_CONFIGURATION_NEW) {
        ngx_lcb_loc_conf_t *cblcf;
        ngx_http_request_t *r;

        r = (ngx_http_request_t *)lcb_get_cookie(instance);
        cblcf = ngx_http_get_module_loc_conf(r, ngx_http_couchbase_module);
        (void)lcb_set_timeout(instance, cblcf->timeout * 1000); /* in usec */
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "couchbase(%p): the instance has been connected. timeout:%Mms",
                       (void *)instance, cblcf->timeout);
        ngx_lcb_process(r);
    }
    /* supress future updates */
    lcb_set_cookie(instance, NULL);
    (void)lcb_set_configuration_callback(instance, ngx_lcb_null_configuration_callback);
}

ngx_err_t
ngx_lcb_request_set_cas(lcb_t instance, ngx_http_request_t *r, lcb_cas_t cas)
{
    ngx_http_variable_value_t * cas_vv;

    cas_vv = ngx_http_get_indexed_variable(r, ngx_lcb_cas_idx);
    if (cas_vv == NULL) {
        return NGX_ERROR;
    }
    if (cas_vv->not_found) {
        cas_vv->not_found = 0;
        cas_vv->valid = 1;
        cas_vv->no_cacheable = 0;
    }
    cas_vv->data = ngx_pnalloc(r->pool, NGX_UINT64_T_LEN);
    if (cas_vv->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "couchbase(%p): failed to allocate buffer for $couchbase_cas variable", instance);
        return NGX_ERROR;
    }
    cas_vv->len = ngx_sprintf(cas_vv->data, "%uL", (uint64_t)cas) - cas_vv->data;
    return NGX_OK;
}

void
ngx_lcb_store_callback(lcb_t instance, const void *cookie,
                       lcb_storage_t operation, lcb_error_t error,
                       const lcb_store_resp_t *item)
{
    ngx_http_request_t *r = (ngx_http_request_t *)cookie;
    ngx_chain_t out;
    ngx_buf_t *b;
    ngx_int_t rc;

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "couchbase(%p): store response \"%*s\", status: 0x%02xd, operation: 0x%02xd",
                   (void *)instance, item->v.v0.nkey, item->v.v0.key, error, operation);

    r->main->count--;
    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    out.buf = b;
    out.next = NULL;
    b->memory = 1;
    b->last_buf = 1;

    if (error == LCB_SUCCESS) {
        if (ngx_lcb_request_set_cas(instance, r, (uint64_t)item->v.v0.cas) != NGX_OK) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
        r->headers_out.status = NGX_HTTP_CREATED;
        r->headers_out.content_length_n = 0;
        r->header_only = 1;
    } else {
        ngx_str_t errstr;

        rc = cb_format_lcb_error(instance, r, error, &errstr);
        if (rc != NGX_OK) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
        b->pos = errstr.data;
        b->last = errstr.data + errstr.len;
        r->headers_out.content_length_n = errstr.len;
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        ngx_http_finalize_request(r, rc);
        return;
    }
    if (!r->header_only) {
        rc = ngx_http_output_filter(r, &out);
    }
    ngx_http_finalize_request(r, rc);
}

void
ngx_lcb_remove_callback(lcb_t instance, const void *cookie,
                        lcb_error_t error, const lcb_remove_resp_t *item)
{
    ngx_http_request_t *r = (ngx_http_request_t *)cookie;
    ngx_chain_t out;
    ngx_buf_t *b;
    ngx_int_t rc;

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "couchbase(%p): remove response \"%*s\", status: 0x%02xd",
                   (void *)instance, item->v.v0.nkey, item->v.v0.key, error);

    r->main->count--;

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    out.buf = b;
    out.next = NULL;
    b->memory = 1;
    b->last_buf = 1;

    if (error == LCB_SUCCESS) {
        if (ngx_lcb_request_set_cas(instance, r, (uint64_t)item->v.v0.cas) != NGX_OK) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = 0;
        r->header_only = 1;
    } else {
        ngx_str_t errstr;

        rc = cb_format_lcb_error(instance, r, error, &errstr);
        if (rc != NGX_OK) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
        b->pos = errstr.data;
        b->last = errstr.data + errstr.len;
        r->headers_out.content_length_n = errstr.len;
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        ngx_http_finalize_request(r, rc);
        return;
    }
    if (!r->header_only) {
        rc = ngx_http_output_filter(r, &out);
    }
    ngx_http_finalize_request(r, rc);
}

void
ngx_lcb_get_callback(lcb_t instance, const void *cookie, lcb_error_t error,
                     const lcb_get_resp_t *item)
{
    ngx_http_request_t *r = (ngx_http_request_t *)cookie;
    ngx_chain_t out;
    ngx_buf_t *b;
    ngx_int_t rc;

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "couchbase(%p): get response \"%*s\", status: 0x%02xd",
                   (void *)instance, item->v.v0.nkey, item->v.v0.key, error);

    r->main->count--;

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    out.buf = b;
    out.next = NULL;
    b->memory = 1;
    b->last_buf = 1;

    if (error == LCB_SUCCESS) {
        if (ngx_lcb_request_set_cas(instance, r, (uint64_t)item->v.v0.cas) != NGX_OK) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
        b->pos = (u_char *)item->v.v0.bytes;
        b->last = (u_char *)item->v.v0.bytes + item->v.v0.nbytes;
        r->headers_out.content_length_n = item->v.v0.nbytes;
        r->headers_out.status = NGX_HTTP_OK;
    } else {
        ngx_str_t errstr;

        rc = cb_format_lcb_error(instance, r, error, &errstr);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, rc,
                          "couchbase: failed to format libcouchbase error 0x%02xd", rc);
            return;
        }
        b->pos = errstr.data;
        b->last = errstr.data + errstr.len;
        r->headers_out.content_length_n = errstr.len;
    }

    dd("sending headers");
    rc = ngx_http_send_header(r);
    dd("headers sent");
    if (rc == NGX_ERROR || rc > NGX_OK) {
        ngx_http_finalize_request(r, rc);
        return;
    }
    if (!r->header_only) {
        rc = ngx_http_output_filter(r, &out);
    } else {
        rc = NGX_DONE;
    }
    dd("finalizing");
    ngx_http_finalize_request(r, rc);
}
