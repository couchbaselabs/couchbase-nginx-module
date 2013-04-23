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

#include "ngx_http_couchbase_module.h"

#ifndef NGX_HTTP_UNPROCESSABLE_ENTITY
#define NGX_HTTP_UNPROCESSABLE_ENTITY 422
#endif

#define cb_string_arg(str) (u_char *)str, sizeof(str) - 1
static ngx_err_t
cb_add_header_uint64_t(lcb_t instance, ngx_http_request_t *r, u_char *key, size_t nkey, uint64_t val)
{
    ngx_table_elt_t  *h;
    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "couchbase(%p): failed to allocate buffer for \"%s\" header.", instance, key);
        return NGX_ERROR;
    }
    h->key.data = key;
    h->key.len = nkey;
    h->hash = ngx_hash_key(key, nkey);
    h->value.data = ngx_pnalloc(r->pool, NGX_UINT64_T_LEN);
    if (h->value.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "couchbase(%p): failed to allocate buffer for \"%s\" header value.", instance, key);
        return NGX_ERROR;
    }
    h->value.len = ngx_sprintf(h->value.data, "%02uL", val) - h->value.data;
    return NGX_OK;
}

static ngx_err_t
cb_format_lcb_error(lcb_t instance, ngx_http_request_t *r, lcb_error_t rc, ngx_str_t *str)
{
    const u_char *ptr, *reason = (const u_char *)lcb_strerror(NULL, rc);
    const char *error;

    r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    switch (rc) {
    case LCB_SUCCESS:
        error = "success";
        r->headers_out.status = NGX_HTTP_OK;
        break;
    case LCB_AUTH_CONTINUE:
        error = "auth_continue";
        break;
    case LCB_AUTH_ERROR:
        error = "auth_error";
        break;
    case LCB_DELTA_BADVAL:
        error = "delta_badval";
        r->headers_out.status = NGX_HTTP_UNPROCESSABLE_ENTITY;
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
        r->headers_out.status = NGX_HTTP_CONFLICT;
        break;
    case LCB_KEY_ENOENT:
        error = "key_enoent";
        r->headers_out.status = NGX_HTTP_NOT_FOUND;
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
        r->headers_out.status = NGX_HTTP_UNPROCESSABLE_ENTITY;
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
        r->headers_out.status = NGX_HTTP_REQUEST_TIME_OUT;
        break;
    case LCB_CONNECT_ERROR:
        error = "connect_error";
        break;
    case LCB_BUCKET_ENOENT:
        error = "bucket_enoent";
        r->headers_out.status = NGX_HTTP_NOT_FOUND;
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
                      "couchbase(%p): failed to allocate buffer while formatting libcouchbase error", instance);
        return NGX_ERROR;
    }
    ptr = ngx_sprintf(str->data, "{\"error\":\"%s\",\"reason\":\"%s\"}", error, reason);
    if ((size_t)(ptr - str->data) != str->len) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "couchbase(%p): failed to format libcouchbase error", instance);
        return NGX_ERROR;
    }
    return NGX_OK;
}

void null_configuration_callback(lcb_t arg1, lcb_configuration_t arg2)
{
    (void)arg1;
    (void)arg2;
}

void
ngx_lcb_configuration_callback(lcb_t instance, lcb_configuration_t config)
{
    if (config == LCB_CONFIGURATION_NEW) {
        ngx_http_request_t *r;

        r = (ngx_http_request_t *)lcb_get_cookie(instance);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "couchbase(%p): the instance has been connected",
                       (void *)instance);
        ngx_http_couchbase_process(r);
    }
    /* supress future updates */
    lcb_set_cookie(instance, NULL);
    (void)lcb_set_configuration_callback(instance, null_configuration_callback);
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

    switch (error) {
    case LCB_SUCCESS:
        if (cb_add_header_uint64_t(instance, r, cb_string_arg("X-Couchbase-CAS"),
                                   (uint64_t)item->v.v0.cas) != NGX_OK) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
        r->headers_out.status = NGX_HTTP_CREATED;
        r->headers_out.content_length_n = 0;
        r->header_only = 1;
        break;
    default: {
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
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        ngx_http_finalize_request(r, rc);
        return;
    }
    if (!r->header_only) {
        rc = ngx_http_output_filter(r, &out);
    } else {
        rc = NGX_DONE;
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

    switch (error) {
    case LCB_SUCCESS:
        if (cb_add_header_uint64_t(instance, r, cb_string_arg("X-Couchbase-CAS"),
                                   (uint64_t)item->v.v0.cas) != NGX_OK) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = 0;
        r->header_only = 1;
        break;
    default: {
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
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        ngx_http_finalize_request(r, rc);
        return;
    }
    if (!r->header_only) {
        rc = ngx_http_output_filter(r, &out);
    } else {
        rc = NGX_DONE;
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

    switch (error) {
    case LCB_SUCCESS:
        if (cb_add_header_uint64_t(instance, r, cb_string_arg("X-Couchbase-CAS"),
                                   (uint64_t)item->v.v0.cas) != NGX_OK) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
        b->pos = (u_char *)item->v.v0.bytes;
        b->last = (u_char *)item->v.v0.bytes + item->v.v0.nbytes;
        r->headers_out.content_length_n = item->v.v0.nbytes;
        r->headers_out.status = NGX_HTTP_OK;
        break;
    default: {
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
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        ngx_http_finalize_request(r, rc);
        return;
    }
    if (!r->header_only) {
        rc = ngx_http_output_filter(r, &out);
    } else {
        rc = NGX_DONE;
    }
    ngx_http_finalize_request(r, rc);
}
