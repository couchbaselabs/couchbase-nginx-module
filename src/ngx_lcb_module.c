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

static ngx_int_t ngx_lcb_init_process(ngx_cycle_t *cycle);
static void ngx_lcb_exit_process(ngx_cycle_t *cycle);
static void *ngx_lcb_create_main_conf(ngx_conf_t *cf);
static void *ngx_lcb_create_loc_conf(ngx_conf_t *cf);
static char *ngx_lcb_merge_loc_conf(ngx_conf_t *cf, void *prev, void *conf);
static char *ngx_lcb_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_lcb_postconf(ngx_conf_t *cf);

static ngx_flag_t ngx_lcb_enabled = 0;

static ngx_str_t ngx_lcb_cmd = ngx_string("couchbase_cmd");
static ngx_int_t ngx_lcb_cmd_idx;
static ngx_str_t ngx_lcb_key = ngx_string("couchbase_key");
static ngx_int_t ngx_lcb_key_idx;
static ngx_str_t ngx_lcb_val = ngx_string("couchbase_val");
static ngx_int_t ngx_lcb_val_idx;

enum ngx_lcb_cmd {
    ngx_lcb_cmd_get,
    ngx_lcb_cmd_set,
    ngx_lcb_cmd_add,
    ngx_lcb_cmd_delete
};

static struct ngx_lcb_cookie_s lcb_cookie;
typedef struct ngx_lcb_connection_s {
    ngx_str_t name;
    lcb_t lcb;
} ngx_lcb_connection_t;
static ngx_array_t lcb_connections; /* ngx_lcb_connection_t */
static ngx_lcb_connection_t* ngx_http_get_couchbase_connection(ngx_str_t name);

static ngx_command_t ngx_lcb_commands[] = {

    {
        ngx_string("couchbase_pass"),
        NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1234,
        ngx_lcb_pass,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },

    {
        ngx_string("couchbase_connect_timeout"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_lcb_connection_conf_t, connect_timeout),
        NULL
    },

    {
        ngx_string("couchbase_timeout"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_lcb_connection_conf_t, timeout),
        NULL
    },

    ngx_null_command
};

static ngx_http_module_t ngx_lcb_module_ctx = {
    NULL,   /* preconfiguration */
    ngx_lcb_postconf,    /* postconfiguration */

    ngx_lcb_create_main_conf,   /* create main configuration */
    NULL,   /* init main configuration */

    NULL,   /* create server configuration */
    NULL,   /* merge server configuration */

    ngx_lcb_create_loc_conf, /* create location configuration */
    ngx_lcb_merge_loc_conf   /* merge location configuration */
};

ngx_module_t ngx_http_couchbase_module = {
    NGX_MODULE_V1,
    &ngx_lcb_module_ctx, /* module context */
    ngx_lcb_commands,    /* module directives */
    NGX_HTTP_MODULE,                /* module type */
    NULL,                           /* init master */
    NULL,                           /* init module */
    ngx_lcb_init_process,    /* init process */
    NULL,                           /* init thread */
    NULL,                           /* exit thread */
    ngx_lcb_exit_process,    /* exit process */
    NULL,                           /* exit master */
    NGX_MODULE_V1_PADDING
};

ngx_int_t
ngx_lcb_process(ngx_http_request_t *r)
{
    lcb_error_t err = LCB_NOT_SUPPORTED;
    ngx_http_variable_value_t *cmd_vv, *key_vv, *val_vv;
    ngx_str_t key, val;
    enum ngx_lcb_cmd opcode;
    ngx_http_core_loc_conf_t *clcf;
    ngx_lcb_connection_t *conn;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    conn = ngx_http_get_couchbase_connection(clcf->name);
    if (conn == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "couchbase: connection not found: \"%V\"", &clcf->name);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* setup command: use variable or fallback to HTTP method */
    cmd_vv = ngx_http_get_indexed_variable(r, ngx_lcb_cmd_idx);
    if (cmd_vv == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (cmd_vv->not_found || cmd_vv->len == 0) {
        if (r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD)) {
            opcode = ngx_lcb_cmd_get;
        } else if (r->method == NGX_HTTP_POST) {
            opcode = ngx_lcb_cmd_add;
        } else if (r->method == NGX_HTTP_PUT) {
            opcode = ngx_lcb_cmd_set;
        } else if (r->method == NGX_HTTP_DELETE) {
            opcode = ngx_lcb_cmd_delete;
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
            opcode = ngx_lcb_cmd_get;
        } else if (ngx_strncmp(cmd_vv->data, "set", 3) == 0) {
            opcode = ngx_lcb_cmd_set;
        } else if (ngx_strncmp(cmd_vv->data, "add", 3) == 0) {
            opcode = ngx_lcb_cmd_add;
        } else if (ngx_strncmp(cmd_vv->data, "delete", 6) == 0) {
            opcode = ngx_lcb_cmd_delete;
        } else {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "ngx_memc: unknown $couchbase_cmd \"%v\"", cmd_vv);
            ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
            return NGX_HTTP_BAD_REQUEST;
        }
    }

    /* setup key: use variable or fallback to URI */
    key_vv = ngx_http_get_indexed_variable(r, ngx_lcb_key_idx);
    if (key_vv == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (key_vv->not_found || key_vv->len == 0) {
        size_t loc_len;

        loc_len = r->valid_location ? clcf->name.len : 0;
        key.data = r->uri.data + loc_len;
        key.len = r->uri.len - loc_len;
    } else {
        u_char *dst, *src;
        key.data = ngx_palloc(r->pool, key_vv->len);
        if (key.data == NULL) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        dst = key.data;
        src = key_vv->data;
        ngx_unescape_uri(&dst, &src, key_vv->len, 0);
        *dst = 0;
        key.len = dst - key.data;
    }

    /* setup value: use variable or fallback to HTTP body */
    ngx_str_null(&val);
    val_vv = NULL;
    if (opcode == ngx_lcb_cmd_set || opcode == ngx_lcb_cmd_add) {
        val_vv = ngx_http_get_indexed_variable(r, ngx_lcb_val_idx);
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
                if (p == NULL) {
                    ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                for (cl = r->request_body->bufs; cl; cl = cl->next) {
                    p = ngx_copy(p, cl->buf->pos, cl->buf->last - cl->buf->pos);
                }
                val_vv = NULL;
            }
        } else {
            u_char *dst, *src;
            val.data = ngx_palloc(r->pool, val_vv->len);
            if (val.data == NULL) {
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            dst = val.data;
            src = val_vv->data;
            ngx_unescape_uri(&dst, &src, val_vv->len, 0);
            *dst = 0;
            val.len = dst - val.data;
        }
    }

    switch (opcode) {
    case ngx_lcb_cmd_get: {
        lcb_get_cmd_t cmd;
        const lcb_get_cmd_t *commands[1];

        commands[0] = &cmd;
        memset(&cmd, 0, sizeof(cmd));
        cmd.v.v0.key = key.data;
        cmd.v.v0.nkey = key.len;
        err = lcb_get(conn->lcb, r, 1, commands);
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "couchbase(%p): get request \"%*s\"",
                       (void *)conn->lcb, cmd.v.v0.nkey, cmd.v.v0.key);
    }
    break;
    case ngx_lcb_cmd_set:
    case ngx_lcb_cmd_add: {
        lcb_store_cmd_t cmd;
        const lcb_store_cmd_t *commands[1];

        commands[0] = &cmd;
        memset(&cmd, 0, sizeof(cmd));
        cmd.v.v0.operation = (opcode == ngx_lcb_cmd_set) ? LCB_SET : LCB_ADD;
        cmd.v.v0.key = key.data;
        cmd.v.v0.nkey = key.len;
        cmd.v.v0.bytes = val.data;
        cmd.v.v0.nbytes = val.len;
        err = lcb_store(conn->lcb, r, 1, commands);
        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "couchbase(%p): store request \"%*s\", operation: 0x%02xd",
                       (void *)conn->lcb, cmd.v.v0.nkey, cmd.v.v0.key, cmd.v.v0.operation);
    }
    break;
    case ngx_lcb_cmd_delete: {
        lcb_remove_cmd_t cmd;
        const lcb_remove_cmd_t *commands[1];

        commands[0] = &cmd;
        memset(&cmd, 0, sizeof(cmd));
        cmd.v.v0.key = key.data;
        cmd.v.v0.nkey = key.len;
        err = lcb_remove(conn->lcb, r, 1, commands);
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "couchbase(%p): remove request \"%*s\"",
                       (void *)conn->lcb, cmd.v.v0.nkey, cmd.v.v0.key);
    }
    break;
    }
    if (val_vv == NULL && val.data) {
        ngx_pfree(r->pool, val.data);
    }
    if (err != LCB_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "couchbase: failed to schedule couchbase request: %s",
                      lcb_strerror(conn->lcb, err));
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }
    return NGX_OK;
}

static void
ngx_lcb_upstream_init(ngx_http_request_t *r)
{
    lcb_configuration_callback cb;
    ngx_http_core_loc_conf_t *clcf;
    ngx_lcb_connection_t *conn;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    conn = ngx_http_get_couchbase_connection(clcf->name);
    if (conn == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "couchbase: connection not found: \"%V\"", &clcf->name);
        return;
    }

    r->main->count++;
    cb = lcb_set_configuration_callback(conn->lcb, null_configuration_callback);
    if (cb == null_configuration_callback) {
        /* the instance has been connected */
        ngx_lcb_process(r);
    } else {
        lcb_error_t err;

        lcb_set_configuration_callback(conn->lcb, cb);
        lcb_set_cookie(conn->lcb, r);
        err = lcb_connect(conn->lcb);
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "couchbase(%p): connecting to \"%s:%s\"",
                       (void *)conn->lcb, lcb_get_host(conn->lcb), lcb_get_port(conn->lcb));
        if (err != LCB_SUCCESS) {
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "couchbase(%p): failed to initiate connection: 0x%02xd \"%s\"",
                          conn->lcb, err, lcb_strerror(NULL, err));
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        }
    }
}

static ngx_int_t
ngx_lcb_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;

    rc = ngx_http_read_client_request_body(r, ngx_lcb_upstream_init);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_http_finalize_request(r, rc);
    }
    return NGX_DONE;
}

static void *
ngx_lcb_create_loc_conf(ngx_conf_t *cf)
{
    ngx_lcb_connection_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_lcb_connection_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->timeout = NGX_CONF_UNSET_MSEC;

    return conf;
}

static char *
ngx_lcb_merge_loc_conf(ngx_conf_t *cf, void *prev, void *conf)
{
    ngx_lcb_connection_conf_t *parent = prev;
    ngx_lcb_connection_conf_t *child = conf;
    ngx_lcb_connection_conf_t **confp;
    ngx_lcb_main_conf_t *cmcf;

    ngx_conf_merge_msec_value(child->connect_timeout, parent->connect_timeout, 2500);
    ngx_conf_merge_msec_value(child->timeout, parent->timeout, 2500);

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_couchbase_module);
    if (child->name.data) {
        confp = ngx_array_push(&cmcf->connection_confs);
        *confp = child;
    }
    return NGX_CONF_OK;
}
/* parse couchbase_pass arguments.
 * full form is:
 *
 *   couchbase_pass host:port bucket=val user=val password=val
 */
static char *
ngx_lcb_lcb_options(ngx_conf_t *cf, struct lcb_create_st *options)
{
    ngx_str_t *value;
    size_t ii, len;
    char *ptr;

    if (cf->args->nelts < 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "couchbase: address argument required for couchbase_pass");
        return NGX_CONF_ERROR;
    }
    options->version = 0;

    value = cf->args->elts;
    ii = 1;
    ptr = ngx_pcalloc(cf->pool, sizeof(char) * (value[1].len + 1));
    if (ptr == NULL) {
        goto nomem;
    }
    /* HACK nginx has special meaning for ';' therefore we are using
     * comma as separator for multiple bootstrap hosts. */
    for (ii = 0; ii < value[1].len; ++ii) {
        ptr[ii] = value[1].data[ii];
        if (ptr[ii] == ',') {
            ptr[ii] = ';';
        }
    }
    options->v.v0.host = ptr;
    /* optional arguments */
    for (ii = 2; ii < cf->args->nelts; ii++) {

        if (ngx_strncmp(value[ii].data, "bucket=", sizeof("bucket=") - 1) == 0) {
            len = value[ii].len - (sizeof("bucket=") - 1);
            ptr = ngx_pcalloc(cf->pool, sizeof(char) * (len + 1));
            if (ptr == NULL) {
                goto nomem;
            }
            ngx_memcpy(ptr, &value[ii].data[sizeof("bucket=") - 1], len);
            options->v.v0.bucket = ptr;
            continue;
        }

        if (ngx_strncmp(value[ii].data, "user=", sizeof("user=") - 1) == 0) {
            len = value[ii].len - (sizeof("user=") - 1);
            ptr = ngx_pcalloc(cf->pool, sizeof(char) * (len + 1));
            if (ptr == NULL) {
                goto nomem;
            }
            ngx_memcpy(ptr, &value[ii].data[sizeof("user=") - 1], len);
            options->v.v0.user = ptr;
            continue;
        }

        if (ngx_strncmp(value[ii].data, "password=", sizeof("password=") - 1) == 0) {
            len = value[ii].len - (sizeof("password=") - 1);
            ptr = ngx_pcalloc(cf->pool, sizeof(char) * (len + 1));
            if (ptr == NULL) {
                goto nomem;
            }
            ngx_memcpy(ptr, &value[ii].data[sizeof("password=") - 1], len);
            options->v.v0.passwd = ptr;
            continue;
        }

        goto invalid;
    }
    return NGX_CONF_OK;

nomem:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "couchbase: failed to allocate memory for \"%V\" in %s:%ui", &value[ii]);
    return NGX_CONF_ERROR;

invalid:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "couchbase: invalid parameter \"%V\"", &value[ii]);
    return NGX_CONF_ERROR;
}


static char *
ngx_lcb_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_lcb_connection_conf_t *ccf = conf;
    ngx_http_core_loc_conf_t *clcf;
    char *rc;

    if (ccf->name.data) {
        return "is duplicate";
    }
    ngx_lcb_enabled = 1;

    rc = ngx_lcb_lcb_options(cf, &ccf->options);
    if (rc != NGX_CONF_OK) {
        return rc;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_lcb_handler;
    if (clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }
    ccf->name = clcf->name;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "couchbase: added connection config \"%V\"", &ccf->name);

    (void)cmd;
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_lcb_variable_not_found(ngx_http_request_t *r,
                                      ngx_http_variable_value_t *v,
                                      uintptr_t data)
{
    v->not_found = 1;
    (void)r;
    (void)data;
    return NGX_OK;
}

static ngx_int_t
ngx_lcb_add_variable(ngx_conf_t *cf, ngx_str_t *name)
{
    ngx_http_variable_t *v;

    v = ngx_http_add_variable(cf, name, NGX_HTTP_VAR_CHANGEABLE);
    if (v == NULL) {
        return NGX_ERROR;
    }

    v->get_handler = ngx_lcb_variable_not_found;

    return ngx_http_get_variable_index(cf, name);
}

static ngx_int_t
ngx_lcb_postconf(ngx_conf_t *cf)
{
    if (!ngx_lcb_enabled) {
        return NGX_OK;
    }

    ngx_lcb_cmd_idx = ngx_lcb_add_variable(cf, &ngx_lcb_cmd);
    if (ngx_lcb_cmd_idx == NGX_ERROR) {
        return NGX_ERROR;
    }
    ngx_lcb_key_idx = ngx_lcb_add_variable(cf, &ngx_lcb_key);
    if (ngx_lcb_key_idx == NGX_ERROR) {
        return NGX_ERROR;
    }
    ngx_lcb_val_idx = ngx_lcb_add_variable(cf, &ngx_lcb_val);
    if (ngx_lcb_val_idx == NGX_ERROR) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t
ngx_lcb_init_process(ngx_cycle_t *cycle)
{
    ngx_lcb_main_conf_t *cmcf;
    struct lcb_create_io_ops_st options;
    lcb_error_t err;
    ngx_int_t rc;
    ngx_uint_t i;
    ngx_lcb_connection_t *conn;
    ngx_lcb_connection_conf_t **ccfp;

    /* initialize libcouchbase IO plugin */
    memset(&options, 0, sizeof(options));
    options.version = 2;
    options.v.v2.create = ngx_lcb_create_io_opts;
    options.v.v2.cookie = &lcb_cookie;
    err = lcb_create_io_ops(&lcb_cookie.io, &options);
    if (err != LCB_SUCCESS) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                      "couchbase: failed to create IO object for libcouchbase: 0x%02xd \"%s\"",
                      err, lcb_strerror(NULL, err));
        return NGX_ERROR;
    }

    lcb_cookie.log = cycle->log;
    lcb_cookie.pool = cycle->pool;

    /* materialize upstream connections */
    rc = ngx_array_init(&lcb_connections, cycle->pool, 4, sizeof(ngx_lcb_connection_t));
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }
    cmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_couchbase_module);
    ccfp = cmcf->connection_confs.elts;
    for (i = 0; i < cmcf->connection_confs.nelts; i++) {
        struct lcb_create_st opts = ccfp[i]->options;

        conn = ngx_array_push(&lcb_connections);
        if (conn == NULL) {
            return NGX_ERROR;
        }
        conn->name = ccfp[i]->name;
        opts.v.v0.io = lcb_cookie.io;
        err = lcb_create(&conn->lcb, &opts);
        if (err != LCB_SUCCESS) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "couchbase: failed to create libcouchbase instance: 0x%02xd \"%s\"",
                          err, lcb_strerror(NULL, err));
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        (void)lcb_set_timeout(conn->lcb, ccfp[i]->connect_timeout * 1000); /* in usec */
        (void)lcb_set_get_callback(conn->lcb, ngx_lcb_get_callback);
        (void)lcb_set_store_callback(conn->lcb, ngx_lcb_store_callback);
        (void)lcb_set_remove_callback(conn->lcb, ngx_lcb_remove_callback);
        (void)lcb_set_configuration_callback(conn->lcb, ngx_lcb_configuration_callback);
        ngx_log_debug7(NGX_LOG_DEBUG_HTTP, cycle->log, 0,
                       "couchbase(%p): configured connection \"%V\": connect_timeout:%Mms "
                       "address:%s bucket:%s user:%s password:%s",
                       conn->lcb, &conn->name, ccfp[i]->connect_timeout,
                       opts.v.v0.host ? opts.v.v0.host : "(null)",
                       opts.v.v0.bucket ? opts.v.v0.bucket : "(null)",
                       opts.v.v0.user ? opts.v.v0.user : "(null)",
                       opts.v.v0.passwd ? opts.v.v0.passwd : "(null)");
    }
    return NGX_OK;
}

static void
ngx_lcb_exit_process(ngx_cycle_t *cycle)
{
    lcb_destroy_io_ops(lcb_cookie.io);
    (void)cycle;
}

static void *
ngx_lcb_create_main_conf(ngx_conf_t *cf)
{
    ngx_lcb_main_conf_t *cmcf;
    ngx_int_t rc;

    cmcf = ngx_pcalloc(cf->pool, sizeof(ngx_lcb_main_conf_t));
    if (cmcf == NULL) {
        return NULL;
    }

    rc = ngx_array_init(&cmcf->connection_confs, cf->pool, 4,
                        sizeof(ngx_lcb_connection_conf_t *));
    if (rc != NGX_OK) {
        return NULL;
    }

    return cmcf;
}

static ngx_lcb_connection_t *
ngx_http_get_couchbase_connection(ngx_str_t name)
{
    ngx_lcb_connection_t *conn;
    ngx_uint_t i;

    conn = lcb_connections.elts;
    for (i = 0; i < lcb_connections.nelts; i++) {
        if (name.len == conn[i].name.len &&
            ngx_strncmp(name.data, conn[i].name.data, name.len) == 0) {
            return &conn[i];
        }
    }

    return NULL;
}
