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
#include "ddebug.h"

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

static ngx_command_t ngx_http_couchbase_commands[] = {

    {
        ngx_string("couchbase_pass"),
        NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1234,
        ngx_http_couchbase_pass,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },

    {
        ngx_string("couchbase_connect_timeout"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_couchbase_loc_conf_t, upstream.connect_timeout),
        NULL
    },

    {
        ngx_string("couchbase_send_timeout"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_couchbase_loc_conf_t, upstream.send_timeout),
        NULL
    },

    {
        ngx_string("couchbase_read_timeout"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_couchbase_loc_conf_t, upstream.read_timeout),
        NULL
    },

    ngx_null_command
};

static ngx_http_module_t ngx_http_couchbase_module_ctx = {
    NULL,   /* preconfiguration */
    ngx_http_couchbase_postconf,    /* postconfiguration */

    ngx_http_couchbase_create_main_conf,    /* create main configuration */
    ngx_http_couchbase_init_main_conf,      /* init main configuration */

    NULL,   /* create server configuration */
    NULL,   /* merge server configuration */

    ngx_http_couchbase_create_loc_conf, /* create location configuration */
    NULL                                /* merge location configuration */
};

ngx_module_t ngx_http_couchbase_module = {
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

ngx_int_t
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
        size_t loc_len;
        ngx_http_core_loc_conf_t *clcf;

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
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
    case ngx_http_couchbase_cmd_get:
        {
            lcb_get_cmd_t cmd;
            const lcb_get_cmd_t *commands[1];

            commands[0] = &cmd;
            memset(&cmd, 0, sizeof(cmd));
            cmd.v.v0.key = key.data;
            cmd.v.v0.nkey = key.len;
            err = lcb_get(cblcf->lcb, r, 1, commands);
            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "couchbase(%p): get request \"%*s\"",
                           (void *)cblcf->lcb, cmd.v.v0.nkey, cmd.v.v0.key);
        }
        break;
    case ngx_http_couchbase_cmd_set:
    case ngx_http_couchbase_cmd_add:
        {
            lcb_store_cmd_t cmd;
            const lcb_store_cmd_t *commands[1];

            commands[0] = &cmd;
            memset(&cmd, 0, sizeof(cmd));
            cmd.v.v0.operation = (opcode == ngx_http_couchbase_cmd_set) ? LCB_SET : LCB_ADD;
            cmd.v.v0.key = key.data;
            cmd.v.v0.nkey = key.len;
            cmd.v.v0.bytes = val.data;
            cmd.v.v0.nbytes = val.len;
            err = lcb_store(cblcf->lcb, r, 1, commands);
            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "couchbase(%p): store request \"%*s\", operation: 0x%02xd",
                           (void *)cblcf->lcb, cmd.v.v0.nkey, cmd.v.v0.key, cmd.v.v0.operation);
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
            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "couchbase(%p): remove request \"%*s\"",
                           (void *)cblcf->lcb, cmd.v.v0.nkey, cmd.v.v0.key);
        }
        break;
    }
    if (val_vv == NULL && val.data) {
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
ngx_http_couchbase_upstream_init(ngx_http_request_t *r)
{
    ngx_http_couchbase_loc_conf_t *cblcf;

    r->main->count++;
    cblcf = ngx_http_get_module_loc_conf(r, ngx_http_couchbase_module);
    if (cblcf->connected) {
        ngx_http_couchbase_process(r);
    } else {
        lcb_error_t err;

        lcb_set_cookie(cblcf->lcb, r);
        err = lcb_connect(cblcf->lcb);
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "couchbase(%p): connecting to \"%s:%s\"",
                       (void *)cblcf->lcb, lcb_get_host(cblcf->lcb), lcb_get_port(cblcf->lcb));
        if (err != LCB_SUCCESS) {
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "couchbase(%p): failed to initiate connection: 0x%02xd \"%s\"",
                          cblcf->lcb, err, lcb_strerror(NULL, err));
        }
    }
}

static ngx_int_t
ngx_http_couchbase_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;

    rc = ngx_http_read_client_request_body(r, ngx_http_couchbase_upstream_init);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_http_finalize_request(r, rc);
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
    size_t ii, len;
    char *ptr;

    if (cf->args->nelts < 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "couchbase: address argument required for couchbase_pass");
        return NGX_CONF_ERROR;
    }
    value = cf->args->elts;

    ii = 1;
    ptr = calloc(sizeof(char), value[1].len);
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
    if (err != LCB_SUCCESS) {
        /* You can't initialize the library without a io-handler! */
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                      "couchbase: failed to create libcouchbase instance: 0x%02xd \"%s\"",
                      err, lcb_strerror(NULL, err));
        return NGX_CONF_ERROR;
    }
    (void)lcb_set_get_callback(cblcf->lcb, ngx_lcb_get_callback);
    (void)lcb_set_store_callback(cblcf->lcb, ngx_lcb_store_callback);
    (void)lcb_set_remove_callback(cblcf->lcb, ngx_lcb_remove_callback);
    (void)lcb_set_configuration_callback(cblcf->lcb, ngx_lcb_configuration_callback);
    free((void*)options.v.v0.host);
    free((void*)options.v.v0.bucket);
    free((void*)options.v.v0.user);
    free((void*)options.v.v0.passwd);

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

    (void)cmd;
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
    (void)r;
    (void)data;
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
