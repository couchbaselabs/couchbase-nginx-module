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

#ifndef NGX_HTTP_COUCHBASE_MODULE_H
#define NGX_HTTP_COUCHBASE_MODULE_H

#include <ngx_core.h>
#include <ngx_http.h>
#include <libcouchbase/couchbase.h>

#include "ngx_http_couchbase_callbacks.h"
#include "ngx_lcb_plugin.h"

typedef struct {
    lcb_t lcb;

    unsigned connected:1;
} ngx_http_couchbase_loc_conf_t;

typedef struct {
    lcb_io_opt_t lcb_io;
    ngx_lcb_cookie_t lcb_cookie;
} ngx_http_couchbase_main_conf_t;

extern ngx_module_t ngx_http_couchbase_module;

ngx_int_t ngx_http_couchbase_process(ngx_http_request_t *r);

#endif /* NGX_HTTP_COUCHBASE_MODULE_H */

