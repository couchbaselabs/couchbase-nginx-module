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

#ifndef NGX_LCB_PLUGIN_H
#define NGX_LCB_PLUGIN_H 1

struct ngx_lcb_cookie_s {
    ngx_log_t *log;
    ngx_pool_t *pool;
};
typedef struct ngx_lcb_cookie_s *ngx_lcb_cookie_t;

lcb_error_t ngx_lcb_create_io_opts(int version, lcb_io_opt_t *io, void *cookie);

#endif

