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

#ifndef NGX_HTTP_COUCHBASE_CALLBACKS_H
#define NGX_HTTP_COUCHBASE_CALLBACKS_H

void ngx_lcb_get_callback(lcb_t instance, const void *cookie, lcb_error_t error, const lcb_get_resp_t *item);
void ngx_lcb_remove_callback(lcb_t instance, const void *cookie, lcb_error_t error, const lcb_remove_resp_t *item);
void ngx_lcb_store_callback(lcb_t instance, const void *cookie, lcb_storage_t operation, lcb_error_t error, const lcb_store_resp_t *item);
void ngx_lcb_configuration_callback(lcb_t instance, lcb_configuration_t config);

#endif /* NGX_HTTP_COUCHBASE_CALLBACKS_H */

