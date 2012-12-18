#ifndef DDEBUG_H
#define DDEBUG_H

#include <ngx_core.h>

#if defined(NGX_DEBUG) && (NGX_DEBUG)

#   if (NGX_HAVE_VARIADIC_MACROS)

#       define dd(...) \
	    fprintf(stderr, "couchbase[%d] *** %4d:%-45s ", (int)getpid(), __LINE__, __func__); \
            fprintf(stderr, __VA_ARGS__); \
            fprintf(stderr, "\n")

#   else

#include <stdarg.h>
#include <stdio.h>

#include <stdarg.h>

static void dd(const char* fmt, ...) {
}

#    endif

#else

#   if (NGX_HAVE_VARIADIC_MACROS)

#       define dd(...)

#   else

#include <stdarg.h>

static void dd(const char* fmt, ...) {
}

#   endif

#endif

#if defined(NGX_DEBUG) && (NGX_DEBUG)
#   define dd_request(req)	\
	dd("request: %p, connection: %p,  upstream: %p", \
	   (void *)req,	\
	   (void *)req->connection, \
	   (void *)req->upstream)
#else
#   define dd_request(req)
#endif

#endif /* DDEBUG_H */

