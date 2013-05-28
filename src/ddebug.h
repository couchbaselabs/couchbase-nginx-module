#ifndef DDEBUG_H
#define DDEBUG_H

#include <ngx_core.h>

#if defined(DDEBUG) && (DDEBUG)

#   if (NGX_HAVE_VARIADIC_MACROS)

#       define dd(...) \
	    fprintf(stderr, "couchbase *** %s:%d ", __func__, __LINE__); \
            fprintf(stderr, __VA_ARGS__); \
            fprintf(stderr, "\n")

#   else

#include <stdarg.h>
#include <stdio.h>

static void dd(const char *fmt, ...)
{
}

#    endif

#else

#   if (NGX_HAVE_VARIADIC_MACROS)

#       define dd(...)

#   else

#include <stdarg.h>

static void dd(const char *fmt, ...)
{
}

#   endif

#endif

#endif /* DDEBUG_H */
