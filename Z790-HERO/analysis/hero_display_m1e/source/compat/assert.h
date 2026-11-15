/* The vendored encoder is built like a release C library with NDEBUG. */
#ifndef NDEBUG
#error This freestanding shim is for release builds only
#endif
#define assert(expression) ((void)0)
