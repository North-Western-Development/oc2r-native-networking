#if defined(__linux__)
#include <linux/jni_md.h>
#elif defined(_WIN32)
#include <win32/jni_md.h>
#elif defined(__APPLE__)
#include <darwin/jni_md.h>
#else
#error platform not supported
#endif
