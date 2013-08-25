/******************************************************************************
 * $Id$
 *
 * Project:  seccomp_launcher
 * Purpose:  GLibc overload that must be loaded with LD_PRELOAD
 * Author:   Even Rouault, even.rouault at mines-paris.org
 *
 ******************************************************************************
 * Copyright (c) 2013, Even Rouault
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 ****************************************************************************/

#define _BSD_SOURCE
#define _LARGEFILE64_SOURCE 1
#define _GNU_SOURCE 1 /* RTLD_NEXT */

/*#define VERBOSE 1 */

#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <sys/resource.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <malloc.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <locale.h>
#include <dlfcn.h>
#include <dirent.h>
#include <time.h>
#include <wchar.h>
#include <signal.h>
#include <setjmp.h>
#include <pthread.h>

#include "seccomp_launcher.h"

#define TRUE 1
#define FALSE 0

void *my_sbrk(intptr_t increment);

/* Doug Lea public domain malloc() implementation */ 
void* dlmalloc(size_t);
void  dlfree(void*);
void* dlcalloc(size_t, size_t);
void* dlrealloc(void*, size_t);
void* dlmemalign(size_t, size_t);
int dlposix_memalign(void**, size_t, size_t);
void* dlvalloc(size_t);
int dlmallopt(int, int);
struct mallinfo dlmallinfo(void);

static int pipe_in = -1;
static int pipe_out = -1;
static int bInSecomp = FALSE;

static int bUseDlMalloc = FALSE;

/* Our brk() implementation */
#define MAX_VIRTUAL_MEM     (500*1024*1024)
static void* mybrk = NULL;
static int offsetmallocbuffer = 0;
static int maxbrk = 0;

/* For the initial dummy implementation of malloc */
#define STATIC_MEMORY_SIZE  (1024*1024)
static char staticmemory[STATIC_MEMORY_SIZE];
static int offsetstaticmemory = 0;

static int val_SC_CLK_TCK = 0;
static struct lconv* p_globale_locale = NULL;

static char szCWD[PATH_MAX] = { 0 };
static char szReadlinkSelf[PATH_MAX] = { 0 };
/*
static int stdin_isatty = 0;
static int stdout_isatty = 0;
static int stderr_isatty = 0;*/

/* buffer should be at least 21 byte large (20 + 1) for a 64bit val */
static void printuint(char* buffer, unsigned long long val)
{
    int i = 0;
    while( 1 )
    {
        buffer[i++] = '0' + (val % 10);
        val /= 10;
        if( val == 0 )
            break;
    }
    int n = i;
    for(i = 0; i < n/2; i++)
    {
        char ch = buffer[i];
        buffer[i] = buffer[n-1-i];
        buffer[n-1-i] = ch;
    }
    buffer[n] = 0;
}

static void DISPLAY(const char* pszCriticity, const char* pszMsg)
{
    syscall( SYS_write, 2, pszCriticity, strlen(pszCriticity));
    syscall( SYS_write, 2, ": ", strlen(": "));
    syscall( SYS_write, 2, pszMsg, strlen(pszMsg) );
    syscall( SYS_write, 2, "\n", 1 );
}

static void FATAL_ERROR(const char* pszMsg)
{
    DISPLAY("FATAL", pszMsg);
    abort();
}

static void UNIMPLEMENTED(const char* pszMsg)
{
    DISPLAY("UNIMPLEMENTED", pszMsg);
}

static void UNSUPPORTED(const char* pszMsg)
{
    DISPLAY("UNSUPPORTED", pszMsg);
}

#define UNSUPPORTED_FUNC() UNSUPPORTED(__FUNCTION__)

#if VERBOSE
#define ENTER_FUNC() DISPLAY("ENTER", __FUNCTION__)

static void INFO(const char* pszMsg)
{
    DISPLAY("INFO", pszMsg);
}

#define UNIMPLEMENTED_FUNC() UNIMPLEMENTED(__FUNCTION__)
#define DUMMY_FUNC() DISPLAY("DUMMY_FUNC", __FUNCTION__)

#else
#define ENTER_FUNC()
#define INFO(x)
#define UNIMPLEMENTED_FUNC()
#define DUMMY_FUNC()

#endif

/* Used by dlmalloc() routines */
void *my_sbrk(intptr_t increment)
{
    char szBuf[128];
    sprintf(szBuf, "in my_sbrk: inc = %d (offset=%d, maxbrk = %d)",
            (int)increment, offsetmallocbuffer, maxbrk);
    INFO(szBuf);

    if( maxbrk == 0 )
    {
        return sbrk(increment);
    }
    if( offsetmallocbuffer + increment > maxbrk )
    {
        errno = ENOMEM;
        return (void*)-1;
    }

    void* ret = mybrk + offsetmallocbuffer;
    offsetmallocbuffer += increment;
    return ret;
}

void* malloc(size_t size)
{
    if( bUseDlMalloc )
    {
        return dlmalloc(size);
    }
    else
    {
        char buffer[32];
        void* ret;
        ENTER_FUNC();
        strcpy(buffer, "size = ");
        printuint(buffer + strlen("size = "), size);
        INFO(buffer);
        assert(offsetstaticmemory + size < STATIC_MEMORY_SIZE);
        ret = staticmemory + offsetstaticmemory;
        offsetstaticmemory = offsetstaticmemory + ((size + 7) & ~7);
        return ret;
    }
}

void free(void* ptr)
{
    if( bUseDlMalloc && !((char*)ptr >= staticmemory &&
                          (char*)ptr < staticmemory + STATIC_MEMORY_SIZE) )
    {
        dlfree(ptr);
    }
    else
    {
        ENTER_FUNC();
    }
}

void* calloc(size_t nmemb, size_t size)
{
    if( bUseDlMalloc )
        return dlcalloc(nmemb, size);
    else
    {
        void* ptr;
        ENTER_FUNC();
        ptr = malloc(nmemb * size);
        memset(ptr, 0, nmemb * size);
        return ptr;
    }
}

void* realloc(void* ptr, size_t newsize)
{
    if( bUseDlMalloc )
        return dlrealloc(ptr, newsize);
    else
    {
        void* newptr;
        ENTER_FUNC();
        newptr = malloc(newsize);
        if( (size_t)(newptr - ptr) < newsize )
            memcpy(newptr, ptr, (size_t)(newptr - ptr));
        else
            memcpy(newptr, ptr, newsize);
        return newptr;
    }
}

void* memalign(size_t boundary, size_t size)
{
    if( bUseDlMalloc )
        return dlmemalign(boundary, size);
    else
    {
        UNIMPLEMENTED_FUNC();
        return NULL;
    }
}

int posix_memalign(void **memptr, size_t alignment, size_t size)
{
    if( bUseDlMalloc )
        return dlposix_memalign(memptr, alignment, size);
    else
    {
        UNIMPLEMENTED_FUNC();
        return -1; 
    }
}

void* valloc(size_t size)
{
    if( bUseDlMalloc )
        return dlvalloc(size);
    else
    {
        UNIMPLEMENTED_FUNC();
        return NULL; 
    }
}


int mallopt(int param_number, int value)
{
    if( bUseDlMalloc )
        return dlmallopt(param_number, value);
    else
    {
        UNIMPLEMENTED_FUNC();
        return 0;
    }
}

struct mallinfo mallinfo(void)
{
    if( bUseDlMalloc )
        return dlmallinfo();
    else
    {
        UNIMPLEMENTED_FUNC();
        struct mallinfo info;
        memset(&info, 0, sizeof(info));
        return info;
    }
}

typedef struct
{
    const char  *pszLibName;
    void        *pLibHandle;
} Library;

static Library libs[] =
{
    { "libproj.so", NULL },
    { "osgeo/_gdal.so", NULL },
    { "osgeo/_gdalconst.so", NULL },
    { "osgeo/_ogr.so", NULL },
    { "osgeo/_osr.so", NULL },
    { "lib-dynload/readline.so", NULL},

    { "osgeo/_gdal.cpython-32m.so", NULL },
    { "osgeo/_gdalconst.cpython-32m.so", NULL },
    { "osgeo/_ogr.cpython-32m.so", NULL },
    { "osgeo/_osr.cpython-32m.so", NULL },
    { "lib-dynload/readline.cpython-32m.so", NULL},

    { "osgeo/_gdal.cpython-32mu.so", NULL },
    { "osgeo/_gdalconst.cpython-32mu.so", NULL },
    { "osgeo/_ogr.cpython-32mu.so", NULL },
    { "osgeo/_osr.cpython-32mu.so", NULL },
    { "lib-dynload/readline.cpython-32mu.so", NULL},

};

#define N_LIBS (sizeof(libs) / sizeof(libs[0]))

typedef struct
{
    const char  *pszLibName;
    const char  *pszSymName;
    void        *pLibHandle;
    void        *pfn;
} Symbol;

static Symbol syms[] =
{
    { "osgeo/_gdal.so", "init_gdal", NULL, NULL },
    { "osgeo/_gdal.so", "PyInit__gdal", NULL, NULL },
    { "osgeo/_gdalconst.so", "init_gdalconst", NULL, NULL },
    { "osgeo/_gdalconst.so", "PyInit__gdalconst", NULL, NULL },
    { "osgeo/_ogr.so", "init_ogr", NULL, NULL },
    { "osgeo/_ogr.so", "PyInit__ogr", NULL, NULL },
    { "osgeo/_osr.so", "init_osr", NULL, NULL },
    { "osgeo/_osr.so", "PyInit__osr", NULL, NULL },
    { "lib-dynload/readline.so", "initreadline", NULL, NULL },
    { "lib-dynload/readline.so", "PyInit_readline", NULL, NULL },

    { "osgeo/_gdal.cpython-32m.so", "PyInit__gdal", NULL, NULL },
    { "osgeo/_gdalconst.cpython-32m.so", "PyInit__gdalconst", NULL, NULL },
    { "osgeo/_ogr.cpython-32m.so", "PyInit__ogr", NULL, NULL },
    { "osgeo/_osr.cpython-32m.so", "PyInit__osr", NULL, NULL },
    { "lib-dynload/readline.cpython-32m.so", "PyInit_readline", NULL, NULL },

    { "osgeo/_gdal.cpython-32mu.so", "PyInit__gdal", NULL, NULL },
    { "osgeo/_gdalconst.cpython-32mu.so", "PyInit__gdalconst", NULL, NULL },
    { "osgeo/_ogr.cpython-32mu.so", "PyInit__ogr", NULL, NULL },
    { "osgeo/_osr.cpython-32mu.so", "PyInit__osr", NULL, NULL },
    { "lib-dynload/readline.cpython-32mu.so", "PyInit_readline", NULL, NULL },

    { "libproj.so", "pj_init", NULL, NULL },
    { "libproj.so", "pj_init_plus", NULL, NULL },
    { "libproj.so", "pj_free", NULL, NULL },
    { "libproj.so", "pj_transform", NULL, NULL },
    { "libproj.so", "pj_get_errno_ref", NULL, NULL },
    { "libproj.so", "pj_strerrno", NULL, NULL },
    { "libproj.so", "pj_get_def", NULL, NULL },
    { "libproj.so", "pj_dalloc", NULL, NULL },
    { "libproj.so", "pj_ctx_alloc", NULL, NULL },
    { "libproj.so", "pj_ctx_free", NULL, NULL },
    { "libproj.so", "pj_init_plus_ctx", NULL, NULL },
    { "libproj.so", "pj_ctx_get_errno", NULL, NULL }
};

#define N_SYMS (sizeof(syms) / sizeof(syms[0]))

static void resolveSyms(void)
{
    size_t i, j;
    char szPythonPath[256];
    char szLocalPythonPath[256];
    char* pythonpathenv = NULL;
    char* pythonpath = NULL;
    char* pythonlocalpath = NULL;
    if( strstr(szReadlinkSelf, "python") != NULL )
    {
        pythonpathenv = getenv("PYTHONPATH");
        const char* pszBinPython = strstr(szReadlinkSelf, "/bin/python");
        if( pszBinPython != NULL )
        {
            strcpy(szPythonPath, szReadlinkSelf);
            memcpy(szPythonPath + (pszBinPython - szReadlinkSelf + 1), "lib", 3);
            pythonpath = szPythonPath;
            if( strncmp(szReadlinkSelf, "/usr/bin/python", strlen("/usr/bin/python")) == 0 )
            {
                sprintf(szLocalPythonPath, "/usr/local/lib/%s/dist-packages",
                        szReadlinkSelf + strlen("/usr/bin/"));
                pythonlocalpath = szLocalPythonPath;
            }
        }
    }

    for(i = 0; i < N_LIBS; i++)
    {
        if( strncmp(libs[i].pszLibName, "osgeo/", 6) == 0 )
        {
            char szPath[1024];
            if( libs[i].pLibHandle == NULL &&
                pythonpathenv != NULL && strlen(pythonpathenv) < 512 )
            {
                strcpy(szPath, pythonpathenv);
                strcat(szPath, "/");
                strcat(szPath, libs[i].pszLibName);
                libs[i].pLibHandle = dlopen(szPath, RTLD_NOW);
            }
            if( libs[i].pLibHandle == NULL &&
                pythonpath != NULL && strlen(pythonpath) < 512 )
            {
                strcpy(szPath, pythonpath);
                strcat(szPath, "/dist-packages/");
                strcat(szPath, libs[i].pszLibName);
                libs[i].pLibHandle = dlopen(szPath, RTLD_NOW);
            }
            if( libs[i].pLibHandle == NULL &&
                pythonpath != NULL && strlen(pythonpath) < 512 )
            {
                strcpy(szPath, pythonpath);
                strcat(szPath, "/site-packages/");
                strcat(szPath, libs[i].pszLibName);
                /* DISPLAY("trying", szPath); */
                libs[i].pLibHandle = dlopen(szPath, RTLD_NOW);
            }
            if( libs[i].pLibHandle == NULL &&
                pythonlocalpath != NULL && strlen(pythonlocalpath) < 512  )
            {
                strcpy(szPath, pythonlocalpath);
                strcat(szPath, "/");
                strcat(szPath, libs[i].pszLibName);
                libs[i].pLibHandle = dlopen(szPath, RTLD_NOW);
            }
            /*if( libs[i].pLibHandle == NULL )
            {
                fprintf(stderr, "Cannot dlopen(%s) : %s\n",
                        libs[i].pszLibName, dlerror());
            }*/
        }
        else if( strstr(libs[i].pszLibName, "lib-dynload/readline") != NULL )
        {
            char szPath[1024];
            if( pythonpath != NULL && strlen(pythonpath) < 512 )
            {
                strcpy(szPath, pythonpath);
                strcat(szPath, "/");
                strcat(szPath, libs[i].pszLibName);
                libs[i].pLibHandle = dlopen(szPath, RTLD_NOW);
            }
            /*if( libs[i].pLibHandle == NULL )
            {
                fprintf(stderr, "Cannot dlopen(%s) : %s\n",
                        libs[i].pszLibName, dlerror());
            }*/
        }
        else
        {
            libs[i].pLibHandle = dlopen(libs[i].pszLibName, RTLD_NOW);
            /*if( libs[i].pLibHandle == NULL )
            {
                fprintf(stderr, "Cannot dlopen(%s) : %s\n",
                        libs[i].pszLibName, dlerror());
            }*/
        }
    }

    for(i = 0; i < N_SYMS; i++)
    {
        void* pLibHandle = NULL;
        for(j = 0; j < N_LIBS; j++)
        {
            if( strcmp(syms[i].pszLibName, libs[j].pszLibName) == 0 )
            {
                pLibHandle = libs[j].pLibHandle;
                break;
            }
        }
        syms[i].pLibHandle = pLibHandle;
        if( syms[i].pLibHandle != NULL )
            syms[i].pfn = dlsym(syms[i].pLibHandle, syms[i].pszSymName);
    }
}

/* This is an horrible hack to disable dlopen() and friends after going */
/* into seccomp mode. Ideally we would have overriden dlopen() and let it */
/* call the glibc dlopen() before seccomp, but to get the glibc dlopen(), */
/* we need to use dlopen()... */
/* We use here a glibc internal, the _dlfcn_hook pointer, to be able to */
/* switch to our implementation after having gone into seccomp... */
/* Overly fragile ! */

static void* mydlopen (const char *file, int mode, void *dl_caller)
{
    size_t i;
    if( file != NULL )
    {
        for(i = 0; i < N_LIBS; i++)
        {
            if( strcmp(file, libs[i].pszLibName) == 0 ||
                (strncmp(libs[i].pszLibName, "osgeo/", 6) == 0 &&
                 strstr(file, libs[i].pszLibName) != NULL) ||
                (strstr(libs[i].pszLibName, "lib-dynload/readline") !=NULL &&
                 strstr(file, libs[i].pszLibName) != NULL) )
            {
                return libs[i].pLibHandle;
            }
        }
        DISPLAY("cannot dlopen", file);
    }
    UNIMPLEMENTED_FUNC();
    return NULL;
}

static void* mydlsym (void *handle, const char *name, void *dl_caller)
{
    size_t i;
    for(i = 0; i < N_SYMS; i++)
    {
        if( handle == syms[i].pLibHandle &&
            strcmp(name, syms[i].pszSymName) == 0 )
        {
            return syms[i].pfn;
        }
    }
    UNIMPLEMENTED_FUNC();
    return NULL;
}

static char* mydlerror(void)
{
    UNIMPLEMENTED_FUNC();
    return NULL;
}

static void* mydlvsym(void *handle, const char *name, const char *version,
                      void *dl_caller)
{
    UNIMPLEMENTED_FUNC();
    return NULL;
}

static int mydladdr(const void *address, Dl_info *info)
{
    UNIMPLEMENTED_FUNC();
    return 0;
}

static int mydladdr1(const void *address, Dl_info *info,
                     void **extra_info, int flags)
{
    UNIMPLEMENTED_FUNC();;
    return 0;
}

static int mydlinfo(void *handle, int request, void *arg, void *dl_caller)
{
    UNIMPLEMENTED_FUNC();
    return -1;
}

static void* mydlmopen (Lmid_t nsid, const char *file, int mode, void *dl_caller)
{
    UNIMPLEMENTED_FUNC();
    return NULL;
}

/* GLibc internal ! */
struct dlfcn_hook
{
  void *(*dlopen) (const char *file, int mode, void *dl_caller);
  int (*dlclose) (void *handle);
  void *(*dlsym) (void *handle, const char *name, void *dl_caller);
  void *(*dlvsym) (void *handle, const char *name, const char *version,
           void *dl_caller);
  char *(*dlerror) (void);
    int (*dladdr) (const void *address, Dl_info *info);
  int (*dladdr1) (const void *address, Dl_info *info,
          void **extra_info, int flags);
  int (*dlinfo) (void *handle, int request, void *arg, void *dl_caller);
  void *(*dlmopen) (Lmid_t nsid, const char *file, int mode, void *dl_caller);
  void *pad[4];
};

extern struct dlfcn_hook *_dlfcn_hook;
static struct dlfcn_hook myhook = { mydlopen, dlclose, mydlsym, mydlvsym,
                                    mydlerror, mydladdr, mydladdr1,
                                    mydlinfo, mydlmopen, {NULL, NULL, NULL, NULL} };

/* Make sure that the end of the process by a normal return in the main() */
/* calls _exit() directly and does not do any fancy glibc termination stuff */
/* that will choke on seccomp */
static void our_exit(int status, void* unused)
{
    exit(status);
}

void exit(int status)
{
    ENTER_FUNC();
    syscall( SYS_exit, status );
    /* just to please the compiler : warning: incompatible implicit */
    /* declaration of built-in function ‘exit’ but we will never reach that point */
    abort();
}


#ifdef TEST_THREAD_COUNT_DETECTION
static void* dummyThreadFunc(void* ignored)
{
    while(1)
    {
        unsigned int (*pfn_sleep)(unsigned int) = (unsigned int(*)(unsigned int))
            dlsym(RTLD_NEXT, "sleep");
        assert(pfn_sleep);
        pfn_sleep(1);
    }
    return NULL;
}

static void createThreadForTestPurposes()
{
    int (*pfn_pthread_attr_init)(pthread_attr_t*) = (int(*)(pthread_attr_t*))
        dlsym(RTLD_NEXT, "pthread_attr_init");
    assert(pfn_pthread_attr_init);
    int (*pfn_pthread_create)(pthread_t *, const pthread_attr_t *,
                          void *(*) (void *), void *) =
        (int (*)(pthread_t *, const pthread_attr_t *, void *(*) (void *), void *))
            dlsym(RTLD_NEXT, "pthread_create");
    assert(pfn_pthread_create);

    pthread_attr_t hThreadAttr;
    pfn_pthread_attr_init( &hThreadAttr );

    pthread_t hThread;
    pfn_pthread_create(&hThread, &hThreadAttr, dummyThreadFunc, NULL);
}

#endif

/* Purpose: if there are more than 1 thread, abort, since seccomp could be */
/* defeated by hostile code manipulating the other threads. Indeed, seccomp */
/* only affects the current thread. */
/* Note: this is not guaranted at all to detect in all situations that there */
/* are more than 1 thread. If hostile code managed to run before us, they */
/* could manipulate all kind of things and make the test fail. However, */
/* for non-hostile code, this is a usefull sanity checks. (But I'm not sure */
/* why regular non-hostile code would create threads before the start of its */
/* main()... ) */
static void checkThreadCount()
{
    FILE* (*pfn_fopen)(const char*, const char*) =
        (FILE* (*)(const char*, const char*)) dlsym(RTLD_NEXT, "fopen");
    void (*pfn_fclose)(FILE*) = (void(*)(FILE*)) dlsym(RTLD_NEXT, "fclose");
    char* (*pfn_fgets)(char *, int, FILE *) =
        (char*(*)(char *, int, FILE *)) dlsym(RTLD_NEXT, "fgets");
    assert(pfn_fopen);
    assert(pfn_fclose);
    assert(pfn_fgets);
    FILE* f = pfn_fopen("/proc/self/status", "rb");
    assert(f);
    char buf[80];
    int nThreads = 0;
    while( pfn_fgets(buf, sizeof(buf), f) != NULL )
    {
        if( strncmp(buf, "Threads:\t", strlen("Threads:\t")) == 0 )
        {
            nThreads = atoi(buf + strlen("Threads:\t"));
            break;
        }
    }
    pfn_fclose(f);

    if( nThreads != 1 )
    {
        char szMsg[64];
        strcpy(szMsg, "Wrong number of threads : ");
        printuint(szMsg + strlen(szMsg), nThreads);
        FATAL_ERROR(szMsg);
    }
}

static int dummySortFunction(const void * a, const void *b)
{
    return 0;
}

static void pipe_read(void *buf, size_t count)
{
    syscall( SYS_read, pipe_in, buf, count);
}

static void pipe_write(const void *buf, size_t count)
{
    syscall( SYS_write, pipe_out, buf, count);
}

__attribute__((constructor)) static void seccomp_preload_init()
{
    const char* pipein = getenv("PIPE_IN");
    const char* pipeout = getenv("PIPE_OUT");
    if( pipein == NULL )
    {
        FATAL_ERROR("PIPE_IN environmenet variable undefined");
    }
    if( pipeout == NULL )
    {
        FATAL_ERROR("PIPE_OUT environmenet variable undefined");
    }

    pipe_in = atoi(pipein);
    const char* pszComma = strchr(pipein, ',');
    if( pszComma )
    {
        syscall( SYS_close, atoi(pszComma + 1));
    }
    pipe_out = atoi(pipeout);
    pszComma = strchr(pipeout, ',');
    if( pszComma )
    {
        syscall( SYS_close, atoi(pszComma + 1));
    }

#ifdef TEST_THREAD_COUNT_DETECTION
    createThreadForTestPurposes();
#endif

    checkThreadCount();

    on_exit(our_exit, NULL);

    maxbrk = MAX_VIRTUAL_MEM;
    mybrk = sbrk(0);
    sbrk(maxbrk);
    /* We can start using dlmalloc() now */
    bUseDlMalloc = 1;

    /* At its first call, qsort_r() calls __sysconf (_SC_PHYS_PAGES) that */
    /* reads /proc/meminfo with glibc i/o that do mmap... */
    /* so do it now before going into seccomp */
    /* The size parameter must be at least 1024 */
    qsort((void*)0xDEADBEEF, 0, 1024, dummySortFunction);

    /* Check if stdin is a tty */
    /*
    int (*p_glibc_isatty)(int) = (int(*)(int))dlsym(RTLD_NEXT, "isatty");
    assert(p_glibc_isatty);
    assert(p_glibc_isatty != isatty);
    stdin_isatty = p_glibc_isatty(0);
    stdout_isatty = p_glibc_isatty(1);
    stderr_isatty = p_glibc_isatty(2);*/

    /* Fetch current working dir */
    char *(*p_glibc_getcwd)(char *buf, size_t size) =
        (char*(*)(char*,size_t))dlsym(RTLD_NEXT, "getcwd");
    assert(p_glibc_getcwd);
    assert(p_glibc_getcwd != getcwd);
    if( p_glibc_getcwd(szCWD, sizeof(szCWD)) == NULL )
    {
        szCWD[0] = 0;
    }

    /* Fetch current executable name */
    ssize_t (*p_glibc_readlink)(const char *path, char *buf, size_t bufsiz)
        = (ssize_t (*)(const char *, char *, size_t)) dlsym(RTLD_NEXT, "readlink");
    assert(p_glibc_readlink);
    assert(p_glibc_readlink != readlink);
    int readlink_ret = p_glibc_readlink(
        "/proc/self/exe", szReadlinkSelf, sizeof(szReadlinkSelf) - 1);
    if( readlink_ret <= 0 )
        readlink_ret = 0;
    szReadlinkSelf[readlink_ret] = 0;

    /* Read a few sysconf values */
    long int (*p_glibc_sysonf)(int) = (long int(*)(int)) dlsym(RTLD_NEXT, "sysconf");
    assert(p_glibc_sysonf);
    assert(p_glibc_sysonf != sysconf);
    val_SC_CLK_TCK = p_glibc_sysonf(_SC_CLK_TCK);
    
    struct lconv* (*p_glibc_localeconv)(void) = (struct lconv*(*)(void)) dlsym(RTLD_NEXT, "localeconv");
    assert(p_glibc_localeconv);
    assert(p_glibc_localeconv != localeconv);
    p_globale_locale = p_glibc_localeconv();
    assert(p_globale_locale);

        if( getenv("WAIT") != NULL )
        {
            unsigned int (*p_glibc_sleep)(unsigned int) =
                (unsigned int(*)(unsigned int)) dlsym(RTLD_NEXT, "sleep");
            p_glibc_sleep(10);
        }

    /* Load proj.4 and GDAL python bindings symbols */
    resolveSyms();

    /* And now go at least in seccomp ! */
    if( getenv("DISABLE_SECCOMP") == NULL )
    {
        if( prctl( PR_SET_SECCOMP, 1, 0, 0, 0 ) != 0 )
        {
            FATAL_ERROR("prctl( PR_SET_SECCOMP, 1, 0, 0, 0 ) failed");
        }
        DISPLAY("INFO", "in PR_SET_SECCOMP mode");
    }
    else
    {
        DISPLAY("INFO", "should be PR_SET_SECCOMP mode, but no");
    }
    int cmd = CMD_HAS_SWITCHED_TO_SECCOMP;
    pipe_write(&cmd, 4);

    bInSecomp = TRUE;

    /* Use our fake dlopen() and friends */
    _dlfcn_hook = &myhook;
}

static void pipe_write_uint16(unsigned short val)
{
    pipe_write(&val, sizeof(val));
}

int fstat(int fd, struct stat *buf)
{
    return __fxstat(0, fd, buf);
}

static void buf64tobuf(struct stat* buf,
                       const struct stat64* buf64)
{
    buf->st_dev = buf64->st_dev;
    buf->st_ino = buf64->st_ino;
    buf->st_mode = buf64->st_mode;
    buf->st_nlink = buf64->st_nlink;
    buf->st_uid = buf64->st_uid;
    buf->st_gid = buf64->st_gid;
    buf->st_rdev = buf64->st_rdev;
    buf->st_size = buf64->st_size;
    buf->st_blksize = buf64->st_blksize;
    buf->st_blocks = buf64->st_blocks;
    buf->st_atime = buf64->st_atime;
    buf->st_mtime = buf64->st_mtime;
    buf->st_ctime = buf64->st_ctime;
}

int __fxstat (int ver, int fd, struct stat *buf)
{
    struct stat64 buf64;
    int ret;
    ENTER_FUNC();

    ret = __fxstat64(ver, fd, &buf64);
    if( ret == 0 )
    {
        buf64tobuf(buf, &buf64);
    }
    return ret;
}

int __fxstat64(int ver, int fd, struct stat64 *buf)
{
    ENTER_FUNC();

    int cmd = CMD_FSTAT;
    pipe_write(&cmd, 4);
    pipe_write(&fd, 4);
    int ret;
    pipe_read(&ret, 4);
    pipe_read(buf, sizeof(struct stat64));
    int myerrno = 0;
    if( ret < 0 )
        pipe_read(&myerrno, 4);
    errno = myerrno;

    return ret;
}

int __fxstatat (int ver, int dirfd, const char *pathname, struct stat *buf,
                int flags)
{
    UNIMPLEMENTED_FUNC();
    return -1;
}

int __fxstatat64 (int ver, int dirfd, const char *pathname, struct stat64 *buf,
                int flags)
{
    UNIMPLEMENTED_FUNC();
    return -1;
}

int __lxstat(int ver, const char *path, struct stat *buf)
{
    return __xstat(ver, path, buf);
}

int __lxstat64(int ver, const char *path, struct stat64 *buf)
{
    return __xstat64(ver, path, buf);
}

int __xstat(int ver, const char *path, struct stat *buf)
{
    struct stat64 buf64;
    int ret;
    ENTER_FUNC();

    ret = __xstat64(ver, path, &buf64);
    if( ret == 0 )
    {
        buf64tobuf(buf, &buf64);
    }
    return ret;
}

int __xstat64(int ver, const char *path, struct stat64 *buf)
{
    ENTER_FUNC();
    INFO(path);

    int len = strlen(path);
    if( len >= 65536 )
    {
        errno = ENAMETOOLONG;
        return -1;
    }

    int cmd = CMD_STAT;
    pipe_write(&cmd, 4);
    pipe_write_uint16(len);
    pipe_write(path, len);
    int ret;
    pipe_read(&ret, 4);
    pipe_read(buf, sizeof(struct stat64));
    int myerrno = 0;
    if( ret < 0 )
        pipe_read(&myerrno, 4);
    errno = myerrno;
    return ret;
}

int stat(const char *path, struct stat *buf)
{
    return __xstat(0, path, buf);
}

int stat64(const char *path, struct stat64 *buf)
{
    return __xstat64(0, path, buf);
}


ssize_t readlink(const char *path, char *buf, size_t bufsiz)
{
    if( strcmp(path, "/proc/self/exe") == 0 )
    {
        int szReadlinkSelfLen = (int)strlen(szReadlinkSelf);
        strncpy(buf, szReadlinkSelf, bufsiz);
        return szReadlinkSelfLen;
    }
    else
    {
        UNIMPLEMENTED_FUNC();
        errno = EINVAL;
        return -1;
    }
}

int chdir(const char *path)
{
    UNIMPLEMENTED_FUNC();
    return -1;
}

int fchdir(int fd)
{
    UNIMPLEMENTED_FUNC();
    return -1;
}

char *getcwd(char *buf, size_t size)
{
    ENTER_FUNC();
    if( buf == NULL )
    {
        if( size == 0 )
            size = strlen(szCWD) + 1;
        buf = (char*) malloc(size);
    }
    strncpy(buf, szCWD, size);
    if( strlen(szCWD) >= size )
    {
        errno = ERANGE;
        return NULL;
    }
    errno = 0;
    return buf;
}

char *getwd(char *buf)
{
    ENTER_FUNC();
    return getcwd(buf, PATH_MAX);
}

char *get_current_dir_name(void)
{
    ENTER_FUNC();
    return getcwd(NULL, 0);
}

char *__realpath_chk(const char *path, char *resolved_path, size_t resolved_len)
{
    return realpath(path, resolved_path);
}

char *realpath(const char *path, char *resolved_path)
{
    ENTER_FUNC();
    /* Not conformant: should remove ./, ../, resolve symlinks, etc... */
    if( resolved_path == NULL )
        resolved_path = (char*) malloc(PATH_MAX);
    if( *path == '/' )
        strcpy(resolved_path, path);
    else
    {
        getcwd(resolved_path, PATH_MAX);
        strcat(resolved_path, "/");
        strcat(resolved_path, path);
    }
    return resolved_path;
}

int gethostname(char *name, size_t len)
{
    ENTER_FUNC();
    strncpy(name, "localhost", len);
    if( len <= strlen("localhost") )
    {
        errno = ENAMETOOLONG;
        return -1;
    }
    errno = 0;
    return 0;
}


int uname(struct utsname *buf)
{
    UNIMPLEMENTED_FUNC();
    return -1;
}

struct passwd *getpwnam(const char *name)
{
    UNIMPLEMENTED_FUNC();
    return NULL;
}

struct passwd *getpwuid(uid_t uid)
{
    UNIMPLEMENTED_FUNC();
    return NULL;
}

int fcntl(int fd, int cmd, ...)
{
    UNIMPLEMENTED_FUNC();
    if( cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC || cmd == F_SETFD || cmd == F_SETFL ||
        cmd == F_SETOWN || cmd == F_SETSIG || cmd == F_SETLEASE || cmd == F_NOTIFY )
    {
        va_list args;
        va_start(args, cmd);
        va_arg(args, long);
        va_end(args);
    }
    else if( cmd == F_SETLK || cmd == F_SETLKW || cmd == F_GETLK )
    {
        va_list args;
        va_start(args, cmd);
        va_arg(args, void*);
        va_end(args);
    }
    return 0;
}

int lockf(int fildes, int function, off_t size)
{
    UNIMPLEMENTED_FUNC();
    return 0;
}

int lockf64 (int fd, int cmd, off64_t len64)
{
    UNIMPLEMENTED_FUNC();
    return 0;
}

pid_t getpid(void)
{
    DUMMY_FUNC();
    return 1;
}

pid_t getppid(void)
{
    DUMMY_FUNC();
    return 0;
}

uid_t getuid(void)
{
    DUMMY_FUNC();
    return 1;
}

uid_t geteuid(void)
{
    DUMMY_FUNC();
    return 1;
}

gid_t getgid(void)
{
    DUMMY_FUNC();
    return 1;
}

gid_t getegid(void)
{
    DUMMY_FUNC();
    return 1;
}

int select(int nfds, fd_set *readfds, fd_set *writefds,
            fd_set *exceptfds, struct timeval *timeout)
{
    if( nfds == 1 && readfds != NULL && writefds == NULL && exceptfds == NULL &&
        timeout == NULL )
    {
        int cmd = CMD_SELECT_STDIN;
        pipe_write(&cmd, 4);
        int ret;
        pipe_read(&ret, 4);
        int isset;
        pipe_read(&isset, 4);
        if( isset )
            FD_SET(0, readfds);
        else
            FD_CLR(0, readfds);
        return ret;
    }

    UNIMPLEMENTED_FUNC();
    return -1;
}

int socket(int domain, int type, int protocol)
{
    UNIMPLEMENTED_FUNC();
    return -1;
}

static int myopen(const char *pathname, int flags, int mode)
{
    ENTER_FUNC();
    INFO(pathname);

    if( pipe_out < 0 )
    {
        return -1;
    }

    int len = strlen(pathname);
    if( len >= 65536 )
    {
        errno = ENAMETOOLONG;
        return -1;
    }

    int cmd = CMD_OPEN;
    pipe_write(&cmd, 4);
    pipe_write_uint16(len);
    pipe_write(pathname, len);
    pipe_write(&flags, 4);
    pipe_write(&mode, 4);

    int fd;
    pipe_read(&fd, 4);
    int myerrno = 0;
    if( fd < 0 )
        pipe_read(&myerrno, 4);

    char buffer[32];
    strcpy(buffer, "fd = ");
    if( fd < 0 )
    {
        strcpy(buffer + strlen(buffer), "-");
        printuint(buffer + strlen(buffer), -fd);
    }
    else
        printuint(buffer + strlen(buffer), fd);
    INFO(buffer);

    errno = myerrno;

    return fd;
}


int dup(int oldfd)
{
    ENTER_FUNC();
    int cmd = CMD_DUP;
    pipe_write(&cmd, 4);
    pipe_write(&oldfd, 4);
    int ret;
    pipe_read(&ret, 4);
    int myerrno = 0;
    if( ret < 0 )
        pipe_read(&myerrno, 4);
    errno = myerrno;
    return ret;
}

int dup2(int oldfd, int newfd)
{
    ENTER_FUNC();
    int cmd = CMD_DUP2;
    pipe_write(&cmd, 4);
    pipe_write(&oldfd, 4);
    pipe_write(&newfd, 4);
    int ret;
    pipe_read(&ret, 4);
    int myerrno = 0;
    if( ret < 0 )
        pipe_read(&myerrno, 4);
    errno = myerrno;
    return ret;
}

int open(const char *pathname, int flags, ...)
{
    int mode = 0;
    if( flags & O_CREAT )
    {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }
    return myopen(pathname, flags, mode);
}

int open64(const char *pathname, int flags, ...)
{
    int mode = 0;
    if( flags & O_CREAT )
    {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }
    return myopen(pathname, flags, mode);
}

int creat(const char *pathname, mode_t mode)
{
    return myopen(pathname, O_CREAT|O_WRONLY|O_TRUNC, mode);
}


int close(int fd)
{
    char buffer[32];

    ENTER_FUNC();

    strcpy(buffer, "fd = ");
    if( fd < 0 )
    {
        strcpy(buffer + strlen(buffer), "-");
        printuint(buffer + strlen(buffer), -fd);
    }
    else
        printuint(buffer + strlen(buffer), fd);
    INFO(buffer);

    if( fd < 0 )
        return -1;
    if( pipe_out < 0 )
        return -1;

    int cmd = CMD_CLOSE;
    pipe_write(&cmd, 4);
    pipe_write(&fd, 4);
    int ret;
    pipe_read(&ret, 4);
    int myerrno = 0;
    if( ret < 0 )
        pipe_read(&myerrno, 4);
    errno = myerrno;
    return ret;
}

static int silent = 0;
ssize_t read(int fd, void *buf, size_t count)
{
    if( pipe_out < 0 )
        return 0;

    int cmd = CMD_READ;
    pipe_write(&cmd, 4);
    pipe_write(&fd, 4);
    int len = count;
    pipe_write(&len, 4);

    int ret;
    pipe_read(&ret, 4);
    int myerrno = 0;
    if( ret > 0 )
        pipe_read(buf, ret);
    else
        pipe_read(&myerrno, 4);

    if( !silent )
    {
        char szBuffer[64];
        sprintf(szBuffer, "read(%d, %p, %d) = %d", fd, buf, (int)count, ret);
        INFO(szBuffer);
    }
    errno = myerrno;

    return ret;
}

ssize_t write(int fd, const void *buf, size_t count)
{
    /* ENTER_FUNC(); */
    if( pipe_out < 0 )
        return 0;

    int cmd = CMD_WRITE;
    pipe_write(&cmd, 4);
    pipe_write(&fd, 4);
    int len = count;
    pipe_write(&len, 4);
    pipe_write(buf, len);

    int ret;
    pipe_read(&ret, 4);
    int myerrno = 0;
    if( ret <= 0 )
        pipe_read(&myerrno, 4);
    errno = myerrno;
    return ret;
}

ssize_t pread(int fd, void *buf, size_t count, off_t offset)
{
    return pread64(fd, buf, count, offset);
}

ssize_t pread64(int fd, void *buf, size_t count, off64_t offset)
{
    ENTER_FUNC();
    if( lseek64(fd, offset, SEEK_SET) != offset )
        return 0;
    return read(fd, buf, count);
}

off_t lseek(int fd, off_t offset, int whence)
{
    return lseek64(fd, offset, whence);
}

loff_t llseek(int fd, loff_t offset, int whence)
{
    return lseek64(fd, offset, whence);
}

__off64_t lseek64(int fd, __off64_t offset, int whence)
{
    ENTER_FUNC();
    if( pipe_out < 0 )
    {
        DISPLAY("ERROR", "invalid lseek");
        return -1;
    }

    int cmd = CMD_SEEK;
    pipe_write(&cmd, 4);
    pipe_write(&fd, 4);
    long long loffset = offset;
    pipe_write(&loffset, 8);
    pipe_write(&whence, 4);
    long long ret;
    pipe_read(&ret, 8);
    int myerrno = 0;
    if( ret < 0 )
        pipe_read(&myerrno, 4);

    char szBuffer[64];
    sprintf(szBuffer, "lseek(%d, %d, %d) = %d", fd, (int)offset, whence, (int)ret);
    INFO(szBuffer);
    errno = myerrno;

    return (__off64_t)ret;
}

int fsync(int fd)
{
    UNIMPLEMENTED_FUNC();
    return 0;
}

int fdatasync(int fd)
{
    UNIMPLEMENTED_FUNC();
    return 0;
}

typedef struct
{
    int server_handle;
} MYDIR;


DIR *opendir(const char *name)
{
    ENTER_FUNC();

    int len = strlen(name);
    if( len >= 65536 )
    {
        errno = ENAMETOOLONG;
        return NULL;
    }

    int cmd = CMD_OPENDIR;
    pipe_write(&cmd, 4);
    pipe_write_uint16(len);
    pipe_write(name, len);

    int server_handle;
    pipe_read(&server_handle, 4);

    if( server_handle < 0 )
        return NULL;

    MYDIR* mydir = (MYDIR*) malloc(sizeof(MYDIR));
    mydir->server_handle = server_handle;
    return (DIR*) mydir;
}

struct dirent ent;

struct dirent *readdir(DIR *dirp)
{
    struct dirent* ret;
    readdir_r(dirp, &ent, &ret);
    return ret;
}

int readdir_r(DIR *dirp, struct dirent *entry, struct dirent **result)
{
    ENTER_FUNC();

    MYDIR* mydir = (MYDIR*) dirp;

    int cmd = CMD_READDIR;
    pipe_write(&cmd, 4);
    pipe_write(&mydir->server_handle, 4);
    int ret;
    pipe_read(&ret, 4);
    if( ret == 0 )
    {
        pipe_read(entry, sizeof(struct dirent));
        *result = entry;
        return 0;
    }
    else
    {
        *result = NULL;
        return -1;
    }
}

struct dirent64 ent64;

struct dirent64 *readdir64(DIR *dirp)
{
    struct dirent64* ret;
    readdir64_r(dirp, &ent64, &ret);
    return ret;
}

int readdir64_r(DIR *dirp, struct dirent64 *entry, struct dirent64 **result)
{
    ENTER_FUNC();

    MYDIR* mydir = (MYDIR*) dirp;

    int cmd = CMD_READDIR64;
    pipe_write(&cmd, 4);
    pipe_write(&mydir->server_handle, 4);
    int ret;
    pipe_read(&ret, 4);
    if( ret == 0 )
    {
        pipe_read(entry, sizeof(struct dirent64));
        *result = entry;
        return 0;
    }
    else
    {
        *result = NULL;
        return -1;
    }
}


void rewinddir(DIR *dirp)
{
    ENTER_FUNC();

    MYDIR* mydir = (MYDIR*) dirp;

    int cmd = CMD_REWINDDIR;
    pipe_write(&cmd, 4);
    pipe_write(&mydir->server_handle, 4);
}


int closedir(DIR *dirp)
{
    ENTER_FUNC();

    MYDIR* mydir = (MYDIR*) dirp;

    int cmd = CMD_CLOSEDIR;
    pipe_write(&cmd, 4);
    pipe_write(&mydir->server_handle, 4);
    int ret;
    pipe_read(&ret, 4);
    free(mydir);
    return ret;
}



int pthread_key_create(pthread_key_t *key,
                        void (*__destr_function) (void *))
{
    DUMMY_FUNC();
    static int countKeys = 0;
    *key = countKeys;
    countKeys ++;
    return 0;
}

int pthread_key_delete(pthread_key_t __key)
{
    DUMMY_FUNC();
    return 0;
}

typedef struct
{
    pthread_key_t key;
    void* value;
} specific;
specific tab_specs[16];
static int nspecs = 0;

void* pthread_getspecific(pthread_key_t key)
{
    /* ENTER_FUNC(); */
    int i;
    for(i = 0; i < nspecs; i ++)
    {
        if( key == tab_specs[i].key )
            return tab_specs[i].value;
    }
    //fprintf(stderr, "pthread_getspecific %d\n", ignored);
    return NULL;
}

int pthread_setspecific(pthread_key_t key, __const void *p)
{
    /* ENTER_FUNC(); */
    int i;
    for(i = 0; i < nspecs; i ++)
    {
        if( key == tab_specs[i].key )
        {
            /* fprintf(stderr, "pthread_setspecific %d = %p\n", key, p); */
            tab_specs[i].value = (void*)p;
            return 0;
        }
    }
    if( nspecs == 16 )
        return -1;
    tab_specs[nspecs].key = key;
    tab_specs[nspecs].value = (void*)p;
    nspecs ++;
    return 0;
}

pthread_once_t* tab_onces[16] = { NULL };
static int nkeys = 0;

int pthread_once(pthread_once_t *once_control,
             void (*__init_routine) (void))
{
    /* ENTER_FUNC(); */
    int i;
    for(i = 0; i < nkeys; i ++)
    {
        if( once_control == tab_onces[i] )
            return 0;
    }
    if( nkeys == 16 )
        return -1;
    tab_onces[nkeys ++] = once_control;

    __init_routine();
    return 0;
}

int pthread_getattr_np(pthread_t thread, pthread_attr_t *attr)
{
    UNIMPLEMENTED_FUNC();
    return -1;
}

int pthread_mutexattr_init(pthread_mutexattr_t *__attr)
{
    /* FIXME! : we need UNIMPLEMENTED_FUNC() to make that work ! weird !! */
    UNIMPLEMENTED_FUNC();
    return 0;
}

int pthread_mutexattr_settype(pthread_mutexattr_t *__attr, int __kind)
{
    /* DUMMY_FUNC(); */
    return 0;
}

int pthread_setcanceltype(int __type, int *__oldtype)
{
    /*UNIMPLEMENTED_FUNC(); */
    return 0;
}

int pthread_attr_init(pthread_attr_t *__attr)
{
    /* DUMMY_FUNC(); */
    return 0;
}

int pthread_attr_destroy(pthread_attr_t *__attr)
{
    /* DUMMY_FUNC(); */
    return 0;
}

int pthread_attr_setdetachstate(pthread_attr_t *__attr, int __detachstate)
{
    /* DUMMY_FUNC(); */
    return 0;
}

int pthread_attr_setschedpolicy(pthread_attr_t *__attr, int __policy)
{
    /* DUMMY_FUNC(); */
    return 0;
}

int pthread_attr_setstack(pthread_attr_t *attr,
                                 void *stackaddr, size_t stacksize)
{
    UNIMPLEMENTED_FUNC();
    return -1;
}

int pthread_attr_getstack(const pthread_attr_t *__restrict __attr,
                  void **__restrict __stackaddr,
                  size_t *__restrict __stacksize)
{
    UNIMPLEMENTED_FUNC();
    return -1;
}

int pthread_attr_setstacksize(pthread_attr_t *__attr,
                      size_t __stacksize)
{
    UNIMPLEMENTED_FUNC();
    return -1;
}

int pthread_attr_setscope(pthread_attr_t *__attr, int __scope)
{
    UNIMPLEMENTED_FUNC();
    return -1;
}

int pthread_mutex_init(pthread_mutex_t *__mutex,
                   __const pthread_mutexattr_t *__mutexattr)
{
    /* DUMMY_FUNC(); */
    return 0;
}

int pthread_mutex_trylock(pthread_mutex_t *__mutex)
{
    /* DUMMY_FUNC(); */
    return 0;
}

int pthread_mutex_lock(pthread_mutex_t *__mutex)
{
    /* DUMMY_FUNC(); */
    return 0;
}

int pthread_mutex_timedlock(pthread_mutex_t *__restrict __mutex,
                                    __const struct timespec *__restrict
                                    __abstime)
{
    /* DUMMY_FUNC(); */
    return 0;
}

int pthread_mutex_unlock(pthread_mutex_t *__mutex)
{
    /* DUMMY_FUNC(); */
    return 0;
}

int pthread_mutex_destroy(pthread_mutex_t *__mutex)
{
    /* DUMMY_FUNC(); */
    return 0;
}

int pthread_cond_init(pthread_cond_t *__restrict __cond,
                  __const pthread_condattr_t *__restrict
                  __cond_attr)
{
    /* DUMMY_FUNC(); */
    return 0;
}

int pthread_cond_signal(pthread_cond_t *__cond)
{
    /* DUMMY_FUNC(); */
    return 0;
}

int pthread_cond_broadcast(pthread_cond_t *__cond)
{
    /* DUMMY_FUNC(); */
    return 0;
}

int pthread_cond_wait(pthread_cond_t *__restrict __cond,
                  pthread_mutex_t *__restrict __mutex)
{
    /* DUMMY_FUNC(); */
    return 0;
}

int pthread_cond_timedwait(pthread_cond_t *__restrict __cond,
                   pthread_mutex_t *__restrict __mutex,
                   __const struct timespec *__restrict __abstime)
{
    /* DUMMY_FUNC(); */
    return 0;
}

int pthread_cond_destroy(pthread_cond_t *__cond)
{
    /* DUMMY_FUNC(); */
    return 0;
}


int pthread_getschedparam(pthread_t __target_thread,
                  int *__restrict __policy,
                  struct sched_param *__restrict __param)
{
    /* DUMMY_FUNC(); */
    return 0;
}

int pthread_join(pthread_t __th, void **__thread_return)
{
    UNIMPLEMENTED_FUNC();
    return 0;
}

int pthread_detach(pthread_t __th)
{
    UNIMPLEMENTED_FUNC();
    return 0;
}

int pthread_sigmask(int __how,
                __const __sigset_t *__restrict __newmask,
                __sigset_t *__restrict __oldmask)
{
    /* DUMMY_FUNC(); */
    return 0;
}

int pthread_kill (pthread_t __threadid, int __signo)
{
    UNIMPLEMENTED_FUNC();
    return -1;
}

int pthread_yield()
{
    UNIMPLEMENTED_FUNC();
    return -1;
}

int sched_yield(void)
{
    UNIMPLEMENTED_FUNC();
    return -1;
}

int nanosleep(const struct timespec *req, struct timespec *rem)
{
    UNIMPLEMENTED_FUNC();
    return -1;
}

unsigned int sleep(unsigned int seconds)
{
    UNIMPLEMENTED_FUNC();
    return -1;
}

int usleep(useconds_t usec)
{
    char szBuf[128];
    sprintf(szBuf, "in usleep: usec = %d\n", usec);
    INFO(szBuf);
    return 0;
}

int pthread_create(pthread_t *__restrict __newthread,
               __const pthread_attr_t *__restrict __attr,
               void *(*__start_routine) (void *),
               void *__restrict __arg)
{
    UNIMPLEMENTED_FUNC();
    return -1;
}

int pthread_cancel(pthread_t __th)
{
    UNIMPLEMENTED_FUNC();
    return 0;
}

void pthread_exit(void *__retval)
{
    UNIMPLEMENTED_FUNC();
    abort();
}

pthread_t pthread_self(void)
{
    return 1;
}

int pthread_equal(pthread_t t1, pthread_t t2)
{
    return t1 == t2;
}

int sem_init()
{
    UNIMPLEMENTED_FUNC();
    return 0;
}

int sem_destroy()
{
    UNIMPLEMENTED_FUNC();
    return 0;
}

int sem_post()
{
    UNIMPLEMENTED_FUNC();
    return 0;
}

int sem_wait()
{
    UNIMPLEMENTED_FUNC();
    return 0;
}

int sem_timedwait()
{
    UNIMPLEMENTED_FUNC();
    return 0;
}

int sem_trywait()
{
    UNIMPLEMENTED_FUNC();
    errno = EAGAIN;
    return -1;
}

#define BUFFERSIZE  4096

typedef struct
{
    _IO_FILE baseFile;
    long long offset;
    int eof;
    int errorflag;
/*
    long long fdoffset;
    unsigned char buffer[BUFFERSIZE];
    int ibufoff;
    int ibufsize;*/
} MYFILE;

FILE *fopen(const char *path, const char *mode)
{
    int fd = -1;
    long long offset = 0;
    ENTER_FUNC();

    if( strchr(mode, 'r') && strchr(mode, '+') )
        fd = open(path, O_RDWR, 0);
    else if( strchr(mode, 'r') )
        fd = open(path, O_RDONLY, 0);
    else if( strchr(mode, 'w') && strchr(mode, '+') )
        fd = open(path, O_RDWR | O_CREAT, 0666);
    else if( strchr(mode, 'w') )
        fd = open(path, O_WRONLY | O_CREAT, 0666);
    else if( strchr(mode, 'a') && strchr(mode, '+') )
    {
        fd = open(path, O_RDWR | O_CREAT, 0666);
        if( fd >= 0 )
            offset = lseek(fd, 0, SEEK_END);
    }
    else if( strchr(mode, 'a') )
    {
        fd = open(path, O_WRONLY | O_CREAT, 0666);
        if( fd >= 0 )
            offset = lseek(fd, 0, SEEK_END);
    }
    int myerrno = errno;
    if( fd >= 0 )
    {
        MYFILE* myfile = (MYFILE*)malloc(sizeof(MYFILE));
        memset(myfile, 0, sizeof(MYFILE));
        myfile->baseFile._fileno = fd;
        myfile->offset = offset;
        myfile->eof = 0;
        myfile->errorflag = 0;
        /*myfile->fdoffset = 0;
        myfile->ibufoff = -1;
        myfile->ibufsize = 0;*/
        errno = myerrno;
        return (FILE*)myfile;
    }
    errno = myerrno;
    return NULL;
}

FILE *fopen64(const char *path, const char *mode)
{
    return fopen(path, mode);
}

FILE *fdopen(int fd, const char *mode)
{
    ENTER_FUNC();
    MYFILE* myfile = (MYFILE*)malloc(sizeof(MYFILE));
    memset(myfile, 0, sizeof(MYFILE));
    myfile->baseFile._fileno = fd;
    return (FILE*)myfile;
}

FILE *freopen(const char *path, const char *mode, FILE *stream)
{
    UNIMPLEMENTED_FUNC();
    return NULL;
}

int fclose(FILE *f)
{
    if (f == stdin )
        return -1;
    else if( f == stdout )
        return -1;
    else if( f == stderr )
        return -1;
    else
    {
        MYFILE* myfile = (MYFILE*)f;
        int ret = close(myfile->baseFile._fileno);
        int myerrno = errno;
        free(myfile);
        errno = myerrno;
        if( ret < 0 ) 
            return EOF;
        else
            return 0;
    }
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *f)
{
    if( size == 0 || nmemb == 0 )
        return 0;
    if (f == stdin )
        return 0;
    else if( f == stdout )
        return 0;
    else if( f == stderr )
        return 0;
    else
    {
        MYFILE* myfile = (MYFILE*)f;
        ssize_t read_bytes = read(myfile->baseFile._fileno, ptr, size * nmemb);
        int myerrno = errno;
        if( read_bytes == 0 )
            myfile->eof = 1;
        myfile->offset += read_bytes;
        errno = myerrno;
        return read_bytes / size;
    }
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *f)
{
    if( size == 0 || nmemb == 0 )
        return 0;
    if (f == stdin )
        return 0;
    else if( f == stdout )
    {
        write(1, ptr, size * nmemb);
        return nmemb;
    }
    else if( f == stderr )
    {
        write(2, ptr, size * nmemb);
        return nmemb;
    }
    else
    {
        MYFILE* myfile = (MYFILE*)f;
        ssize_t written = write(myfile->baseFile._fileno, ptr, size * nmemb);
        int myerrno = errno;
        myfile->offset += written;
        errno = myerrno;
        return written / size;
    }
}

void rewind(FILE *f)
{
    fseek(f, 0, SEEK_SET);
    if ( !(f == stdin || f == stdout || f == stderr) )
    {
        MYFILE* myfile = (MYFILE*)f;
        myfile->errorflag = 0;
    }
}


int fseek(FILE *f, long offset, int whence)
{
    return fseeko64(f, offset, whence);
}

int fseeko(FILE *f, off_t offset, int whence)
{
    return fseeko64(f, offset, whence);
}

int fseeko64(FILE *f, off64_t offset, int whence)
{
    if (f == stdin )
        return 0;
    else if( f == stdout )
        return 0;
    else if( f == stderr )
        return 0;
    else
    {
        MYFILE* myfile = (MYFILE*)f;
        off_t ret = lseek(myfile->baseFile._fileno, (off_t)offset, whence);
        myfile->eof = 0;
        myfile->offset = ret;
        return (ret != -1) ? 0 : -1;
    }
}

char *fgets(char *s, int size, FILE *stream)
{
    int i;
    silent = 1;
    for(i=0;i<size-1;i++)
    {
        char ch;
        if (fread(&ch, 1, 1, stream) == 1)
        {
            s[i] = ch;
            if( ch == 10 )
            {
                i ++;
                break;
            }
        }
        else
            return NULL;
    }
    silent = 0;
    s[i] = 0;
    return s;
}

char *fgets_unlocked(char *s, int size, FILE *stream)
{
    ENTER_FUNC();
    return fgets(s, size, stream);
}


ssize_t getline(char **lineptr, size_t *n, FILE *stream)
{
    UNIMPLEMENTED_FUNC();
    return -1;
}

ssize_t getdelim(char **lineptr, size_t *n, int delim, FILE *stream)
{
    UNIMPLEMENTED_FUNC();
    return -1;
}

static int myfgetc(FILE *stream)
{
    unsigned char c;
    if( fread(&c, 1, 1, stream) == 1 )
        return c;
    else
        return EOF;
}

int getc(FILE *stream)
{
    return myfgetc(stream);
}

int getc_unlocked(FILE *stream)
{
    return myfgetc(stream);
}

int fgetc(FILE *stream)
{
    return myfgetc(stream);
}

int getchar(void)
{
    return myfgetc(stdin);
}

char *gets(char *s)
{
    UNIMPLEMENTED_FUNC();
    abort();
    return 0;
}

int ungetc(int c, FILE *stream)
{
    long long pos = ftello64(stream);
    if( pos == 0 )
        return EOF;
    fseek(stream, -1, SEEK_CUR);
    if( c != getc(stream) )
    {
        DISPLAY("UNSUPPORTED", "ungetc does not return same char");
        return EOF;
    }
    fseek(stream, -1, SEEK_CUR);
    return c;
}

void flockfile(FILE *filehandle)
{
}

int ftrylockfile(FILE *filehandle)
{
    return 0;
}

void funlockfile(FILE *filehandle)
{
}

int __uflow (FILE *stream)
{
    return myfgetc(stream);
}

wchar_t *fgetws(wchar_t *ws, int n, FILE *stream)
{
    UNIMPLEMENTED_FUNC();
    ws[0] = 0;
    return ws;
}

wint_t fgetwc(FILE *stream)
{
    UNIMPLEMENTED_FUNC();
    return WEOF;
}

wint_t getwc(FILE *stream)
{
    UNIMPLEMENTED_FUNC();
    return WEOF;
}

wint_t fputwc(wchar_t wc, FILE *stream)
{
    UNIMPLEMENTED_FUNC();
    return WEOF;
}

wint_t putwc(wchar_t wc, FILE *stream)
{
    UNIMPLEMENTED_FUNC();
    return WEOF;
}

wint_t ungetwc(wint_t wc, FILE *stream)
{
    UNIMPLEMENTED_FUNC();
    return WEOF;
}

int puts(const char *s)
{
    return fprintf(stdout, "%s\n", s);
}

int putc(int c, FILE *stream)
{
    int ret = fwrite(&c, 1, 1, stream);
    return (ret == 1) ? c : EOF;
}

int fputc(int c, FILE *stream)
{
    int ret = fwrite(&c, 1, 1, stream);
    return (ret == 1) ? c : EOF;
}

int putchar(int c)
{
    return putc(c,stdout);
}

int fputs(const char *s, FILE *stream)
{
    return fwrite(s, 1, strlen(s), stream);
}

int flock(int fd, int operation)
{
    UNIMPLEMENTED_FUNC();
    return 0;
}

int fflush(FILE* f)
{
    UNIMPLEMENTED_FUNC();
    return 0;
}

void clearerr(FILE *f)
{
    if ( !(f == stdin || f == stdout || f == stderr) )
    {
        MYFILE* myfile = (MYFILE*)f;
        myfile->eof = 0;
        myfile->errorflag = 0;
    }
}

int ferror(FILE *f)
{
    if ( !(f == stdin || f == stdout || f == stderr) )
    {
        MYFILE* myfile = (MYFILE*)f;
        return myfile->errorflag;
    }
    return 0;
}

int fileno(FILE *f)
{
    if (f == stdin )
        return 0;
    else if( f == stdout )
        return 1;
    else if( f == stderr )
        return 2;
    else
    {
        MYFILE* myfile = (MYFILE*)f;
        return myfile->baseFile._fileno;
    }
}


int feof(FILE *f)
{
    if (f == stdin )
        return 0;
    else if( f == stdout )
        return 0;
    else if( f == stderr )
        return 0;
    else
    {
        MYFILE* myfile = (MYFILE*)f;
        return myfile->eof;
    }
}

long ftell(FILE* f)
{
    return (long)ftello64(f);
}

off_t ftello(FILE *f)
{
    return ftello64(f);
}

off64_t ftello64(FILE *f)
{
    if (f == stdin )
        return 0;
    else if( f == stdout )
        return 0;
    else if( f == stderr )
        return 0;
    else
    {
        MYFILE* myfile = (MYFILE*)f;
        return myfile->offset;
    }
}


int truncate(const char *path, off_t length)
{
    UNIMPLEMENTED_FUNC();
    return -1;
}

int ftruncate(int fd, off_t length)
{
    return ftruncate64(fd, length);
}

int ftruncate64(int fd, off64_t length)
{
    ENTER_FUNC();

    int cmd = CMD_FTRUNCATE;
    pipe_write(&cmd, 4);
    pipe_write(&fd, 4);
    long long l = length;
    pipe_write(&l, 8);

    int ret;
    pipe_read(&ret, 4);
    int myerrno = 0;
    if( ret < 0 )
        pipe_read(&myerrno, 4);
    errno = myerrno;

    return ret;
}

int mkdir(const char *pathname, mode_t mode)
{
    ENTER_FUNC();

    int len = strlen(pathname);
    if( len >= 65536 )
    {
        errno = ENAMETOOLONG;
        return -1;
    }

    int cmd = CMD_MKDIR;
    pipe_write(&cmd, 4);
    pipe_write_uint16(len);
    pipe_write(pathname, len);
    pipe_write(&mode, 4);

    int ret;
    pipe_read(&ret, 4);
    int myerrno = 0;
    if( ret < 0 )
        pipe_read(&myerrno, 4);
    errno = myerrno;

    return ret;
}

int unlink(const char *pathname)
{
    ENTER_FUNC();

    int len = strlen(pathname);
    if( len >= 65536 )
    {
        errno = ENAMETOOLONG;
        return -1;
    }

    int cmd = CMD_UNLINK;
    pipe_write(&cmd, 4);
    pipe_write_uint16(len);
    pipe_write(pathname, len);

    int ret;
    pipe_read(&ret, 4);
    int myerrno = 0;
    if( ret < 0 )
        pipe_read(&myerrno, 4);
    errno = myerrno;

    return ret;
}

int remove(const char *pathname)
{
    ENTER_FUNC();

    int len = strlen(pathname);
    if( len >= 65536 )
    {
        errno = ENAMETOOLONG;
        return -1;
    }

    int cmd = CMD_REMOVE;
    pipe_write(&cmd, 4);
    pipe_write_uint16(len);
    pipe_write(pathname, len);

    int ret;
    pipe_read(&ret, 4);
    int myerrno = 0;
    if( ret < 0 )
        pipe_read(&myerrno, 4);
    errno = myerrno;

    return ret;
}

int rmdir(const char *pathname)
{
    ENTER_FUNC();

    int len = strlen(pathname);
    if( len >= 65536 )
    {
        errno = ENAMETOOLONG;
        return -1;
    }

    int cmd = CMD_RMDIR;
    pipe_write(&cmd, 4);
    pipe_write_uint16(len);
    pipe_write(pathname, len);

    int ret;
    pipe_read(&ret, 4);
    int myerrno = 0;
    if( ret < 0 )
        pipe_read(&myerrno, 4);
    errno = myerrno;

    return ret;
}

int access(const char *pathname, int mode)
{
    UNIMPLEMENTED_FUNC();
    return 0;
}

int gettimeofday(struct timeval *tv, struct timezone *tz)
{
    UNIMPLEMENTED_FUNC();
    tv->tv_sec = 0;
    tv->tv_usec = 0;
    return 0;
}

clock_t times(struct tms *buf)
{
    UNIMPLEMENTED_FUNC();
    memset(buf, 0, sizeof(struct tms));
    return -1;
}

time_t time(time_t *t)
{
    UNIMPLEMENTED_FUNC();
    if( t )
        *t = 0;
    return 0;
}

clock_t clock(void)
{
    UNIMPLEMENTED_FUNC();
    return 0;
}


struct tm atm;

struct tm *localtime(const time_t *timep)
{
    UNIMPLEMENTED_FUNC();
    memset(&atm, 0, sizeof(struct tm));
    return &atm;
}

struct tm *localtime_r(const time_t *timep, struct tm *result)
{
    UNIMPLEMENTED_FUNC();
    memset(result, 0, sizeof(struct tm));
    return result;
}

struct tm *gmtime(const time_t *timep)
{
    UNIMPLEMENTED_FUNC();
    memset(&atm, 0, sizeof(struct tm));
    return &atm;
}

struct tm *gmtime_r(const time_t *timep, struct tm *result)
{
    UNIMPLEMENTED_FUNC();
    memset(result, 0, sizeof(struct tm));
    return result;
}


void *mmap(void *addr, size_t length, int prot, int flags,
            int fd, off_t offset)
{
    if( bUseDlMalloc )
    {
        UNIMPLEMENTED_FUNC();
        return NULL;
    }
    else
    {
        void* (*pfn_mmap)(void*,size_t,int,int,int,off_t) = 
            (void*(*)(void*,size_t,int,int,int,off_t)) dlsym(RTLD_NEXT, "mmap");
        assert(pfn_mmap);
        return pfn_mmap(addr,length,prot,flags,fd,offset);
    }
}

int munmap(void *addr, size_t length)
{
    if( bUseDlMalloc )
    {
        UNIMPLEMENTED_FUNC();
        return -1;
    }
    else
    {
        int (*pfn_munmap)(void*, size_t) = 
            (int(*)(void*,size_t)) dlsym(RTLD_NEXT, "munmap");
        assert(pfn_munmap);
        return pfn_munmap(addr,length);
    }
}

int __printf_chk(int flag, const char * format, ...)
{
    va_list args;
    int ret;
    va_start(args, format);
    ret = vfprintf(stdout, format, args);
    va_end(args);
    return ret;
}

int printf(const char *format, ...)
{
    va_list args;
    int ret;
    va_start(args, format);
    ret = vfprintf(stdout, format, args);
    va_end(args);
    return ret;
}

int __fprintf_chk(FILE* f, int flag, const char *format, ...)
{
    va_list args;
    int ret;
    va_start(args, format);
    ret = vfprintf(f, format, args);
    va_end(args);
    return ret;
}

int fprintf(FILE* f, const char *format, ...)
{
    va_list args;
    int ret;
    va_start(args, format);
    ret = vfprintf(f, format, args);
    va_end(args);
    return ret;
}

int __vfprintf_chk(FILE * fp, int flag, const char * format, va_list ap)
{
    return vfprintf(fp, format, ap);
}

int vfprintf(FILE *f, const char *format, va_list ap)
{
    va_list wrk_args;
    int ret;
    va_copy( wrk_args, ap );
    char szBuffer[512];
    ret = vsnprintf(szBuffer, sizeof(szBuffer), format, wrk_args);
    char* tmp ;
    if( ret >= (int)sizeof(szBuffer) )
    {
        tmp = (char*)malloc(ret + 1);
        va_end( wrk_args );
        va_copy( wrk_args, ap );
        ret = vsnprintf(tmp, ret + 1, format, wrk_args);
    }
    else
        tmp = szBuffer;
    va_end(wrk_args);

    ret = fwrite(tmp, 1, ret, f);
    if( tmp != szBuffer )
        free(tmp);
    return ret;
}

char *setlocale(int category, const char *locale)
{
    DUMMY_FUNC();
    return "C";
}

struct lconv *localeconv(void)
{
    return p_globale_locale;
}

locale_t uselocale(locale_t newloc)
{
    DUMMY_FUNC();
    return LC_GLOBAL_LOCALE;
}

locale_t newlocale(int category_mask, const char *locale,
                   locale_t base)
{
    DUMMY_FUNC();
    return 0;
}

void freelocale(locale_t locobj)
{
    DUMMY_FUNC();
}

long int sysconf (int name)
{
    char buffer[32];

    ENTER_FUNC();
    strcpy(buffer, "name = ");
    printuint(buffer + strlen("name = "), name);
    INFO(buffer);

    if( name == _SC_CLK_TCK )
        return val_SC_CLK_TCK;
    if( name == _SC_NPROCESSORS_CONF ||
        name == _SC_NPROCESSORS_ONLN )
        return 1;
    if( name == _SC_AVPHYS_PAGES ||
        name == _SC_PHYS_PAGES )
        return (MAX_VIRTUAL_MEM - MAX_VIRTUAL_MEM / 5) / 4096;
    if( name == _SC_PAGESIZE )
        return 4096;
    if( name == _SC_OPEN_MAX )
        return 1024;

    sprintf(buffer, "sysconf(%d)", name);
    UNIMPLEMENTED(buffer);
    return -1;
}


int ioctl (int __fd, unsigned long int __request, ...)
{
    UNIMPLEMENTED_FUNC();
    return -1;
}


sighandler_t signal(int signum, sighandler_t handler)
{
    UNIMPLEMENTED_FUNC();
    return 0;
}

int sigsetjmp(sigjmp_buf env, int savemask)
{
    UNIMPLEMENTED_FUNC();
    return 0;
}

int sigaction(int signum, const struct sigaction *act,
                struct sigaction *oldact)
{
    UNIMPLEMENTED_FUNC();
    return 0;
}

int sigemptyset(sigset_t *set)
{
    UNIMPLEMENTED_FUNC();
    return 0;
}

int sigaddset(sigset_t *set, int signo)
{
    UNIMPLEMENTED_FUNC();
    return 0;
}

int sigdelset(sigset_t *set, int signo)
{
    UNIMPLEMENTED_FUNC();
    return 0;
}

int sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
    UNIMPLEMENTED_FUNC();
    return 0;
}

int tcgetattr(void)
{
    UNIMPLEMENTED_FUNC();
    return -1;
}

int tcsetattr(void)
{
    UNIMPLEMENTED_FUNC();
    return -1;
}

int isatty(int fd)
{
    if( fd == 0 || fd == 1 || fd == 2 )
        return 1;
    return 0;
}

pid_t fork(void)
{
    UNSUPPORTED_FUNC();
    return -1;
}

int execve(const char *filename, char *const argv[],
                  char *const envp[])
{
    UNSUPPORTED_FUNC();
    return -1;
}

int getrusage(int who, struct rusage *usage)
{
    UNIMPLEMENTED_FUNC();
    return -1;
}
