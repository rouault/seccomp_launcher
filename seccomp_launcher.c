/******************************************************************************
 * $Id$
 *
 * Project:  seccomp_launcher
 * Purpose:  
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

#define _LARGEFILE64_SOURCE 1

#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <spawn.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>

#define TRUE 1
#define FALSE 0

#include "seccomp_launcher.h"

#define HAVE_POSIX_SPAWNP

#ifdef WIN32
#include <windows.h>
typedef HANDLE CPL_FILE_HANDLE;
#define CPL_FILE_INVALID_HANDLE NULL
typedef DWORD  CPL_PID;
#else
#include <sys/types.h>
typedef int    CPL_FILE_HANDLE;
#define CPL_FILE_INVALID_HANDLE -1
typedef pid_t  CPL_PID;
#endif

#define IN_FOR_PARENT   0
#define OUT_FOR_PARENT  1

typedef struct _CPLSpawnedProcess CPLSpawnedProcess;

#define CPLMalloc malloc
#define CPLFree free
#define CPLStrdup strdup
extern char** environ;

/************************************************************************/
/*                              CSLCount()                              */
/************************************************************************/

/**
 * Return number of items in a string list.
 *
 * Returns the number of items in a string list, not counting the 
 * terminating NULL.  Passing in NULL is safe, and will result in a count
 * of zero.  
 *
 * Lists are counted by iterating through them so long lists will
 * take more time than short lists.  Care should be taken to avoid using
 * CSLCount() as an end condition for loops as it will result in O(n^2)
 * behavior. 
 *
 * @param papszStrList the string list to count.
 * 
 * @return the number of entries.
 */
int CSLCount(char **papszStrList)
{
    int nItems=0;

    if (papszStrList)
    {
        while(*papszStrList != NULL)
        {
            nItems++;
            papszStrList++;
        }
    }

    return nItems;
}

/************************************************************************/
/*                             CSLDestroy()                             */
/************************************************************************/

/**
 * Free string list.
 * 
 * Frees the passed string list (null terminated array of strings).
 * It is safe to pass NULL. 
 *
 * @param papszStrList the list to free.
 */
void  CSLDestroy(char **papszStrList)
{
    char **papszPtr;

    if (papszStrList)
    {
        papszPtr = papszStrList;
        while(*papszPtr != NULL)
        {
            CPLFree(*papszPtr);
            papszPtr++;
        }

        CPLFree(papszStrList);
    }
}

/************************************************************************/
/*                            CSLDuplicate()                            */
/************************************************************************/

/**
 * Clone a string list.
 *
 * Efficiently allocates a copy of a string list.  The returned list is
 * owned by the caller and should be freed with CSLDestroy().
 *
 * @param papszStrList the input string list.
 * 
 * @return newly allocated copy.
 */

char **CSLDuplicate(char **papszStrList)
{
    char **papszNewList, **papszSrc, **papszDst;
    int  nLines;

    nLines = CSLCount(papszStrList);

    if (nLines == 0)
        return NULL;

    papszNewList = (char **)CPLMalloc((nLines+1)*sizeof(char*));
    papszSrc = papszStrList;
    papszDst = papszNewList;

    while(*papszSrc != NULL)
    {
        *papszDst = CPLStrdup(*papszSrc);

        papszSrc++;
        papszDst++;
    }
    *papszDst = NULL;

    return papszNewList;
}



/************************************************************************/
/*                            CPLSpawnAsync()                           */
/************************************************************************/

struct _CPLSpawnedProcess
{
    pid_t pid;
    CPL_FILE_HANDLE fin;
    CPL_FILE_HANDLE fout;
    CPL_FILE_HANDLE ferr;
#ifdef HAVE_POSIX_SPAWNP
    int bFreeActions;
    posix_spawn_file_actions_t actions;
#endif
};

/**
 * Runs an executable in another process (or fork the current process)
 * and return immediately.
 *
 * This function launches an executable and returns immediately, while letting
 * the sub-process to run asynchronously.
 *
 * It is implemented as CreateProcess() on Windows platforms, and fork()/exec()
 * on other platforms.
 *
 * On Unix, a pointer of function can be provided to run in the child process,
 * without exec()'ing a new executable.
 *
 * @param pfnMain the function to run in the child process (Unix only).
 * @param papszArgv argument list of the executable to run. papszArgv[0] is the
 *                  name of the executable.
 * @param bCreateInputPipe set to TRUE to create a pipe for the child input stream.
 * @param bCreateOutputPipe set to TRUE to create a pipe for the child output stream.
 * @param bCreateErrorPipe set to TRUE to create a pipe for the child error stream.
 *
 * @return a handle, that must be freed with CPLSpawnAsyncFinish()
 *
 * @since GDAL 1.10.0
 */
CPLSpawnedProcess* CPLSpawnAsync(int (*pfnMain)(CPL_FILE_HANDLE, CPL_FILE_HANDLE),
                                 const char * const papszArgv[],
                                 int bCreateInputPipe,
                                 int bCreateOutputPipe,
                                 int bCreateErrorPipe,
                                 char** papszOptions)
{
    pid_t pid;
    int pipe_in[2] = { -1, -1 };
    int pipe_out[2] = { -1, -1 };
    int pipe_err[2] = { -1, -1 };
    int i;
    char** papszArgvDup = CSLDuplicate((char**)papszArgv);
    int bDup2In = bCreateInputPipe,
        bDup2Out = bCreateOutputPipe,
        bDup2Err = bCreateErrorPipe;

    if ((bCreateInputPipe && pipe(pipe_in)) ||
        (bCreateOutputPipe && pipe(pipe_out)) ||
        (bCreateErrorPipe && pipe(pipe_err)))
        goto err_pipe;

    /* If we don't do any file actions, posix_spawnp() might be implemented */
    /* efficiently as a vfork()/exec() pair (or if it is not available, we */
    /* can use vfork()/exec()), so if the child is cooperative */
    /* we pass the pipe handles as commandline arguments */
    if( papszArgv != NULL )
    {
        for(i=0; papszArgvDup[i] != NULL; i++)
        {
            char buf[32];
            if( bCreateInputPipe && strcmp(papszArgvDup[i], "{pipe_in}") == 0 )
            {
                CPLFree(papszArgvDup[i]);
                sprintf(buf, "%d,%d",
                    pipe_in[IN_FOR_PARENT], pipe_in[OUT_FOR_PARENT]);
                papszArgvDup[i] = CPLStrdup(buf);
                bDup2In = FALSE;
            }
            else if( bCreateOutputPipe && strcmp(papszArgvDup[i], "{pipe_out}") == 0 )
            {
                CPLFree(papszArgvDup[i]);
                sprintf(buf, "%d,%d",
                    pipe_out[OUT_FOR_PARENT], pipe_out[IN_FOR_PARENT]);
                papszArgvDup[i] = CPLStrdup(buf);
                bDup2Out = FALSE;
            }
            else if( bCreateErrorPipe && strcmp(papszArgvDup[i], "{pipe_err}") == 0 )
            {
                CPLFree(papszArgvDup[i]);
                sprintf(buf, "%d,%d",
                    pipe_err[OUT_FOR_PARENT], pipe_err[IN_FOR_PARENT]);
                papszArgvDup[i] = CPLStrdup(buf);
                bDup2Err = FALSE;
            }
        }
    }

#ifdef HAVE_POSIX_SPAWNP
    if( papszArgv != NULL )
    {
        int bHasActions = FALSE;
        posix_spawn_file_actions_t actions;

        if( bCreateInputPipe )
        {
            if( !bHasActions ) posix_spawn_file_actions_init(&actions);
            posix_spawn_file_actions_adddup2(&actions, pipe_in[IN_FOR_PARENT], fileno(stdin));
            posix_spawn_file_actions_addclose(&actions, pipe_in[OUT_FOR_PARENT]);
            bHasActions = TRUE;
        }

        if( bCreateOutputPipe )
        {
            if( !bHasActions ) posix_spawn_file_actions_init(&actions);
            posix_spawn_file_actions_adddup2(&actions, pipe_out[OUT_FOR_PARENT], fileno(stdout));
            posix_spawn_file_actions_addclose(&actions, pipe_out[IN_FOR_PARENT]);
            bHasActions = TRUE;
        }

        if( bCreateErrorPipe )
        {
            if( !bHasActions ) posix_spawn_file_actions_init(&actions);
            posix_spawn_file_actions_adddup2(&actions, pipe_err[OUT_FOR_PARENT], fileno(stderr));
            posix_spawn_file_actions_addclose(&actions, pipe_err[IN_FOR_PARENT]);
            bHasActions = TRUE;
        }
        
        char strpipe_in[32], strpipe_out[32];
        sprintf(strpipe_in, "PIPE_IN=%d,%d",
                    pipe_in[IN_FOR_PARENT], pipe_in[OUT_FOR_PARENT]);
        sprintf(strpipe_out, "PIPE_OUT=%d,%d",
                    pipe_out[OUT_FOR_PARENT], pipe_out[IN_FOR_PARENT]);

        int c = CSLCount(environ);
        // TODO: check that LD_PRELOAD is not already defined
        char** envp = (char**) malloc((c + 4) * sizeof(char*));
        memcpy(envp, environ, c * sizeof(char*));
        
        char szSelfCWD[512];
        assert(readlink("/proc/self/exe", szSelfCWD, sizeof(szSelfCWD)) > 0);
        char* szLastSlash = strrchr(szSelfCWD, '/');
        assert(szLastSlash);
        szLastSlash[0] = '\0';
        char szLibSeccompWrapper[1024];
        sprintf(szLibSeccompWrapper, "%s/libseccomp_preload.so", szSelfCWD);
        FILE* f = fopen(szLibSeccompWrapper, "rb");
        assert(f);
        fclose(f);
        char szPreload[1024];
        sprintf(szPreload, "LD_PRELOAD=%s", szLibSeccompWrapper);
        // TODO check that libseccomp_wrapper.so is of the same architecture
        // as the binary that will be launched with it.

        envp[c] = szPreload;
        envp[c+1] = strpipe_in;
        envp[c+2] = strpipe_out;
        envp[c+3] = NULL;

        //const char const* envp[] = { "LD_PRELOAD=./libmylibc.so", strpipe_in, strpipe_out, NULL };

        if( posix_spawnp(&pid, papszArgvDup[0],
                         bHasActions ? &actions : NULL,
                         NULL,
                         (char* const*) papszArgvDup,
                         (char* const*) envp) != 0 )
        {
            if( bHasActions )
                posix_spawn_file_actions_destroy(&actions);
            fprintf(stderr, "posix_spawnp() failed");
            goto err;
        }

        CSLDestroy(papszArgvDup);

        /* Close unused end of pipe */
        if( bCreateInputPipe )
            close(pipe_in[IN_FOR_PARENT]);
        if( bCreateOutputPipe )
            close(pipe_out[OUT_FOR_PARENT]);
        if( bCreateErrorPipe )
            close(pipe_err[OUT_FOR_PARENT]);

        /* Ignore SIGPIPE */
    #ifdef SIGPIPE
        signal (SIGPIPE, SIG_IGN);
    #endif
        CPLSpawnedProcess* p = (CPLSpawnedProcess*)CPLMalloc(sizeof(CPLSpawnedProcess));
        if( bHasActions )
            memcpy(&p->actions, &actions, sizeof(actions));
        p->bFreeActions = bHasActions;
        p->pid = pid;
        p->fin = pipe_out[IN_FOR_PARENT];
        p->fout = pipe_in[OUT_FOR_PARENT];
        p->ferr = pipe_err[IN_FOR_PARENT];
        return p;
    }
#endif // #ifdef HAVE_POSIX_SPAWNP

#ifdef HAVE_VFORK
    if( papszArgv != NULL && !bDup2In && !bDup2Out && !bDup2Err )
        pid = vfork();
    else
#endif
        pid = fork();
    if (pid == 0)
    {
        /* Close unused end of pipe */
        if( bDup2In )
            close(pipe_in[OUT_FOR_PARENT]);
        if( bDup2Out )
            close(pipe_out[IN_FOR_PARENT]);
        if( bDup2Err )
            close(pipe_err[IN_FOR_PARENT]);

#ifndef HAVE_POSIX_SPAWNP
        if( papszArgv != NULL )
        {
            if( bDup2In )
                dup2(pipe_in[IN_FOR_PARENT], fileno(stdin));
            if( bDup2Out )
                dup2(pipe_out[OUT_FOR_PARENT], fileno(stdout));
            if( bDup2Err )
                dup2(pipe_err[OUT_FOR_PARENT], fileno(stderr));

            execvp(papszArgvDup[0], (char* const*) papszArgvDup);

            _exit(1);
        }
        else
#endif // HAVE_POSIX_SPAWNP
        {
            if( bCreateErrorPipe )
                close(pipe_err[OUT_FOR_PARENT]);

            int nRet = 0;
            if (pfnMain != NULL)
                nRet = pfnMain((bCreateInputPipe) ? pipe_in[IN_FOR_PARENT] : fileno(stdin),
                               (bCreateOutputPipe) ? pipe_out[OUT_FOR_PARENT] : fileno(stdout));
            _exit(nRet);
        }
    }
    else if( pid > 0 )
    {
        CSLDestroy(papszArgvDup);

        /* Close unused end of pipe */
        if( bCreateInputPipe )
            close(pipe_in[IN_FOR_PARENT]);
        if( bCreateOutputPipe )
            close(pipe_out[OUT_FOR_PARENT]);
        if( bCreateErrorPipe )
            close(pipe_err[OUT_FOR_PARENT]);

        /* Ignore SIGPIPE */
#ifdef SIGPIPE
        signal (SIGPIPE, SIG_IGN);
#endif
        CPLSpawnedProcess* p = (CPLSpawnedProcess*)CPLMalloc(sizeof(CPLSpawnedProcess));
#ifdef HAVE_POSIX_SPAWNP
        p->bFreeActions = FALSE;
#endif
        p->pid = pid;
        p->fin = pipe_out[IN_FOR_PARENT];
        p->fout = pipe_in[OUT_FOR_PARENT];
        p->ferr = pipe_err[IN_FOR_PARENT];
        return p;
    }
    else
    {
        fprintf(stderr, "Fork failed");
        goto err;
    }

err_pipe:
    fprintf(stderr, "Could not create pipe");
err:
    CSLDestroy(papszArgvDup);
    for(i=0;i<2;i++)
    {
        if (pipe_in[i] >= 0)
            close(pipe_in[i]);
        if (pipe_out[i] >= 0)
            close(pipe_out[i]);
        if (pipe_err[i] >= 0)
            close(pipe_err[i]);
    }

    return NULL;
}

/************************************************************************/
/*                  CPLSpawnAsyncGetChildProcessId()                    */
/************************************************************************/

CPL_PID CPLSpawnAsyncGetChildProcessId(CPLSpawnedProcess* p)
{
    return p->pid;
}

/************************************************************************/
/*                 CPLSpawnAsyncCloseInputFileHandle()                  */
/************************************************************************/

void CPLSpawnAsyncCloseInputFileHandle(CPLSpawnedProcess* p)
{
    if( p->fin >= 0 )
        close(p->fin);
    p->fin = -1;
}

/************************************************************************/
/*                 CPLSpawnAsyncCloseOutputFileHandle()                 */
/************************************************************************/

void CPLSpawnAsyncCloseOutputFileHandle(CPLSpawnedProcess* p)
{
    if( p->fout >= 0 )
        close(p->fout);
    p->fout = -1;
}

/************************************************************************/
/*                 CPLSpawnAsyncCloseErrorFileHandle()                  */
/************************************************************************/

void CPLSpawnAsyncCloseErrorFileHandle(CPLSpawnedProcess* p)
{
    if( p->ferr >= 0 )
        close(p->ferr);
    p->ferr = -1;
}

/************************************************************************/
/*                        CPLSpawnAsyncFinish()                         */
/************************************************************************/

/**
 * Wait for the forked process to finish.
 *
 * @param p handle returned by CPLSpawnAsync()
 * @param bWait set to TRUE to wait for the child to terminate. Otherwise the associated
 *              handles are just cleaned.
 * @param bKill set to TRUE to force child termination (unimplemented right now).
 *
 * @return the return code of the forked process if bWait == TRUE, 0 otherwise
 *
 * @since GDAL 1.10.0
 */
int CPLSpawnAsyncFinish(CPLSpawnedProcess* p, int bWait, int bKill)
{
    int status = 0;

    if( bWait )
    {
        while(1)
        {
            status = -1;
            int ret = waitpid (p->pid, &status, 0);
            if (ret < 0)
            {
                if (errno != EINTR)
                {
                    break;
                }
            }
            else
                break;
        }
    }
    else
        bWait = FALSE;
    CPLSpawnAsyncCloseInputFileHandle(p);
    CPLSpawnAsyncCloseOutputFileHandle(p);
    CPLSpawnAsyncCloseErrorFileHandle(p);
#ifdef HAVE_POSIX_SPAWNP
    if( p->bFreeActions )
        posix_spawn_file_actions_destroy(&p->actions);
#endif
    CPLFree(p);
    return status;
}

static int child_fd[1024];

int main(int argc, char* argv[])
{
    char** my_argv = (char**)malloc(sizeof(char*)* (argc+1));
    memcpy(my_argv, argv+1, sizeof(char*)* (argc-1));
    my_argv[argc] = 0;
    CPLSpawnedProcess* sp = CPLSpawnAsync(NULL, my_argv, TRUE, TRUE, FALSE, NULL);
    int bReadOnly = getenv("READONLY") != NULL;
    
    memset(child_fd, 0, sizeof(child_fd));
    child_fd[1] = 1;
    child_fd[2] = 1;

    /*write(sp->fout, "go!", 3);*/
    while(TRUE)
    {
        int cmd = 0;
        if( read(sp->fin, &cmd, 4) == 0 )
            break;
        if( cmd == CMD_OPEN )
        {
            unsigned short len;
            read(sp->fin, &len, sizeof(len));
            char* path = (char*)malloc(len + 1);
            read(sp->fin, path, len);
            path[len] = 0;
            int flags;
            read(sp->fin, &flags, 4);
            int mode;
            read(sp->fin, &mode, 4);
            int fd;
            int myerrno = 0;
            if( bReadOnly && flags != O_RDONLY )
            {
                fprintf(stderr, "AccCtrl: open(%s,%d,0%o) rejected\n", path, flags, mode);
                fd = -1;
                myerrno = EACCES;
            }
            else
            {
                fd = open64(path, flags, mode);
                myerrno = errno;
                /*fprintf(stderr, "server: open(%s,%d,0%o) = %d\n", path, flags, mode, fd);*/
                if( fd >= 1024 )
                {
                    close(fd);
                    fd = -1;
                    myerrno = ENFILE;
                }
                else if( fd >= 0 )
                    child_fd[fd] = 1;
            }
            write(sp->fout, &fd, 4);
            if( fd < 0 )
                write(sp->fout, &myerrno, 4);
            free(path);
        }
        else if( cmd == CMD_CLOSE )
        {
            int fd;
            read(sp->fin, &fd, 4);
            if( fd < 0 || fd >= 1024 || !child_fd[fd] )
                fd = -1;
            else
                child_fd[fd] = 0;
            int ret = close(fd);
            int myerrno = errno;
            write(sp->fout, &ret, 4);
            if( ret < 0 )
                write(sp->fout, &myerrno, 4);
        }
        else if( cmd == CMD_READ )
        {
            int fd;
            read(sp->fin, &fd, 4);
            if( fd < 0 || fd >= 1024 || !child_fd[fd] )
                fd = -1;
            int len;
            read(sp->fin, &len, 4);
            char* buffer = (char*)malloc(len);
            int ret = (int)read(fd, buffer, len);
            int myerrno = errno;
            write(sp->fout, &ret, 4);
            if( ret > 0 )
                write(sp->fout, buffer, ret);
            else
                write(sp->fout, &myerrno, 4);
            free(buffer);
        }
        else if( cmd == CMD_WRITE )
        {
            int fd;
            read(sp->fin, &fd, 4);
            if( fd < 0 || fd >= 1024 || !child_fd[fd] )
                fd = -1;
            int len;
            read(sp->fin, &len, 4);
            char* buffer = (char*)malloc(len);
            read(sp->fin, buffer, len);
            int ret = (int)write(fd, buffer, len);
            int myerrno = errno;
            free(buffer);
            write(sp->fout, &ret, 4);
            if( ret <= 0 )
                write(sp->fout, &myerrno, 4);
        }
        else if( cmd == CMD_SEEK )
        {
            int fd;
            read(sp->fin, &fd, 4);
            if( fd < 0 || fd >= 1024 || !child_fd[fd] )
                fd = -1;
            long long off;
            read(sp->fin, &off, 8);
            int whence;
            read(sp->fin, &whence, 4);
            long long ret = lseek64(fd, (off_t)off, whence);
            int myerrno = errno;
            write(sp->fout, &ret, 8);
            if( ret < 0 )
                write(sp->fout, &myerrno, 4);
        }
        else if( cmd == CMD_STAT )
        {
            unsigned short len;
            read(sp->fin, &len, sizeof(len));
            char* path = (char*)malloc(len+1);
            read(sp->fin, path, len);
            path[len] = '\0';
            struct stat64 mystat;
            memset(&mystat, 0, sizeof(mystat));
            int ret = stat64(path, &mystat);
            int myerrno = errno;
            free(path);
            write(sp->fout, &ret, 4);
            write(sp->fout, &mystat, sizeof(mystat));
            if( ret < 0 )
                write(sp->fout, &myerrno, 4);
        }
        else if( cmd == CMD_FSTAT )
        {
            int fd;
            read(sp->fin, &fd, 4);
            if( fd < 0 || fd >= 1024 || !child_fd[fd] )
                fd = -1;
            struct stat64 mystat;
            memset(&mystat, 0, sizeof(mystat));
            int ret = fstat64(fd, &mystat);
            int myerrno = errno;
            write(sp->fout, &ret, 4);
            write(sp->fout, &mystat, sizeof(mystat));
            if( ret < 0 )
                write(sp->fout, &myerrno, 4);
        }
        else if (cmd == CMD_MKDIR )
        {
            unsigned short len;
            read(sp->fin, &len, sizeof(len));
            char* path = (char*)malloc(len+1);
            read(sp->fin, path, len);
            path[len] = '\0';
            int mode;
            read(sp->fin, &mode, 4);
            int ret;
            int myerrno;
            if( bReadOnly )
            {
                fprintf(stderr, "AccCtrl: mkdir(%s,0%o) rejected\n", path, mode);
                myerrno = EACCES;
                ret = -1;
            }
            else
            {
                ret = mkdir(path, mode);
                myerrno = errno;
                /*fprintf(stderr, "server: mkdir(%s,0%o) = %d\n", path, mode, ret);*/
            }
            free(path);
            write(sp->fout, &ret, 4);
            if( ret < 0 )
                write(sp->fout, &myerrno, 4);
        }
        else if (cmd == CMD_FTRUNCATE )
        {
            int fd;
            read(sp->fin, &fd, 4);
            long long off;
            read(sp->fin, &off, 8);
            int ret = ftruncate64(fd, off);
            int myerrno = errno;
            /*fprintf(stderr, "server: ftruncate(%d,%lld) = %d\n", fd, off, ret);*/
            write(sp->fout, &ret, 4);
            if( ret < 0 )
                write(sp->fout, &myerrno, 4);
        }
    }

    return CPLSpawnAsyncFinish(sp, TRUE, FALSE);
}
