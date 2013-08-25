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
#include <dirent.h>

#define TRUE 1
#define FALSE 0

#include "seccomp_launcher.h"

typedef int    CPL_FILE_HANDLE;
#define CPL_FILE_INVALID_HANDLE -1
typedef pid_t  CPL_PID;

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
    int bFreeActions;
    posix_spawn_file_actions_t actions;
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
CPLSpawnedProcess* SeccompCPLSpawnAsync(int (*pfnMain)(CPL_FILE_HANDLE, CPL_FILE_HANDLE),
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

    if ((bCreateInputPipe && pipe(pipe_in)) ||
        (bCreateOutputPipe && pipe(pipe_out)) ||
        (bCreateErrorPipe && pipe(pipe_err)))
        goto err_pipe;

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
    sprintf(strpipe_in, "PIPE_IN=%d", pipe_in[IN_FOR_PARENT]);
    sprintf(strpipe_out, "PIPE_OUT=%d", pipe_out[OUT_FOR_PARENT]);

    /* Build LD_PRELOAD environmenet option */
    char szSelfCWD[512];
    int written = readlink("/proc/self/exe", szSelfCWD, sizeof(szSelfCWD)-1);
    assert(written > 0);
    szSelfCWD[written] = 0;
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

    /* Prepare the environment for the child */
    int c = CSLCount(environ);
    // TODO: check that LD_PRELOAD is not already defined
    char** envp = (char**) CPLMalloc((c + 4) * sizeof(char*));
    memcpy(envp, environ, c * sizeof(char*));

    envp[c] = szPreload;
    envp[c+1] = strpipe_in;
    envp[c+2] = strpipe_out;
    envp[c+3] = NULL;

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

    CPLFree(envp);

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
    if( p->bFreeActions )
        posix_spawn_file_actions_destroy(&p->actions);
    CPLFree(p);
    return status;
}

static void Usage(char* argv[])
{
    printf("Usage: %s [-ro | -rw | -ro_extended | -rw_extended] a_binary option1...\n", argv[0]);
    printf("\n");
    printf("Options:\n");
    printf(" -ro (default): set sandbox in read-only mode, restricted to files explicitely listed or white listed.\n");
    printf(" -ro_extended : set sandbox in read-only mode (access to all files readable by the current user).\n");
    printf(" -rw : set sandbox in read/write mode, restricted to files explicitely listed or white listed..\n");
    printf(" -rw_extended : set sandbox in full read/write mode (access to all files readable by the current user).\n");
    printf("\n");
    exit(1);
}

char* make_full_filename(const char* pszCurDir, const char* pszFilename)
{
    char* ret;
    if( pszFilename[0] != '/' )
    {
        char* tmp = (char*) malloc(strlen(pszCurDir) + 1 + strlen(pszFilename) + 1);
        strcpy(tmp, pszCurDir);
        strcat(tmp, "/");
        strcat(tmp, pszFilename);
        ret = realpath(tmp, NULL);
        if( ret == NULL && strstr(pszFilename, "..") == NULL &&
            strstr(pszFilename, "./") == NULL )
        {
            return tmp;
        }
        free(tmp);
    }
    else
        ret = realpath(pszFilename, NULL);
    return ret;
}

typedef struct _ListFile ListFile;
struct _ListFile
{
    char* pszFilename;
    struct _ListFile* psNext;
};

ListFile* psHead = NULL;

enum
{
    OP_READ,
    OP_WRITE,
    OP_UNLINK
};

/* Only authorized reading files mentionned on the command line, or in */
/* white-list */
static int file_allowed(const char* pszFilename, int argc, char* argv[], int op)
{
    int i;
    if( strncmp(pszFilename, "/tmp/", 5) == 0 &&
        strstr(pszFilename, "..") == NULL )
    {
        if( op == OP_WRITE )
        {
            ListFile* psNew = (ListFile*)calloc(sizeof(ListFile), 1);
            if( psHead == NULL )
                psHead = psNew;
            else
            {
                psNew->psNext = psHead;
                psHead = psNew;
            }
            psHead->pszFilename = strdup(pszFilename);
            return 1;
        }
        else
        {
            ListFile* psPrev = NULL;
            ListFile* psIter = psHead;
            while(psIter != NULL)
            {
                if( strcmp(psIter->pszFilename, pszFilename) == 0 )
                {
                    if( op == OP_UNLINK )
                    {
                        free(psIter->pszFilename);
                        if( psPrev != NULL )
                            psPrev->psNext = psIter->psNext;
                        else
                            psHead = psIter->psNext;
                        free(psIter);
                    }
                    return 1;
                }
                psPrev = psIter;
                psIter = psIter->psNext;
            }
            return 0;
        }
    }

    if( op == OP_READ )
    {
        if( strcmp(pszFilename, "/dev/urandom") == 0 )
            return 1;
        if( strcmp(pszFilename, "/etc/inputrc") == 0 )
            return 1;
        if( strcmp(pszFilename, "/lib/terminfo/x/xterm") == 0 )
            return 1;
        if( strstr(pszFilename, "/lib/python") != NULL)
            return 1;
        if( strstr(pszFilename, "/include/python") != NULL)
            return 1;
        if( strncmp(pszFilename, "/usr/share/gdal", strlen("/usr/share/gdal")) == 0 )
            return 1;
        char* gdal_data = getenv("GDAL_DATA");
        if( gdal_data != NULL &&
            strncmp(pszFilename, gdal_data, strlen(gdal_data)) == 0 )
            return 1;
    }
    char* pszCurDir = getcwd(NULL, 0);
    char* pszFullFilename = make_full_filename(pszCurDir, pszFilename);
    if( pszFullFilename == NULL )
    {
        pszFullFilename = strdup(pszFilename);
    }
    
    struct stat buf;
    if( op == OP_READ && stat(pszFullFilename, &buf) == 0 && S_ISDIR(buf.st_mode) )
    {
        free(pszFullFilename);
        free(pszCurDir);
        return 1;
    }

    const char* pszDot1 = strrchr(pszFullFilename, '.');
    char* pszFullArg = NULL;
    int ret = 0;
    for(i=1;i<argc;i++)
    {
        if( argv[i][0] == '-' )
            continue;
        free(pszFullArg);
        pszFullArg = make_full_filename(pszCurDir, argv[i]);
        if( pszFullArg == NULL )
        {
            pszFullArg = strdup(argv[i]);
        }

        /*printf("%s %s\n", pszFullFilename, pszFullArg);*/
        if( strcmp(pszFullFilename, pszFullArg) == 0 )
        {
            ret = 1;
            break;
        }
        if( pszDot1 != NULL )
        {
            /* Accept also files that share the same radix */
            if( strncmp(pszFullFilename, pszFullArg, pszDot1 - pszFullFilename) == 0 &&
                strchr(pszFullArg + (pszDot1 - pszFullFilename + 1), '/') == NULL )
            {
                ret = 1;
                break;
            }
        }
        struct stat buf;
        if( stat(pszFullArg, &buf) == 0 && S_ISDIR(buf.st_mode) )
        {
            if( strncmp(pszFullFilename, pszFullArg, strlen(pszFullArg)) == 0 )
            {
                ret = 1;
                break;
            }
        }
    }
    free(pszFullArg);
    free(pszFullFilename);
    free(pszCurDir);
    return ret;
}

enum
{
    MODE_RO,
    MODE_RO_EXTENDED,
    MODE_RW,
    MODE_RW_EXTENDED
};

static int child_fd[1024];

#define N_CHILD_DIR 32
static DIR* child_dir[N_CHILD_DIR] = { NULL };

int main(int argc, char* argv[])
{
    int i;
    int eMode = MODE_RO;
    int bInSecComp = FALSE;
    for(i=1;i<argc;i++)
    {
        if( strcmp(argv[i], "-ro") == 0 )
            eMode = MODE_RO;
        else if( strcmp(argv[i], "-ro_extended") == 0 )
            eMode = MODE_RO_EXTENDED;
        else if( strcmp(argv[i], "-rw") == 0 )
            eMode = MODE_RW;
        else if( strcmp(argv[i], "-rw_extended") == 0 )
            eMode = MODE_RW_EXTENDED;
        else if( argv[i][0] == '-' )
        {
            Usage(argv);
        }
        else
            break;
    }
    
    if( argv[i] == NULL )
        Usage(argv);

    /* Prepare the argument command line for the child */
    char** my_argv = (char**)CPLMalloc(sizeof(char*)* (argc-i+1));
    memcpy(my_argv, argv+i, sizeof(char*)* (argc-i+1));
    CPLSpawnedProcess* sp = SeccompCPLSpawnAsync(NULL, (const char* const*)my_argv,
                                          TRUE, TRUE, FALSE, NULL);
    CPLFree(my_argv);

    /* Child file descriptors availability: register stdout(1) and stderr(2) */
    memset(child_fd, 0, sizeof(child_fd));
    child_fd[0] = 1;
    child_fd[1] = 1;
    child_fd[2] = 1;

    /*write(sp->fout, "go!", 3);*/
    while(TRUE)
    {
        int cmd = 0;
        if( read(sp->fin, &cmd, 4) == 0 )
            break;
        if( cmd == CMD_HAS_SWITCHED_TO_SECCOMP )
        {
            bInSecComp = TRUE;
        }
        else if( cmd == CMD_OPEN )
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
            if( bInSecComp && (eMode == MODE_RO || eMode == MODE_RW) &&
                !file_allowed(path, argc, argv, (flags == O_RDONLY) ? OP_READ : OP_WRITE) )
            {
                fprintf(stderr, "AccCtrl: open(%s,%d,0%o) rejected. Not in white list\n", path, flags, mode);
                fd = -1;
                myerrno = EACCES;
            }
            else if( !(eMode == MODE_RW || eMode == MODE_RW_EXTENDED) && flags != O_RDONLY )
            {
                fprintf(stderr, "AccCtrl: open(%s,%d,0%o) rejected. Nead write permissions.\n", path, flags, mode);
                fd = -1;
                myerrno = EACCES;
            }
            else
            {
                fd = open64(path, flags, mode);
                myerrno = errno;
                if( fd >= 1024 )
                {
                    fprintf(stderr, "AccCtrl: too many files opened\n");
                    close(fd);
                    fd = -1;
                    myerrno = ENFILE;
                }
                else if( fd >= 0 )
                    child_fd[fd] = 1;
                /*else
                    fprintf(stderr, "server: open(%s,%d,0%o) failed: %d\n", path, flags, mode, fd);*/
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
            if( !bInSecComp )
            {
                fprintf(stderr, "AccCtrl: mkdir(%s,0%o) rejected\n", path, mode);
                myerrno = EACCES;
                ret = -1;
            }
            else if( eMode != MODE_RW && eMode != MODE_RW_EXTENDED )
            {
                fprintf(stderr, "AccCtrl: mkdir(%s,0%o) rejected\n", path, mode);
                myerrno = EACCES;
                ret = -1;
            }
            else if( eMode == MODE_RW && !file_allowed(path, argc, argv, OP_WRITE) )
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
        else if (cmd == CMD_UNLINK || cmd == CMD_REMOVE || cmd == CMD_RMDIR)
        {
            unsigned short len;
            read(sp->fin, &len, sizeof(len));
            char* path = (char*)malloc(len+1);
            read(sp->fin, path, len);
            path[len] = '\0';
            int ret;
            int myerrno;
            const char* pszOp = ( cmd == CMD_UNLINK ) ? "unlink" :
                                ( cmd == CMD_REMOVE ) ? "remove" : "rmdir";
            if( !bInSecComp )
            {
                fprintf(stderr, "AccCtrl: %s(%s) rejected\n", pszOp, path);
                myerrno = EACCES;
                ret = -1;
            }
            else if( eMode != MODE_RW && eMode != MODE_RW_EXTENDED )
            {
                fprintf(stderr, "AccCtrl: %s(%s) rejected\n", pszOp, path);
                myerrno = EACCES;
                ret = -1;
            }
            else if( eMode == MODE_RW && !file_allowed(path, argc, argv, OP_UNLINK) )
            {
                fprintf(stderr, "AccCtrl: %s(%s) rejected\n", pszOp, path);
                myerrno = EACCES;
                ret = -1;
            }
            else
            {
                if( cmd == CMD_UNLINK )
                    ret = unlink(path);
                else if( cmd == CMD_REMOVE )
                    ret = remove(path);
                else
                    ret = rmdir(path);
                /*if( ret < 0 )
                    fprintf(stderr, "%s(%s) failed\n", pszOp, path);*/
                myerrno = errno;
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
        else if( cmd == CMD_DUP )
        {
            int oldfd;
            read(sp->fin, &oldfd, 4);
            if( oldfd < 0 || oldfd >= 1024 || !child_fd[oldfd] )
                oldfd = -1;
            int newfd = dup(oldfd);
            int myerrno = errno;
            /*fprintf(stderr, "server: open(%s,%d,0%o) = %d\n", path, flags, mode, fd);*/
            if( newfd >= 1024 )
            {
                close(newfd);
                newfd = -1;
                myerrno = ENFILE;
            }
            else if( newfd >= 0 )
                child_fd[newfd] = 1;
            write(sp->fout, &newfd, 4);
            if( newfd < 0 )
                write(sp->fout, &myerrno, 4);
        }
        else if( cmd == CMD_DUP2 )
        {
            int oldfd, newfd;
            read(sp->fin, &oldfd, 4);
            read(sp->fin, &newfd, 4);
            if( oldfd < 0 || oldfd >= 1024 || !child_fd[oldfd] )
                oldfd = -1;
            if( newfd < 0 || newfd >= 1024 || !child_fd[newfd] )
                newfd = -1;
            int ret = dup2(oldfd, newfd);
            int myerrno = errno;
            /*fprintf(stderr, "server: open(%s,%d,0%o) = %d\n", path, flags, mode, fd);*/
            if( ret >= 0 && oldfd != newfd )
            {
                child_fd[oldfd] = 0;
                child_fd[newfd] = 1;
            }
            write(sp->fout, &ret, 4);
            if( ret < 0 )
                write(sp->fout, &myerrno, 4);
        }
        else if( cmd == CMD_OPENDIR )
        {
            unsigned short len;
            read(sp->fin, &len, sizeof(len));
            char* path = (char*)malloc(len + 1);
            read(sp->fin, path, len);
            path[len] = 0;
            if( bInSecComp && (eMode == MODE_RO || eMode == MODE_RW) &&
                !file_allowed(path, argc, argv, OP_READ) )
            {
                fprintf(stderr, "AccCtrl: opendir(%s) rejected. Not in white list\n", path);
                int ret = -1;
                write(sp->fout, &ret, 4);
            }
            else
            {
                DIR* dir = opendir(path);
                if( dir == NULL )
                {
                    int ret = -1;
                    write(sp->fout, &ret, 4);
                }
                else
                {
                    int i;
                    for(i=0;i<N_CHILD_DIR;i++)
                    {
                        if( child_dir[i] == NULL )
                        {
                            child_dir[i] = dir;
                            int ret = i;
                            write(sp->fout, &ret, 4);
                            break;
                        }
                    }
                    if( i == N_CHILD_DIR )
                    {
                        fprintf(stderr, "AccCtrl: too many directories opened\n");
                        closedir(dir);
                        int ret = -1;
                        write(sp->fout, &ret, 4);
                    }
                }
            }
            free(path);
        }
        else if( cmd == CMD_READDIR )
        {
            int handle;
            read(sp->fin, &handle, 4);
            struct dirent * pent = NULL;
            int ret;
            if( handle < 0 || handle >= N_CHILD_DIR || child_dir[handle] == NULL )
                ret = -1;
            else
            {
                pent = readdir(child_dir[handle]);
                if( pent == NULL )
                    ret = -1;
                else
                    ret = 0;
            }
            write(sp->fout, &ret, 4);
            if( ret == 0 )
                write(sp->fout, pent, sizeof(struct dirent));
        }
        else if( cmd == CMD_READDIR64 )
        {
            int handle;
            read(sp->fin, &handle, 4);
            struct dirent64 * pent = NULL;
            int ret;
            if( handle < 0 || handle >= N_CHILD_DIR || child_dir[handle] == NULL )
                ret = -1;
            else
            {
                pent = readdir64(child_dir[handle]);
                if( pent == NULL )
                    ret = -1;
                else
                    ret = 0;
            }
            write(sp->fout, &ret, 4);
            if( ret == 0 )
                write(sp->fout, pent, sizeof(struct dirent64));
        }
        else if( cmd == CMD_REWINDDIR )
        {
            int handle;
            read(sp->fin, &handle, 4);
            if( handle < 0 || handle >= N_CHILD_DIR || child_dir[handle] == NULL )
                ;
            else
            {
                rewinddir(child_dir[handle]);
            }
        }
        else if( cmd == CMD_CLOSEDIR )
        {
            int handle;
            read(sp->fin, &handle, 4);
            int ret;
            if( handle < 0 || handle >= N_CHILD_DIR || child_dir[handle] == NULL )
                ret = -1;
            else
            {
                ret = closedir(child_dir[handle]);
                child_dir[handle] = NULL;
            }
            write(sp->fout, &ret, 4);
        }
        else if( cmd == CMD_SELECT_STDIN )
        {
            if( child_fd[0] )
            {
                fd_set readfds;
                FD_ZERO(&readfds);
                FD_SET(0, &readfds);
                int ret = select(1, &readfds, NULL, NULL, NULL);
                write(sp->fout, &ret, 4);
                int isset = FD_ISSET(0, &readfds);
                write(sp->fout, &isset, 4);
            }
            else
            {
                int ret = -1;
                write(sp->fout, &ret, 4);
                int isset = 0;
                write(sp->fout, &isset, 4);
            }
        }
    }

    return CPLSpawnAsyncFinish(sp, TRUE, FALSE);
}
