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

#ifndef GUARD_SECCOMP_WRAPPER_H
#define GUARD_SECCOMP_WRAPPER_H

enum
{
    CMD_HAS_SWITCHED_TO_SECCOMP, /* not a syscall, but an hint from seccomp_preload */
                                 /* to seccomp_launcher that it has switched */
                                 /* into SECCOMP protection */
    CMD_OPEN,
    CMD_CLOSE,
    CMD_READ,
    CMD_WRITE,
    CMD_SEEK,
    CMD_STAT,
    CMD_FSTAT,
    CMD_MKDIR,
    CMD_UNLINK,
    CMD_REMOVE,
    CMD_RMDIR,
    CMD_FTRUNCATE,
    CMD_DUP,
    CMD_DUP2,
    CMD_OPENDIR,
    CMD_READDIR,
    CMD_READDIR64,
    CMD_REWINDDIR,
    CMD_CLOSEDIR,
    CMD_SELECT_STDIN /* not a regular system call, */
                     /* but select(1, &read_fds, NULL, NULL, NULL) where */
                     /* read_fds is set to fd 0. This is used by the Python */
                     /* interactive console */
};

#endif /*  GUARD_SECCOMP_WRAPPER_H */
