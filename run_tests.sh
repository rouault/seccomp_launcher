#!/bin/bash
#strace -f ./seccomp_launcher ./test1
FAILED=0
if ! ./seccomp_launcher ./test1 2>/dev/null; then
    echo "test1 failed"
    FAILED=1
fi
# Test must return a non zero code
if ./seccomp_launcher ./test2  2>/dev/null; then
    echo "test2 failed"
    FAILED=1
fi
if ! ./seccomp_launcher ./test3 test3.c >/dev/null 2>/dev/null; then
    echo "test3 failed"
    FAILED=1
fi

if test "$FAILED" = "0"; then
    echo "Test finished successfully"
    exit 0
else
    exit 1
fi
