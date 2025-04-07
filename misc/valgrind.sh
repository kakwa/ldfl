#!/bin/sh

cd  $(dirname $0)/..

for ftest in ldfl-test-*
do
    echo "checking '$ftest' for memleaks"
    valgrind --tool=memcheck --leak-check=yes --show-reachable=yes --num-callers=20 --track-fds=yes --track-origins=yes --error-exitcode=42 ./$ftest || exit 1
done
