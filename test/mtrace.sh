#!/bin/bash

if [ $# -lt 2 ]
then
    echo "$0 mtracelogfile executefile"
    exit 1
fi

mtrace $1 | awk '{print $4}' | sort -n | uniq -c | awk '{print $2}' | xargs  addr2line -f -e $2 -a
