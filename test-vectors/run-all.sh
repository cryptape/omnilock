#!/bin/bash
for file in *.json; do
    echo $file
    ckb-debugger --bin ../build/omni_lock -f $file -i 0 -s lock
    if (($? != 0)); then
        exit 1
    fi
done

