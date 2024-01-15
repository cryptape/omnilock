#!/bin/bash

for file in *.json; do
    ckb-debugger --bin ../build/omni_lock -f $file -i 0 -s lock
done

