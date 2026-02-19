#!/bin/bash

cd /run/secrets
for file in `ls`
do
  export ${file}=`cat ${file}`
done
cd -

##
# Hack to bypass checks that prevents postgres from starting
source /usr/local/bin/docker-entrypoint.sh
_main postgres "$@"
