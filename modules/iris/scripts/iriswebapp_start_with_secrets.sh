#!/bin/bash

cd /run/secrets
for file in `ls`
do
  export ${file}=`cat ${file}`
done
cd -

/iriswebapp/iris-entrypoint.sh iriswebapp
