#!/bin/sh

. "$(dirname $0)/../exec/docker.conf"

VOLUMES=""
for cnr in ${CONTAINERS}; do
    name=`echo $cnr | cut -d@ -f1`
    path=`echo $cnr | cut -d@ -f2`
    localname=`echo ${name} | tr ':' '_' | cut -d/ -f2`
    volume="${localname}-vol"
    if [ ! $(docker ps -q -a -f name=${volume}) ]; then
        echo "Instanciating missing volume $volume" >&2
        docker create -v ${path} --name ${volume} ${name} \
            /bin/true > /dev/null
        if [ $? -ne 0 ]; then
            exit 1
        fi
    fi
    if [ -n "${VOLUMES}" ]; then
        VOLUMES="${VOLUMES} ${volume}"
    else
        VOLUMES="${volume}"
    fi
done

# pass the volume list to the caller
echo "${VOLUMES}"