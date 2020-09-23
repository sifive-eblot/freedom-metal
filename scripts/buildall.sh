#!/bin/sh
#------------------------------------------------------------------------------
# Build all BSPs/builds combinations.
#
# This script only exists to circumvent current GitHub actions limitations,
# where the strategy matrix feature does not allow to perform global actions
# before running the matrix combinations
#------------------------------------------------------------------------------

SCRIPT_DIR=$(dirname $0)
DTS=""
BUILDS="debug release"

export TERM=ansi

# Die with an error message
die() {
    echo "$*" >&2
    exit 1
}

usage() {
    NAME=`basename $0`
    cat <<EOT
$NAME [-h] [-a] [-s] [dts] ...

 dts: the name of a dts file (w/o path or extension)

 -h:  print this help
 -a:  abort on first failed build (default: resume)
 -s:  run static analyzer in addition to regular builds
EOT
}

SA=0
ABORT=0
for arg in $*; do
    case ${arg} in
        -s)
            SA=1
            ;;
        -a)
            ABORT=1
            ;;
        -h)
            usage
            exit 0
            ;;
        -*)
            ;;
        *)
            DTS="${DTS} ${arg}"
            ;;
    esac
done
if [ $SA -gt 0 ]; then
    BUILDS="${BUILDS} static_analysis"
fi

test -n "${DTS}" || die "No target specified"

FAILURE=0
for dts in ${DTS}; do
    for build in ${BUILDS}; do
        udts=$(echo "${dts}" | tr [:lower:] [:upper:])
        ubuild=$(echo "${build}" | tr [:lower:] [:upper:])
        echo "" >&2
        echo "\033[36m[Building ${udts} in ${ubuild}]\033[39m"
        ${SCRIPT_DIR}/build.sh ${dts} ${build}
        if [ $? -ne 0 ]; then
            echo "\033[31mBuild failed (${udts} in ${ubuild})\033[39m" >&2
            if [ ${ABORT} -gt 0 ]; then
                exit $?
            else
                FAILURE=1
            fi
        fi
    done
done

if [ ${FAILURE} -ne 0 ]; then
    echo "\033[31mAt least one build failed\033[39m" >&2
    exit 1
fi
