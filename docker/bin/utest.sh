#!/bin/sh
#------------------------------------------------------------------------------
# Execute freedom-metal unit tests with a QEMU virtual machine
#
# Dependencies:
#  * qemu VM with FDT support
#  * riscv64-unknown-elf-readelf (from RISC-V ELF binutils)
#  * dtc (device tree compiler)
#  * POSIX shell, find, sed, grep, cut
#------------------------------------------------------------------------------

TMPDIR=""

# Die with an error message
die() {
    echo "$*" >&2
    exit 1
}

# Print the absolute path
abspath() {
    echo "$(cd "$(dirname "$1")"; pwd)/$(basename "$1")"
}

# Cleanup function on exit
cleanup() {
    if [ -n "${TMPDIR}" -a -d ${TMPDIR} ]; then
        rm -rf TMPDIR
    fi
}

# Show script usage
usage() {
    NAME=`basename $0`
    cat <<EOT
$NAME [-h] <-d DTS> [-q QEMU_DIR] [unit_test|unit_test_dir] ...
EOT
}

READELF=$(which riscv64-unknown-elf-readelf 2>/dev/null)
test -n "${READELF}" || die "Unable to locate readelf for RISC-V"
DTC=$(which dtc 2>/dev/null)
test -n "${READELF}" || die "Unable to locate dtc"

DTS=""
UNIT_TESTS=""
QEMUPATH=""
while [ $# -gt 0 ]; do
    case "$1" in
        -h)
            usage
            exit 0
            ;;
        -d)
            shift
            DTS="$1"
            test -f "${DTS}" || die "Unable to find DTS ${DTS}"
            ;;
        -q)
            shift
            QEMUPATH="$1"
            test -d "${QEMUPATH}" || die "Invalid QEMU directory ${QEMUPOATH}"
            ;;
        *.elf)
            test -f $1 || die "UT $1 does not exist"
            UNIT_TESTS="${UNIT_TESTS} $1"
            ;;
        *)  if [ -d $1 ]; then
                for ut in $(find $1 -type f -name "*.elf"); do
                    UNIT_TESTS="${UNIT_TESTS} ${ut}"
                done
            fi
            ;;
    esac
    shift
done

test -n "${DTS}" || die "DTS should be specified"

# Be sure to leave on first error
set -eu

TMPDIR=$(mktemp -d)
trap cleanup EXIT

${DTC} ${DTS} > ${TMPDIR}/qemu.dtb

RV=""
for ut in ${UNIT_TESTS}; do
    if [ -z "${RV}" ]; then
        RV=$(${READELF} -h ${ut} | grep Class | cut -d: -f2 | sed 's/^ *ELF//')
        if [ -z "$QEMUPATH" ]; then
            QEMU="qemu-system-riscv${RV}"
        else
            QEMU="${QEMUPATH}/qemu-system-riscv${RV}"
        fi
        test -x ${QEMU} || die "Unable to locate QEMU for RV${RV}"
    fi
    echo "> Running UT $(basename ${ut})"
    ${QEMU} -machine sifive_fdt -dtb ${TMPDIR}/qemu.dtb -nographic -kernel ${ut}
done
