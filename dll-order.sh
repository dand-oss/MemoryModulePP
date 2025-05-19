declare -r SRCDIR="${r3}/memorymodulepp"
declare -r BUILDDIR="${SRCDIR}/build"
declare -r EXE_DIR="${BUILDDIR}/dll-order/Debug"

declare -r PROG="${EXE_DIR}/dll-order.exe"
if [ -f "${PROG}" ] ; then 
    declare -r CMD=(
        ${PROG}
       	--db "${SRCDIR}/dlls.db"
	"${@}"
    )
    echo "${CMD[@]}"
    "${CMD[@]}"
else
    echo "${PROG} not found"
fi
