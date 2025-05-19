declare -r SRCDIR="${r3}/memorymodulepp"
declare -r BUILDDIR="${SRCDIR}/build"
declare -r EXE_DIR="${BUILDDIR}/db-dll-loader/Debug"
declare -r DLL_DIR="${BUILDDIR}/MemoryModule/Debug"
export PATH="${DLL_DIR}:${PATH}"
echo ${PATH}

# Added: Function to reverse an array
reverse_array() {
    local -a input=("$@")
    local -a reversed=()
    for ((i=${#input[@]}-1; i>=0; i--)); do
        reversed+=("${input[i]}")
    done
    echo "${reversed[@]}"
}

declare -r PROG="${EXE_DIR}/db-dll-loader.exe"
if [ -f "${PROG}" ] ; then 
    declare do_few='0'
    if [ "${do_few}" != '0' ] ; then 
        declare -ra DLLS=(
            "audit_customize_d.dll"
        )
    else
        declare -ra DLLS=(
            "audit_customize_d"
	    "oildll_d"
            "glueapp_d"
        )
    fi

    declare -r REVERSE_DLLS='1'
    if [ "${REVERSE_DLLS}" == '1' ]; then
        declare -ra DLLS_TO_USE=($(reverse_array "${DLLS[@]}"))
    else
        declare -ra DLLS_TO_USE=("${DLLS[@]}")
    fi

    declare -r CMD=(
        ${PROG}
        --db "${SRCDIR}/dlls.db"
        "${DLLS_TO_USE[@]}"
        "${@}"
    )
    echo "${CMD[@]}"
    "${CMD[@]}"
else
    echo "${PROG} not found"
fi
