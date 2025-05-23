declare -r SRCDIR="${r3}/memorymodulepp"
declare -r BUILDDIR="${SRCDIR}/build"
declare -r EXE_DIR="${BUILDDIR}/db-dll-loader/Debug"
declare -r DLL_DIR="${BUILDDIR}/MemoryModule/Debug"
export PATH="${DLL_DIR}:${PATH}"
echo ${PATH}

declare -r PROG="${EXE_DIR}/db-dll-loader.exe"
if [ -f "${PROG}" ] ; then 
    declare do_few='0'
    if [ "${do_few}" != '0' ] ; then 
        declare -ra DLLS=(
            "I77_d.dll"
        )
    else
        declare -ra DLLS=(
            "I77_d.dll"
            "Qt5CoreASVd.dll"
            "audit_customize_d.dll"
            "ibpp_d.dll"
            "nlopt_d.dll"
            "ntools_d.dll"
            "objstore_d.dll"
            "qhttpserver_d.dll"
            "rttr_core_d.dll"
            "rwtool_d.dll"
            "xlsx_d.dll"
            "yaml-cpp_d.dll"
            "F77_d.dll"
            "Qt5GuiASVd.dll"
            "Qt5NetworkASVd.dll"
            "Qt5XmlASVd.dll"
            "apptools_d.dll"
            "athread_d.dll"
            "tools_d.dll"
            "Qt5WidgetsASVd.dll"
            "Wt2_d.dll"
            "dynalift_d.dll"
            "oilcore1_d.dll"
            "ole_d.dll"
            "twophase_d.dll"
            "win31_d.dll"
            "Qt5PrintSupportASVd.dll"
            "Qt5SvgASVd.dll"
            "gtools_d.dll"
            "winhelp_d.dll"
            "oilcore2_d.dll"
            "glsupdll1_d.dll"
            "piapi_d.dll"
            "oilrunt_d.dll"
            "otools_d.dll"
            "glsupdll2_d.dll"
            "piapi_oil_d.dll"
            "asirpc_d.dll"
            "oilapi_d.dll"
            "oilapp_d.dll"
            "oilcomp_d.dll"
            "oilole_d.dll"
            "qtoil_d.dll"
            "Wt2_Oil_d.dll"
            "calc_d.dll"
            "dstng_d.dll"
            "glsuplib1_d.dll"
            "oildll_d.dll"
            "qtxlsx_d.dll"
            "network_d.dll"
            "glsuplib2_d.dll"
            "gluecomlib_d.dll"
            "dbobj_d.dll"
            "dstng_odbc_d.dll"
            "dstng_oracle_d.dll"
            "dstng_firebird_d.dll"
            "dstng_vanilla_d.dll"
            "gui_d.dll"
            "graphds_d.dll"
            "asv-settings-app_d.dll"
            "glueapp_d.dll"
        )
    fi
    declare -r CMD=(
        ${PROG}
       	--db "${SRCDIR}/dlls.db"
	${DLLS[@]}
    )
    echo "${CMD[@]}"
    "${CMD[@]}"
else
    echo "${PROG} not found"
fi
