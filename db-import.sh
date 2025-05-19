#!/usr/bin/env bash

# fail on error
#
set -eo pipefail

declare -r SRCDIR="${r3}/memorymodulepp"
declare -r BUILDDIR="${SRCDIR}/build"
declare -r EXE_DIR="${BUILDDIR}/db-dll-import/Debug"
declare -r PROG="${EXE_DIR}/db-dll-import.exe"

# add plugins to path
declare -r PORTS_DIR="${iASV_PLAT_PORTS}"
export PATH="${PATH}:${PORTS_DIR}/qt5/plugins/platforms:${PORTS_DIR}/qt5/plugins/imageformats"

declare -ar FILEZ=(
    "apptools_d.dll"
    "asirpc_d.dll"
    "asv-settings-app_d.dll"
    "athread_d.dll"
    "audit_customize_d.dll"
    "calc_d.dll"
    "dbobj_d.dll"
    "dstng_d.dll"
    "dstng_firebird_d.dll"
    "dstng_odbc_d.dll"
    "dstng_oracle_d.dll"
    "dstng_vanilla_d.dll"
    "dynalift_d.dll"
    "glsupdll1_d.dll"
    "glsupdll2_d.dll"
    "glsuplib1_d.dll"
    "glsuplib2_d.dll"
    "glueapp_d.dll"
    "gluecomlib_d.dll"
    "graphds_d.dll"
    "gtools_d.dll"
    "gui_d.dll"
    "network_d.dll"
    "ntools_d.dll"
    "oilapi_d.dll"
    "oilapp_d.dll"
    "oilcomp_d.dll"
    "oilcore1_d.dll"
    "oilcore2_d.dll"
    "oildll_d.dll"
    "oilole_d.dll"
    "oilrunt_d.dll"
    "ole_d.dll"
    "otools_d.dll"
    "piapi_d.dll"
    "piapi_oil_d.dll"
    "qtoil_d.dll"
    "qtxlsx_d.dll"
    "tools_d.dll"
    "twophase_d.dll"
    "win31_d.dll"
    "winhelp_d.dll"
    "Wt2_d.dll"
    "Wt2_Oil_d.dll"
)

declare -ar PORTZ=(
    "F77_d.dll"
    "I77_d.dll"
    "ibpp_d.dll"
    "qhttpserver_d.dll"
    "rwtool_d.dll"
    "xlsx_d.dll"
    "nlopt_d.dll"
    "rttr_core_d.dll"
    "yaml-cpp_d.dll"
)

declare -ar QT_BIN=(
    "Qt5CoreASVd.dll"
    "Qt5GuiASVd.dll"
    "Qt5NetworkASVd.dll"
    "Qt5PrintSupportASVd.dll"
    "Qt5SvgASVd.dll"
    "Qt5WidgetsASVd.dll"
    "Qt5XmlASVd.dll"
)

declare -ar QT_PLUG=(
    "qwindowsd.dll"
    "qjpegd.dll"
)

function import {
    declare CMD=(
        ${PROG}
       	--db "${SRCDIR}/dlls.db"
	"${FILEZ[@]}"
	"${PORTZ[@]}"
	"${QT_BIN[@]}"
	"${QT_PLUG[@]}"
	"${@}"
    )
    echo "${CMD[@]}"
    "${CMD[@]}"
}

if [ -f "${PROG}" ] ; then 
    import
else
    echo "${PROG} not found"
fi
