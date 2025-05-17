
declare -ar DIRS=(
    # output
    ${ASV_PLAT_PORTS}/memorymodulepp
    # build
    ${b3}/memorymodulepp-build-${aplatform}-Debug
    ${b3}/memorymodulepp-build-${aplatform}-Release
)

rm -rf "${DIRS[@]}"
