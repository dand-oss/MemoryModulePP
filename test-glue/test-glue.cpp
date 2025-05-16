#include "../glue-loader/run-glue.hpp"

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nCmdShow) {
    const auto argc = __argc;
    const char** argv = const_cast<const char**>(__argv);
    return run_glue(argc, argv, hInst, hPrev, lpCmdLine, nCmdShow);
}
