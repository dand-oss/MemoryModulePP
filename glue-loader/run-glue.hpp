// run-glue.hpp
#pragma once

#include <Windows.h>
#include <string>

extern "C" __declspec(dllexport)
int run_glue(int argc, const char* argv[], HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nCmdShow);

HMODULE LoadAllDllsAndReturnGlueApp(const std::string& dbPathInput = "asv.hfb");

int launch_main(int argc, const char* argv[], HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR cmdLine, int nCmdShow);
