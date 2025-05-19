// ========================================================================== //
// Copyright (c) 2017 by AppSmiths Software LLC.  All Rights Reserved.        //
// -------------------------------------------------------------------------- //
// All material is proprietary to AppSmiths Software LLC and may be used only //
// pursuant to license rights granted by AppSmiths Software LLC.  Other       //
// reproduction, distribution, or use is strictly prohibited.                 //
// ========================================================================== //

#pragma once

#include <string>
#include <vector>

extern int load_dlls(
    const std::string& dbPath,
    const std::vector<std::string>& dllNames,
    bool verbose = false);

extern void unload_dlls();

extern void unload_dll_list(
    const std::vector<std::string>& dllNames,
    bool verbose) ;

extern bool Cleanup_Resolver() ;
extern int MmpCleanup() ;
