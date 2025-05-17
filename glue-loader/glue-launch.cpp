// ========================================================================== //
// Copyright (c) 2015 by AppSmiths Software LLC.  All Rights Reserved.        //
// -------------------------------------------------------------------------- //
// All material is proprietary to AppSmiths Software LLC and may be used only //
// pursuant to license rights granted by AppSmiths Software LLC.  Other       //
// reproduction, distribution, or use is strictly prohibited.                 //
// ========================================================================== //

#include <applaunch/procopt.hpp>
#include <applaunch/applaunch.hpp>
#include <hfb/hfb_tools.hpp>
#include <objstore/orkork.hpp>
#include "run-glue.hpp"
#include "hfbfuncs.hpp"

#ifdef _WIN32

#include <hfb/load_patcher.hpp>
#include <iostream> // std::cout
#include <fstream>
static std::ofstream* hook_log_fd = NULL;
#endif // USE_HOOK

#include <boost/exception/diagnostic_information.hpp>

#include <applaunch/attach_console.hpp>
#ifdef ASI_PLAT_WIN32
#include <comdef.h>
#else
#include <iostream>
#endif // ASI_PLAT_WIN32

#include <fmt/ostream.h>

namespace fs = std::filesystem;

static const auto g_prog_name = "glue";


//-----------------------------------------------------------------------------
static void do_msg(const std::string& msg, const char* boxname)
{
#if defined( ASI_PLAT_WIN32)
    MessageBoxA(nullptr, msg.c_str(), boxname, 0);
#else
    fmt::print(std::cerr, "{}\n", msg);
#endif // ASI_PLAT_WIN32
}

//-----------------------------------------------------------------------------
static void print_args(
    std::ostream& os,
    const std::string& name,
    int argc,
    const char* argv[],
    const std::map<std::string, docopt::value>& arg_map)
{
    const auto& sargv = applaunch::repr_argv(argc, argv);
    fmt::print(os, "{} {}\n", name, sargv);

    const auto& srep = applaunch::repr_map(arg_map);
    fmt::print(os, "{}\n", srep);
}

//-----------------------------------------------------------------------------
static std::string launch_usage_str(const std::string& progname)
{
    // start with the launcher version
    std::string fmt_str(applaunch::usage_str());

    // on windows, add COM
#ifdef ASI_PLAT_WINDOWS
    fmt_str.append(
        R"(
    --regserver           register COM server
    --unregserver         unregister COM server
    -c --com-server       run COM server)");
#endif // ASI_PLAT_WINDOWS

    // rpyc command
    fmt_str.append(
        R"(

Commands:
    rpyc                  run rpyc server

    See '{0} <command> help' for more information on a specific command
)");
    return fmt::format(fmt::runtime(fmt_str), progname);
}

aVarMap build_default_settings() {
    bool compiled_debug =
#ifndef NDEBUG
        true;
#else
        false;
#endif

    return aVarMap{
        { "prog_name", g_prog_name },
        { "appdll_name", "glueapp" },
        { "module_path", "" },
        { "dll_path", "" },
        { "work_dir", "" },
        { "hfb_file_path", "" },
        { "settings_file_path", "" },
        { "use_debug_dll_names", compiled_debug },
        { "use_hfb", !compiled_debug },
        { "use_console", false },
        { "trace_nt_level", 0 },
        { "trace_nt_file_path", "trace-nt-log.txt" },
        { "uninstall", false },
        { "usage_str", launch_usage_str(g_prog_name) }
    };
}

int parse_and_fix_args(int argc, const char* argv[], const std::string& prog_name, aVarMap& settings, const char* fixed_argv[]) {
    const std::string ms_ole_embed("-Embedding");
    int fixed_argc = 0;

    for (int i = 0; i < argc; ++i) {
        std::string arg(argv[i]);
        size_t pos = arg.find(ms_ole_embed);
        if (pos != std::string::npos) {
            arg.erase(pos, ms_ole_embed.length());
            if (!arg.empty()) fixed_argv[fixed_argc++] = _strdup(arg.c_str());
        }
        else {
            fixed_argv[fixed_argc++] = argv[i];
        }
    }
    fixed_argv[fixed_argc] = nullptr;

    applaunch::parse_launch_args(fixed_argc, fixed_argv, settings);
    return fixed_argc;
}

hfb::handle_ret handle_hfb_setup(const fs::path& module_path, aVarMap& settings) {
    const auto& hfb_path = settings.get<std::string>("hfb_file_path");
    const auto& settings_path = settings.get<std::string>("settings_file_path");
    auto hfb_info = hfb::handle_ret::handle_hfbs(module_path, hfb_path, settings_path);

    if (!hfb_info.exitmsg().empty()) {
        do_msg(hfb_info.exitmsg(), g_prog_name);
        exit(hfb_info.exitrc());
    }

    if (settings.get<bool>("uninstall") && hfb_info.is_overlay()) {
        ork::ork_delete_extracted_zones(hfb_info.use_this_hfb().parent_path(), hfb_info.use_this_hfb(), { "TNT", "UPDATE" });
        exit(0);
    }

    settings.set("hfb_file_path", hfb_info.use_this_hfb().string());
    settings.set("settings_file_path", hfb_info.use_this_settings().string());
    return hfb_info;
}

dynalo::library setup_somux(const aVarMap& settings) {
    auto somux_map = applaunch::find_app_setup("glueapp", true);
    somux_map["use_debug_dll_names"] = settings.get<bool>("use_debug_dll_names");

    fs::path path = applaunch::make_dll_name("somux", settings.get<bool>("use_debug_dll_names"));
    if (!settings.get<bool>("use_hfb")) {
        path = fs::path(settings.get<std::string>("dll_path")) / path;
    }

    return applaunch::launch_somux(path.string(), somux_map);
}

int launch_main_app(const aVarMap& settings, const hfb::handle_ret& hfb_info, int fixed_argc, const char* fixed_argv[]
#ifdef ASI_PLAT_WINDOWS
    , HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR cmdLine, int nCmdShow
#endif
) {
    auto& hfb_args = applaunch::make_hfb_args(
        fixed_argc, fixed_argv,
        applaunch::parse_launch_args(fixed_argc, fixed_argv, const_cast<aVarMap&>(settings)),
        hfb_info.use_this_hfb().parent_path(),
        hfb_info.use_this_settings()
#ifdef ASI_PLAT_WINDOWS
        , hInstance, hPrevInstance, cmdLine, nCmdShow
#endif
    );

    fs::path appdll = applaunch::make_dll_name(settings.get<std::string>("appdll_name"), settings.get<bool>("use_debug_dll_names"));
    if (!settings.get<bool>("use_hfb")) {
        appdll = fs::path(settings.get<std::string>("dll_path")) / appdll;
    }

    return applaunch::launch_HfbMain(appdll.string(), hfb_args);
}

static int do_launch_main(int argc, const char* argv[]
#ifdef ASI_PLAT_WINDOWS
    , HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR cmdLine, int nCmdShow
#endif
) {
    auto module_path = applaunch::get_module_path();
    auto launch_settings = build_default_settings();
    launch_settings.set("module_path", module_path.string());
    launch_settings.set("dll_path", module_path.string());

    const char* fixed_argv[512];
    int fixed_argc = parse_and_fix_args(argc, argv, g_prog_name, launch_settings, fixed_argv);

    auto hfb_info = handle_hfb_setup(module_path, launch_settings);

    auto use_console = launch_settings.get<bool>("use_console");
    if (use_console) attach_console();

    applaunch::set_working_directory(launch_settings.get<std::string>("work_dir"));

    auto somux_lib = setup_somux(launch_settings);

#ifdef ASI_PLAT_WINDOWS
    LoadAllDllsAndReturnGlueApp(hfb_info.use_this_hfb().string());
#endif

    return launch_main_app(launch_settings, hfb_info, fixed_argc, fixed_argv
#ifdef ASI_PLAT_WINDOWS
        , hInstance, hPrevInstance, cmdLine, nCmdShow
#endif
    );
}


//-----------------------------------------------------------------------------
int launch_main(int argc, const char* argv[],
#ifdef ASI_PLAT_WIN32
    HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR cmdLine, int nCmdShow)
#endif // ASI_PLAT_WIN32
{
    int rc = 0;
    try {
        rc = do_launch_main(argc, argv
            , hInstance, hPrevInstance, cmdLine, nCmdShow
        );
    }

#ifdef ASI_PLAT_WIN32
    catch (_com_error& exc) {
        do_msg(std::string(exc.Description()), g_prog_name);
    } // boost::exception
#endif // ASI_PLAT_WIN32

    catch (const boost::exception& ex) {
        do_msg(boost::diagnostic_information(ex), g_prog_name);
    } // boost::exception

    catch (const std::exception& se) {
        do_msg(se.what(), g_prog_name);
        return -2;
    }

    //  Weirdo drip-pan
    catch (...) {
        do_msg("no exception info", g_prog_name);
    }

    return rc;
}

