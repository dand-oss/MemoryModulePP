//==============================================================================
// (c) Copyright 1995, by Royal Dutch / Shell.  All Rights Reserved.
// Unauthorized reproduction, distribution, or use is prohibited.
//------------------------------------------------------------------------------
// $Header: /CVS/ASI/src/galoo/0.cpp,v 1.49 2004/07/23 20:09:22 larry Exp $
//==============================================================================

#include <ntools/auditsys.hpp> // Audit_System

// This is a place for turning some basic app debug stuff on
#define BASIC_APP_DEBUG
#ifdef BASIC_APP_DEBUG
#   define DBGVAL TRUE
#   define CUTLEVEL 10
#else
#   define DBGVAL FALSE
#   define CUTLEVEL 0
#endif

//#define LEACKCHECK
#ifdef LEACKCHECK
#   define LEAKVAL TRUE
#   define CUTLEVEL 10
#else
#   define LEAKVAL FALSE
#endif

//------------------------------------------------------------------------------
// Audit will call this early on.  You do initialize, and poke any flags
extern SOMUX_API aVoid audit_customize( Audit_System& as )
{
    // init audit parameters
    as.max_methods = 32767;// method table fills up when using =cl10
    as.max_depth = 1024;

//  Heap debugging can only be set up once, right here
    as.heap_debug_enabled = FALSE ;

//  This also should be setup once up front
    as.no_debug_buffer = DBGVAL ;

//  If you want some debugging before main
    as.cutoff_level = CUTLEVEL ;
    as.call_stack_enabled = DBGVAL ;

//  Heap goodies
    as.heap_verify_enabled = FALSE ;
    as.heap_verify_divisor = 2000 ;
    as.heap_verify_countdown = 0L ;
    as.report_heap_leaks = LEAKVAL ;

//  Trace (see above)
    as.run_time_trace = FALSE ;
    as.run_time_countdown = 2550000l ;
    as.no_console_output = FALSE ;

//  Dump at the end
    as.profile_summary_enabled = DBGVAL ;

//  Timer
    as.profile_enabled = FALSE ;

//  Traces
    as.gui_msg_trace = FALSE ;

//  Win 3.1 fault handler
    as.fault_handler_disabled = FALSE ;

//  Use of threads
    as.no_threads = FALSE ;

//  Handy subsets of audit settings

    return ;
}
