#pragma once
/******************************************************************************
	   Module: dqr_interface.hpp
	 Engineer: Arjun Suresh
  Description: Header for Sifive TraceProfiler Decoder Interface Class
  Date         Initials    Description
  3-Nov-2022   AS          Initial
******************************************************************************/
#include <iostream>
#include <iomanip>
#include <fstream>
#include <cstring>
#include <cstdint>
#include <thread>

#include "SocketIntf.h"
#include "dqr_profiler.h"
//#pragma comment(lib, "Ws2_32.lib")

#define TRANSFER_DATA_OVER_SOCKET 1
#define WRITE_SEND_DATA_TO_FILE 0
#define SEND_DATA_FILE_DUMP_PATH "trc_send"
#define PROFILE_THREAD_BUFFER_SIZE (1024 * 128 * 2)  // 2 MB

using namespace std;

// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the DLL_EXPORT
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// DLLEXPORTEDAPI functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef DLL_EXPORT
#ifdef __linux__
#define DLLEXPORTEDAPI __attribute__ ((visibility ("default")))
#else
#define DLLEXPORTEDAPI __declspec(dllexport)
#endif
#else
#ifdef __linux__
#define DLLEXPORTEDAPI __attribute__ ((visibility ("default")))
#else
#define DLLEXPORTEDAPI __declspec(dllimport)
#endif
#endif

// Sifive TraceProfiler Decoder Error Types
typedef enum
{
	SIFIVE_TRACE_PROFILER_OK,
	SIFIVE_TRACE_PROFILER_FILE_NOT_FOUND,
	SIFIVE_TRACE_PROFILER_CANNOT_OPEN_FILE,
	SIFIVE_TRACE_PROFILER_INPUT_ARG_NULL,
	SIFIVE_TRACE_PROFILER_ELF_NULL,
	SIFIVE_TRACE_PROFILER_MEM_CREATE_ERR,
	SIFIVE_TRACE_PROFILER_SIM_STATUS_ERROR,
	SIFIVE_TRACE_PROFILER_VCD_STATUS_ERROR,
	SIFIVE_TRACE_PROFILER_TRACE_STATUS_ERROR,
	SIFIVE_TRACE_PROFILER_ERR
} TySifiveTraceProfileError;

// Sifive TraceProfiler Decoder ProfilerAnalytics Log Level
typedef enum
{
	P_LEVEL_0 = 0,
	P_LEVEL_1 = 1,
	P_LEVEL_2 = 2,
	P_LEVEL_3 = 3
} TySifiveProfilerMsgLogLevel;

// Sifive TraceProfiler Decoder ProfilerAnalytics Log Level
typedef enum
{
	P_DISABLE = 0,
	P_SORT_SYSTEM_TOTALS = 1,
	P_DISPLAY_ANALYTICS_BY_CORE = 2
} TySifiveProfilerAnalyticsLogLevel;

// Sifive TraceProfiler Decoder Target Arch Size
typedef enum
{
	P_ARCH_GET_FROM_ELF = 0,
	P_ARCH_32_BIT = 32,
	P_ARCH_64_BIT = 64
} TySifiveProfilerTargetArchSize;

// Decoder Config Structure
struct TProfilerConfig
{
	char* trace_filepath = nullptr;
	char* elf_filepath = nullptr;;
	char* objdump_path = nullptr;;
	char* strip_flag = nullptr;
	char* cutPath = nullptr;
	char* newRoot = nullptr;
	bool display_src_info = true;
	bool display_file_info = true;
	bool display_dissassembly_info = true;
	bool display_trace_msg = false;
	bool display_function_info = true;
	bool display_call_return_info = true;
	bool display_branches_info = true;
	bool display_raw_message_info = false;
	bool enable_common_trace_format = false;
	bool enable_profiling_format = false;
	uint32_t analytics_detail_log_level = TySifiveProfilerAnalyticsLogLevel::P_DISABLE;
	TraceDqrProfiler::CATraceType cycle_accuracte_type = TraceDqrProfiler::CATRACE_NONE;
	TraceDqrProfiler::TraceType trace_type = TraceDqrProfiler::TRACETYPE_BTM;
	uint32_t numAddrBits = 0;
	uint32_t addrDispFlags = 0;
	uint32_t archSize = 0;
	uint32_t trace_msg_log_level = 1;
	uint32_t timestamp_counter_size_in_bits = 40;
	uint32_t timestamp_tick_clk_freq_hz = 0;
	uint32_t src_field_size_bits = 0;
	TraceDqrProfiler::ITCOptions itc_print_options = TraceDqrProfiler::ITC_OPT_NLS;
	uint32_t itc_print_channel = 0;
    uint16_t portno = 6000;
};

// Interface Class that provides access to the decoder related
// functionality
class SifiveProfilerInterface
{
private:
	char* tf_name = nullptr; // TraceProfiler File
	char* ef_name = nullptr; // ELF File
	char* od_name = nullptr; // Objdump Path
	char* sf_name = nullptr; // Simulator File
	char* ca_name = nullptr; // Cycle Accurate Count File
	char* pf_name = nullptr; // Properties File
	char* vf_name = nullptr; // VF File
	char* strip_flag = nullptr; // Flag to strip path
	char* cutPath = nullptr; // String to cut from path
	char* newRoot = nullptr; // String to add to path after cutting cutPath string

	// Decoder Output Info Enable/Disable Flags
	bool src_flag = true;	      // Output ProfilerSource Info
	bool file_flag = true;	      // Output File Info
	bool dasm_flag = true;	      // Output Dissassembly Info
	bool trace_flag = false; 	  // Output TraceProfiler Messages
	bool func_flag = true;   	  // Output Function Info
	bool showCallsReturns = true; // Output Call Return Info
	bool showBranches = true;     // Output Branch Info
	bool ctf_flag = false;		  // Output TraceProfiler as Common TraceProfiler Format (Limited Support)
	bool profile_flag = false;	  // Output PC value with timestamp only
	int numAddrBits = 0;		  // Display Address as n bits
	uint32_t addrDispFlags = 0;   // Address display formatting options
	TraceDqrProfiler::pathType pt = TraceDqrProfiler::PATH_TO_UNIX; // Display format for path info
	int analytics_detail = TySifiveProfilerAnalyticsLogLevel::P_DISABLE;	// Output ProfilerAnalytics
	int msgLevel = TySifiveProfilerMsgLogLevel::P_LEVEL_1;			    // Nexus TraceProfiler Msg logging level
    uint16_t m_port_no = 6000;

	// ITC Print Settings
	int itcPrintOpts = TraceDqrProfiler::ITC_OPT_NLS; // ITC Print Options
	int itcPrintChannel = 0;                  // ITC Print Channel

	// Timestamp Info Settings
	int tssize = 40;	// Timestamp counter size in bits
	uint32_t freq = 0;	// Timestamp clock frequency

	// Cycle Accurate count and trace type settings
	TraceDqrProfiler::CATraceType caType = TraceDqrProfiler::CATRACE_NONE;    // Cycle Accurate Count Type
	TraceDqrProfiler::TraceType traceType = TraceDqrProfiler::TRACETYPE_BTM;  // TraceProfiler Type

	// Arch Size and Src bit Settings
	int srcbits = 0;												// Size of ProfilerSource bit fields in bits (used for multicore tracing)
	int archSize = TySifiveProfilerTargetArchSize::P_ARCH_GET_FROM_ELF;	// Target Architecture Size (32/64)

	TraceProfiler* trace = nullptr;
	FILE* fp = nullptr;
    SocketIntf *m_client = nullptr;
    std::thread m_profiling_thread;
    uint64_t *mp_buffer = nullptr;
    uint32_t m_thread_idx = 0;

    virtual TySifiveTraceProfileError ProfilingThread();
    virtual void CleanUp();
    virtual void WaitforACK();
public:
	virtual TySifiveTraceProfileError Configure(const TProfilerConfig& config);
	virtual ~SifiveProfilerInterface() { CleanUp(); }
    virtual TySifiveTraceProfileError StartProfilingThread(uint32_t thread_idx);
    virtual TySifiveTraceProfileError PushTraceData(uint8_t *p_buff, const uint64_t &size);
    virtual void WaitForProfilerCompletion();
    virtual void SetEndOfData();
};

// Function pointer typedef
typedef SifiveProfilerInterface* (*fpGetSifiveProfilerInterface)();

// Exported C API function that returns the pointer to the Sifive decoder class instance
extern "C" DLLEXPORTEDAPI SifiveProfilerInterface * GetSifiveProfilerInterface();