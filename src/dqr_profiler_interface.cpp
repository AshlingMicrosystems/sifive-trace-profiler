/******************************************************************************
	   Module: dqr_interface.cpp
	 Engineer: Arjun Suresh
  Description: Implementation for Sifive TraceProfiler Decoder Interface
  Date         Initials    Description
  26-Apr-2024  AS          Initial
******************************************************************************/
#include <iostream>
#include <iomanip>
#include <fstream>
#include <cstring>
#include <cstdint>
#include <thread>
#include <string>
#ifndef __linux__
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif
#include "SocketIntf.h"
#include "dqr_profiler_interface.h"
#include "PacketFormat.h"

#ifdef __linux__

#define TYP_INIT 0 
#define TYP_SMLE 1 
#define TYP_BIGE 2 

uint64_t htonll(uint64_t src);

/****************************************************************************
     Function: htonll
     Engineer: Arjun Suresh
        Input: src - Host byte order value
       Output: None
       return: uint64_t - Value in host byte order
  Description: Converts host to network byte order for 64bit variables
  Date         Initials    Description
  26-Apr-2024  AS          Initial
****************************************************************************/
uint64_t htonll(uint64_t src)
{
    static int typ = TYP_INIT;
    unsigned char c;
    union {
        unsigned long long ull;
        unsigned char c[8];
    } x;
    if (typ == TYP_INIT)
    {
        x.ull = 0x01;
        typ = (x.c[7] == 0x01ULL) ? TYP_BIGE : TYP_SMLE;
    }
    if (typ == TYP_BIGE)
        return src;
    x.ull = src;
    c = x.c[0]; x.c[0] = x.c[7]; x.c[7] = c;
    c = x.c[1]; x.c[1] = x.c[6]; x.c[6] = c;
    c = x.c[2]; x.c[2] = x.c[5]; x.c[5] = c;
    c = x.c[3]; x.c[3] = x.c[4]; x.c[4] = c;
    return x.ull;
}
#endif

/****************************************************************************
     Function: StartProfilingThread
     Engineer: Arjun Suresh
        Input: thread_idx - Index of the thread. There can be multiple threads 
                            to parallel process data. Thread idx is required
                            by the server side to reconstruct the data in
                            correct order
       Output: None
       return: TySifiveTraceProfileError
  Description: Starts the profiling thread to process the trace data to generate
               the PC samples
  Date         Initials    Description
  26-Apr-2024  AS          Initial
****************************************************************************/
TySifiveTraceProfileError SifiveProfilerInterface::StartProfilingThread(uint32_t thread_idx)
{
    trace = new (std::nothrow) TraceProfiler(tf_name, ef_name, numAddrBits, addrDispFlags, srcbits, od_name, freq);
    if (trace == nullptr)
    {
        printf("Error: Could not create TraceProfiler object\n");
        CleanUp();
        return SIFIVE_TRACE_PROFILER_MEM_CREATE_ERR;
    }

    if (trace->getStatus() != TraceDqrProfiler::DQERR_OK)
    {
        printf("Error: new TraceProfiler(%s,%s) failed\n", tf_name, ef_name);
        CleanUp();
        return SIFIVE_TRACE_PROFILER_TRACE_STATUS_ERROR;
    }

    trace->setTraceType(traceType);
    trace->setTSSize(tssize);
    trace->setPathType(pt);

    m_thread_idx = thread_idx;

#if TRANSFER_DATA_OVER_SOCKET == 1
    m_client = new SocketIntf(m_port_no);
    if (m_client->open() != 0)
        return SIFIVE_TRACE_PROFILER_ERR;
    // Send the packet
    PICP msg(32, PICP_TYPE_INTERNAL, PICP_CMD_BULK_WRITE);
    uint32_t temp = htonl(thread_idx);
    msg.AttachData(reinterpret_cast<uint8_t *>(&temp), sizeof(temp));
    uint32_t maxSize = 0;
    uint8_t *msgPacket = msg.GetPacketToSend(&maxSize);
    m_client->write(msgPacket, maxSize);
    WaitforACK();
#endif

    mp_buffer = new uint64_t[PROFILE_THREAD_BUFFER_SIZE];
    if (mp_buffer == nullptr)
    {
        CleanUp();
        return SIFIVE_TRACE_PROFILER_MEM_CREATE_ERR;
    }

    try
    { 
        m_profiling_thread = std::thread(&SifiveProfilerInterface::ProfilingThread, this);
    }
    catch (...)
    {
        return SIFIVE_TRACE_PROFILER_ERR;
    }

    return SIFIVE_TRACE_PROFILER_OK;
}

/****************************************************************************
     Function: SetEndOfData
     Engineer: Arjun Suresh
        Input: None
       Output: None
       return: None
  Description: Marks the end of trace data. If this is not called the profiling
               thread will not exit as it will be waiting for more data.
               Expected to be called at the end of a trace fetch.
  Date         Initials    Description
  26-Apr-2024  AS          Initial
****************************************************************************/
void SifiveProfilerInterface::SetEndOfData()
{
    trace->SetEndOfData();
}

/****************************************************************************
     Function: PushTraceData
     Engineer: Arjun Suresh
        Input: p_buff - Pointer to buffer that contains the trace data
               size - Size in bytes of the trace data
       Output: None
       return: TySifiveTraceProfileError
  Description: Pushes the trace data for processing
  Date         Initials    Description
  26-Apr-2024  AS          Initial
****************************************************************************/
TySifiveTraceProfileError SifiveProfilerInterface::PushTraceData(uint8_t *p_buff, const uint64_t& size)
{
    return (trace->PushTraceData(p_buff, size) == TraceDqrProfiler::DQERR_OK) ? SIFIVE_TRACE_PROFILER_OK : SIFIVE_TRACE_PROFILER_ERR;
}

/****************************************************************************
     Function: WaitForProfilerCompletion
     Engineer: Arjun Suresh
        Input: None
       Output: None
       return: None
  Description: Waits till the profilng thread completes. For each thread 
               there will be a seperate profiler interface instance, so
               thread idx is not required here.
  Date         Initials    Description
  26-Apr-2024  AS          Initial
****************************************************************************/
void SifiveProfilerInterface::WaitForProfilerCompletion()
{
    if (m_profiling_thread.joinable())
        m_profiling_thread.join();
    CleanUp();
}

/****************************************************************************
     Function: ProfilingThread
     Engineer: Arjun Suresh
        Input: None
       Output: None
       return: TySifiveTraceProfileError
  Description: The profiling thread functions that generates the PC sample
               data and send the data over socket.
  Date         Initials    Description
  26-Apr-2024  AS          Initial
****************************************************************************/
TySifiveTraceProfileError SifiveProfilerInterface::ProfilingThread()
{
    uint64_t address_out = 0;
    uint64_t prev_addr = 0;
    uint64_t idx = 0;
    uint64_t total_bytes_sent = 0;
    uint64_t inst_cnt = 0;
    uint32_t mp_buffer_size_bytes = (PROFILE_THREAD_BUFFER_SIZE * sizeof(mp_buffer[0]));
    ProfilerInstruction *instInfo = nullptr;
    ProfilerNexusMessage *nm = nullptr;
    uint64_t flush_offset = m_ui_file_split_size_bytes;

#if WRITE_SEND_DATA_TO_FILE == 1
    std::string file_path = std::string(SEND_DATA_FILE_DUMP_PATH) + to_string(m_thread_idx) + ".txt";
    FILE *fp = fopen(file_path.c_str(), "wb");
#endif

    // Send the packet
    while (trace->NextInstruction(&instInfo, &nm, address_out) == TraceDqrProfiler::DQERR_OK)
    {
        {
            std::lock_guard<std::mutex> m_flush_data_offsets_guard(m_flush_data_offsets_mutex);
            if (m_flush_data_offsets.size() > 0)
            {
                uint64_t offset = m_flush_data_offsets.front(); 
                if (nm->offset >= offset)
                {
                    m_flush_data_offsets.pop_front();
                    m_fp_cum_ins_cnt_callback(inst_cnt, false);
                    if(offset != 0)
                        m_fp_cum_ins_cnt_callback(inst_cnt, true);
                    flush_offset = offset + m_ui_file_split_size_bytes;
                    inst_cnt = 0;
                }
            }
        }
        if (nm->offset >= flush_offset)
        {
           // printf("\nFile %d Instructions %u", block_no, cum_inst_cnt);
            m_fp_cum_ins_cnt_callback(inst_cnt, false);
            //m_cum_inst_cnt.push_back(cum_inst_cnt);
            flush_offset += m_ui_file_split_size_bytes;
            inst_cnt = 0;
        }
        if (idx >= PROFILE_THREAD_BUFFER_SIZE)
        {
#if TRANSFER_DATA_OVER_SOCKET == 1
            // Send the packet
            PICP msg(32, PICP_TYPE_INTERNAL, PICP_CMD_BULK_WRITE);
            uint32_t temp = htonl(mp_buffer_size_bytes);
            msg.AttachData(reinterpret_cast<uint8_t *>(&temp), sizeof(temp));
            uint32_t maxSize = 0;
            uint8_t *msgPacket = msg.GetPacketToSend(&maxSize);

           // printf("\nSending Header Thread ID %d", m_thread_idx);
            total_bytes_sent += m_client->write(msgPacket, maxSize);

           // printf("\nWaiting for Header ACK Thread ID %d", m_thread_idx);
            WaitforACK();
           // printf("\nReceived Header ACK Thread ID %d", m_thread_idx);

            //printf("\nSending Data Thread ID %d", m_thread_idx);
            total_bytes_sent += m_client->write((uint8_t *)mp_buffer, mp_buffer_size_bytes);

           // printf("\nWaiting for Data ACK Thread ID %d", m_thread_idx);
            WaitforACK();
           // printf("\nReceived Data ACK Thread ID %d", m_thread_idx);
            //printf("+");
#endif
            idx = 0;
        }
        if (address_out != prev_addr)
        {
#if WRITE_SEND_DATA_TO_FILE == 1
            fprintf(fp, "%llx\n", address_out);
#endif
            mp_buffer[idx++] = htonll(address_out);
            inst_cnt++;
            prev_addr = address_out;
        }
    }

    if (idx > 0)
    {
#if TRANSFER_DATA_OVER_SOCKET == 1
        // Send the packet
        uint32_t size_to_send = (idx * sizeof(mp_buffer[0]));
        PICP msg(32, PICP_TYPE_INTERNAL, PICP_CMD_BULK_WRITE);
        uint32_t temp = htonl(size_to_send);
        msg.AttachData(reinterpret_cast<uint8_t *>(&temp), sizeof(temp));
        uint32_t maxSize = 0;
        uint8_t *msgPacket = msg.GetPacketToSend(&maxSize);
        //printf("\n-Sending Header Thread ID %d", m_thread_idx);
        total_bytes_sent += m_client->write(msgPacket, maxSize);

       // printf("\n-Waiting for Header ACK Thread ID %d", m_thread_idx);
        WaitforACK();
        //printf("\n-Received Header ACK Thread ID %d", m_thread_idx);


       // printf("\n-Sending Data Thread ID %d", m_thread_idx);
       total_bytes_sent += m_client->write((uint8_t *) mp_buffer, size_to_send);
       printf("\n-Total Bytes Sent : %llu", total_bytes_sent);

       // printf("\n-Waiting for Data ACK Thread ID %d", m_thread_idx);
        WaitforACK();
       // printf("\n-Received Data ACK Thread ID %d", m_thread_idx);

        //printf("\nFile %d Instructions %u", block_no, cum_inst_cnt);
        m_fp_cum_ins_cnt_callback(inst_cnt, false);
        m_fp_cum_ins_cnt_callback(inst_cnt, true);
        inst_cnt = 0;
        //block_no++;
#endif
    }

#if WRITE_SEND_DATA_TO_FILE == 1
    fclose(fp);
#endif

#if TRANSFER_DATA_OVER_SOCKET == 1
    if (m_client)
    {
        m_client->close();
        delete m_client;
        m_client = nullptr;
    }
#endif
    return SIFIVE_TRACE_PROFILER_OK;
}

/****************************************************************************
     Function: WaitforACK
     Engineer: Arjun Suresh
        Input: None
       Output: None
       return: None
  Description: Waits till the UI sends an ACK packet
  Date         Initials    Description
  26-Apr-2024  AS          Initial
****************************************************************************/
void SifiveProfilerInterface::WaitforACK()
{
    uint32_t maxSize = 64;
    uint8_t buff[64] = { 0 };
    int32_t recvSize = m_client->read(buff, &maxSize);
    if (recvSize < static_cast<int>(PICP::GetMinimumSize()))
    {
        printf("\nSocket Error");
    }
    else
    {
        PICP retPacket(buff, maxSize);
        if (retPacket.Validate())
        {
            if (PICP_TYPE_RESPONSE == retPacket.GetType())
            {
                if (retPacket.GetResponse() != 0xDEADBEEF)
                {
                    printf("\nCRC Failed");
                }
            }
        }
    }
}

/****************************************************************************
	 Function: CleanUp
	 Engineer: Arjun Suresh
		Input: None
	   Output: None
	   return: None
  Description: CleanUp Function
  Date         Initials    Description
2-Nov-2022     AS          Initial
****************************************************************************/
void SifiveProfilerInterface::CleanUp()
{
#if TRANSFER_DATA_OVER_SOCKET == 1
    if (m_client)
    {
        m_client->close();
        delete m_client;
        m_client = nullptr;
    }
#endif
    if (mp_buffer)
    {
        delete[] mp_buffer;
        mp_buffer = nullptr;
    }
	if (fp != nullptr)
	{
		fclose(fp);
		fp = nullptr;
	}
	if (trace != nullptr) {
		trace->cleanUp();

		delete trace;
		trace = nullptr;
	}
}

/****************************************************************************
	 Function: Configure
	 Engineer: Arjun Suresh
		Input: config - Decoder config structure
	   Output: None
	   return: TySifiveTraceProfileError
  Description: Function to configure the decoder
  Date         Initials    Description
2-Nov-2022     AS          Initial
****************************************************************************/
TySifiveTraceProfileError SifiveProfilerInterface::Configure(const TProfilerConfig& config)
{
	tf_name = config.trace_filepath;
	ef_name = config.elf_filepath;
	od_name = config.objdump_path;
	src_flag = config.display_src_info;
	file_flag = config.display_file_info;
	dasm_flag = config.display_dissassembly_info;
	trace_flag = config.display_trace_msg;
	func_flag = config.display_function_info;
	showCallsReturns = config.display_call_return_info;
	showBranches = config.display_branches_info;
	profiler_globalDebugFlag = config.display_raw_message_info;
	ctf_flag = config.enable_common_trace_format;
	profile_flag = config.enable_profiling_format;
	analytics_detail = config.analytics_detail_log_level;
	caType = config.cycle_accuracte_type;
	traceType = config.trace_type;
	numAddrBits = config.numAddrBits;
	addrDispFlags = config.addrDispFlags;
	archSize = config.archSize;
	msgLevel = config.trace_msg_log_level;
	tssize = config.timestamp_counter_size_in_bits;
	freq = config.timestamp_tick_clk_freq_hz;
	srcbits = config.src_field_size_bits;
	itcPrintOpts = config.itc_print_options;
	itcPrintChannel = config.itc_print_channel;
    m_port_no = config.portno;
    m_ui_file_split_size_bytes = config.ui_file_split_size_bytes;

	return SIFIVE_TRACE_PROFILER_OK;
}

/****************************************************************************
     Function: SetCumUIFileInsCntCallback
     Engineer: Arjun Suresh
        Input: fp_callback - Callback to the function that will be called
                             with the instruction count in a UI file
       Output: None
       return: None
  Description: Function to set the file instruction count callback
  Date         Initials    Description
13-May-2022    AS          Initial
****************************************************************************/
void SifiveProfilerInterface::SetCumUIFileInsCntCallback(std::function<void(uint64_t cum_ins_cnt, bool is_empty_file_offset)> fp_callback)
{
    m_fp_cum_ins_cnt_callback = fp_callback;
}

void SifiveProfilerInterface::AddFlushDataOffset(const uint64_t offset)
{
    // Initialize the fetch status info
    {
        std::lock_guard<std::mutex> m_flush_data_offsets_guard(m_flush_data_offsets_mutex);
        m_flush_data_offsets.push_back(offset);
    }
}

/****************************************************************************
	 Function: GetSifiveProfilerInterface
	 Engineer: Arjun Suresh
		Input: None
	   Output: None
	   return: The pointer to the interface class object
  Description: Function that creates the interface class object
  Date         Initials    Description
2-Nov-2022     AS          Initial
****************************************************************************/
SifiveProfilerInterface* GetSifiveProfilerInterface()
{
	return new SifiveProfilerInterface;
}

