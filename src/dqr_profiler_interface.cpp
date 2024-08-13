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
#include "logger.h"

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
    {
        std::lock_guard<std::mutex> m_abort_profiling_mutex_guard(m_abort_profiling_mutex);
        m_abort_profiling = false;
    }

    trace = new (std::nothrow) TraceProfiler(tf_name, ef_name, numAddrBits, addrDispFlags, srcbits, od_name, freq);
    if (trace == nullptr)
    {
        LOG_ERR("Could not create Trace Profiler instance");
        CleanUp();
        return SIFIVE_TRACE_PROFILER_MEM_CREATE_ERR;
    }

    if (trace->getStatus() != TraceDqrProfiler::DQERR_OK)
    {
        LOG_ERR("Trace Profiler Status Error");
        CleanUp();
        return SIFIVE_TRACE_PROFILER_TRACE_STATUS_ERROR;
    }

    trace->setTraceType(traceType);
    trace->setTSSize(tssize);
    trace->setPathType(pt);

    m_thread_idx = thread_idx;

#if TRANSFER_DATA_OVER_SOCKET == 1
    m_client = new SocketIntf(m_port_no);
    if (m_client == NULL)
    {
        LOG_ERR("Unable to create Socket Intf");
        return SIFIVE_TRACE_PROFILER_MEM_CREATE_ERR;
    }

    if (m_client->open() != 0)
    {
        LOG_ERR("Unable to Open Socket");
        return SIFIVE_TRACE_PROFILER_ERR;
    }

    // Send the Thread ID to UI
    PICP msg(32, PICP_TYPE_INTERNAL, PICP_CMD_BULK_WRITE);
    uint32_t thread_idx_nw_byte_order = htonl(thread_idx);
    msg.AttachData(reinterpret_cast<uint8_t *>(&thread_idx_nw_byte_order), sizeof(thread_idx_nw_byte_order));
    uint32_t max_size = 0;
    uint8_t *msg_packet = msg.GetPacketToSend(&max_size);
    m_client->write(msg_packet, max_size);

    if (!WaitforACK())
    {
        LOG_DEBUG("Error in ACK");
        return SIFIVE_TRACE_PROFILER_ACK_ERR;
    }
#endif

    mp_buffer = new uint64_t[PROFILE_THREAD_BUFFER_SIZE];
    if (mp_buffer == nullptr)
    {
        LOG_ERR("Unable to Create Socket Buffer");
        CleanUp();
        return SIFIVE_TRACE_PROFILER_MEM_CREATE_ERR;
    }

    try
    { 
        LOG_DEBUG("Creating Profiling Thread [%u]", m_thread_idx);
        m_profiling_thread = std::thread(&SifiveProfilerInterface::ProfilingThread, this);
    }
    catch (...)
    {
        LOG_ERR("Error in creating Profiling Thread [%u]", m_thread_idx);
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
    if (trace == NULL)
        return;
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
    if (trace == NULL)
        return SIFIVE_TRACE_PROFILER_MEM_CREATE_ERR;
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
    LOG_DEBUG("Joining Profiler Thread");
    if (m_profiling_thread.joinable())
        m_profiling_thread.join();

    CleanUp();
    LOG_DEBUG("Cleanup Complete");
}

/****************************************************************************
     Function: FlushDataOverSocket
     Engineer: Arjun Suresh
        Input: None
       Output: None
       return: TySifiveTraceProfileError
  Description: Writes the socket buffer data to the socket
  Date         Initials    Description
  26-Apr-2024  AS          Initial
****************************************************************************/
TySifiveTraceProfileError SifiveProfilerInterface::FlushDataOverSocket()
{
    // Create the Size Packet
    const uint32_t size_to_send = (m_curr_buff_idx * sizeof(mp_buffer[0]));
    PICP msg(32, PICP_TYPE_INTERNAL, PICP_CMD_BULK_WRITE);
    uint32_t size_to_send_nw_byte_order = htonl(size_to_send);
    msg.AttachData(reinterpret_cast<uint8_t*>(&size_to_send_nw_byte_order), sizeof(size_to_send_nw_byte_order));
    uint32_t max_size = 0;
    uint8_t* msg_packet = msg.GetPacketToSend(&max_size);

    LOG_DEBUG("Sending Size Packet");
    int32_t send_bytes = m_client->write(msg_packet, max_size);
    if (send_bytes <= 0)
    {
        LOG_DEBUG("Error in sending packet");
        return SIFIVE_TRACE_PROFILER_ERR;
    }

    if (!WaitforACK())
    {
        LOG_DEBUG("Error in ACK");
        return SIFIVE_TRACE_PROFILER_ACK_ERR;
    }

    LOG_DEBUG("Sending Data");
    send_bytes = m_client->write((uint8_t*)mp_buffer, size_to_send);
    if (send_bytes <= 0)
    {
        LOG_DEBUG("Error in sending packet");
        return SIFIVE_TRACE_PROFILER_ERR;
    }

    if (!WaitforACK())
    {
        LOG_DEBUG("Error in ACK");
        return SIFIVE_TRACE_PROFILER_ACK_ERR;
    }

    m_curr_buff_idx = 0;

    return SIFIVE_TRACE_PROFILER_OK;
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
    uint64_t total_bytes_sent = 0;
    uint64_t inst_cnt = 0;
    uint32_t mp_buffer_size_bytes = (PROFILE_THREAD_BUFFER_SIZE * sizeof(mp_buffer[0]));
    ProfilerInstruction *instInfo = nullptr;
    ProfilerNexusMessage *nm = nullptr;
    uint64_t flush_offset = m_ui_file_split_size_bytes;
    bool update_empty_file_ins_cnt = false;
    m_curr_buff_idx = 0;

#if WRITE_SEND_DATA_TO_FILE == 1
    std::string file_path = std::string(SEND_DATA_FILE_DUMP_PATH) + to_string(m_thread_idx) + ".txt";
    FILE *fp = fopen(file_path.c_str(), "wb");
#endif

    // Send the packet
    while (trace->NextInstruction(&instInfo, &nm, address_out) == TraceDqrProfiler::DQERR_OK)
    {
        {
            std::lock_guard<std::mutex> m_abort_profiling_mutex_guard(m_abort_profiling_mutex);
            if (m_abort_profiling)
            {
                LOG_ERR("Aborting Profiling");
                break;
            }
        }
        update_empty_file_ins_cnt = false;
        {
            // Check if flush trace data was called
            std::lock_guard<std::mutex> m_flush_data_offsets_guard(m_flush_data_offsets_mutex);
            if (m_flush_data_offsets.size() > 0)
            {
                // Get the offet at which flush was called
                uint64_t offset = m_flush_data_offsets.front();
                // If the profiler has exceeded decoding that offset
                if (nm->offset >= offset)
                {
                    // Remove the offset from the vector
                    m_flush_data_offsets.pop_front();
                    // Update the instruction count till this point to the file manager
                    // This is not an empty file so the second argument should be false
                    m_fp_cum_ins_cnt_callback(inst_cnt, false);
                    // Check if flush was called at the start even before any trace data
                    // was pushed. If so, there is no need to create an empty file and so
                    // we do not have to report the instruction count again to account for
                    // the creation of empty file at the end of a trace fetch or when flush
                    // trace data is called
                    if (offset != 0)
                    {
                        // If offset is not 0 then there will be an empty file
                        // created so we need to update the instruction count with 
                        // second argument as true. Note the instruction count will
                        // be the same, but we need to report it since an empty file
                        // will be created
                        m_fp_cum_ins_cnt_callback(inst_cnt, true);
                    }
                    // Update the flush offset to the next UI split file offset
                    // This is the expected flush offset, if again flush is called
                    // before reaching this offset then the above code will be executed
                    flush_offset = offset + m_ui_file_split_size_bytes;
                    // Set the current instruction count to 0
                    inst_cnt = 0;
                }
            }
        }
        // Normal Case when the profiling offset reaches the UI split file size offset
        if (nm->offset >= flush_offset)
        {
            // Update the instruction count to the file manager
            m_fp_cum_ins_cnt_callback(inst_cnt, false);
            // Flag to mark that we have only updated the instruction count for non-empty file
            update_empty_file_ins_cnt = true;
            // Set the next expected flush offset
            flush_offset += m_ui_file_split_size_bytes;
            // Set the current instruction count to 0
            inst_cnt = 0;
        }
        {
            std::lock_guard<std::mutex> m_buffer_data_mutex_guard(m_buffer_data_mutex);
            if (m_curr_buff_idx >= PROFILE_THREAD_BUFFER_SIZE)
            {
#if TRANSFER_DATA_OVER_SOCKET == 1
                if (SIFIVE_TRACE_PROFILER_OK != FlushDataOverSocket())
                {
                    break;
                }
#endif
            }
        }
        if (address_out != prev_addr)
        {
#if WRITE_SEND_DATA_TO_FILE == 1
            fprintf(fp, "%llx\n", address_out);
#endif
            {
                std::lock_guard<std::mutex> m_buffer_data_mutex_guard(m_buffer_data_mutex);
                mp_buffer[m_curr_buff_idx++] = htonll(address_out);
            }
            // Increment the instruction count
            inst_cnt++;
            prev_addr = address_out;
        }
            
    }

    {
        std::lock_guard<std::mutex> m_buffer_data_mutex_guard(m_buffer_data_mutex);
        if (m_curr_buff_idx > 0)
        {
#if TRANSFER_DATA_OVER_SOCKET == 1
            FlushDataOverSocket();

            // Update the instruction count to the file manager
            m_fp_cum_ins_cnt_callback(inst_cnt, false);
            // Update the instruction count to the file manager again with
            // second argument as flase to account for empty file
            m_fp_cum_ins_cnt_callback(inst_cnt, true);
            // Set intruction count to 0
            inst_cnt = 0;
#endif
        }
    }

    // In some cases if the total trace data is an exact multiple of UI split file size and
    // flush data or set end of data is called after profiling is complete, then the ins
    // cnt for empty file won't be updated. Check the flag and update the cnt if that is the
    // case. This is a rare scenario.
    if(update_empty_file_ins_cnt)
    {
        // In case the profiler has reached an exact multiple of UI split file size
        // and the flush was called or end data was called we need to report the 
        // instruction count for empty file
        m_fp_cum_ins_cnt_callback(inst_cnt, true);
        inst_cnt = 0;
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
    LOG_DEBUG("Exiting Profiling Thread");
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
bool SifiveProfilerInterface::WaitforACK()
{
    uint32_t maxSize = 64;
    uint8_t buff[64] = { 0 };

    LOG_DEBUG("Waiting For ACK");
    int32_t recvSize = m_client->read(buff, &maxSize);
    if (recvSize < static_cast<int>(PICP::GetMinimumSize()))
    {
        LOG_ERR("Socket Error");
        return false;
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
                    LOG_ERR("CRC Failed Expected [0xDEADBEEF], Received [%x]", retPacket.GetResponse());
                    return false;
                }
            }
        }
    }
    LOG_DEBUG("ACK Received");
    return true;
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
    LOG_DEBUG("Closing socket");
    if (m_client)
    {
        m_client->close();
        delete m_client;
        m_client = nullptr;
    }
#endif
    LOG_DEBUG("Deleting Socket Buffer");
    if (mp_buffer)
    {
        delete[] mp_buffer;
        mp_buffer = nullptr;
    }

    LOG_DEBUG("Trace Class Clenup");
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
void SifiveProfilerInterface::SetCumUIFileInsCntCallback(std::function<void(uint64_t cum_ins_cnt, bool is_empty_file_idx)> fp_callback)
{
    m_fp_cum_ins_cnt_callback = fp_callback;
}

/****************************************************************************
     Function: AddFlushDataOffset
     Engineer: Arjun Suresh
        Input: offset - The offset at which flush data was called
       Output: None
       return: None
  Description: Function to set the offset at which flush data was called.
               The profiler should call the callback with the instruction
               count uptil this point
  Date         Initials    Description
13-May-2022    AS          Initial
****************************************************************************/
void SifiveProfilerInterface::AddFlushDataOffset(const uint64_t offset)
{
    LOG_DEBUG("Adding Flush Data Offset %llu", offset);
    // Add the flush data offset to the vector
    {
        std::lock_guard<std::mutex> m_flush_data_offsets_guard(m_flush_data_offsets_mutex);
        m_flush_data_offsets.push_back(offset);
    }

    LOG_DEBUG("Flush data over socket");
    {
        std::lock_guard<std::mutex> m_buffer_data_mutex_guard(m_buffer_data_mutex);
        FlushDataOverSocket();
    }
}

/****************************************************************************
     Function: AbortProfiling
     Engineer: Arjun Suresh
        Input: None
       Output: None
       return: None
  Description: Sets the profiling abort flag
  Date         Initials    Description
13-May-2022    AS          Initial
****************************************************************************/
void SifiveProfilerInterface::AbortProfiling()
{
    LOG_DEBUG("Setting Abort Profiling Flag");
    {
        std::lock_guard<std::mutex> m_abort_profiling_mutex_guard(m_abort_profiling_mutex);
        m_abort_profiling = true;
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
    LOG_DEBUG("Creating Sifive Profiler Interface");
	return new SifiveProfilerInterface;
}

/****************************************************************************
     Function: DeleteSifiveProfilerInterface
     Engineer: Arjun Suresh
        Input: None
       Output: None
       return: None
  Description: Function to delete the profiler interface class object
               Memory allocated within a DLL should always be deleted
               within it.
  Date         Initials    Description
2-Nov-2022     AS          Initial
****************************************************************************/
void DeleteSifiveProfilerInterface(SifiveProfilerInterface** p_sifive_profiler_intf)
{
    LOG_DEBUG("Deleting Sifive Profiler Interface");
    if (*p_sifive_profiler_intf)
    {
        delete* p_sifive_profiler_intf;
        *p_sifive_profiler_intf = NULL;
    }
}
