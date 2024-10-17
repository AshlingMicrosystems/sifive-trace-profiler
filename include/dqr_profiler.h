/* Copyright 2022 SiFive, Inc */
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef DQR_PROFILER_HPP_
#define DQR_PROFILER_HPP_

// PUBLIC definitions

#include <iostream>
#include <iomanip>
#include <fstream>
#include <cstring>
#include <cstdint>
#include <cassert>
#include <unordered_map>
#include <mutex>
#include <functional>
#include <atomic>

#define DQR_PROFILER_MAXCORES	16

#define PROFILER_DEFAULTOBJDUMPNAME	"riscv64-unknown-elf-objdump"

extern int profiler_globalDebugFlag;
extern const char* const DQR_PROFILER_VERSION;

class PROFILER_CTF {
public:
	struct trace_packet_header {
		uint32_t magic;
		uint8_t uuid[16];				// optional?
		uint32_t stream_id;
		uint64_t stream_instance_id;	// optional?
	};

	enum event_type {
		event_tracePoint = 0,
		event_funcEntry = 1,
		event_funcExit = 2,
		event_stateDumpStart = 3,
		event_stateDumpBinInfo = 4,
		event_stateDumpEnd = 7,
		event_extended = 0xffff
	};

	// metadata file needs to have an env struct!!

	typedef uint64_t uint64_clock_monotonic_t;

	struct stream_packet_context {
		uint64_clock_monotonic_t timestamp_begin;
		uint64_clock_monotonic_t timestamp_end;
		uint64_t content_size;
		uint64_t packet_size;
		uint64_t packet_seq_num;
		uint64_t events_discarded;	// or unsigned long?
		uint32_t cpu_id;
	};

	struct stream_packet_header_extended {
		uint16_t id;	// this should be 0xffff for extended headers
		uint32_t extended_id;
		uint64_clock_monotonic_t extended_timestamp;
	};

	struct stream_event_context {
		uint32_t _vpid;
		uint32_t _vtid;
		uint8_t  _procname[17];
	};

	struct stream_event_callret {
		uint64_t src;
		uint64_t dst;
	};

	enum event_t {
		et_controlIndex,
		et_extTriggerIndex,
		et_callRetIndex,
		et_exceptionIndex,
		et_interruptIndex,
		et_mContextIndex,
		et_sContextIndex,
		et_watchpointIndex,
		et_periodicIndex,
		et_numEventTypes
	};
};

class TraceDqrProfiler 
{
public:
	typedef uint32_t RV_INST;

	typedef uint64_t ADDRESS;
	typedef uint64_t TIMESTAMP;
	typedef int RCode;

	enum {
		TRACE_HAVE_INSTINFO = 0x01,
		TRACE_HAVE_SRCINFO = 0x02,
		TRACE_HAVE_MSGINFO = 0x04,
		TRACE_HAVE_ITCPRINTINFO = 0x08,
	};

	typedef enum {
		MSEO_NORMAL = 0x00,
		MSEO_VAR_END = 0x01,
		MSEO_END = 0x03,
	} MSEO;

	typedef enum {
		DQERR_OK = 0,		// no error
		DQERR_OPEN = 1,		// can't open file
		DQERR_EOF = 2,		// at file eof
		DQERR_EOM = 3,		// at file eom
		DQERR_BM = 4,		// bad message (mallformed)
		DQERR_ERR = 5,		// general error
		DQERR_DONE = 6,		// done with trace message
	} DQErr;

	typedef enum {
		TCODE_DEBUG_STATUS = 0,
		TCODE_DEVICE_ID = 1,
		TCODE_OWNERSHIP_TRACE = 2,
		TCODE_DIRECT_BRANCH = 3,
		TCODE_INDIRECT_BRANCH = 4,
		TCODE_DATA_WRITE = 5,
		TCODE_DATA_READ = 6,
		TCODE_DATA_ACQUISITION = 7,
		TCODE_ERROR = 8,
		TCODE_SYNC = 9,
		TCODE_CORRECTION = 10,
		TCODE_DIRECT_BRANCH_WS = 11,
		TCODE_INDIRECT_BRANCH_WS = 12,
		TCODE_DATA_WRITE_WS = 13,
		TCODE_DATA_READ_WS = 14,
		TCODE_WATCHPOINT = 15,
		TCODE_OUTPUT_PORTREPLACEMENT = 20,
		TCODE_INPUT_PORTREPLACEMENT = 21,
		TCODE_AUXACCESS_READ = 22,
		TCODE_AUXACCESS_WRITE = 23,
		TCODE_AUXACCESS_READNEXT = 24,
		TCODE_AUXACCESS_WRITENEXT = 25,
		TCODE_AUXACCESS_RESPONSE = 26,
		TCODE_RESOURCEFULL = 27,
		TCODE_INDIRECTBRANCHHISTORY = 28,
		TCODE_INDIRECTBRANCHHISTORY_WS = 29,
		TCODE_REPEATBRANCH = 30,
		TCODE_REPEATINSTRUCTION = 31,
		TCODE_REPEATINSTRUCTION_WS = 32,
		TCODE_CORRELATION = 33,
		TCODE_INCIRCUITTRACE = 34,
		TCODE_INCIRCUITTRACE_WS = 35,

		TCODE_UNDEFINED
	} TCode;

	typedef enum {
		EVCODE_ENTERDEBUG = 0,
		EVCODE_TRACEDISABLE = 4,
		EVCODE_ENTERRESET = 8
	} EVCode;

	typedef enum {
		SYNC_EVTI = 0,
		SYNC_EXIT_RESET = 1,
		SYNC_T_CNT = 2,
		SYNC_EXIT_DEBUG = 3,
		SYNC_I_CNT_OVERFLOW = 4,
		SYNC_TRACE_ENABLE = 5,
		SYNC_WATCHPINT = 6,
		SYNC_FIFO_OVERRUN = 7,
		SYNC_EXIT_POWERDOWN = 9,
		SYNC_MESSAGE_CONTENTION = 11,
		SYNC_PC_SAMPLE = 15,
		SYNC_NONE
	} SyncReason;

	typedef enum {
		ICT_CONTROL = 0,
		ICT_EXT_TRIG = 8,
		ICT_INFERABLECALL = 9,
		ICT_EXCEPTION = 10,
		ICT_INTERRUPT = 11,
		ICT_CONTEXT = 13,
		ICT_WATCHPOINT = 14,
		ICT_PC_SAMPLE = 15,
		ICT_NONE
	} ICTReason;

	typedef enum {
		ICT_CONTROL_NONE = 0,
		ICT_CONTROL_TRACE_ON = 2,
		ICT_CONTROL_TRACE_OFF = 3,
		ICT_CONTROL_EXIT_DEBUG = 4,
		ICT_CONTROL_ENTER_DEBUG = 5,
		ICT_CONTROL_EXIT_RESET = 6,
		ICT_CONTROL_ENTER_RESET = 8,
	} ICTControl;

	typedef enum {
		ITC_OPT_NONE = 0,
		ITC_OPT_PRINT = 1,
		ITC_OPT_NLS = 2,
	} ITCOptions;

	typedef enum {
		BTYPE_INDIRECT = 0,
		BTYPE_EXCEPTION = 1,
		BTYPE_HARDWARE = 2,

		BTYPE_UNDEFINED
	} BType;

	typedef enum {
		ADDRDISP_WIDTHAUTO = 1,
		ADDRDISP_SEP = 2,
	} AddrDisp;

	enum InstType {
		INST_UNKNOWN = 0,
		INST_JAL,
		INST_JALR,
		INST_BEQ,
		INST_BNE,
		INST_BLT,
		INST_BGE,
		INST_BLTU,
		INST_BGEU,
		INST_C_J,
		INST_C_JAL,
		INST_C_JR,
		INST_C_JALR,
		INST_C_BEQZ,
		INST_C_BNEZ,
		INST_EBREAK,
		INST_C_EBREAK,
		INST_ECALL,
		INST_MRET,
		INST_SRET,
		INST_URET,
		// the following intTypes are generic and do not specify an actual instruction
		INST_SCALER,
		INST_VECT_ARITH,
		INST_VECT_LOAD,
		INST_VECT_STORE,
		INST_VECT_AMO,
		INST_VECT_AMO_WW,
		INST_VECT_CONFIG,
	};

	enum CountType {
		COUNTTYPE_none,
		COUNTTYPE_i_cnt,
		COUNTTYPE_history,
		COUNTTYPE_taken,
		COUNTTYPE_notTaken
	};

	enum Reg {
		REG_0 = 0,
		REG_1 = 1,
		REG_2 = 2,
		REG_3 = 3,
		REG_4 = 4,
		REG_5 = 5,
		REG_6 = 6,
		REG_7 = 7,
		REG_8 = 8,
		REG_9 = 9,
		REG_10 = 10,
		REG_11 = 11,
		REG_12 = 12,
		REG_13 = 13,
		REG_14 = 14,
		REG_15 = 15,
		REG_16 = 16,
		REG_17 = 17,
		REG_18 = 18,
		REG_19 = 19,
		REG_20 = 20,
		REG_21 = 21,
		REG_22 = 22,
		REG_23 = 23,
		REG_24 = 24,
		REG_25 = 25,
		REG_26 = 26,
		REG_27 = 27,
		REG_28 = 28,
		REG_29 = 29,
		REG_30 = 30,
		REG_31 = 31,
		REG_unknown,
	};

	enum TraceType {
		TRACETYPE_unknown = 0,
		TRACETYPE_BTM,
		TRACETYPE_HTM,
		TRACETYPE_VCD,
	};

	enum CallReturnFlag {
		isNone = 0,
		isCall = (1 << 0),
		isReturn = (1 << 1),
		isSwap = (1 << 2),
		isInterrupt = (1 << 3),
		isException = (1 << 4),
		isExceptionReturn = (1 << 5),
	};

	enum BranchFlags {
		BRFLAG_none = 0,
		BRFLAG_unknown,
		BRFLAG_taken,
		BRFLAG_notTaken,
	};

	enum tsType {
		TS_full,
		TS_rel,
	};

	enum pathType {
		PATH_RAW,
		PATH_TO_WINDOWS,
		PATH_TO_UNIX,
	};

	enum CATraceType {
		CATRACE_NONE,
		CATRACE_INSTRUCTION,
		CATRACE_VECTOR,
	};

	enum CAVectorTraceFlags {
		CAVFLAG_V0 = 0x20,
		CAVFLAG_V1 = 0x10,
		CAVFLAG_VISTART = 0x08,
		CAVFLAG_VIARITH = 0x04,
		CAVFLAG_VISTORE = 0x02,
		CAVFLAG_VILOAD = 0x01,
	};

	enum CATraceFlags {
		CAFLAG_NONE = 0x00,
		CAFLAG_PIPE0 = 0x01,
		CAFLAG_PIPE1 = 0x02,
		CAFLAG_SCALER = 0x04,
		CAFLAG_VSTART = 0x08,
		CAFLAG_VSTORE = 0x10,
		CAFLAG_VLOAD = 0x20,
		CAFLAG_VARITH = 0x40,
	};

	struct nlStrings {
		int nf;
		int signedMask;
		char* format;
	};
};

// class ProfilerInstruction: work with an instruction
class ProfilerInstruction {
public:
	void addressToText(char* dst, size_t len, int labelLevel);
	std::string addressToString(int labelLevel);
	std::string addressLabelToString();
	void instructionToText(char* dst, size_t len, int labelLevel);
	std::string instructionToString(int labelLevel);

	static int        addrSize;
	static uint32_t   addrDispFlags;
	static int        addrPrintWidth;

	uint8_t           coreId;

	int               CRFlag;
	int               brFlags; // this is an int instead of TraceDqrProfiler::BancheFlags because it is easier to work with in java

	TraceDqrProfiler::ADDRESS address;
	int               instSize;
	TraceDqrProfiler::RV_INST instruction;
	char* instructionText;

#ifdef SWIG
	% immutable		addressLabel;
#endif // SWIG
	const char* addressLabel;
	int               addressLabelOffset;

	TraceDqrProfiler::TIMESTAMP timestamp;

	uint32_t            caFlags;
	uint32_t            pipeCycles;
	uint32_t            VIStartCycles;
	uint32_t            VIFinishCycles;

	uint8_t             qDepth;
	uint8_t             arithInProcess;
	uint8_t             loadInProcess;
	uint8_t             storeInProcess;

	uint32_t r0Val;
	uint32_t r1Val;
	uint32_t wVal;
};

// class ProfilerSource: Helper class for source code information for an address

class ProfilerSource {
public:
	std::string  sourceFileToString();
	std::string  sourceFileToString(std::string path);
	std::string  sourceLineToString();
	std::string  sourceFunctionToString();
	uint8_t      coreId;
#ifdef SWIG
	% immutable sourceFile;
	% immutable sourceFunction;
	% immutable sourceLine;
#endif // SWIG
	const char* sourceFile;
	int          cutPathIndex;
	const char* sourceFunction;
	const char* sourceLine;
	unsigned int sourceLineNum;

private:
	const char* stripPath(const char* path);
};


class ProfilerNexusMessage {
public:
	ProfilerNexusMessage();
	bool processITCPrintData(class ITCPrint* itcPrint);
	void messageToText(char* dst, size_t dst_len, int level);
	std::string messageToString(int detailLevel);
	double seconds();

	void dumpRawMessage();
	void dump();

	static uint32_t targetFrequency;

	int                 msgNum;
	TraceDqrProfiler::TCode     tcode;
	bool       	        haveTimestamp;
	TraceDqrProfiler::TIMESTAMP timestamp;
	TraceDqrProfiler::ADDRESS   currentAddress;
	TraceDqrProfiler::TIMESTAMP time;

	uint8_t             coreId;

	union {
		struct {
			int	i_cnt;
		} directBranch;
		struct {
			int          i_cnt;
			TraceDqrProfiler::ADDRESS u_addr;
			TraceDqrProfiler::BType   b_type;
		} indirectBranch;
		struct {
			int             i_cnt;
			TraceDqrProfiler::ADDRESS    f_addr;
			TraceDqrProfiler::SyncReason sync;
		} directBranchWS;
		struct {
			int             i_cnt;
			TraceDqrProfiler::ADDRESS    f_addr;
			TraceDqrProfiler::BType      b_type;
			TraceDqrProfiler::SyncReason sync;
		} indirectBranchWS;
		struct {
			int             i_cnt;
			TraceDqrProfiler::ADDRESS    u_addr;
			TraceDqrProfiler::BType      b_type;
			uint64_t		history;
		} indirectHistory;
		struct {
			int             i_cnt;
			TraceDqrProfiler::ADDRESS    f_addr;
			TraceDqrProfiler::BType      b_type;
			uint64_t		history;
			TraceDqrProfiler::SyncReason sync;
		} indirectHistoryWS;
		struct {
			TraceDqrProfiler::RCode rCode;
			union {
				int i_cnt;
				uint64_t history;
				uint32_t takenCount;
				uint32_t notTakenCount;
			};
		} resourceFull;
		struct {
			int             i_cnt;
			TraceDqrProfiler::ADDRESS    f_addr;
			TraceDqrProfiler::SyncReason sync;
		} sync;
		struct {
			uint8_t etype;
		} error;
		struct {
			uint64_t history;
			int     i_cnt;
			uint8_t cdf;
			uint8_t evcode;
		} correlation;
		struct {
			uint32_t data;
			uint32_t addr;
		} auxAccessWrite;
		struct {
			uint32_t idTag;
			uint32_t data;
		} dataAcquisition;
		struct {
			uint32_t process;
		} ownership;
		struct {
			TraceDqrProfiler::ICTReason cksrc;
			uint8_t ckdf;
			TraceDqrProfiler::ADDRESS ckdata[2];
		} ict;
		struct {
			TraceDqrProfiler::ICTReason cksrc;
			uint8_t ckdf;
			TraceDqrProfiler::ADDRESS ckdata[2];
		} ictWS;
	};
	uint32_t size_message = 0;
	uint32_t offset = 0;
	uint8_t  rawData[32];

	int getI_Cnt();
	TraceDqrProfiler::ADDRESS    getU_Addr();
	TraceDqrProfiler::ADDRESS    getF_Addr();
	TraceDqrProfiler::ADDRESS    getNextAddr() { return currentAddress; };
	TraceDqrProfiler::ADDRESS    getICTCallReturnTarget();
	TraceDqrProfiler::BType      getB_Type();
	TraceDqrProfiler::SyncReason getSyncReason();
	uint8_t  getEType();
	uint8_t  getCKDF();
	TraceDqrProfiler::ICTReason  getCKSRC();
	TraceDqrProfiler::ADDRESS getCKData(int i);
	uint8_t  getCDF();
	uint8_t  getEVCode();
	uint32_t getData();
	uint32_t getAddr();
	uint32_t getIdTag();
	uint32_t getProcess();
	uint32_t getRCode();
	uint64_t getRData();
	uint64_t getHistory();
};

class ProfilerAnalytics {
public:
	ProfilerAnalytics();
	~ProfilerAnalytics();

	TraceDqrProfiler::DQErr updateTraceInfo(ProfilerNexusMessage& nm, uint32_t bits, uint32_t meso_bits, uint32_t ts_bits, uint32_t addr_bits);
	TraceDqrProfiler::DQErr updateInstructionInfo(uint32_t core_id, uint32_t inst, int instSize, int crFlags, TraceDqrProfiler::BranchFlags brFlags);
	int currentTraceMsgNum() { return num_trace_msgs_all_cores; }
	void setSrcBits(int sbits) { srcBits = sbits; }
	void toText(char* dst, int dst_len, int detailLevel);
	std::string toString(int detailLevel);

private:
	TraceDqrProfiler::DQErr status;
#ifdef DO_TIMES
	class Timer* etimer;
#endif // DO_TIMES

	uint32_t cores;

	int srcBits;

	uint32_t num_trace_msgs_all_cores;
	uint32_t num_trace_mseo_bits_all_cores;
	uint32_t num_trace_bits_all_cores;
	uint32_t num_trace_bits_all_cores_max;
	uint32_t num_trace_bits_all_cores_min;

	uint32_t num_inst_all_cores;
	uint32_t num_inst16_all_cores;
	uint32_t num_inst32_all_cores;

	uint32_t num_branches_all_cores;

	struct {
		uint32_t num_inst;
		uint32_t num_inst16;
		uint32_t num_inst32;

		uint32_t num_trace_msgs;
		uint32_t num_trace_syncs;
		uint32_t num_trace_dbranch;
		uint32_t num_trace_ibranch;
		uint32_t num_trace_dataacq;
		uint32_t num_trace_dbranchws;
		uint32_t num_trace_ibranchws;
		uint32_t num_trace_ihistory;
		uint32_t num_trace_ihistoryws;
		uint32_t num_trace_takenhistory;
		uint32_t num_trace_resourcefull;
		uint32_t num_trace_correlation;
		uint32_t num_trace_auxaccesswrite;
		uint32_t num_trace_ownership;
		uint32_t num_trace_error;
		uint32_t num_trace_incircuittraceWS;
		uint32_t num_trace_incircuittrace;

		uint32_t trace_bits;
		uint32_t trace_bits_max;
		uint32_t trace_bits_min;
		uint32_t trace_bits_mseo;

		uint32_t max_hist_bits;
		uint32_t min_hist_bits;
		uint32_t max_notTakenCount;
		uint32_t min_notTakenCount;
		uint32_t max_takenCount;
		uint32_t min_takenCount;

		uint32_t trace_bits_sync;
		uint32_t trace_bits_dbranch;
		uint32_t trace_bits_ibranch;
		uint32_t trace_bits_dataacq;
		uint32_t trace_bits_dbranchws;
		uint32_t trace_bits_ibranchws;
		uint32_t trace_bits_ihistory;
		uint32_t trace_bits_ihistoryws;
		uint32_t trace_bits_resourcefull;
		uint32_t trace_bits_correlation;
		uint32_t trace_bits_auxaccesswrite;
		uint32_t trace_bits_ownership;
		uint32_t trace_bits_error;
		uint32_t trace_bits_incircuittraceWS;
		uint32_t trace_bits_incircuittrace;

		uint32_t num_trace_ts;
		uint32_t num_trace_uaddr;
		uint32_t num_trace_faddr;
		uint32_t num_trace_ihistory_taken_branches;
		uint32_t num_trace_ihistory_nottaken_branches;
		uint32_t num_trace_resourcefull_i_cnt;
		uint32_t num_trace_resourcefull_hist;
		uint32_t num_trace_resourcefull_takenCount;
		uint32_t num_trace_resourcefull_notTakenCount;
		uint32_t num_trace_resourcefull_taken_branches;
		uint32_t num_trace_resourcefull_nottaken_branches;

		uint32_t num_taken_branches;
		uint32_t num_notTaken_branches;
		uint32_t num_calls;
		uint32_t num_returns;
		uint32_t num_swaps;
		uint32_t num_exceptions;
		uint32_t num_exception_returns;
		uint32_t num_interrupts;

		uint32_t trace_bits_ts;
		uint32_t trace_bits_ts_max;
		uint32_t trace_bits_ts_min;

		uint32_t trace_bits_uaddr;
		uint32_t trace_bits_uaddr_max;
		uint32_t trace_bits_uaddr_min;

		uint32_t trace_bits_faddr;
		uint32_t trace_bits_faddr_max;
		uint32_t trace_bits_faddr_min;

		uint32_t trace_bits_hist;
	} core[DQR_PROFILER_MAXCORES];
};

class ProfilerCATraceRec {
public:
	ProfilerCATraceRec();
	void dump();
	void dumpWithCycle();
	int consumeCAInstruction(uint32_t& pipe, uint32_t& cycles);
	int consumeCAVector(uint32_t& record, uint32_t& cycles);
	int offset;
	TraceDqrProfiler::ADDRESS address;
	uint32_t data[32];
};

class ProfilerCATrace {
public:
	ProfilerCATrace(char* caf_name, TraceDqrProfiler::CATraceType catype);
	~ProfilerCATrace();
	TraceDqrProfiler::DQErr consume(uint32_t& caFlags, TraceDqrProfiler::InstType iType, uint32_t& pipeCycles, uint32_t& viStartCycles, uint32_t& viFinishCycles, uint8_t& qDepth, uint8_t& arithDepth, uint8_t& loadDepth, uint8_t& storeDepth);

	TraceDqrProfiler::DQErr rewind();
	TraceDqrProfiler::ADDRESS getCATraceStartAddr();

	TraceDqrProfiler::DQErr getStatus() { return status; }

private:
	struct CATraceQItem {
		uint32_t cycle;
		uint8_t record;
		uint8_t qDepth;
		uint8_t arithInProcess;
		uint8_t loadInProcess;
		uint8_t storeInProcess;
	};

	TraceDqrProfiler::DQErr status;

	TraceDqrProfiler::CATraceType caType;
	int      caBufferSize;
	uint8_t* caBuffer;
	int      caBufferIndex;
	int      blockRecNum;

	TraceDqrProfiler::ADDRESS startAddr;
	//uint32_t baseCycles;
	ProfilerCATraceRec catr;
	int       traceQSize;
	int       traceQOut;
	int       traceQIn;
	CATraceQItem* caTraceQ;

	int roomQ();
	TraceDqrProfiler::DQErr packQ();

	TraceDqrProfiler::DQErr addQ(uint32_t data, uint32_t t);

	void dumpCAQ();

	TraceDqrProfiler::DQErr parseNextVectorRecord(int& newDataStart);
	TraceDqrProfiler::DQErr parseNextCATraceRec(ProfilerCATraceRec& car);
	TraceDqrProfiler::DQErr dumpCurrentCARecord(int level);
	TraceDqrProfiler::DQErr consumeCAInstruction(uint32_t& pipe, uint32_t& cycles);
	TraceDqrProfiler::DQErr consumeCAPipe(int& QStart, uint32_t& cycles, uint32_t& pipe);
	TraceDqrProfiler::DQErr consumeCAVector(int& QStart, TraceDqrProfiler::CAVectorTraceFlags type, uint32_t& cycles, uint8_t& qInfo, uint8_t& arithInfo, uint8_t& loadInfo, uint8_t& storeInfo);
};

class ProfilerObjFile {
public:
	ProfilerObjFile(char* ef_name, const char* odExe);
	~ProfilerObjFile();
	void cleanUp();

	TraceDqrProfiler::DQErr getStatus() { return status; }
	TraceDqrProfiler::DQErr sourceInfo(TraceDqrProfiler::ADDRESS addr, ProfilerInstruction& instInfo, ProfilerSource& srcInfo);
	TraceDqrProfiler::DQErr setPathType(TraceDqrProfiler::pathType pt);

	TraceDqrProfiler::DQErr subSrcPath(const char* cutPath, const char* newRoot);
	TraceDqrProfiler::DQErr parseNLSStrings(TraceDqrProfiler::nlStrings(&nlsStrings)[32]);

	TraceDqrProfiler::DQErr dumpSyms();

private:
	TraceDqrProfiler::DQErr        status;
	char* cutPath;
	char* newRoot;
	class ElfReader* elfReader;
	class Disassembler* disassembler;
};

class TraceProfiler {
public:
	TraceProfiler(char* tf_name, char* ef_name, int numAddrBits, uint32_t addrDispFlags, int srcBits, const char* odExe, uint32_t freq = 0);
	TraceProfiler(char* mf_ame);
	~TraceProfiler();
	void cleanUp();
	static const char* version();
	TraceDqrProfiler::DQErr setTraceType(TraceDqrProfiler::TraceType tType);
	TraceDqrProfiler::DQErr setTSSize(int size);
	TraceDqrProfiler::DQErr setITCPrintOptions(int intFlags, int buffSize, int channel);
	TraceDqrProfiler::DQErr setPathType(TraceDqrProfiler::pathType pt);
	TraceDqrProfiler::DQErr setCATraceFile(char* caf_name, TraceDqrProfiler::CATraceType catype);
	TraceDqrProfiler::DQErr enableCTFConverter(int64_t startTime, char* hostName);
	TraceDqrProfiler::DQErr enableEventConverter();
	TraceDqrProfiler::DQErr enablePerfConverter(int perfChannel, uint32_t markerValue);

	TraceDqrProfiler::DQErr subSrcPath(const char* cutPath, const char* newRoot);

	enum TraceFlags {
		TF_INSTRUCTION = 0x01,
		TF_ADDRESS = 0x02,
		TF_DISSASEMBLE = 0x04,
		TF_TIMESTAMP = 0x08,
		TF_TRACEINFO = 0x10,
	};
	TraceDqrProfiler::DQErr getStatus() { return status; }
	TraceDqrProfiler::DQErr NextInstruction(ProfilerInstruction** instInfo, ProfilerNexusMessage** msgInfo, ProfilerSource** srcInfo);
	TraceDqrProfiler::DQErr NextInstruction(ProfilerInstruction* instInfo, ProfilerNexusMessage* msgInfo, ProfilerSource* srcInfo, int* flags);
	TraceDqrProfiler::DQErr NextInstruction(ProfilerInstruction** instInfo, ProfilerNexusMessage **nm_out, uint64_t &address_out);

	TraceDqrProfiler::DQErr getTraceFileOffset(int& size, int& offset);

	TraceDqrProfiler::DQErr haveITCPrintData(int numMsgs[DQR_PROFILER_MAXCORES], bool havePrintData[DQR_PROFILER_MAXCORES]);
	bool        getITCPrintMsg(int core, char* dst, int dstLen, TraceDqrProfiler::TIMESTAMP& startTime, TraceDqrProfiler::TIMESTAMP& endTime);
	bool        flushITCPrintMsg(int core, char* dst, int dstLen, TraceDqrProfiler::TIMESTAMP& startTime, TraceDqrProfiler::TIMESTAMP& endTime);
	std::string getITCPrintStr(int core, bool& haveData, TraceDqrProfiler::TIMESTAMP& startTime, TraceDqrProfiler::TIMESTAMP& endTime);
	std::string flushITCPrintStr(int core, bool& haveData, TraceDqrProfiler::TIMESTAMP& startTime, TraceDqrProfiler::TIMESTAMP& endTime);

	std::string getITCPrintStr(int core, bool& haveData, double& startTime, double& endTime);
	std::string flushITCPrintStr(int core, bool& haveData, double& startTime, double& endTime);

	//	const char *getSymbolByAddress(TraceDqrProfiler::ADDRESS addr);
	TraceDqrProfiler::DQErr Disassemble(TraceDqrProfiler::ADDRESS addr);
	int         getArchSize();
	int         getAddressSize();
	void        analyticsToText(char* dst, int dst_len, int detailLevel) { analytics.toText(dst, dst_len, detailLevel); }
	std::string analyticsToString(int detailLevel) { return analytics.toString(detailLevel); }
	TraceDqrProfiler::TIMESTAMP processTS(TraceDqrProfiler::tsType tstype, TraceDqrProfiler::TIMESTAMP lastTs, TraceDqrProfiler::TIMESTAMP newTs);
	int         getITCPrintMask();
	int         getITCFlushMask();
	TraceDqrProfiler::DQErr getInstructionByAddress(TraceDqrProfiler::ADDRESS addr, ProfilerInstruction* instInfo, ProfilerSource* srcInfo, int* flags);

	TraceDqrProfiler::DQErr getNumBytesInSWTQ(int& numBytes);
	TraceDqrProfiler::DQErr GenerateHistogram();
	void SetHistogramCallback(std::function<void(std::unordered_map<uint64_t, uint64_t>& hist_map, uint64_t total_bytes_processed, uint64_t total_ins, int32_t ret)> fp_callback)
	{
		m_fp_hist_callback = fp_callback;
	}
	void AddFlushDataOffset(const uint64_t offset)
	{
		m_flush_data_offset = offset;
	}
	void ClearHistogram()
	{
		m_hist_map.clear();
	}
private:
	enum state {
		TRACE_STATE_SYNCCATE,
		TRACE_STATE_GETFIRSTSYNCMSG,
		TRACE_STATE_GETMSGWITHCOUNT,
		TRACE_STATE_RETIREMESSAGE,
		TRACE_STATE_GETNEXTMSG,
		TRACE_STATE_GETNEXTINSTRUCTION,
		TRACE_STATE_DONE,
		TRACE_STATE_ERROR
	};
	std::atomic<uint64_t> m_flush_data_offset;
	std::unordered_map<uint64_t, uint64_t> m_hist_map;
	std::function<void(std::unordered_map<uint64_t, uint64_t>& hist_map, uint64_t total_bytes_processed, uint64_t total_ins, int32_t ret)> m_fp_hist_callback = nullptr;
	TraceDqrProfiler::DQErr        status;
	TraceDqrProfiler::TraceType	   traceType;
	class SliceFileParser* sfp;
	class ElfReader* elfReader;
	class Disassembler* disassembler;
	class CTFConverter* ctf;
	class EventConverter* eventConverter;
	class PerfConverter* perfConverter;
	char* objdump;
	char* rtdName;
	char* efName;
	char* cutPath;
	char* newRoot;
	class ITCPrint* itcPrint;
	TraceDqrProfiler::nlStrings* nlsStrings;
	TraceDqrProfiler::ADDRESS      currentAddress[DQR_PROFILER_MAXCORES];
	TraceDqrProfiler::ADDRESS	   lastFaddr[DQR_PROFILER_MAXCORES];
	TraceDqrProfiler::TIMESTAMP    lastTime[DQR_PROFILER_MAXCORES];
	class Count* counts;
	enum state       state[DQR_PROFILER_MAXCORES];
	bool             readNewTraceMessage;
	int              currentCore;
	int              srcbits;
	bool             bufferItc;
	int              enterISR[DQR_PROFILER_MAXCORES];

	int              startMessageNum;
	int              endMessageNum;

	uint32_t         eventFilterMask;

	int              tsSize;
	TraceDqrProfiler::pathType pathType;

	uint32_t         freq;

	ProfilerAnalytics        analytics;

	//	need current message number and list of messages??

	ProfilerNexusMessage     nm;

	ProfilerNexusMessage     messageInfo;
	ProfilerInstruction      instructionInfo;
	ProfilerSource           sourceInfo;

	int              syncCount;
	TraceDqrProfiler::ADDRESS caSyncAddr;
	class ProfilerCATrace* caTrace;
	TraceDqrProfiler::TIMESTAMP lastCycle[DQR_PROFILER_MAXCORES];
	int               eCycleCount[DQR_PROFILER_MAXCORES];
	std::mutex m_hist_mutex;

	TraceDqrProfiler::DQErr configure(class TraceSettings& settings);

	int decodeInstructionSize(uint32_t inst, int& inst_size);
	int decodeInstruction(uint32_t instruction, int& inst_size, TraceDqrProfiler::InstType& inst_type, TraceDqrProfiler::Reg& rs1, TraceDqrProfiler::Reg& rd, int32_t& immediate, bool& is_branch);
	TraceDqrProfiler::DQErr getCRBRFlags(TraceDqrProfiler::ICTReason cksrc, TraceDqrProfiler::ADDRESS addr, int& crFlag, int& brFlag);
	TraceDqrProfiler::DQErr nextAddr(TraceDqrProfiler::ADDRESS addr, TraceDqrProfiler::ADDRESS& nextAddr, int& crFlag);
	TraceDqrProfiler::DQErr nextAddr(int currentCore, TraceDqrProfiler::ADDRESS addr, TraceDqrProfiler::ADDRESS& pc, TraceDqrProfiler::TCode tcode, int& crFlag, TraceDqrProfiler::BranchFlags& brFlag);
	TraceDqrProfiler::DQErr nextCAAddr(TraceDqrProfiler::ADDRESS& addr, TraceDqrProfiler::ADDRESS& savedAddr);

	TraceDqrProfiler::ADDRESS computeAddress();
	TraceDqrProfiler::DQErr processTraceMessage(ProfilerNexusMessage& nm, TraceDqrProfiler::ADDRESS& pc, TraceDqrProfiler::ADDRESS& faddr, TraceDqrProfiler::TIMESTAMP& ts, bool& consumed);
public:
    // Function to add data to the message queue
    TraceDqrProfiler::DQErr PushTraceData(uint8_t *p_buff, const uint64_t size);
    void SetEndOfData();
};

#endif /* DQR_HPP_ */
