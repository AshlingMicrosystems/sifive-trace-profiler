/* Copyright 2022 SiFive, Inc */
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef DQR_TRACE_PROFILER_HPP_
#define DQR_TRACE_PROFILER_HPP_

// private definitions
#include<stdint.h>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <cstring>
#include <cstdint>
#include <cassert>
#include <fcntl.h>
#include <cctype>    // std::tolower
#include <algorithm> // std::equal
#include <deque>
#include <mutex>
//#include <unistd.h>
#ifdef WINDOWS
#include<windows.h>
#endif
int32_t ichar_equals(char a, char b);
int32_t strcasecmp(const std::string& a, const std::string& b);


#ifdef DO_TIMES
class Timer {
public:
	Timer();
	~Timer();

	double start();
	double etime();

private:
	double startTime;
};
#endif // DO_TIMES

void sanePath(TraceDqrProfiler::pathType pt, const char* src, char* dst);

class cachedInstInfo {
public:
	cachedInstInfo(const char* file, int cutPathIndex, const char* func, int linenum, const char* lineTxt, const char* instText, TraceDqrProfiler::RV_INST inst, int instSize, const char* addresslabel, int addresslabeloffset);
	~cachedInstInfo();

	void dump();

	const char* filename;
	int         cutPathIndex;
	const char* functionname;
	int         linenumber;
	const char* lineptr;

	TraceDqrProfiler::RV_INST instruction;
	int               instsize;

	char* instructionText;

	const char* addressLabel;
	int               addressLabelOffset;
};

// class Section: work with elf file sections

class SrcFile {
public:
	SrcFile(char* fName, SrcFile* nxt);
	~SrcFile();

	class SrcFile* next;
	char* file;
};

class SrcFileRoot {
public:
	SrcFileRoot();
	~SrcFileRoot();

	char* addFile(char* fName);
	void dump();

private:
	SrcFile* fileRoot;
};

class Section {
public:

	enum {
		sect_CONTENTS = 1 << 0,
		sect_ALLOC = 1 << 1,
		sect_LOAD = 1 << 2,
		sect_READONLY = 1 << 3,
		sect_DATA = 1 << 4,
		sect_CODE = 1 << 5,
		sect_THREADLOCAL = 1 << 6,
		sect_DEBUGGING = 1 << 7,
		sect_OCTETS = 1 << 8
	};

	Section();
	~Section();

	Section* getSectionByAddress(TraceDqrProfiler::ADDRESS addr);
	Section* getSectionByName(char* secName);

	cachedInstInfo* setCachedInfo(TraceDqrProfiler::ADDRESS addr, const char* file, int cutPathIndex, const char* func, int linenum, const char* lineTxt, const char* instTxt, TraceDqrProfiler::RV_INST inst, int instSize, const char* addresslabel, int addresslabeloffset);
	cachedInstInfo* getCachedInfo(TraceDqrProfiler::ADDRESS addr);

	void dump();

	Section* next;
	char         name[256];
	TraceDqrProfiler::ADDRESS startAddr;
	TraceDqrProfiler::ADDRESS endAddr;
	uint32_t     flags;
	uint32_t     size;	// size of section
	uint32_t     offset; // offset of section in elf file
	uint32_t     align;
	uint16_t* code;
	char** fName; // file name - array of pointers
	uint32_t* line;  // line number
	char** diss;  // disassembly text - array of pointers

	cachedInstInfo** cachedInfo; // array of pointers
};

// class fileReader: Helper class to handler list of source code files

class fileReader {
public:
	struct funcList {
		funcList* next;
		char* func;
	};
	struct fileList {
		fileList* next;
		char* name;
		int           cutPathIndex;
		funcList* funcs;
		unsigned int  lineCount;
		char** lines;
	};

	fileReader(/*paths?*/);
	~fileReader();

	TraceDqrProfiler::DQErr subSrcPath(const char* cutPath, const char* newRoot);
	fileList* findFile(const char* file);

private:
	char* cutPath;
	char* newRoot;

	fileList* readFile(const char* file);

	fileList* lastFile;
	fileList* files;
};

// class Symtab: Interface class between bfd symbols and what is needed for dqr

struct Sym {
	enum {
		symNone = 0,
		symLocal = 1 << 0,
		symGlobal = 1 << 1,
		symWeak = 1 << 2,
		symConstructor = 1 << 3,
		symIndirect = 1 << 4,
		symIndirectFunc = 1 << 5,
		symDebug = 1 << 6,
		symDynamic = 1 << 7,
		symFunc = 1 << 8,
		symFile = 1 << 9,
		symObj = 1 << 10
	};

	struct Sym* next;
	char* name;
	uint32_t flags;
	class Section* section;
	uint64_t address;
	uint64_t size;
	struct Sym* srcFile;
};

class Symtab {
public:
	Symtab(Sym* syms);
	~Symtab();
	TraceDqrProfiler::DQErr lookupSymbolByAddress(TraceDqrProfiler::ADDRESS addr, Sym*& sym);
	void         dump();

	TraceDqrProfiler::DQErr getStatus() { return status; }

private:
	TraceDqrProfiler::DQErr status;

	TraceDqrProfiler::ADDRESS cachedSymAddr;
	int cachedSymSize;
	int cachedSymIndex;

	long      numSyms;
	Sym* symLst;
	Sym** symPtrArray;

	TraceDqrProfiler::DQErr fixupFunctionSizes();
};

// find : Interface class between dqr and bfd

class ObjDump {
public:
	ObjDump(const char* elfName, const char* objDumpPath, int& archSize, Section*& codeSectionLst, Sym*& syms, SrcFileRoot& srcFileRoot);
	~ObjDump();

	TraceDqrProfiler::DQErr getStatus() { return status; }

private:
	enum objDumpTokenType {
		odtt_error,
		odtt_eol,
		odtt_eof,
		odtt_colon,
		odtt_lt,
		odtt_gt,
		odtt_lp,
		odtt_rp,
		odtt_comma,
		odtt_string,
		odtt_number,
	};

	enum elfType {
		elfType_unknown,
		elfType_64_little,
		elfType_32_little,
	};

	enum line_t {
		line_t_label,
		line_t_diss,
		line_t_path,
		line_t_func,
	};

	TraceDqrProfiler::DQErr status;

	int stdoutPipe;
	FILE* fpipe;

	bool pipeEOF;
	char pipeBuffer[2048];
	int  pipeIndex = 0;
	int  endOfBuffer = 0;

	int32_t objdumpPid;
#ifdef WINDOWS
	HANDLE hStdOutPipeRead = NULL;
	HANDLE hStdOutPipeWrite = NULL;
	PROCESS_INFORMATION pi;
#endif
	TraceDqrProfiler::DQErr execObjDump(const char* elfName, const char* objdumpPath);
	TraceDqrProfiler::DQErr fillPipeBuffer();
	objDumpTokenType getNextLex(char* lex);
	bool isWSLookahead();
	bool isStringAHexNumber(char* s, uint64_t& n);
	bool isStringADecNumber(char* s, uint64_t& n);
	objDumpTokenType getRestOfLine(char* lex);
	TraceDqrProfiler::DQErr parseSection(objDumpTokenType& nextType, char* nextLex, Section*& codeSection);
	TraceDqrProfiler::DQErr parseSectionList(objDumpTokenType& nextType, char* nextLex, Section*& codeSectionLst);
	TraceDqrProfiler::DQErr parseFileLine(uint32_t& line);
	TraceDqrProfiler::DQErr parseFuncName();
	TraceDqrProfiler::DQErr parseFileOrLabelOrDisassembly(line_t& lineType, char* text, int& length, uint32_t& value);
	TraceDqrProfiler::DQErr parseDisassembly(bool& isLabel, int& instSize, uint32_t& inst, char* disassembly);
	TraceDqrProfiler::DQErr parseDisassemblyList(objDumpTokenType& nextType, char* nextLex, Section* codeSectionLst, SrcFileRoot& srcFileRoot);
	TraceDqrProfiler::DQErr parseFixedField(uint32_t& flags);
	TraceDqrProfiler::DQErr parseSymbol(bool& haveSym, char* secName, char* symName, uint32_t& symFlags, uint64_t& symSize);
	TraceDqrProfiler::DQErr parseSymbolTable(objDumpTokenType& nextType, char* nextLex, Sym*& syms, Section*& codeSectionLst);
	TraceDqrProfiler::DQErr parseElfName(char* elfName, enum elfType& et);
	TraceDqrProfiler::DQErr parseObjdump(int& archSize, Section*& codeSectionLst, Sym*& syms, SrcFileRoot& srcFileRoot);
};

class ElfReader {
public:
	ElfReader(const char* elfname, const char* odExe);
	~ElfReader();
	TraceDqrProfiler::DQErr getStatus() { return status; }
	TraceDqrProfiler::DQErr getInstructionByAddress(TraceDqrProfiler::ADDRESS addr, TraceDqrProfiler::RV_INST& inst);
	Symtab* getSymtab();
	Section* getSections() { return codeSectionLst; }
	int        getArchSize() { return archSize; }
	int        getBitsPerAddress() { return bitsPerAddress; }

	TraceDqrProfiler::DQErr parseNLSStrings(TraceDqrProfiler::nlStrings* nlsStrings);

	TraceDqrProfiler::DQErr dumpSyms();

private:
	TraceDqrProfiler::DQErr  status;
	char* elfName;
	int         archSize;
	int         bitsPerAddress;
	Section* codeSectionLst;
	Symtab* symtab;
	SrcFileRoot srcFileRoot;

	TraceDqrProfiler::DQErr fixupSourceFiles(Section* sections, Sym* syms);
};

class TsList {
public:
	TsList();
	~TsList();

	class TsList* prev;
	class TsList* next;
	bool terminated;
	TraceDqrProfiler::TIMESTAMP startTime;
	TraceDqrProfiler::TIMESTAMP endTime;
	char* message;
};

class ITCPrint {
public:
	ITCPrint(int itcPrintOpts, int numCores, int buffSize, int channel, TraceDqrProfiler::nlStrings* nlsStrings);
	~ITCPrint();
	bool print(uint8_t core, uint32_t address, uint32_t data);
	bool print(uint8_t core, uint32_t address, uint32_t data, TraceDqrProfiler::TIMESTAMP tstamp);
	void haveITCPrintData(int numMsgs[DQR_PROFILER_MAXCORES], bool havePrintData[DQR_PROFILER_MAXCORES]);
	bool getITCPrintMsg(uint8_t core, char* dst, int dstLen, TraceDqrProfiler::TIMESTAMP& startTime, TraceDqrProfiler::TIMESTAMP& endTime);
	bool flushITCPrintMsg(uint8_t core, char* dst, int dstLen, TraceDqrProfiler::TIMESTAMP& startTime, TraceDqrProfiler::TIMESTAMP& endTime);
	bool getITCPrintStr(uint8_t core, std::string& s, TraceDqrProfiler::TIMESTAMP& startTime, TraceDqrProfiler::TIMESTAMP& endTime);
	bool flushITCPrintStr(uint8_t core, std::string& s, TraceDqrProfiler::TIMESTAMP& starTime, TraceDqrProfiler::TIMESTAMP& endTime);
	int  getITCPrintMask();
	int  getITCFlushMask();
	bool haveITCPrintMsgs();

private:
	int  roomInITCPrintQ(uint8_t core);
	TsList* consumeTerminatedTsList(int core);
	TsList* consumeOldestTsList(int core);

	int itcOptFlags;
	int numCores;
	int buffSize;
	int printChannel;
	TraceDqrProfiler::nlStrings* nlsStrings;
	char** pbuff;
	int* pbi;
	int* pbo;
	int* numMsgs;
	class TsList** tsList;
	class TsList* freeList;
};

// class SliceFileParser: Class to parse binary or ascii nexus messages into a ProfilerNexusMessage object
class SliceFileParser {
public:
	SliceFileParser(char* filename, int srcBits);
	~SliceFileParser();
	TraceDqrProfiler::DQErr readNextTraceMsg(ProfilerNexusMessage& nm, class ProfilerAnalytics& analytics, bool& haveMsg);
	TraceDqrProfiler::DQErr getFileOffset(int& size, int& offset);

	TraceDqrProfiler::DQErr getErr() { return status; };
	void       dump();

	TraceDqrProfiler::DQErr getNumBytesInSWTQ(int& numBytes);
    // Function to add data to the message queue
    TraceDqrProfiler::DQErr PushTraceData(uint8_t *p_buff, const uint64_t size)
    {
        if (!p_buff)
        {
            return TraceDqrProfiler::DQERR_ERR;
        }
        std::lock_guard<std::mutex> msg_queue_guard(m_msg_queue_mutex);
        m_msg_queue.insert(m_msg_queue.end(), p_buff, p_buff + size);
        return TraceDqrProfiler::DQERR_OK;
    }
    // Function to set end of data
    void SetEndOfData()
    {
        std::lock_guard<std::mutex> msg_eod_guard(m_end_of_data_mutex);
        m_end_of_data = true;
    }
private:
	TraceDqrProfiler::DQErr status;

	// add other counts for each message type

	int           srcbits;
	std::ifstream tf;
	uint8_t* m_string;
	uint64_t m_size;
	uint64_t m_idx;
	int           tfSize;
	int           SWTsock;
	int           bitIndex;
	int           msgSlices;
	uint32_t      msgOffset;
	int           pendingMsgIndex;
	uint8_t       msg[64];
	bool          eom;

	int           bufferInIndex;
	int           bufferOutIndex;
	uint8_t       sockBuffer[2048];
    // Mutex to sync m_msg_queue 
    std::mutex m_msg_queue_mutex;
    // Mutex to sync m_end_of_data 
    std::mutex m_end_of_data_mutex;
    std::deque<uint8_t> m_msg_queue;
    bool m_end_of_data;

	TraceDqrProfiler::DQErr readBinaryMsg(bool& haveMsg);
	TraceDqrProfiler::DQErr bufferSWT();
	TraceDqrProfiler::DQErr readNextByte(uint8_t* byte);
	TraceDqrProfiler::DQErr parseVarField(uint64_t* val, int* width);
	TraceDqrProfiler::DQErr parseFixedField(int width, uint64_t* val);
	TraceDqrProfiler::DQErr parseDirectBranch(ProfilerNexusMessage& nm, ProfilerAnalytics& analytics);
	TraceDqrProfiler::DQErr parseIndirectBranch(ProfilerNexusMessage& nm, ProfilerAnalytics& analytics);
	TraceDqrProfiler::DQErr parseDirectBranchWS(ProfilerNexusMessage& nm, ProfilerAnalytics& analytics);
	TraceDqrProfiler::DQErr parseIndirectBranchWS(ProfilerNexusMessage& nm, ProfilerAnalytics& analytics);
	TraceDqrProfiler::DQErr parseSync(ProfilerNexusMessage& nm, ProfilerAnalytics& analytics);
	TraceDqrProfiler::DQErr parseCorrelation(ProfilerNexusMessage& nm, ProfilerAnalytics& analytics);
	TraceDqrProfiler::DQErr parseAuxAccessWrite(ProfilerNexusMessage& nm, ProfilerAnalytics& analytics);
	TraceDqrProfiler::DQErr parseDataAcquisition(ProfilerNexusMessage& nm, ProfilerAnalytics& analytics);
	TraceDqrProfiler::DQErr parseOwnershipTrace(ProfilerNexusMessage& nm, ProfilerAnalytics& analytics);
	TraceDqrProfiler::DQErr parseError(ProfilerNexusMessage& nm, ProfilerAnalytics& analytics);
	TraceDqrProfiler::DQErr parseIndirectHistory(ProfilerNexusMessage& nm, ProfilerAnalytics& analytics);
	TraceDqrProfiler::DQErr parseIndirectHistoryWS(ProfilerNexusMessage& nm, ProfilerAnalytics& analytics);
	TraceDqrProfiler::DQErr parseResourceFull(ProfilerNexusMessage& nm, ProfilerAnalytics& analytics);
	TraceDqrProfiler::DQErr parseICT(ProfilerNexusMessage& nm, ProfilerAnalytics& analytics);
	TraceDqrProfiler::DQErr parseICTWS(ProfilerNexusMessage& nm, ProfilerAnalytics& analytics);
};
#if 1
class propertiesParser {
public:
	propertiesParser(const char* srcData);
	~propertiesParser();

	TraceDqrProfiler::DQErr getStatus() { return status; }

	void            rewind();
	TraceDqrProfiler::DQErr getNextProperty(char** name, char** value);

private:
	TraceDqrProfiler::DQErr status;

	struct line {
		char* name;
		char* value;
		char* line;
	};

	int   size;
	int   numLines;
	int   nextLine;
	line* lines;
	char* propertiesBuff;

	TraceDqrProfiler::DQErr getNextToken(char* inputText, int& startIndex, int& endIndex);
};

// class TraceSettings. Used to initialize trace objects

class TraceSettings {
public:
	TraceSettings();
	~TraceSettings();

	TraceDqrProfiler::DQErr addSettings(propertiesParser* properties);

	TraceDqrProfiler::DQErr propertyToTFName(const char* value);
	TraceDqrProfiler::DQErr propertyToEFName(const char* value);
	TraceDqrProfiler::DQErr propertyToPFName(const char* value);
	TraceDqrProfiler::DQErr propertyToSrcBits(const char* value);
	TraceDqrProfiler::DQErr propertyToNumAddrBits(const char* value);
	TraceDqrProfiler::DQErr propertyToITCPrintOpts(const char* value);
	TraceDqrProfiler::DQErr propertyToITCPrintBufferSize(const char* value);
	TraceDqrProfiler::DQErr propertyToITCPrintChannel(const char* value);
	TraceDqrProfiler::DQErr propertyToITCPerfEnable(const char* value);
	TraceDqrProfiler::DQErr propertyToITCPerfChannel(const char* value);
	TraceDqrProfiler::DQErr propertyToITCPerfMarkerValue(const char* value);
	TraceDqrProfiler::DQErr propertyToSrcRoot(const char* value);
	TraceDqrProfiler::DQErr propertyToSrcCutPath(const char* value);
	TraceDqrProfiler::DQErr propertyToCAName(const char* value);
	TraceDqrProfiler::DQErr propertyToCAType(const char* value);
	TraceDqrProfiler::DQErr propertyToPathType(const char* value);
	TraceDqrProfiler::DQErr propertyToFreq(const char* value);
	TraceDqrProfiler::DQErr propertyToTSSize(const char* value);
	TraceDqrProfiler::DQErr propertyToAddrDispFlags(const char* value);
	TraceDqrProfiler::DQErr propertyToCTFEnable(const char* value);
	TraceDqrProfiler::DQErr propertyToEventConversionEnable(const char* value);
	TraceDqrProfiler::DQErr propertyToStartTime(const char* value);
	TraceDqrProfiler::DQErr propertyToHostName(const char* value);
	TraceDqrProfiler::DQErr propertyToObjdumpName(const char* value);

	char* odName;
	char* tfName;
	char* efName;
	char* caName;
	char* pfName;
	TraceDqrProfiler::CATraceType caType;
	int srcBits;
	int numAddrBits;
	int itcPrintOpts;
	int itcPrintBufferSize;
	int itcPrintChannel;
	char* cutPath;
	char* srcRoot;
	TraceDqrProfiler::pathType pathType;
	uint32_t freq;
	uint32_t addrDispFlags;
	int64_t  startTime;
	int tsSize;
	bool CTFConversion;
	bool eventConversionEnable;
	char* hostName;
	bool filterControlEvents;

	bool itcPerfEnable;
	int itcPerfChannel;
	uint32_t itcPerfMarkerValue;

private:
	TraceDqrProfiler::DQErr propertyToBool(const char* src, bool& value);
};
#endif
// class Disassembler: class to help in the dissasemblhy of instrucitons

class Disassembler {
public:
	Disassembler(Symtab* stp, Section* sp, int archsize);
	~Disassembler();

	TraceDqrProfiler::DQErr disassemble(TraceDqrProfiler::ADDRESS addr);

	TraceDqrProfiler::DQErr getSrcLines(TraceDqrProfiler::ADDRESS addr, const char** filename, int* cutPathIndex, const char** functionname, unsigned int* linenumber, const char** lineptr);

	TraceDqrProfiler::DQErr getFunctionName(TraceDqrProfiler::ADDRESS addr, const char*& function, int& offset);

	static TraceDqrProfiler::DQErr   decodeInstructionSize(uint32_t inst, int& inst_size);
	static int   decodeInstruction(uint32_t instruction, int archSize, int& inst_size, TraceDqrProfiler::InstType& inst_type, TraceDqrProfiler::Reg& rs1, TraceDqrProfiler::Reg& rd, int32_t& immediate, bool& is_branch);

	ProfilerInstruction getInstructionInfo() { return instruction; }
	ProfilerSource      getSourceInfo() { return source; }

	TraceDqrProfiler::DQErr setPathType(TraceDqrProfiler::pathType pt);
	TraceDqrProfiler::DQErr subSrcPath(const char* cutPath, const char* newRoot);

	TraceDqrProfiler::DQErr getStatus() { return status; }

private:
	TraceDqrProfiler::DQErr   status;

	int               archSize;

	Section* sectionLst;		// owned by elfReader - don't delete
	Symtab* symtab;			// owned by elfReader - don't delete

	// cached section information

	TraceDqrProfiler::ADDRESS cachedAddr;
	Section* cachedSecPtr;
	int               cachedIndex;

	ProfilerInstruction instruction;
	ProfilerSource      source;

	class fileReader* fileReader;

	TraceDqrProfiler::pathType pType;

	TraceDqrProfiler::DQErr getDissasembly(TraceDqrProfiler::ADDRESS addr, char*& dissText);
	TraceDqrProfiler::DQErr cacheSrcInfo(TraceDqrProfiler::ADDRESS addr);

	TraceDqrProfiler::DQErr lookupInstructionByAddress(TraceDqrProfiler::ADDRESS addr, uint32_t& ins, int& insSize);
	TraceDqrProfiler::DQErr findNearestLine(TraceDqrProfiler::ADDRESS addr, const char*& file, int& line);

	TraceDqrProfiler::DQErr getInstruction(TraceDqrProfiler::ADDRESS addr, ProfilerInstruction& instruction);

	// need to make all the decode function static. Might need to move them to public?

	static int decodeRV32Q0Instruction(uint32_t instruction, int& inst_size, TraceDqrProfiler::InstType& inst_type, TraceDqrProfiler::Reg& rs1, TraceDqrProfiler::Reg& rd, int32_t& immediate, bool& is_branch);
	static int decodeRV32Q1Instruction(uint32_t instruction, int& inst_size, TraceDqrProfiler::InstType& inst_type, TraceDqrProfiler::Reg& rs1, TraceDqrProfiler::Reg& rd, int32_t& immediate, bool& is_branch);
	static int decodeRV32Q2Instruction(uint32_t instruction, int& inst_size, TraceDqrProfiler::InstType& inst_type, TraceDqrProfiler::Reg& rs1, TraceDqrProfiler::Reg& rd, int32_t& immediate, bool& is_branch);
	static int decodeRV32Instruction(uint32_t instruction, int& inst_size, TraceDqrProfiler::InstType& inst_type, TraceDqrProfiler::Reg& rs1, TraceDqrProfiler::Reg& rd, int32_t& immediate, bool& is_branch);

	static int decodeRV64Q0Instruction(uint32_t instruction, int& inst_size, TraceDqrProfiler::InstType& inst_type, TraceDqrProfiler::Reg& rs1, TraceDqrProfiler::Reg& rd, int32_t& immediate, bool& is_branch);
	static int decodeRV64Q1Instruction(uint32_t instruction, int& inst_size, TraceDqrProfiler::InstType& inst_type, TraceDqrProfiler::Reg& rs1, TraceDqrProfiler::Reg& rd, int32_t& immediate, bool& is_branch);
	static int decodeRV64Q2Instruction(uint32_t instruction, int& inst_size, TraceDqrProfiler::InstType& inst_type, TraceDqrProfiler::Reg& rs1, TraceDqrProfiler::Reg& rd, int32_t& immediate, bool& is_branch);
	static int decodeRV64Instruction(uint32_t instruction, int& inst_size, TraceDqrProfiler::InstType& inst_type, TraceDqrProfiler::Reg& rs1, TraceDqrProfiler::Reg& rd, int32_t& immediate, bool& is_branch);
};

class AddrStack {
public:
	AddrStack(int size = 2048);
	~AddrStack();
	void reset();
	int push(TraceDqrProfiler::ADDRESS addr);
	TraceDqrProfiler::ADDRESS pop();
	int getNumOnStack() { return stackSize - sp; }

private:
	int stackSize;
	int sp;
	TraceDqrProfiler::ADDRESS* stack;
};

class Count {
public:
	Count();
	~Count();

	void resetCounts(int core);

	TraceDqrProfiler::CountType getCurrentCountType(int core);
	TraceDqrProfiler::DQErr setICnt(int core, int count);
	TraceDqrProfiler::DQErr setHistory(int core, uint64_t hist);
	TraceDqrProfiler::DQErr setHistory(int core, uint64_t hist, int count);
	TraceDqrProfiler::DQErr setTakenCount(int core, int takenCnt);
	TraceDqrProfiler::DQErr setNotTakenCount(int core, int notTakenCnt);
	TraceDqrProfiler::DQErr setCounts(ProfilerNexusMessage* nm);
	int consumeICnt(int core, int numToConsume);
	int consumeHistory(int core, bool& taken);
	int consumeTakenCount(int core);
	int consumeNotTakenCount(int core);

	int getICnt(int core) { return i_cnt[core]; }
	uint32_t getHistory(int core) { return history[core]; }
	int getNumHistoryBits(int core) { return histBit[core]; }
	uint32_t getTakenCount(int core) { return takenCount[core]; }
	uint32_t getNotTakenCount(int core) { return notTakenCount[core]; }
	uint32_t isTaken(int core) { return (history[core] & (1 << histBit[core])) != 0; }

	int push(int core, TraceDqrProfiler::ADDRESS addr) { return stack[core].push(addr); }
	TraceDqrProfiler::ADDRESS pop(int core) { return stack[core].pop(); }
	void resetStack(int core) { stack[core].reset(); }
	int getNumOnStack(int core) { return stack[core].getNumOnStack(); }


	void dumpCounts(int core);

	//	int getICnt(int core);
	//	int adjustICnt(int core,int delta);
	//	bool isHistory(int core);
	//	bool takenHistory(int core);

private:
	int i_cnt[DQR_PROFILER_MAXCORES];
	uint64_t history[DQR_PROFILER_MAXCORES];
	int histBit[DQR_PROFILER_MAXCORES];
	int takenCount[DQR_PROFILER_MAXCORES];
	int notTakenCount[DQR_PROFILER_MAXCORES];
	AddrStack stack[DQR_PROFILER_MAXCORES];
};

#endif /* TRACE_HPP_ */


// Improvements:
//
// Disassembler class:
//  Should be able to creat disassembler object without elf file
//  Should have a diasassemble method that takes an address and an instruciotn, not just an address
//  Should be able us use a block of memory for the code, not from an elf file
//  Use new methods to cleanup verilator nextInstruction()

// move some stuff in instruction object to a separate object pointed to from instruciton object so that coppies
// of the object don't need to copy it all (regfile is an example). Create accessor method to get. Destructor should
// delete all
