/* Copyright 2022 SiFive, Inc */
/* SPDX-License-Identifier: Apache-2.0 */

#include <iostream>
#include <iomanip>
#include <fstream>
#include <cstring>
#include <cstdint>
#include <time.h>
#include <sys/stat.h>
#ifdef WINDOWS
#include <winsock2.h>
#else // WINDOWS
//#include <unistd.h>
#endif // WINDOWS

#include "dqr_profiler.h"
#include "dqr_trace_profiler.h"

int32_t ichar_equals(char a, char b)
{
	return std::tolower(static_cast<unsigned char>(a)) ==
		std::tolower(static_cast<unsigned char>(b));
}

int32_t strcasecmp(const std::string& a, const std::string& b)
{
	if (a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), ichar_equals))
	{
		return 0;
	}
	return -1;
}


#ifdef DO_TIMES
Timer::Timer()
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);

	startTime = ts.tv_sec + (ts.tv_nsec / 1000000000.0);
}

Timer::~Timer()
{
}

double Timer::start()
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);

	startTime = ts.tv_sec + (ts.tv_nsec / 1000000000.0);

	return startTime;
}

double Timer::etime()
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);

	double t = ts.tv_sec + (ts.tv_nsec / 1000000000.0);

	return t - startTime;
}
#endif // DO_TIMES

// class ProfilerCATrace methods

ProfilerCATraceRec::ProfilerCATraceRec()
{
	offset = 0;
	address = 0;
}

void ProfilerCATraceRec::dump()
{
	printf("0x%08x\n", (uint32_t)address);
	for (int i = 0; (size_t)i < sizeof data / sizeof data[0]; i++) {
		printf("%3d  ", (i * 30) >> 1);

		for (int j = 28; j >= 0; j -= 2) {
			if (j != 28) {
				printf(":");
			}
			printf("%01x", (data[i] >> j) & 0x3);
		}

		printf("\n");
	}
}

void ProfilerCATraceRec::dumpWithCycle()
{
	printf("0x%08x\n", (uint32_t)address);
	for (int i = 0; (size_t)i < sizeof data / sizeof data[0]; i++) {
		for (int j = 28; j >= 0; j -= 2) {
			printf("%d %01x\n", (i * 30 + (28 - j)) >> 1, (data[i] >> j) & 0x3);
		}
	}
}

int ProfilerCATraceRec::consumeCAVector(uint32_t& record, uint32_t& cycles)
{
	int dataIndex;

	// check if we have exhausted all bits in this record

	// for vectors, offset and dataIndex are the array index for data[]

	dataIndex = offset;

	while (((size_t)dataIndex <= sizeof data / sizeof data[0]) && ((data[dataIndex] & 0x3fffffff) == 0)) {
		dataIndex += 1;
	}

	if ((size_t)dataIndex >= sizeof data / sizeof data[0]) {
		// out of records in the trace record. Signal caller to get more records

		record = 0;
		cycles = 0;

		return 0;
	}

	record = data[dataIndex];
	offset = dataIndex + 1;

	// cycle is the start cycle of the record returned relative to the start of the 32 word block.
	// The record represents 5 cycles (5 cycles in each 32 bit record)

	cycles = dataIndex * 5;

	return 1;
}

int ProfilerCATraceRec::consumeCAInstruction(uint32_t& pipe, uint32_t& cycles)
{
	int dataIndex;
	int bitIndex;
	bool found = false;

	// this function looks for pipe finish bits in an instruction trace (non-vector trace)

	// check if we have exhausted all bits in this record

//	printf("ProfilerCATraceRec::consumCAInstruction(): offset: %d\n",offset);

	if (offset >= 30 * 32) {
		// this record is exhausted. Tell caller to read another record

		return 0;
	}

	// find next non-zero bit field

	dataIndex = offset / 30; // 30 bits of data in each data word. dataIndex is data[] index
	bitIndex = 29 - (offset % 30);  // 0 - 29 is the bit index to start looking at (29 oldest, 0 newest)

	//	for (int i = 0; i < 32; i++) {
	//		printf("data[%d]: %08x\n",i,data[i]);
	//	}

	while (found == false) {
		while ((bitIndex >= 0) && ((data[dataIndex] & (1 << bitIndex)) == 0)) {
			bitIndex -= 1;
			offset += 1;
		}

		if (bitIndex < 0) {
			// didn't find any 1s in data[dataIndex]. Check next data item
			dataIndex += 1;

			if ((size_t)dataIndex >= sizeof data / sizeof data[0]) {
				return 0; // failure
			}

			bitIndex = 29;
		}
		else {
			// found a one

			// cycle is the start cycle of the pipe bit relative to the start of the 32 word block.

//			cycles = dataIndex * 15 + (29-bitIndex)/2;
//			or:
			cycles = offset / 2;

			//			printf("one at offset: %d, dataIndex: %d, bitindex: %d, cycle: %d\n",offset,dataIndex,bitIndex,cycles);

						// Bump past it
			offset += 1;
			found = true;
		}
	}

	if (bitIndex & 0x01) {
		pipe = TraceDqrProfiler::CAFLAG_PIPE0;
	}
	else {
		pipe = TraceDqrProfiler::CAFLAG_PIPE1;
	}

	//	printf("ProfilerCATraceRec::consumeCAInstruction(): Found: offset: %d cycles: %d\n",offset,cycles);

	return 1;	// success
}

ProfilerCATrace::ProfilerCATrace(char* caf_name, TraceDqrProfiler::CATraceType catype)
{
	caBufferSize = 0;
	caBuffer = nullptr;
	caBufferIndex = 0;
	blockRecNum = 0;

	status = TraceDqrProfiler::DQERR_OK;

	if (caf_name == nullptr) {
		status = TraceDqrProfiler::DQERR_ERR;
		return;
	}

	std::ifstream catf;

	catf.open(caf_name, std::ios::in | std::ios::binary);

	if (!catf) {
		printf("Error: ProfilerCATrace::ProfilerCATrace(): could not open cycle accurate trace file %s for input\n", caf_name);
		status = TraceDqrProfiler::DQERR_OPEN;
		return;
	}

	catf.seekg(0, catf.end);
	caBufferSize = catf.tellg();
	catf.seekg(0, catf.beg);

	caBuffer = new uint8_t[caBufferSize];

	catf.read((char*)caBuffer, caBufferSize);

	catf.close();

	//	printf("caBufferSize: %d\n",caBufferSize);
	//
	//	int *ip;
	//	ip = (int*)caBuffer;
	//
	//	for (int i = 0; (size_t)i < caBufferSize / sizeof(int); i++) {
	//		printf("%3d  ",(i*30)>>1);
	//
	//		for (int j = 28; j >= 0; j -= 2) {
	//			if (j != 28) {
	//				printf(":");
	//			}
	//			printf("%01x",(ip[i] >> j) & 0x3);
	//		}
	//
	//		printf("\n");
	//	}

	traceQOut = 0;
	traceQIn = 0;

	caType = catype;

	switch (catype) {
	case TraceDqrProfiler::CATRACE_VECTOR:
		traceQSize = 512;
		caTraceQ = new CATraceQItem[traceQSize];
		break;
	case TraceDqrProfiler::CATRACE_INSTRUCTION:
		traceQSize = 0;
		caTraceQ = nullptr;
		break;
	case TraceDqrProfiler::CATRACE_NONE:
		traceQSize = 0;
		caTraceQ = nullptr;
		status = TraceDqrProfiler::DQERR_ERR;

		printf("Error: ProfilerCATrace::ProfilerCATrace(): invalid trace type CATRACE_NONE\n");
		return;
	}

	TraceDqrProfiler::DQErr rc;

	rc = parseNextCATraceRec(catr);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		printf("Error: ProfilerCATrace::ProfilerCATrace(): Error parsing first CA trace record\n");
		status = rc;
	}
	else {
		status = TraceDqrProfiler::DQERR_OK;
	}

	startAddr = catr.address;
};

ProfilerCATrace::~ProfilerCATrace()
{
	if (caBuffer != nullptr) {
		delete[] caBuffer;
		caBuffer = nullptr;
	}

	caBufferSize = 0;
	caBufferIndex = 0;
}

TraceDqrProfiler::DQErr ProfilerCATrace::rewind()
{
	TraceDqrProfiler::DQErr rc;

	// this function needs to work for both CA instruction and CA Vector

	caBufferIndex = 0;

	catr.offset = 0;
	catr.address = 0;

	rc = parseNextCATraceRec(catr);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		printf("Error: ProfilerCATrace::rewind(): Error parsing first CA trace record\n");
		status = rc;
	}
	else {
		status = TraceDqrProfiler::DQERR_OK;
	}

	startAddr = catr.address;

	traceQOut = 0;
	traceQIn = 0;

	return status;
}

TraceDqrProfiler::DQErr ProfilerCATrace::dumpCurrentCARecord(int level)
{
	switch (level) {
	case 0:
		catr.dump();
		break;
	case 1:
		catr.dumpWithCycle();
		break;
	default:
		printf("Error: ProfilerCATrace::dumpCurrentCARecord(): invalid level %d\n", level);
		return TraceDqrProfiler::DQERR_ERR;
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr ProfilerCATrace::packQ()
{
	int src;
	int dst;

	dst = traceQOut;
	src = traceQOut;

	while ((dst != traceQIn) && (src != traceQIn)) { // still have stuff in Q
		// find next empty record

		while ((dst != traceQIn) && (caTraceQ[dst].record != 0)) {
			// look for an empty slot

			dst += 1;
			if (dst >= traceQSize) {
				dst = 0;
			}
		}

		if (dst != traceQIn) {
			// dst is an empty slot

			// now find next valid record

			src = dst + 1;
			if (src >= traceQSize) {
				src = 0;
			}

			while ((src != traceQIn) && (caTraceQ[src].record == 0)) {
				// look for a record with data in it to move

				src += 1;
				if (src >= traceQSize) {
					src = 0;
				}
			}

			if (src != traceQIn) {
				caTraceQ[dst] = caTraceQ[src];
				caTraceQ[src].record = 0; // don't forget to mark this record as empty!

				// zero out the q depth stats fields

				caTraceQ[src].qDepth = 0;
				caTraceQ[src].arithInProcess = 0;
				caTraceQ[src].loadInProcess = 0;
				caTraceQ[src].storeInProcess = 0;
			}
		}
	}

	// dst either points to traceQIn, or the last full record

	if (dst != traceQIn) {
		// update traceQin

		dst += 1;
		if (dst >= traceQSize) {
			dst = 0;
		}
		traceQIn = dst;
	}

	return TraceDqrProfiler::DQERR_OK;
}

int ProfilerCATrace::roomQ()
{
	if (traceQIn == traceQOut) {
		return traceQSize - 1;
	}

	if (traceQIn < traceQOut) {
		return traceQOut - traceQIn - 1;
	}

	return traceQSize - traceQIn + traceQOut - 1;
}

TraceDqrProfiler::DQErr ProfilerCATrace::addQ(uint32_t data, uint32_t t)
{
	// first see if there is enough room in the Q for 5 new entries

	int r;

	r = roomQ();

	if (r < 5) {
		TraceDqrProfiler::DQErr rc;

		rc = packQ();
		if (rc != TraceDqrProfiler::DQERR_OK) {
			return rc;
		}

		r = roomQ();
		if (r < 5) {
			printf("Error: addQ(): caTraceQ[] full\n");

			dumpCAQ();

			return TraceDqrProfiler::DQERR_ERR;
		}
	}

	for (int i = 0; i < 5; i++) {
		uint8_t rec;

		rec = (uint8_t)(data >> (6 * (4 - i))) & 0x3f;
		if (rec != 0) {
			caTraceQ[traceQIn].record = rec;
			caTraceQ[traceQIn].cycle = t;

			// zero out the q depth stats fields

			caTraceQ[traceQIn].qDepth = 0;
			caTraceQ[traceQIn].arithInProcess = 0;
			caTraceQ[traceQIn].loadInProcess = 0;
			caTraceQ[traceQIn].storeInProcess = 0;

			traceQIn += 1;
			if (traceQIn >= traceQSize) {
				traceQIn = 0;
			}
		}

		t += 1;
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr ProfilerCATrace::parseNextVectorRecord(int& newDataStart)
{
	uint32_t cycles;
	uint32_t record;
	TraceDqrProfiler::DQErr rc;

	// get another CA Vector record (32 bits) from the catr object and add to traceQ

	int numConsumed;
	numConsumed = 0;

	while (numConsumed == 0) {
		numConsumed = catr.consumeCAVector(record, cycles);
		if (numConsumed == 0) {
			// need to read another record

			rc = parseNextCATraceRec(catr); // this will reload catr.data[]
			if (rc != TraceDqrProfiler::DQERR_OK) {
				status = rc;
				return rc;
			}
		}
	}

	newDataStart = traceQIn;

	cycles += blockRecNum * 5 * 32;

	rc = addQ(record, cycles);

	status = rc;

	return rc;
}

TraceDqrProfiler::DQErr ProfilerCATrace::consumeCAInstruction(uint32_t& pipe, uint32_t& cycles)
{
	// Consume next pipe flag. Reloads catr.data[] from caBuffer if needed

	int numConsumed;
	numConsumed = 0;

	TraceDqrProfiler::DQErr rc;

	//	printf("ProfilerCATrace::consumeCAInstruction()\n");

	while (numConsumed == 0) {
		numConsumed = catr.consumeCAInstruction(pipe, cycles);
		//		printf("ProfilerCATrace::consumeCAInstruction(): num consumed: %d\n",numConsumed);

		if (numConsumed == 0) {
			// need to read another record

			rc = parseNextCATraceRec(catr);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				status = rc;
				return rc;
			}
		}
	}

	cycles += blockRecNum * 15 * 32;

	//	printf("ProfilerCATrace::consumeCAInstruction(): cycles: %d\n",cycles);

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr ProfilerCATrace::consumeCAPipe(int& QStart, uint32_t& cycles, uint32_t& pipe)
{
	if (caTraceQ == nullptr) {
		return TraceDqrProfiler::DQERR_ERR;
	}

	// first look for pipe info in Q

	// look in Q and see if record with matching type is found

	while (QStart != traceQIn) {
		if ((caTraceQ[QStart].record & TraceDqrProfiler::CAVFLAG_V0) != 0) {
			pipe = TraceDqrProfiler::CAFLAG_PIPE0;
			cycles = caTraceQ[QStart].cycle;
			caTraceQ[QStart].record &= ~TraceDqrProfiler::CAVFLAG_V0;

			//			QStart += 1;
			//			if (QStart >= traceQSize) {
			//				QStart = 0;
			//			}

			return TraceDqrProfiler::DQERR_OK;
		}

		if ((caTraceQ[QStart].record & TraceDqrProfiler::CAVFLAG_V1) != 0) {
			pipe = TraceDqrProfiler::CAFLAG_PIPE1;
			cycles = caTraceQ[QStart].cycle;
			caTraceQ[QStart].record &= ~TraceDqrProfiler::CAVFLAG_V1;

			//			QStart += 1;
			//			if (QStart >= traceQSize) {
			//				QStart = 0;
			//			}

			return TraceDqrProfiler::DQERR_OK;
		}

		QStart += 1;

		if (QStart >= traceQSize) {
			QStart = 0;
		}
	}

	// otherwise, start reading records and adding them to the Q until
	// matching type is found

	TraceDqrProfiler::DQErr rc;

	for (;;) {
		// get next record

		rc = parseNextVectorRecord(QStart);	// reads a record and adds it to the Q (adds five entries to the Q. Packs the Q if needed
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;
			return rc;
		}

		while (QStart != traceQIn) {
			if ((caTraceQ[QStart].record & TraceDqrProfiler::CAVFLAG_V0) != 0) {
				pipe = TraceDqrProfiler::CAFLAG_PIPE0;
				cycles = caTraceQ[QStart].cycle;
				caTraceQ[QStart].record &= ~TraceDqrProfiler::CAVFLAG_V0;

				//				QStart += 1;
				//				if (QStart >= traceQSize) {
				//					QStart = 0;
				//				}

				return TraceDqrProfiler::DQERR_OK;
			}

			if ((caTraceQ[QStart].record & TraceDqrProfiler::CAVFLAG_V1) != 0) {
				pipe = TraceDqrProfiler::CAFLAG_PIPE1;
				cycles = caTraceQ[QStart].cycle;
				caTraceQ[QStart].record &= ~TraceDqrProfiler::CAVFLAG_V1;

				//				QStart += 1;
				//				if (QStart >= traceQSize) {
				//					QStart = 0;
				//				}

				return TraceDqrProfiler::DQERR_OK;
			}

			QStart += 1;
			if (QStart >= traceQSize) {
				QStart = 0;
			}
		}
	}

	return TraceDqrProfiler::DQERR_ERR;
}

TraceDqrProfiler::DQErr ProfilerCATrace::consumeCAVector(int& QStart, TraceDqrProfiler::CAVectorTraceFlags type, uint32_t& cycles, uint8_t& qInfo, uint8_t& arithInfo, uint8_t& loadInfo, uint8_t& storeInfo)
{
	if (caTraceQ == nullptr) {
		return TraceDqrProfiler::DQERR_ERR;
	}

	// first look for pipe info in Q

	// look in Q and see if record with matching type is found

	TraceDqrProfiler::DQErr rc;

	// QStart will be either traceQOut or after traceQOut

	if (QStart == traceQIn) {
		// get next record

		rc = parseNextVectorRecord(QStart);	// reads a record and adds it to the Q (adds five entries to the Q. Packs the Q if needed
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return rc;
		}
	}

	// we want the stats below at the beginning of the Q, not the end, so we grab them here!

	uint8_t tQInfo = caTraceQ[QStart].qDepth;
	uint8_t tArithInfo = caTraceQ[QStart].arithInProcess;
	uint8_t tLoadInfo = caTraceQ[QStart].loadInProcess;
	uint8_t tStoreInfo = caTraceQ[QStart].storeInProcess;

	while (QStart != traceQIn) {
		switch (type) { // type is what we are looking for. When we find a VISTART in the Q, it means one was removed from the Q!
		case TraceDqrProfiler::CAVFLAG_VISTART:
			caTraceQ[QStart].qDepth += 1;
			break;
		case TraceDqrProfiler::CAVFLAG_VIARITH:
			caTraceQ[QStart].arithInProcess += 1;
			break;
		case TraceDqrProfiler::CAVFLAG_VISTORE:
			caTraceQ[QStart].storeInProcess += 1;
			break;
		case TraceDqrProfiler::CAVFLAG_VILOAD:
			caTraceQ[QStart].loadInProcess += 1;
			break;
		default:
			printf("Error: ProfilerCATrace::consumeCAVector(): invalid type: %08x\n", type);
			return TraceDqrProfiler::DQERR_ERR;
		}

		if ((caTraceQ[QStart].record & type) != 0) { // found what we were looking for in the q
			cycles = caTraceQ[QStart].cycle;
			caTraceQ[QStart].record &= ~type;

			switch (type) {
			case TraceDqrProfiler::CAVFLAG_VISTART:
				tQInfo += 1;
				break;
			case TraceDqrProfiler::CAVFLAG_VIARITH:
				tArithInfo += 1;
				break;
			case TraceDqrProfiler::CAVFLAG_VISTORE:
				tStoreInfo += 1;
				break;
			case TraceDqrProfiler::CAVFLAG_VILOAD:
				tLoadInfo += 1;
				break;
			default:
				printf("Error: ProfilerCATrace::consumeCAVector(): invalid type: %08x\n", type);
				return TraceDqrProfiler::DQERR_ERR;
			}

			qInfo = tQInfo;
			arithInfo = tArithInfo;
			loadInfo = tLoadInfo;
			storeInfo = tStoreInfo;

			QStart += 1;
			if (QStart >= traceQSize) {
				QStart = 0;
			}

			return TraceDqrProfiler::DQERR_OK;
		}

		QStart += 1;

		if (QStart >= traceQSize) {
			QStart = 0;
		}
	}


	// otherwise, start reading records and adding them to the Q until
	// matching type is found

	for (;;) {
		// get next record

		rc = parseNextVectorRecord(QStart);	// reads a record and adds it to the Q (adds five entries to the Q. Packs the Q if needed
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return rc;
		}

		while (QStart != traceQIn) {
			switch (type) {
			case TraceDqrProfiler::CAVFLAG_VISTART:
				caTraceQ[QStart].qDepth += 1;
				break;
			case TraceDqrProfiler::CAVFLAG_VIARITH:
				caTraceQ[QStart].arithInProcess += 1;
				break;
			case TraceDqrProfiler::CAVFLAG_VISTORE:
				caTraceQ[QStart].storeInProcess += 1;
				break;
			case TraceDqrProfiler::CAVFLAG_VILOAD:
				caTraceQ[QStart].loadInProcess += 1;
				break;
			default:
				printf("Error: ProfilerCATrace::consumeCAVector(): invalid type: %08x\n", type);
				return TraceDqrProfiler::DQERR_ERR;
			}

			if ((caTraceQ[QStart].record & type) != 0) {
				cycles = caTraceQ[QStart].cycle;
				caTraceQ[QStart].record &= ~type;

				switch (type) {
				case TraceDqrProfiler::CAVFLAG_VISTART:
					tQInfo += 1;
					break;
				case TraceDqrProfiler::CAVFLAG_VIARITH:
					tArithInfo += 1;
					break;
				case TraceDqrProfiler::CAVFLAG_VISTORE:
					tStoreInfo += 1;
					break;
				case TraceDqrProfiler::CAVFLAG_VILOAD:
					tLoadInfo += 1;
					break;
				default:
					printf("Error: ProfilerCATrace::consumeCAVector(): invalid type: %08x\n", type);
					return TraceDqrProfiler::DQERR_ERR;
				}

				qInfo = tQInfo;
				arithInfo = tArithInfo;
				loadInfo = tLoadInfo;
				storeInfo = tStoreInfo;

				QStart += 1;
				if (QStart >= traceQSize) {
					QStart = 0;
				}

				return TraceDqrProfiler::DQERR_OK;
			}

			QStart += 1;

			if (QStart >= traceQSize) {
				QStart = 0;
			}
		}
	}

	return TraceDqrProfiler::DQERR_ERR;
}

void ProfilerCATrace::dumpCAQ()
{
	printf("dumpCAQ(): traceQSize: %d traceQOut: %d traceQIn: %d\n", traceQSize, traceQOut, traceQIn);

	for (int i = traceQOut; i != traceQIn;) {
		printf("Q[%d]: %4d %02x", i, caTraceQ[i].cycle, caTraceQ[i].record);

		if (caTraceQ[i].record & TraceDqrProfiler::CAVFLAG_V0) {
			printf(" V0");
		}
		else {
			printf("   ");
		}

		if (caTraceQ[i].record & TraceDqrProfiler::CAVFLAG_V1) {
			printf(" V1");
		}
		else {
			printf("   ");
		}

		if (caTraceQ[i].record & TraceDqrProfiler::CAVFLAG_VISTART) {
			printf(" VISTART");
		}
		else {
			printf("        ");
		}

		if (caTraceQ[i].record & TraceDqrProfiler::CAVFLAG_VIARITH) {
			printf(" VIARITH");
		}
		else {
			printf("         ");
		}

		if (caTraceQ[i].record & TraceDqrProfiler::CAVFLAG_VISTORE) {
			printf(" VSTORE");
		}
		else {
			printf("       ");
		}

		if (caTraceQ[i].record & TraceDqrProfiler::CAVFLAG_VILOAD) {
			printf(" VLOAD\n");
		}
		else {
			printf("       \n");
		}

		i += 1;
		if (i >= traceQSize) {
			i = 0;
		}
	}
}

TraceDqrProfiler::DQErr ProfilerCATrace::consume(uint32_t& caFlags, TraceDqrProfiler::InstType iType, uint32_t& pipeCycles, uint32_t& viStartCycles, uint32_t& viFinishCycles, uint8_t& qDepth, uint8_t& arithDepth, uint8_t& loadDepth, uint8_t& storeDepth)
{
	int qStart;

	TraceDqrProfiler::DQErr rc;

	//	printf("ProfilerCATrace::consume()\n");

	if (status != TraceDqrProfiler::DQERR_OK) {
		return status;
	}

	uint8_t tQDepth;
	uint8_t tArithDepth;
	uint8_t tLoadDepth;
	uint8_t tStoreDepth;

	switch (caType) {
	case TraceDqrProfiler::CATRACE_NONE:
		printf("Error: ProfilerCATrace::consume(): invalid trace type CATRACE_NONE\n");
		return TraceDqrProfiler::DQERR_ERR;
	case TraceDqrProfiler::CATRACE_INSTRUCTION:
		rc = consumeCAInstruction(caFlags, pipeCycles);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;
			return rc;
		}

		qDepth = 0;
		arithDepth = 0;
		loadDepth = 0;
		storeDepth = 0;
		break;
	case TraceDqrProfiler::CATRACE_VECTOR:
		// get pipe

		qStart = traceQOut;

		rc = consumeCAPipe(qStart, pipeCycles, caFlags);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;
			return status;
		}

		switch (iType) {
		case TraceDqrProfiler::INST_VECT_ARITH:
			rc = consumeCAVector(qStart, TraceDqrProfiler::CAVFLAG_VISTART, viStartCycles, qDepth, tArithDepth, tLoadDepth, tStoreDepth);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				status = rc;
				return rc;
			}

			rc = consumeCAVector(qStart, TraceDqrProfiler::CAVFLAG_VIARITH, viFinishCycles, tQDepth, arithDepth, loadDepth, storeDepth);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				status = rc;
				return rc;
			}

			caFlags |= TraceDqrProfiler::CAFLAG_VSTART | TraceDqrProfiler::CAFLAG_VARITH;

			if (profiler_globalDebugFlag) {
				printf("ProfilerCATrace::consume(): INST_VECT_ARITH consumed vector instruction. Current qStart: %d traceQOut: %d traceQIn: %d\n", qStart, traceQOut, traceQIn);
				printf("vector: viFinishCycles: %d\n", viFinishCycles);
				dumpCAQ();
			}
			break;
		case TraceDqrProfiler::INST_VECT_LOAD:
			rc = consumeCAVector(qStart, TraceDqrProfiler::CAVFLAG_VISTART, viStartCycles, qDepth, tArithDepth, tLoadDepth, tStoreDepth);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				status = rc;
				return rc;
			}

			rc = consumeCAVector(qStart, TraceDqrProfiler::CAVFLAG_VILOAD, viFinishCycles, tQDepth, arithDepth, loadDepth, storeDepth);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				status = rc;
				return rc;
			}

			caFlags |= TraceDqrProfiler::CAFLAG_VSTART | TraceDqrProfiler::CAFLAG_VLOAD;

			if (profiler_globalDebugFlag) {
				printf("ProfilerCATrace::consume(): INST_VECT_LOAD consumed vector instruction. Current qStart: %d traceQOut: %d traceQIn: %d\n", qStart, traceQOut, traceQIn);
				printf("vector: viFinishCycles: %d\n", viFinishCycles);
				dumpCAQ();
			}
			break;
		case TraceDqrProfiler::INST_VECT_STORE:
			rc = consumeCAVector(qStart, TraceDqrProfiler::CAVFLAG_VISTART, viStartCycles, qDepth, tArithDepth, tLoadDepth, tStoreDepth);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				status = rc;
				return rc;
			}

			rc = consumeCAVector(qStart, TraceDqrProfiler::CAVFLAG_VISTORE, viFinishCycles, tQDepth, arithDepth, loadDepth, storeDepth);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				status = rc;
				return rc;
			}

			caFlags |= TraceDqrProfiler::CAFLAG_VSTART | TraceDqrProfiler::CAFLAG_VSTORE;

			if (profiler_globalDebugFlag) {
				printf("ProfilerCATrace::consume(): INST_VECT_STORE consumed vector instruction. Current qStart: %d traceQOut: %d traceQIn: %d\n", qStart, traceQOut, traceQIn);
				printf("vector: viFinishCycles: %d\n", viFinishCycles);
				dumpCAQ();
			}
			break;
		case TraceDqrProfiler::INST_VECT_AMO:
			rc = consumeCAVector(qStart, TraceDqrProfiler::CAVFLAG_VISTART, viStartCycles, qDepth, tArithDepth, tLoadDepth, tStoreDepth);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				status = rc;
				return rc;
			}

			rc = consumeCAVector(qStart, TraceDqrProfiler::CAVFLAG_VILOAD, viFinishCycles, tQDepth, arithDepth, loadDepth, storeDepth);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				status = rc;
				return rc;
			}

			caFlags |= TraceDqrProfiler::CAFLAG_VSTART | TraceDqrProfiler::CAFLAG_VLOAD;

			if (profiler_globalDebugFlag) {
				printf("ProfilerCATrace::consume(): INST_VECT_AMO consumed vector instruction. Current qStart: %d traceQOut: %d traceQIn: %d\n", qStart, traceQOut, traceQIn);
				printf("vector: viFinishCycles: %d\n", viFinishCycles);
				dumpCAQ();
			}
			break;
		case TraceDqrProfiler::INST_VECT_AMO_WW:
			rc = consumeCAVector(qStart, TraceDqrProfiler::CAVFLAG_VISTART, viStartCycles, qDepth, tArithDepth, tLoadDepth, tStoreDepth);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				status = rc;
				return rc;
			}

			rc = consumeCAVector(qStart, TraceDqrProfiler::CAVFLAG_VILOAD, viFinishCycles, tQDepth, arithDepth, loadDepth, storeDepth);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				status = rc;
				return rc;
			}

			rc = consumeCAVector(qStart, TraceDqrProfiler::CAVFLAG_VISTORE, viFinishCycles, tQDepth, tArithDepth, tLoadDepth, tStoreDepth);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				status = rc;
				return rc;
			}

			caFlags |= TraceDqrProfiler::CAFLAG_VSTART | TraceDqrProfiler::CAFLAG_VLOAD | TraceDqrProfiler::CAFLAG_VSTORE;

			if (profiler_globalDebugFlag) {
				printf("ProfilerCATrace::consume(): INST_VECT_AMO consumed vector instruction. Current qStart: %d traceQOut: %d traceQIn: %d\n", qStart, traceQOut, traceQIn);
				printf("vector: viFinishCycles: %d\n", viFinishCycles);
				dumpCAQ();
			}
			break;
		case TraceDqrProfiler::INST_VECT_CONFIG:
			break;
		default:
			break;
		}

		// update traceQOut for vector traces

		while ((caTraceQ[traceQOut].record == 0) && (traceQOut != traceQIn)) {
			traceQOut += 1;
			if (traceQOut >= traceQSize) {
				traceQOut = 0;
			}
		}
		break;
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::ADDRESS ProfilerCATrace::getCATraceStartAddr()
{
	// of course it ins't this simple. If bit 29 in data[0] is 0, the start address is actually the address of the next
	// instruction! To compute that, we must know the size of the instruction at the reported address. And to make things
	// worse, if that instruction is a conditional branch or an indirect jump (like a return), we can't compute the next
	// address because there is not instruction trace info for that instruction!

	return startAddr;
}

TraceDqrProfiler::DQErr ProfilerCATrace::parseNextCATraceRec(ProfilerCATraceRec& car)
{
	// Reload all 32 catr.data[] records from the raw caBuffer[] data. Update caBufferIndex to start of next record in raw data
	// Works for CAInstruction and CAVector traces

	// needs to update offset and blockRecordNum as well!

	if (status != TraceDqrProfiler::DQERR_OK) {
		return status;
	}

	if ((int)caBufferIndex > (int)(caBufferSize - sizeof(uint32_t))) {
		status = TraceDqrProfiler::DQERR_EOF;
		return TraceDqrProfiler::DQERR_EOF;
	}

	uint32_t d = 0;
	bool firstRecord;

	if (caBufferIndex == 0) {
		// find start of first message (in case buffer wrapped)
		uint32_t last;

		firstRecord = true;

		do {
			last = d >> 30;
			d = *(uint32_t*)(&caBuffer[caBufferIndex]);
			caBufferIndex += sizeof(uint32_t);

			if ((int)caBufferIndex > (int)(caBufferSize - sizeof(uint32_t))) {
				status = TraceDqrProfiler::DQERR_EOF;
				return TraceDqrProfiler::DQERR_EOF;
			}
		} while (((d >> 30) != 0x3) && (last != 0));
	}
	else {
		firstRecord = false;

		// need to get first word into d
		d = *(uint32_t*)(&caBuffer[caBufferIndex]);
		caBufferIndex += sizeof(uint32_t);
	}

	// make sure there are at least 31 more 32 bit records in the caBuffer. If not, EOF

	if ((int)caBufferIndex > (int)(caBufferSize - sizeof(uint32_t) * 31)) {
		return TraceDqrProfiler::DQERR_EOF;
	}

	TraceDqrProfiler::ADDRESS addr;
	addr = 0;

	car.data[0] = d & 0x3fffffff;

	for (int i = 1; i < 32; i++) {
		d = *(uint32_t*)(&caBuffer[caBufferIndex]);
		caBufferIndex += sizeof(uint32_t);

		// don't need to check caBufferIndex for EOF because of the check before for loop

		addr |= (((TraceDqrProfiler::ADDRESS)(d >> 30)) << 2 * (i - 1));
		car.data[i] = d & 0x3fffffff;
	}

	if (firstRecord != false) {
		car.data[0] |= (1 << 29); // set the pipe0 finish flag for first bit of trace file (vector or instruction)
		blockRecNum = 0;
	}
	else {
		blockRecNum += 1;
	}

	car.address = addr;
	car.offset = 0;

	return TraceDqrProfiler::DQERR_OK;
}
#if 1
// might need to add binary struct at beginning of metadata file??

static const char* const CTFMetadataHeader =
"/* PROFILER_CTF 1.8 */\n"
"\n";

static const char* const CTFMetadataTypeAlias =
"typealias integer {size = 8; align = 8; signed = false; } := uint8_t;\n"
"typealias integer {size = 16; align = 8; signed = false; } := uint16_t;\n"
"typealias integer {size = 32; align = 8; signed = false; } := uint32_t;\n"
"typealias integer {size = 64; align = 8; signed = false; } := uint64_t;\n"
"typealias integer {size = 64; align = 8; signed = false; } := unsigned long;\n"
"typealias integer {size = 5; align = 8; signed = false; } := uint5_t;\n"
"typealias integer {size = 27; align = 8; signed = false; } := uint27_t;\n"
"\n";

static const char* const CTFMetadataTraceDef =
"trace {\n"
"\tmajor = 1;\n"
"\tminor = 8;\n"
"\tbyte_order = le;\n"
"\tpacket.header := struct {\n"
"\t\tuint32_t magic;\n"
"\t\tuint32_t stream_id;\n"
"\t};\n"
"};\n"
"\n";

static const char* const CTFMetadataEnvDef =
"env {\n"
"\tdomain = \"ust\";\n"
"\ttracer_name = \"lttng-ust\";\n"
"\ttracer_major = 2;\n"
"\ttracer_minor = 11;\n"
"\ttracer_buffering_scheme = \"uid\";\n"
"\ttracer_buffering_id = 1000;\n"
"\tarchitecture_bit_width = %d;\n"
"\ttrace_name = \"%s\";\n"
"\ttrace_creation_datetime = \"%s\";\n"
"\thostname = \"%s\";\n"
"};\n"
"\n";

static const char* const CTFMetadataClockDef =
"clock {\n"
"\tname = \"monotonic\";\n"
"\tuuid = \"cb35f5a5-f0a6-441f-b5c7-c7fb50c2e051\";\n"
"\tdescription = \"Monotonic Clock\";\n"
"\tfreq = %d; /* Frequency, in Hz */\n"
"\t/* clock value offset from Epoch is: offset * (1/freq) */\n"
"\toffset = %lld;\n"
"};\n"
"\n"
"typealias integer {\n"
"\tsize = 27; align = 1; signed = false;\n"
"\tmap = clock.monotonic.value;\n"
"} := uint27_clock_monotonic_t;\n"
"\n"
"typealias integer {\n"
"\tsize = 32; align = 8; signed = false;\n"
"\tmap = clock.monotonic.value;\n"
"} := uint32_clock_monotonic_t;\n"
"\n"
"typealias integer {\n"
"\tsize = 64; align = 8; signed = false;\n"
"\tmap = clock.monotonic.value;\n"
"} := uint64_clock_monotonic_t;\n"
"\n";

static const char* const CTFMetadataPacketContext =
"struct packet_context {\n"
"\tuint64_clock_monotonic_t timestamp_begin;\n"
"\tuint64_clock_monotonic_t timestamp_end;\n"
"\tuint64_t content_size;\n"
"\tuint64_t packet_size;\n"
"\tuint64_t packet_seq_num;\n"
"\tunsigned long events_discarded;\n"
"\tuint32_t cpu_id;\n"
"};\n"
"\n";

static const char* const CTFMetadataEventHeaders =
"struct event_header_compact {\n"
"\tenum : uint5_t { compact = 0 ... 30, extended = 31 } id;\n"
"\tvariant <id> {\n"
"\t\tstruct {\n"
"\t\t\tuint27_clock_monotonic_t timestamp;\n"
"\t\t} compact;\n"
"\t\tstruct {\n"
"\t\t\tuint32_t id;\n"
"\t\t\tuint64_clock_monotonic_t timestamp;\n"
"\t\t} extended;\n"
"\t} v;\n"
"} align(8);\n"
"\n"
"struct event_header_large {\n"
"\tenum : uint16_t { compact = 0 ... 65534, extended = 65535 } id;\n"
"\tvariant <id> {\n"
"\t\tstruct {\n"
"\t\t\tuint32_clock_monotonic_t timestamp;\n"
"\t\t} compact;\n"
"\t\tstruct {\n"
"\t\t\tuint32_t id;\n"
"\t\t\tuint64_clock_monotonic_t timestamp;\n"
"\t\t} extended;\n"
"\t} v;\n"
"} align(8);\n"
"\n";

static const char* const CTFMetadataStreamDef =
"stream {\n"
"\tid = 0;\n"
"\tevent.header := struct event_header_large;\n"
"\tpacket.context := struct packet_context;\n"
"\tevent.context := struct {\n"
"\t\tinteger { size = 32; align = 8; signed = 1; encoding = none; base = 10; } _vpid;\n"
"\t\tinteger { size = 32; align = 8; signed = 1; encoding = none; base = 10; } _vtid;\n"
"\t\tinteger { size = 8; align = 8; signed = 1; encoding = UTF8; base = 10; } _procname[17];\n"
"\t};\n"
"};\n"
"\n";

static const char* const CTFMetadataCallEventDef =
"event {\n"
"\tname = \"lttng_ust_cyg_profile:func_entry\";\n"
"\tid = 1;\n"
"\tstream_id = 0;\n"
"\tloglevel = 12;\n"
"\tfields := struct {\n"
"\t\tinteger { size = 64; align = 8; signed = 0; encoding = none; base = 16; } _addr;\n"
"\t\tinteger { size = 64; align = 8; signed = 0; encoding = none; base = 16; } _call_site;\n"
"\t};\n"
"};\n"
"\n";

static const char* const CTFMetadataRetEventDef =
"event {\n"
"\tname = \"lttng_ust_cyg_profile:func_exit\";\n"
"\tid = 2;\n"
"\tstream_id = 0;\n"
"\tloglevel = 12;\n"
"\tfields := struct {\n"
"\t\tinteger { size = 64; align = 8; signed = 0; encoding = none; base = 16; } _addr;\n"
"\t\tinteger { size = 64; align = 8; signed = 0; encoding = none; base = 16; } _call_site;\n"
"\t};\n"
"};\n"
"\n";

static const char* const CTFMetadataStatedumpStart =
"event {\n"
"\tname = \"lttng_ust_statedump:start\";\n"
"\tid = 3;\n"
"\tstream_id = 0;\n"
"\tloglevel = 13;\n"
"\tfields := struct {\n"
"\t};\n"
"};\n"
"\n";

static const char* const CTFMetadataStatedumpBinInfo =
"event {\n"
"\tname = \"lttng_ust_statedump:bin_info\";\n"
"\tid = 4;\n"
"\tstream_id = 0;\n"
"\tloglevel = 13;\n"
"\tfields := struct {\n"
"\t\tinteger { size = 64; align = 8; signed = 0; encoding = none; base = 16; } _baddr;\n"
"\t\tinteger { size = 64; align = 8; signed = 0; encoding = none; base = 10; } _memsz;\n"
"\t\tstring _path;\n"
"\t\tinteger { size = 8; align = 8; signed = 0; encoding = none; base = 10; } _is_pic;\n"
"\t\tinteger { size = 8; align = 8; signed = 0; encoding = none; base = 10; } _has_build_id;\n"
"\t\tinteger { size = 8; align = 8; signed = 0; encoding = none; base = 10; } _has_debug_link;\n"
"\t};\n"
"};\n"
"\n";

static const char* const CTFMetadataStatedumpEnd =
"event {\n"
"\tname = \"lttng_ust_statedump:end\";\n"
"\tid = 7;\n"
"\tstream_id = 0;\n"
"\tloglevel = 13;\n"
"\tfields := struct {\n"
"\t};\n"
"};\n"
"\n";

static char CTFMetadataEnvDefDoctored[1024];
static char CTFMetadataClockDefDoctored[1024];

static const char* const CTFMetadataStructs[] = {
		CTFMetadataHeader,
		CTFMetadataTypeAlias,
		CTFMetadataTraceDef,
		CTFMetadataEnvDefDoctored,
		CTFMetadataClockDefDoctored, // need to put freq in string!
		CTFMetadataPacketContext,
		CTFMetadataEventHeaders,
		CTFMetadataStreamDef,
		CTFMetadataCallEventDef,
		CTFMetadataRetEventDef,
		CTFMetadataStatedumpStart,
		CTFMetadataStatedumpBinInfo,
		CTFMetadataStatedumpEnd
};

// class TraceSettings methods

TraceSettings::TraceSettings()
{
	odName = nullptr;
	tfName = nullptr;
	efName = nullptr;
	caName = nullptr;
	pfName = nullptr;
	caType = TraceDqrProfiler::CATRACE_NONE;
	srcBits = 0;
	numAddrBits = 0;
	itcPrintOpts = TraceDqrProfiler::ITC_OPT_NLS;
	itcPrintBufferSize = 4096;
	itcPrintChannel = 0;
	itcPerfEnable = false;
	itcPerfChannel = 6;
	itcPerfMarkerValue = (uint32_t)(('p' << 24) | ('e' << 16) | ('r' << 8) | ('f' << 0));
	cutPath = nullptr;
	srcRoot = nullptr;
	pathType = TraceDqrProfiler::PATH_TO_UNIX;
	freq = 0;
	addrDispFlags = 0;
	tsSize = 40;
	CTFConversion = false;
	eventConversionEnable = false;
	startTime = -1;
	hostName = nullptr;
	filterControlEvents = false;
}

TraceSettings::~TraceSettings()
{
	if (tfName != nullptr) {
		delete[] tfName;
		tfName = nullptr;
	}

	if (efName != nullptr) {
		delete[] efName;
		efName = nullptr;
	}

	if (caName != nullptr) {
		delete[] caName;
		caName = nullptr;
	}

	if (srcRoot != nullptr) {
		delete[] srcRoot;
		srcRoot = nullptr;
	}

	if (cutPath != nullptr) {
		delete[] cutPath;
		cutPath = nullptr;
	}

	if (hostName != nullptr) {
		delete[] hostName;
		hostName = nullptr;
	}

	if (odName != nullptr) {
		delete[] odName;
		odName = nullptr;
	}
}

TraceDqrProfiler::DQErr TraceSettings::addSettings(propertiesParser* properties)
{
	TraceDqrProfiler::DQErr rc;
	char* name = nullptr;
	char* value = nullptr;

	properties->rewind();

	do {
		rc = properties->getNextProperty(&name, &value);
		if (rc == TraceDqrProfiler::DQERR_OK) {
			//			printf("name: %s, value: %s\n",name,value);

			if (strcasecmp("rtd",name) == 0) {
				rc = propertyToTFName(value);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: TraceSettings::addSettings(): Could not set trace file name in settings\n");
					return rc;
				}
			}
			else if (strcasecmp("elf",name) == 0) {
				rc = propertyToEFName(value);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: TraceSettings::addSettings(): Could not set elf file name in settings\n");
					return rc;
				}
			}
			else if (strcasecmp("pcd",name) == 0) {
				rc = propertyToPFName(value);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: TraceSettings::addSettings(): Could net set pcd file name in settings\n");
					return rc;
				}
			}
			else if (strcasecmp("srcbits",name) == 0) {
				rc = propertyToSrcBits(value);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: TraceSettings::addSettings(): Could not set srcBits in settings\n");
					return rc;
				}
			}
			else if (strcasecmp("bits",name) == 0) {
				rc = propertyToNumAddrBits(value);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: TraceSettings::addSettings(): Could not set numAddrBits in settings\n");
					return rc;
				}
			}
			else if (strcasecmp("trace.config.boolean.enable.itc.print.processing",name) == 0) {
				rc = propertyToITCPrintOpts(value); // value should be nul, true, or false
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: TraceSettings::addSettings(): Could not set ITC print options in settings\n");
					return rc;
				}
			}
			else if (strcasecmp("trace.config.int.itc.print.channel",name) == 0) {
				rc = propertyToITCPrintChannel(value);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: TraceSettings::addSettings(): Could not set ITC print channel value in settings\n");
					return rc;
				}
			}
			else if (strcasecmp("trace.config.int.itc.print.buffersize",name) == 0) {
				rc = propertyToITCPrintBufferSize(value);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: TraceSettings::addSettings(): Could not set ITC print buffer size in settings\n");
					return rc;
				}
			}
			else if (strcasecmp("trace.config.int.itc.perf",name) == 0) {
				rc = propertyToITCPerfEnable(value);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: TraceSettings::addSettings(): Could not set ITC perf enable flag in settings\n");
					return rc;
				}
			}
			else if (strcasecmp("trace.config.int.itc.perf.channel",name) == 0) {
				rc = propertyToITCPerfChannel(value);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: TraceSettings::addSettings(): Could not set ITC perf channel in settings\n");
					return rc;
				}
			}
			else if (strcasecmp("trace.config.int.itc.perf.marker",name) == 0) {
				rc = propertyToITCPerfMarkerValue(value);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: TraceSettings::addSettings(): Could not set ITC perf marker value in settings\n");
					return rc;
				}
			}
			else if (strcasecmp("source.root",name) == 0) {
				rc = propertyToSrcRoot(value);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: TraceSettings::addSettings(): Could not set src root path in settings\n");
					return rc;
				}
			}
			else if (strcasecmp("source.cutpath",name) == 0) {
				rc = propertyToSrcCutPath(value);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: TraceSettings::addSettings(): Could not set src cut path in settings\n");
					return rc;
				}
			}
			else if (strcasecmp("caFile",name) == 0) {
				rc = propertyToCAName(value);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: TraceSettings::addSettings(): Could not set CA file name in settings\n");
					return rc;
				}
			}
			else if (strcasecmp("caType",name) == 0) {
				rc = propertyToCAType(value);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: TraceSettings::addSettings(): Could not set CA type in settings\n");
					return rc;
				}
			}
			else if (strcasecmp("TSSize",name) == 0) {
				rc = propertyToTSSize(value);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: TraceSettings::addSettings(): Could not set TS size in settings\n");
					return rc;
				}
			}
			else if (strcasecmp("pathType",name) == 0) {
				rc = propertyToPathType(value);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: TraceSettings::addSettings(): Could not set path type in settings\n");
					return rc;
				}
			}
			else if (strcasecmp("freq",name) == 0) {
				rc = propertyToFreq(value);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: TraceSettings::addSettings(): Could not set frequency in settings\n");
					return rc;
				}
			}
			else if (strcasecmp("ctfenable",name) == 0) {
				rc = propertyToCTFEnable(value);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: TraceSettings::addSettings(): Could not set ctfEnable in settings\n");
					return rc;
				}
			}
			else if (strcasecmp("eventConversionEnable",name) == 0) {
				rc = propertyToEventConversionEnable(value);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: TraceSettings::addSettings(): Could not set eventConversionEnable in settings\n");
					return rc;
				}
			}
			else if (strcasecmp("addressdisplayflags", name) == 0) {
				rc = propertyToAddrDispFlags(value);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: TraceSettings::addSettings(): Could not set address display flags in settings\n");
					return rc;
				}
			}
			else if (strcasecmp("starttime", name) == 0) {
				rc = propertyToStartTime(value);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: TraceSettings::addSettings(): Could not set start time in settings\n");
					return rc;
				}
			}
			else if (strcasecmp("hostname", name) == 0) {
				rc = propertyToHostName(value);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: TraceSettings::addSettings(): Could not set host name in settings\n");
					return rc;
				}
			}
			else if (strcasecmp("objdump",name) == 0) {
				rc = propertyToObjdumpName(value);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: TraceSettings::addSettings(): Could not set name of objdump executable in settings\n");
					return rc;
				}
			}
		}
	} while (rc == TraceDqrProfiler::DQERR_OK);

	// make sure perf and print channel are not the same!!

	if (itcPerfEnable && (itcPrintOpts & TraceDqrProfiler::ITC_OPT_PRINT)) {
		if (itcPrintChannel == itcPerfChannel) {
			printf("Error: TraceSettings::addSettings(): itcPrintChannel and itcPerfChannel cannot be the same\n");
			return TraceDqrProfiler::DQERR_ERR;
		}
	}

	if (rc != TraceDqrProfiler::DQERR_EOF) {
		printf("Error: TraceSettings::addSettings(): problem parsing properties file: %d\n", rc);
		return TraceDqrProfiler::DQERR_ERR;
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr TraceSettings::propertyToObjdumpName(const char* value)
{
	if (value != nullptr) {
		if (odName != nullptr) {
			delete[] odName;
			odName = nullptr;
		}

		int l;
		l = strlen(value) + 1;

		odName = new char[l];
		strcpy(odName, value);
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr TraceSettings::propertyToTFName(const char* value)
{
	if (value != nullptr) {
		if (tfName != nullptr) {
			delete[] tfName;
			tfName = nullptr;
		}

		int l;
		l = strlen(value) + 1;

		tfName = new char[l];
		strcpy(tfName, value);
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr TraceSettings::propertyToEFName(const char* value)
{
	if (value != nullptr) {
		if (efName != nullptr) {
			delete[] efName;
			efName = nullptr;
		}

		int l;
		l = strlen(value) + 1;

		efName = new char[l];
		strcpy(efName, value);
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr TraceSettings::propertyToPFName(const char* value)
{
	if (value != nullptr) {
		if (pfName != nullptr) {
			delete[] pfName;
			pfName = nullptr;
		}

		int l;
		l = strlen(value) + 1;

		pfName = new char[l];
		strcpy(pfName, value);
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr TraceSettings::propertyToAddrDispFlags(const char* value)
{
	if ((value != nullptr) && (value[0] != '\0')) {
		addrDispFlags = 0;

		int l;
		char* endptr;

		l = strtol(value, &endptr, 10);

		if (endptr[0] == 0) {
			numAddrBits = l;
			addrDispFlags = addrDispFlags & ~TraceDqrProfiler::ADDRDISP_WIDTHAUTO;
		}
		else if (endptr[0] == '+') {
			numAddrBits = l;
			addrDispFlags = addrDispFlags | TraceDqrProfiler::ADDRDISP_WIDTHAUTO;
		}
		else {
			return TraceDqrProfiler::DQERR_ERR;
		}

		if ((l < 32) || (l > 64)) {
			return TraceDqrProfiler::DQERR_ERR;
		}
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr TraceSettings::propertyToSrcBits(const char* value)
{
	if ((value != nullptr) && (value[0] != '\0')) {
		char* endp;

		srcBits = strtol(value, &endp, 0);

		if (endp == value) {
			return TraceDqrProfiler::DQERR_ERR;
		}
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr TraceSettings::propertyToNumAddrBits(const char* value)
{
	if ((value != nullptr) && (value[0] != '\0')) {
		char* endp;

		numAddrBits = strtol(value, &endp, 0);

		if (endp == value) {
			return TraceDqrProfiler::DQERR_ERR;
		}
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr TraceSettings::propertyToITCPrintOpts(const char* value)
{
	TraceDqrProfiler::DQErr rc;
	bool opts;

	rc = propertyToBool(value, opts);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		return rc;
	}

	if (opts) {
		itcPrintOpts = TraceDqrProfiler::ITC_OPT_PRINT | TraceDqrProfiler::ITC_OPT_NLS;
	}
	else {
		itcPrintOpts = TraceDqrProfiler::ITC_OPT_NLS;
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr TraceSettings::propertyToITCPrintChannel(const char* value)
{
	if ((value != nullptr) && (value[0] != '\0')) {
		char* endp;

		itcPrintChannel = strtol(value, &endp, 0);

		if (endp == value) {
			return TraceDqrProfiler::DQERR_ERR;
		}
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr TraceSettings::propertyToITCPrintBufferSize(const char* value)
{
	if ((value != nullptr) && (value[0] != '\0')) {
		char* endp;

		itcPrintBufferSize = strtol(value, &endp, 0);

		if (endp == value) {
			return TraceDqrProfiler::DQERR_ERR;
		}
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr TraceSettings::propertyToITCPerfEnable(const char* value)
{
	TraceDqrProfiler::DQErr rc;
	bool opts;

	rc = propertyToBool(value, opts);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		return rc;
	}

	if (opts) {
		itcPerfEnable = true;
	}
	else {
		itcPerfEnable = false;
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr TraceSettings::propertyToITCPerfChannel(const char* value)
{
	if ((value != nullptr) && (value[0] != '\0')) {
		char* endp;

		itcPerfChannel = strtol(value, &endp, 0);

		if (endp == value) {
			return TraceDqrProfiler::DQERR_ERR;
		}
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr TraceSettings::propertyToITCPerfMarkerValue(const char* value)
{
	if ((value != nullptr) && (value[0] != '\0')) {
		char* endp;

		itcPerfMarkerValue = strtol(value, &endp, 0);

		if (endp == value) {
			return TraceDqrProfiler::DQERR_ERR;
		}
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr TraceSettings::propertyToSrcRoot(const char* value)
{
	if (value != nullptr) {
		if (srcRoot != nullptr) {
			delete[] srcRoot;
			srcRoot = nullptr;
		}

		int l;
		l = strlen(value) + 1;

		srcRoot = new char[l];
		strcpy(srcRoot, value);
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr TraceSettings::propertyToSrcCutPath(const char* value)
{
	if (value != nullptr) {
		if (cutPath != nullptr) {
			delete[] cutPath;
			cutPath = nullptr;
		}

		int l;
		l = strlen(value) + 1;

		cutPath = new char[l];
		strcpy(cutPath, value);
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr TraceSettings::propertyToCAName(const char* value)
{
	if (value != nullptr) {
		int l;
		l = strlen(value) + 1;

		caName = new char[l];
		strcpy(caName, value);
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr TraceSettings::propertyToCAType(const char* value)
{
	if ((value != nullptr) && (value[0] != '\0')) {
		if (strcasecmp(value,"none") == 0) {
			caType = TraceDqrProfiler::CATRACE_NONE;
		}
		else if (strcasecmp(value,"catrace_none") == 0) {
			caType = TraceDqrProfiler::CATRACE_NONE;
		}
		else if (strcasecmp(value,"vector") == 0) {
			caType = TraceDqrProfiler::CATRACE_VECTOR;
		}
		else if (strcasecmp(value,"catrace_vector") == 0) {
			caType = TraceDqrProfiler::CATRACE_VECTOR;
		}
		else if (strcasecmp(value,"instruction") == 0) {
			caType = TraceDqrProfiler::CATRACE_INSTRUCTION;
		}
		else if (strcasecmp(value,"catrace_instruction") == 0) {
			caType = TraceDqrProfiler::CATRACE_INSTRUCTION;
		}
		else {
			return TraceDqrProfiler::DQERR_ERR;
		}
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr TraceSettings::propertyToPathType(const char* value)
{
	if ((value != nullptr) && (value[0] != '\0')) {
		if (strcasecmp("unix",value) == 0) {
			pathType = TraceDqrProfiler::PATH_TO_UNIX;
		}
		else if (strcasecmp("windows",value) == 0) {
			pathType = TraceDqrProfiler::PATH_TO_WINDOWS;
		}
		else if (strcasecmp("raw",value) == 0) {
			pathType = TraceDqrProfiler::PATH_RAW;
		}
		else {
			return TraceDqrProfiler::DQERR_ERR;
		}
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr TraceSettings::propertyToBool(const char* src, bool& value)
{
	if ((src != nullptr) && (src[0] != '\0')) {
		if (strcasecmp("true",src) == 0) {
			value = true;		}
		else if (strcasecmp("false",src) == 0) {
			value = false;
		}
		else {
			char* endp;

			value = strtol(src, &endp, 0);
			if (endp == src) {
				return TraceDqrProfiler::DQERR_ERR;
			}
		}
	}
	else {
		value = false;
	}

	return TraceDqrProfiler::DQERR_OK;
}


TraceDqrProfiler::DQErr TraceSettings::propertyToCTFEnable(const char* value)
{
	return propertyToBool(value, CTFConversion);
}

TraceDqrProfiler::DQErr TraceSettings::propertyToEventConversionEnable(const char* value)
{
	return propertyToBool(value, eventConversionEnable);
}

TraceDqrProfiler::DQErr TraceSettings::propertyToFreq(const char* value)
{
	if ((value != nullptr) && (value[0] != '\0')) {
		char* endp;

		freq = strtol(value, &endp, 0);

		if (endp == value) {
			return TraceDqrProfiler::DQERR_ERR;
		}
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr TraceSettings::propertyToStartTime(const char* value)
{
	if ((value != nullptr) && (value[0] != '\0')) {
		char* endp;

		startTime = (int64_t)strtoll(value, &endp, 0);

		if (endp == value) {
			return TraceDqrProfiler::DQERR_ERR;
		}
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr TraceSettings::propertyToHostName(const char* value)
{
	if ((value != nullptr) && (value[0] != '\0')) {
		if (hostName != nullptr) {
			delete[] hostName;
			hostName = nullptr;
		}

		int l;
		l = strlen(value) + 1;

		hostName = new char[l];
		strcpy(hostName, value);
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr TraceSettings::propertyToTSSize(const char* value)
{
	if ((value != nullptr) && (value[0] != '\0')) {
		char* endp;

		tsSize = strtol(value, &endp, 0);

		if (endp == value) {
			return TraceDqrProfiler::DQERR_ERR;
		}
	}

	return TraceDqrProfiler::DQERR_OK;
}

// class propertiesParser methods

propertiesParser::propertiesParser(const char* srcData)
{
	status = TraceDqrProfiler::DQERR_OK;

	propertiesBuff = nullptr;
	lines = nullptr;
	numLines = 0;
	nextLine = 0;
	size = 0;

	if (srcData == nullptr) {
		return;
	}

	std::ifstream  f;

	f.open(srcData, std::ifstream::binary);
	if (!f) {
		printf("Error: propertiesParser::propertiesParser(): could not open file %s for input\n", srcData);

		status = TraceDqrProfiler::DQERR_OPEN;
		return;
	}

	// get length of file:

	f.seekg(0, f.end);
	size = f.tellg();
	f.seekg(0, f.beg);

	if (size < 0) {
		printf("Error: propertiesParser::propertiesParser(): could not get size of file %s for input\n", srcData);

		f.close();

		status = TraceDqrProfiler::DQERR_OPEN;
		return;
	}

	// allocate memory:

	propertiesBuff = new char[size + 1]; // allocate an extra byte in case the file doesn't end with \n

	// read file into buffer

	f.read(propertiesBuff, size);
	int numRead = f.gcount();
	f.close();

	if (numRead != size) {
		printf("Error: propertiesParser::propertiesParser(): could not read file %s into memory\n", srcData);

		delete[] propertiesBuff;
		propertiesBuff = nullptr;
		size = 0;

		status = TraceDqrProfiler::DQERR_OPEN;
		return;
	}

	// count lines

	numLines = 0;

	for (int i = 0; i < size; i++) {
		if (propertiesBuff[i] == '\n') {
			numLines += 1;
		}
		else if (i == size - 1) {
			// last line does not have a \n
			numLines += 1;
		}
	}

	// create array of line pointers

	lines = new line[numLines];

	// initialize array of ptrs

	int l;
	int s;

	l = 0;
	s = 1;

	for (int i = 0; i < numLines; i++) {
		lines[i].line = nullptr;
		lines[i].name = nullptr;
		lines[i].value = nullptr;
	}

	for (int i = 0; i < size; i++) {
		if (s != 0) {
			lines[l].line = &propertiesBuff[i];
			l += 1;
			s = 0;
		}

		// strip out CRs and LFs

		if (propertiesBuff[i] == '\r') {
			propertiesBuff[i] = 0;
		}
		else if (propertiesBuff[i] == '\n') {
			propertiesBuff[i] = 0;
			s = 1;
		}
	}

	propertiesBuff[size] = 0;	// make sure last line is nul terminated

	if (l != numLines) {
		printf("Error: propertiesParser::propertiesParser(): Error computing line count for file %s, l:%d, lc: %d\n", srcData, l, numLines);

		delete[] lines;
		lines = nullptr;
		delete[] propertiesBuff;
		propertiesBuff = nullptr;
		size = 0;
		numLines = 0;

		status = TraceDqrProfiler::DQERR_ERR;
		return;
	}
}

propertiesParser::~propertiesParser()
{
	if (propertiesBuff != nullptr) {
		delete[] propertiesBuff;
		propertiesBuff = nullptr;
	}

	if (lines != nullptr) {
		delete[] lines;
		lines = nullptr;
	}
}

void propertiesParser::rewind()
{
	nextLine = 0;
}

TraceDqrProfiler::DQErr propertiesParser::getNextToken(char* inputText, int& startIndex, int& endIndex)
{
	if (inputText == nullptr) {
		return TraceDqrProfiler::DQERR_ERR;
	}

	// stripi ws

	bool found;

	for (found = false; !found; ) {
		switch (inputText[startIndex]) {
		case '\t':
		case ' ':
			// skip this char
			startIndex += 1;
			break;
		default:
			found = true;
			break;
		}
	}

	endIndex = startIndex;

	// check for end of line

	switch (inputText[startIndex]) {
	case '#':
	case '\0':
	case '\n':
	case '\r':
		// end of line. If end == start, nothing was found

		return TraceDqrProfiler::DQERR_OK;
	}

	// scan to end of token

	// will not start with #, =, \0, \r, \n
	// so scan until we find an end

	for (found = false; !found; ) {
		switch (inputText[endIndex]) {
		case ' ':
		case '#':
		case '\0':
		case '\n':
		case '\r':
			found = true;
			break;
		case '=':
			if (startIndex == endIndex) {
				endIndex += 1;
			}
			found = true;
			break;
		default:
			endIndex += 1;
		}
	}

	//	printf("getNextToken(): start %d, end %d ,'",startIndex,endIndex);
	//	for (int i = startIndex; i < endIndex; i++) {
	//		printf("%c",inputText[i]);
	//	}
	//	printf("'\n");

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr propertiesParser::getNextProperty(char** name, char** value)
{
	if (status != TraceDqrProfiler::DQERR_OK) {
		return status;
	}

	if (lines == nullptr) {
		status = TraceDqrProfiler::DQERR_EOF;
		return TraceDqrProfiler::DQERR_EOF;
	}

	if ((name == nullptr) || (value == nullptr)) {
		return TraceDqrProfiler::DQERR_ERR;
	}

	// if we are at the end, return EOF

	if (nextLine >= numLines) {
		return TraceDqrProfiler::DQERR_EOF;
	}

	// If this name/value pair has already been found, return it

	if ((lines[nextLine].name != nullptr) && (lines[nextLine].value != nullptr)) {
		*name = lines[nextLine].name;
		*value = lines[nextLine].value;

		nextLine += 1;

		return TraceDqrProfiler::DQERR_OK;
	}

	// get name

	int nameStart = 0;
	int nameEnd = 0;

	TraceDqrProfiler::DQErr rc;

	do {
		rc = getNextToken(lines[nextLine].line, nameStart, nameEnd);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;
			return rc;
		}

		if (nameStart == nameEnd) {
			nextLine += 1;
		}
	} while ((nameStart == nameEnd) && (nextLine < numLines));

	if (nextLine >= numLines) {
		return TraceDqrProfiler::DQERR_EOF;
	}

	// check if we got a name, or an '='

	if (((nameStart - nameEnd) == 1) && (lines[nextLine].line[nameStart] == '=')) {
		// error - name cannot be '='
		printf("Error: propertiesParser::getNextProperty(): Line %d: syntax error\n", nextLine);

		status = TraceDqrProfiler::DQERR_ERR;
		return TraceDqrProfiler::DQERR_ERR;
	}

	int eqStart = nameEnd;
	int eqEnd = nameEnd;

	// get '='
	rc = getNextToken(lines[nextLine].line, eqStart, eqEnd);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;
		return rc;
	}

	if ((eqStart == eqEnd) || ((eqEnd - eqStart) != 1) || (lines[nextLine].line[eqStart] != '=')) {
		printf("Error: propertiesParser::getNextProperty(): Line %d: expected '='\n", nextLine);

		status = TraceDqrProfiler::DQERR_ERR;
		return TraceDqrProfiler::DQERR_ERR;
	}

	// get value or end of line

	int valueStart = eqEnd;
	int valueEnd = eqEnd;

	rc = getNextToken(lines[nextLine].line, valueStart, valueEnd);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;
		return rc;
	}

	if (((valueStart - valueEnd) == 1) && (lines[nextLine].line[nameStart] == '=')) {
		// error - value cannot be '='
		printf("Error: propertiesParser::getNextProperty(): Line %d: syntax error\n", nextLine);

		status = TraceDqrProfiler::DQERR_ERR;
		return TraceDqrProfiler::DQERR_ERR;
	}

	lines[nextLine].line[nameEnd] = 0;
	lines[nextLine].name = &lines[nextLine].line[nameStart];

	*name = lines[nextLine].name;

	lines[nextLine].line[valueEnd] = 0;
	lines[nextLine].value = &lines[nextLine].line[valueStart];

	*value = lines[nextLine].value;

	nextLine += 1;

	return TraceDqrProfiler::DQERR_OK;
}

#endif
// class trace methods

TraceProfiler::TraceProfiler(char* mf_name)
{
	sfp = nullptr;
	elfReader = nullptr;
	disassembler = nullptr;
	caTrace = nullptr;
	counts = nullptr;//delete this line if compile error
	efName = nullptr;
	rtdName = nullptr;
	cutPath = nullptr;
	newRoot = nullptr;
	itcPrint = nullptr;
	nlsStrings = nullptr;
	ctf = nullptr;
	eventConverter = nullptr;
	perfConverter = nullptr;
	objdump = nullptr;

	if (mf_name == nullptr) {
		printf("Error: TraceProfiler(): mf_name argument null\n");

		cleanUp();

		status = TraceDqrProfiler::DQERR_ERR;
		return;
	}

	TraceDqrProfiler::DQErr rc;

	propertiesParser properties(mf_name);

	rc = properties.getStatus();
	if (rc != TraceDqrProfiler::DQERR_OK) {
		printf("Error: TraceProfiler(): new propertiesParser(%s) from file failed with %d\n", mf_name, rc);

		cleanUp();

		status = rc;
		return;
	}

	TraceSettings settings;

	rc = settings.addSettings(&properties);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		printf("Error: TraceProfiler(): addSettings() failed\n");

		cleanUp();

		status = rc;

		return;
	}

	rc = configure(settings);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		cleanUp();

		return;
	}

	status = TraceDqrProfiler::DQERR_OK;
}

TraceProfiler::TraceProfiler(char* tf_name, char* ef_name, int numAddrBits, uint32_t addrDispFlags, int srcBits, const char* odExe, uint32_t freq)
{
	TraceDqrProfiler::DQErr rc;
	TraceSettings ts;

	sfp = nullptr;
	elfReader = nullptr;
	disassembler = nullptr;
	caTrace = nullptr;
	counts = nullptr;//delete this line if compile error
	efName = nullptr;
	rtdName = nullptr;
	cutPath = nullptr;
	newRoot = nullptr;
	itcPrint = nullptr;
	nlsStrings = nullptr;
	ctf = nullptr;
	eventConverter = nullptr;
	perfConverter = nullptr;
	objdump = nullptr;
	m_flush_data_offset = UINT64_MAX;

	ts.propertyToTFName(tf_name);
	ts.propertyToEFName(ef_name);
	ts.propertyToObjdumpName(odExe);
	ts.numAddrBits = numAddrBits;

	ts.addrDispFlags = addrDispFlags;
	ts.srcBits = srcBits;
	ts.freq = freq;

	rc = configure(ts);

	if (rc != TraceDqrProfiler::DQERR_OK) {
		cleanUp();
	}

	status = rc;
}

TraceProfiler::~TraceProfiler()
{
	cleanUp();
}

// configure should probably take a options object that contains the seetings for all the options. Easier to add
// new options that way without the arg list getting unmanageable
#if 1

TraceDqrProfiler::DQErr TraceProfiler::configure(TraceSettings& settings)
{
	TraceDqrProfiler::DQErr rc;

	status = TraceDqrProfiler::DQERR_OK;

	sfp = nullptr;
	elfReader = nullptr;
	disassembler = nullptr;
	caTrace = nullptr;
	counts = nullptr;//delete this line if compile error
	efName = nullptr;
	rtdName = nullptr;
	cutPath = nullptr;
	newRoot = nullptr;
	itcPrint = nullptr;
	nlsStrings = nullptr;
	ctf = nullptr;
	eventConverter = nullptr;
	eventFilterMask = 0;
	perfConverter = nullptr;
	objdump = nullptr;

	syncCount = 0;
	caSyncAddr = (TraceDqrProfiler::ADDRESS)-1;

	if (settings.odName != nullptr) {
		int len;

		len = strlen(settings.odName);

		objdump = new char[len + 1];

		strcpy(objdump, settings.odName);
	}
	else {
		objdump = new char[sizeof PROFILER_DEFAULTOBJDUMPNAME + 1];
		strcpy(objdump, PROFILER_DEFAULTOBJDUMPNAME);
	}

	//if (settings.tfName == nullptr) {
	//	printf("Error: TraceProfiler::configure(): No trace file name specified\n");
	//	status = TraceDqrProfiler::DQERR_ERR;

	//	return TraceDqrProfiler::DQERR_ERR;
	//}

	traceType = TraceDqrProfiler::TRACETYPE_BTM;

	pathType = settings.pathType;

	srcbits = settings.srcBits;

	if (settings.filterControlEvents) {
		eventFilterMask = (1 << PROFILER_CTF::et_controlIndex);
	}

	analytics.setSrcBits(srcbits);

	//rtdName = new char[strlen(settings.tfName) + 1];
	//strcpy(rtdName, settings.tfName);

	sfp = new (std::nothrow) SliceFileParser(settings.tfName, srcbits);

	if (sfp == nullptr) {
		printf("Error: TraceProfiler::configure(): Could not create SliceFileParser object\n");

		status = TraceDqrProfiler::DQERR_ERR;

		return TraceDqrProfiler::DQERR_ERR;
	}

	if (sfp->getErr() != TraceDqrProfiler::DQERR_OK) {
		printf("Error: TraceProfiler::Configure(): Could not open trace file '%s' for input\n", settings.tfName);

		delete sfp;
		sfp = nullptr;

		status = TraceDqrProfiler::DQERR_ERR;

		return TraceDqrProfiler::DQERR_ERR;
	}

	if (settings.efName != nullptr) {
		int l = strlen(settings.efName) + 1;
		efName = new char[l];
		strcpy(efName, settings.efName);

		// create elf object - this also forks off objdump and parses the elf file

		elfReader = new (std::nothrow) ElfReader(settings.efName, objdump);

		if (elfReader == nullptr) {
			printf("Error: TraceProfiler::Configure(): Could not create ElfReader object\n");

			status = TraceDqrProfiler::DQERR_ERR;

			return TraceDqrProfiler::DQERR_ERR;
		}

		if (elfReader->getStatus() != TraceDqrProfiler::DQERR_OK) {
			status = TraceDqrProfiler::DQERR_ERR;
			return TraceDqrProfiler::DQERR_ERR;
		}

		// get symbol table

		Symtab* symtab;
		Section* sections;

		symtab = elfReader->getSymtab();
		if (symtab == nullptr) {
			status = TraceDqrProfiler::DQERR_ERR;
			return TraceDqrProfiler::DQERR_ERR;
		}

		sections = elfReader->getSections();
		if (sections == nullptr) {
			status = TraceDqrProfiler::DQERR_ERR;
			return TraceDqrProfiler::DQERR_ERR;
		}

		// create disassembler object

		disassembler = new (std::nothrow) Disassembler(symtab, sections, elfReader->getArchSize());
		if (disassembler == nullptr) {
			printf("Error: TraceProfiler::Configure(): Could not creat disassembler object\n");

			status = TraceDqrProfiler::DQERR_ERR;

			return TraceDqrProfiler::DQERR_ERR;
		}

		if (disassembler->getStatus() != TraceDqrProfiler::DQERR_OK) {
			status = TraceDqrProfiler::DQERR_ERR;
			return TraceDqrProfiler::DQERR_ERR;
		}

		rc = disassembler->setPathType(settings.pathType);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;
			return rc;
		}
	}
	else {
		elfReader = nullptr;
		disassembler = nullptr;
		sfp = nullptr;
	}

	for (int i = 0; (size_t)i < sizeof lastFaddr / sizeof lastFaddr[0]; i++) {
		lastFaddr[i] = 0;
	}

	for (int i = 0; (size_t)i < sizeof currentAddress / sizeof currentAddress[0]; i++) {
		currentAddress[i] = 0;
	}

	counts = new Count[DQR_PROFILER_MAXCORES];

	for (int i = 0; (size_t)i < sizeof state / sizeof state[0]; i++) {
		state[i] = TRACE_STATE_GETFIRSTSYNCMSG;
	}

	readNewTraceMessage = true;
	currentCore = 0;	// as good as eny!

	for (int i = 0; (size_t)i < sizeof lastTime / sizeof lastTime[0]; i++) {
		lastTime[i] = 0;
	}

	for (int i = 0; (size_t)i < sizeof lastCycle / sizeof lastCycle[0]; i++) {
		lastCycle[i] = 0;
	}

	for (int i = 0; (size_t)i < sizeof eCycleCount / sizeof eCycleCount[0]; i++) {
		eCycleCount[i] = 0;
	}

	instructionInfo.CRFlag = TraceDqrProfiler::isNone;
	instructionInfo.brFlags = TraceDqrProfiler::BRFLAG_none;

	instructionInfo.address = 0;
	instructionInfo.instruction = 0;
	instructionInfo.instSize = 0;

	if (settings.numAddrBits != 0) {
		instructionInfo.addrSize = settings.numAddrBits;
	}
	else if (elfReader == nullptr) {
		instructionInfo.addrSize = 0;
	}
	else {
		instructionInfo.addrSize = elfReader->getBitsPerAddress();
	}

	instructionInfo.addrDispFlags = settings.addrDispFlags;

	instructionInfo.addrPrintWidth = (instructionInfo.addrSize + 3) / 4;

	instructionInfo.addressLabel = nullptr;
	instructionInfo.addressLabelOffset = 0;

	instructionInfo.timestamp = 0;
	instructionInfo.caFlags = TraceDqrProfiler::CAFLAG_NONE;
	instructionInfo.pipeCycles = 0;
	instructionInfo.VIStartCycles = 0;
	instructionInfo.VIFinishCycles = 0;

	sourceInfo.sourceFile = nullptr;
	sourceInfo.sourceFunction = nullptr;
	sourceInfo.sourceLineNum = 0;
	sourceInfo.sourceLine = nullptr;

	freq = settings.freq;
	ProfilerNexusMessage::targetFrequency = settings.freq;

	tsSize = settings.tsSize;

	for (int i = 0; (size_t)i < sizeof enterISR / sizeof enterISR[0]; i++) {
		enterISR[i] = TraceDqrProfiler::isNone;
	}

	status = setITCPrintOptions(TraceDqrProfiler::ITC_OPT_NLS, 4096, 0);

	if (settings.itcPrintOpts != TraceDqrProfiler::ITC_OPT_NONE) {
		rc = setITCPrintOptions(settings.itcPrintOpts, settings.itcPrintBufferSize, settings.itcPrintChannel);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;
			return status;
		}
	}

	if ((settings.caName != nullptr) && (settings.caType != TraceDqrProfiler::CATRACE_NONE)) {
		rc = setCATraceFile(settings.caName, settings.caType);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;
			return status;
		}
	}

	if (settings.CTFConversion != false) {

		// Do the code below only after setting efName above

		rc = enableCTFConverter(settings.startTime, settings.hostName);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;
			return status;
		}
	}

	if (settings.eventConversionEnable != false) {

		// Do the code below only after setting efName above

		rc = enableEventConverter();
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;
			return status;
		}
	}

	if (settings.itcPerfEnable != false) {

		// verify itc print (if enabled) and perf are not using the same channel

		if ((settings.itcPrintChannel == settings.itcPerfChannel) && (settings.itcPrintOpts != TraceDqrProfiler::ITC_OPT_NONE) && (settings.itcPrintOpts != TraceDqrProfiler::ITC_OPT_NLS)) {
			printf("ITC Print Channel and ITC PerfChannel cannot be the same (%d)\n", settings.itcPrintChannel);

			status = TraceDqrProfiler::DQERR_ERR;
			return status;
		}

		// Do the code below only after setting efName above

		int perfChannel;
		uint32_t markerValue;

		perfChannel = settings.itcPerfChannel;
		markerValue = settings.itcPerfMarkerValue;

		rc = enablePerfConverter(perfChannel, markerValue);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;
			return status;
		}
	}

	if ((settings.cutPath != nullptr) || (settings.srcRoot != nullptr)) {
		rc = subSrcPath(settings.cutPath, settings.srcRoot);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return status;
		}
	}

	return status;
}
#endif
void TraceProfiler::cleanUp()
{
	if (objdump != nullptr) {
		delete[] objdump;
		objdump = nullptr;
	}

	for (int i = 0; (size_t)i < (sizeof state / sizeof state[0]); i++) {
		state[i] = TRACE_STATE_DONE;
	}

	if (sfp != nullptr) {
		delete sfp;
		sfp = nullptr;
	}

	if (elfReader != nullptr) {
		delete elfReader;
		elfReader = nullptr;
	}

	if (cutPath != nullptr) {
		delete[] cutPath;
		cutPath = nullptr;
	}

	if (newRoot != nullptr) {
		delete[] newRoot;
		newRoot = nullptr;
	}

	if (rtdName != nullptr) {
		delete[] rtdName;
		rtdName = nullptr;
	}

	if (efName != nullptr) {
		delete[] efName;
		efName = nullptr;
	}

	if (itcPrint != nullptr) {
		delete itcPrint;
		itcPrint = nullptr;
	}

	if (nlsStrings != nullptr) {
		for (int i = 0; i < 32; i++) {
			if (nlsStrings[i].format != nullptr) {
				delete[] nlsStrings[i].format;
				nlsStrings[i].format = nullptr;
			}
		}

		delete[] nlsStrings;
		nlsStrings = nullptr;
	}

	if (counts != nullptr) {
		delete[] counts;
		counts = nullptr;
	}

	if (disassembler != nullptr) {
		delete disassembler;
		disassembler = nullptr;
	}

	if (caTrace != nullptr) {
		delete caTrace;
		caTrace = nullptr;
	}

	if (ctf != nullptr) {
		delete ctf;
		ctf = nullptr;
	}

	if (eventConverter != nullptr) {
		delete eventConverter;
		eventConverter = nullptr;
	}

	if (perfConverter != nullptr) {
		delete perfConverter;
		perfConverter = nullptr;
	}
}

const char* TraceProfiler::version()
{
	return DQR_PROFILER_VERSION;
}

int TraceProfiler::decodeInstructionSize(uint32_t inst, int& inst_size)
{
	return disassembler->decodeInstructionSize(inst, inst_size);
}

int TraceProfiler::decodeInstruction(uint32_t instruction, int& inst_size, TraceDqrProfiler::InstType& inst_type, TraceDqrProfiler::Reg& rs1, TraceDqrProfiler::Reg& rd, int32_t& immediate, bool& is_branch)
{
	return disassembler->decodeInstruction(instruction, getArchSize(), inst_size, inst_type, rs1, rd, immediate, is_branch);
}

int TraceProfiler::getArchSize()
{
	if (elfReader == nullptr) {
		return 0;
	}

	return elfReader->getArchSize();
}

int TraceProfiler::getAddressSize()
{
	if (elfReader == nullptr) {
		return 0;
	}

	return elfReader->getBitsPerAddress();
}

TraceDqrProfiler::DQErr TraceProfiler::setTraceType(TraceDqrProfiler::TraceType tType)
{
	switch (tType) {
	case TraceDqrProfiler::TRACETYPE_BTM:
	case TraceDqrProfiler::TRACETYPE_HTM:
		traceType = tType;
		return TraceDqrProfiler::DQERR_OK;
	default:
		break;
	}

	return TraceDqrProfiler::DQERR_ERR;
}

TraceDqrProfiler::DQErr TraceProfiler::setPathType(TraceDqrProfiler::pathType pt)
{
	pathType = pt;

	if (disassembler != nullptr) {
		TraceDqrProfiler::DQErr rc;

		rc = disassembler->setPathType(pt);

		status = rc;
		return rc;
	}

	return TraceDqrProfiler::DQERR_ERR;
}

TraceDqrProfiler::DQErr TraceProfiler::subSrcPath(const char* cutPath, const char* newRoot)
{
	if (this->cutPath != nullptr) {
		delete[] this->cutPath;
		this->cutPath = nullptr;
	}

	if (this->newRoot != nullptr) {
		delete[] this->newRoot;
		this->newRoot = nullptr;
	}

	if (cutPath != nullptr) {
		int l = strlen(cutPath) + 1;

		this->cutPath = new char[l];
		strcpy(this->cutPath, cutPath);
	}

	if (newRoot != nullptr) {
		int l = strlen(newRoot) + 1;

		this->newRoot = new char[l];
		strcpy(this->newRoot, newRoot);
	}

	if (disassembler != nullptr) {
		TraceDqrProfiler::DQErr rc;

		rc = disassembler->subSrcPath(cutPath, newRoot);

		status = rc;
		return rc;
	}

	status = TraceDqrProfiler::DQERR_ERR;

	return TraceDqrProfiler::DQERR_ERR;
}

TraceDqrProfiler::DQErr TraceProfiler::setCATraceFile(char* caf_name, TraceDqrProfiler::CATraceType catype)
{
	caTrace = new ProfilerCATrace(caf_name, catype);

	TraceDqrProfiler::DQErr rc;
	rc = caTrace->getStatus();
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;
		return rc;
	}

	// need to sync up ca trace file and trace file. Here, or in next instruction?

	for (int i = 0; (size_t)i < sizeof state / sizeof state[0]; i++) {
		state[i] = TRACE_STATE_SYNCCATE;
	}

	return status;
}

TraceDqrProfiler::DQErr TraceProfiler::enableCTFConverter(int64_t startTime, char* hostName)
{
	if (ctf != nullptr) {
		delete ctf;
		ctf = nullptr;
	}

	if (efName == nullptr) {
		return TraceDqrProfiler::DQERR_ERR;
	}

	//ctf = new CTFConverter(efName, rtdName, 1 << srcbits, getArchSize(), freq, startTime, hostName);

	//status = ctf->getStatus();
	//if (status != TraceDqrProfiler::DQERR_OK) {
	//	return status;
	//}

	return status;
}

TraceDqrProfiler::DQErr TraceProfiler::enablePerfConverter(int perfChannel, uint32_t markerValue)
{
	if (perfConverter != nullptr) {
		delete perfConverter;
		perfConverter = nullptr;
	}

	if (efName == nullptr) {
		return TraceDqrProfiler::DQERR_ERR;
	}

	//perfConverter = new PerfConverter(efName, rtdName, disassembler, 1 << srcbits, perfChannel, markerValue, freq);

	//status = perfConverter->getStatus();
	//if (status != TraceDqrProfiler::DQERR_OK) {
	//	return status;
	//}

	return status;
}

TraceDqrProfiler::DQErr TraceProfiler::enableEventConverter()
{
	if (eventConverter != nullptr) {
		delete eventConverter;
		eventConverter = nullptr;
	}

	if (efName == nullptr) {
		return TraceDqrProfiler::DQERR_ERR;
	}

	//eventConverter = new EventConverter(efName, rtdName, disassembler, 1 << srcbits, freq);

	//status = eventConverter->getStatus();
	//if (status != TraceDqrProfiler::DQERR_OK) {
	//	return status;
	//}

	return status;
}

TraceDqrProfiler::DQErr TraceProfiler::setTSSize(int size)
{
	tsSize = size;

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::TIMESTAMP TraceProfiler::processTS(TraceDqrProfiler::tsType tstype, TraceDqrProfiler::TIMESTAMP lastTs, TraceDqrProfiler::TIMESTAMP newTs)
{
	TraceDqrProfiler::TIMESTAMP ts;

	if (tstype == TraceDqrProfiler::TS_full) {
		// add in the wrap from previous timestamps
		ts = newTs + (lastTs & (~((((TraceDqrProfiler::TIMESTAMP)1) << tsSize) - 1)));
	}
	else if (lastTs != 0) {
		ts = lastTs ^ newTs;
	}
	else {
		ts = 0;
	}

	if (ts < lastTs) {
		// adjust for wrap
		ts += ((TraceDqrProfiler::TIMESTAMP)1) << tsSize;
	}

	return ts;
}

TraceDqrProfiler::DQErr TraceProfiler::getNumBytesInSWTQ(int& numBytes)
{
	if (sfp == nullptr) {
		return TraceDqrProfiler::DQERR_ERR;
	}

	return sfp->getNumBytesInSWTQ(numBytes);
}

TraceDqrProfiler::DQErr TraceProfiler::getTraceFileOffset(int& size, int& offset)
{
	return sfp->getFileOffset(size, offset);
}

int TraceProfiler::getITCPrintMask()
{
	if (itcPrint == nullptr) {
		return 0;
	}

	return itcPrint->getITCPrintMask();
}

int TraceProfiler::getITCFlushMask()
{
	if (itcPrint == nullptr) {
		return 0;
	}

	return itcPrint->getITCFlushMask();
}

TraceDqrProfiler::ADDRESS TraceProfiler::computeAddress()
{
	switch (nm.tcode) {
	case TraceDqrProfiler::TCODE_DEBUG_STATUS:
		break;
	case TraceDqrProfiler::TCODE_DEVICE_ID:
		break;
	case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
		break;
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
		//		currentAddress = target of branch.
		break;
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
		currentAddress[currentCore] = currentAddress[currentCore] ^ (nm.indirectBranch.u_addr << 1);	// note - this is the next address!
		break;
	case TraceDqrProfiler::TCODE_DATA_WRITE:
		break;
	case TraceDqrProfiler::TCODE_DATA_READ:
		break;
	case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
		break;
	case TraceDqrProfiler::TCODE_ERROR:
		break;
	case TraceDqrProfiler::TCODE_SYNC:
		currentAddress[currentCore] = nm.sync.f_addr << 1;
		break;
	case TraceDqrProfiler::TCODE_CORRECTION:
		break;
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
		currentAddress[currentCore] = nm.directBranchWS.f_addr << 1;
		break;
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
		currentAddress[currentCore] = nm.indirectBranchWS.f_addr << 1;
		break;
	case TraceDqrProfiler::TCODE_DATA_WRITE_WS:
		break;
	case TraceDqrProfiler::TCODE_DATA_READ_WS:
		break;
	case TraceDqrProfiler::TCODE_WATCHPOINT:
		break;
	case TraceDqrProfiler::TCODE_CORRELATION:
		break;
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
		currentAddress[currentCore] = currentAddress[currentCore] ^ (nm.indirectHistory.u_addr << 1);	// note - this is the next address!
		break;
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
		currentAddress[currentCore] = nm.indirectHistoryWS.f_addr << 1;
		break;
	case TraceDqrProfiler::TCODE_RESOURCEFULL:
		break;
	default:
		break;
	}

	std::cout << "New address 0x" << std::hex << currentAddress[currentCore] << std::dec << std::endl;

	return currentAddress[currentCore];
}

TraceDqrProfiler::DQErr TraceProfiler::Disassemble(TraceDqrProfiler::ADDRESS addr)
{
	if (disassembler == nullptr) {
		printf("Error: TraceProfiler::Disassemble(): No disassembler object\n");

		status = TraceDqrProfiler::DQERR_ERR;

		return TraceDqrProfiler::DQERR_ERR;
	}

	TraceDqrProfiler::DQErr rc;

	rc = disassembler->disassemble(addr);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;
		return TraceDqrProfiler::DQERR_ERR;
	}

	// the two lines below copy each structure completely. This is probably
	// pretty inefficient, and just returning pointers and using pointers
	// would likely be better

	instructionInfo = disassembler->getInstructionInfo();
	sourceInfo = disassembler->getSourceInfo();

	return TraceDqrProfiler::DQERR_OK;
}

//const char *TraceProfiler::getSymbolByAddress(TraceDqrProfiler::ADDRESS addr)
//{
//	return symtab->getSymbolByAddress(addr);
//}

TraceDqrProfiler::DQErr TraceProfiler::setITCPrintOptions(int itcFlags, int buffSize, int channel)
{
	if (itcPrint != nullptr) {
		delete itcPrint;
		itcPrint = nullptr;
	}

	if (itcFlags != TraceDqrProfiler::ITC_OPT_NONE) {
		if ((nlsStrings == nullptr) && (elfReader != nullptr)) {
			TraceDqrProfiler::DQErr rc;

			nlsStrings = new TraceDqrProfiler::nlStrings[32];

			rc = elfReader->parseNLSStrings(nlsStrings);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				status = rc;

				delete[] nlsStrings;
				nlsStrings = nullptr;

				return rc;
			}
		}

		itcPrint = new ITCPrint(itcFlags, 1 << srcbits, buffSize, channel, nlsStrings);
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr TraceProfiler::haveITCPrintData(int numMsgs[DQR_PROFILER_MAXCORES], bool havePrintData[DQR_PROFILER_MAXCORES])
{
	if (itcPrint == nullptr) {
		return TraceDqrProfiler::DQERR_ERR;
	}

	itcPrint->haveITCPrintData(numMsgs, havePrintData);

	return TraceDqrProfiler::DQERR_OK;
}

bool TraceProfiler::getITCPrintMsg(int core, char* dst, int dstLen, TraceDqrProfiler::TIMESTAMP& startTime, TraceDqrProfiler::TIMESTAMP& endTime)
{
	if (itcPrint == nullptr) {
		return false;
	}

	return itcPrint->getITCPrintMsg(core, dst, dstLen, startTime, endTime);
}

bool TraceProfiler::flushITCPrintMsg(int core, char* dst, int dstLen, TraceDqrProfiler::TIMESTAMP& startTime, TraceDqrProfiler::TIMESTAMP& endTime)
{
	if (itcPrint == nullptr) {
		return false;
	}

	return itcPrint->flushITCPrintMsg(core, dst, dstLen, startTime, endTime);
}

std::string TraceProfiler::getITCPrintStr(int core, bool& haveData, TraceDqrProfiler::TIMESTAMP& startTime, TraceDqrProfiler::TIMESTAMP& endTime)
{
	std::string s = "";

	if (itcPrint == nullptr) {
		haveData = false;
	}
	else {
		haveData = itcPrint->getITCPrintStr(core, s, startTime, endTime);
	}

	return s;
}

std::string TraceProfiler::getITCPrintStr(int core, bool& haveData, double& startTime, double& endTime)
{
	std::string s = "";
	TraceDqrProfiler::TIMESTAMP sts, ets;

	if (itcPrint == nullptr) {
		haveData = false;
	}
	else {
		haveData = itcPrint->getITCPrintStr(core, s, sts, ets);

		if (haveData != false) {
			if (ProfilerNexusMessage::targetFrequency != 0) {
				startTime = ((double)sts) / ProfilerNexusMessage::targetFrequency;
				endTime = ((double)ets) / ProfilerNexusMessage::targetFrequency;
			}
			else {
				startTime = sts;
				endTime = ets;
			}
		}
	}

	return s;
}

std::string TraceProfiler::flushITCPrintStr(int core, bool& haveData, TraceDqrProfiler::TIMESTAMP& startTime, TraceDqrProfiler::TIMESTAMP& endTime)
{
	std::string s = "";

	if (itcPrint == nullptr) {
		haveData = false;
	}
	else {
		haveData = itcPrint->flushITCPrintStr(core, s, startTime, endTime);
	}

	return s;
}

std::string TraceProfiler::flushITCPrintStr(int core, bool& haveData, double& startTime, double& endTime)
{
	std::string s = "";
	TraceDqrProfiler::TIMESTAMP sts, ets;

	if (itcPrint == nullptr) {
		haveData = false;
	}
	else {
		haveData = itcPrint->flushITCPrintStr(core, s, sts, ets);

		if (haveData != false) {
			if (ProfilerNexusMessage::targetFrequency != 0) {
				startTime = ((double)sts) / ProfilerNexusMessage::targetFrequency;
				endTime = ((double)ets) / ProfilerNexusMessage::targetFrequency;
			}
			else {
				startTime = sts;
				endTime = ets;
			}
		}
	}

	return s;
}

// This routine only works for event traces! In particular, brFlags will assumes there is an
// event message at addresses for conditional branches because the branch was taken!

TraceDqrProfiler::DQErr TraceProfiler::getCRBRFlags(TraceDqrProfiler::ICTReason cksrc, TraceDqrProfiler::ADDRESS addr, int& crFlag, int& brFlag)
{
	int rc;
	TraceDqrProfiler::DQErr ec;
	uint32_t inst;
	int inst_size;
	TraceDqrProfiler::InstType inst_type;
	int32_t immediate;
	bool isBranch;
	TraceDqrProfiler::Reg rs1;
	TraceDqrProfiler::Reg rd;

	//	Need to get the destination of the call, which is in the immediate field

	crFlag = TraceDqrProfiler::isNone;
	brFlag = TraceDqrProfiler::BRFLAG_none;

	switch (cksrc) {
	case TraceDqrProfiler::ICT_CONTROL:
	case TraceDqrProfiler::ICT_EXT_TRIG:
	case TraceDqrProfiler::ICT_WATCHPOINT:
	case TraceDqrProfiler::ICT_PC_SAMPLE:
		break;
	case TraceDqrProfiler::ICT_INFERABLECALL:
		ec = elfReader->getInstructionByAddress(addr, inst);
		if (ec != TraceDqrProfiler::DQERR_OK) {
			printf("Error: getCRBRFlags() failed\n");

			status = ec;
			return ec;
		}

		rc = decodeInstruction(inst, inst_size, inst_type, rs1, rd, immediate, isBranch);
		if (rc != 0) {
			printf("Error: getCRBRFlags(): Cann't decode size of instruction %04x\n", inst);

			status = TraceDqrProfiler::DQERR_ERR;
			return TraceDqrProfiler::DQERR_ERR;
		}

		switch (inst_type) {
		case TraceDqrProfiler::INST_JALR:
			if ((rd == TraceDqrProfiler::REG_1) || (rd == TraceDqrProfiler::REG_5)) { // rd == link
				if ((rs1 != TraceDqrProfiler::REG_1) && (rs1 != TraceDqrProfiler::REG_5)) { // rd == link; rs1 != link
					crFlag = TraceDqrProfiler::isCall;
				}
				else if (rd != rs1) { // rd == link; rs1 == link; rd != rs1
					crFlag = TraceDqrProfiler::isSwap;
				}
				else { // rd == link; rs1 == link; rd == rs1
					crFlag = TraceDqrProfiler::isCall;
				}
			}
			else if ((rs1 == TraceDqrProfiler::REG_1) || (rs1 == TraceDqrProfiler::REG_5)) { // rd != link; rs1 == link
				crFlag = TraceDqrProfiler::isReturn;
			}
			break;
		case TraceDqrProfiler::INST_JAL:
			if ((rd == TraceDqrProfiler::REG_1) || (rd == TraceDqrProfiler::REG_5)) { // rd == link
				crFlag = TraceDqrProfiler::isCall;
			}
			break;
		case TraceDqrProfiler::INST_C_JAL:
			if ((rd == TraceDqrProfiler::REG_1) || (rd == TraceDqrProfiler::REG_5)) { // rd == link
				crFlag = TraceDqrProfiler::isCall;
			}
			break;
		case TraceDqrProfiler::INST_C_JR:
			if ((rs1 == TraceDqrProfiler::REG_1) || (rs1 == TraceDqrProfiler::REG_5)) {
				crFlag = TraceDqrProfiler::isReturn;
			}
			break;
		case TraceDqrProfiler::INST_EBREAK:
		case TraceDqrProfiler::INST_ECALL:
			crFlag = TraceDqrProfiler::isException;
			break;
		case TraceDqrProfiler::INST_MRET:
		case TraceDqrProfiler::INST_SRET:
		case TraceDqrProfiler::INST_URET:
			crFlag = TraceDqrProfiler::isExceptionReturn;
			break;
		case TraceDqrProfiler::INST_BEQ:
		case TraceDqrProfiler::INST_BNE:
		case TraceDqrProfiler::INST_BLT:
		case TraceDqrProfiler::INST_BGE:
		case TraceDqrProfiler::INST_BLTU:
		case TraceDqrProfiler::INST_BGEU:
		case TraceDqrProfiler::INST_C_BEQZ:
		case TraceDqrProfiler::INST_C_BNEZ:
			brFlag = TraceDqrProfiler::BRFLAG_taken;
			break;
		default:
			break;
		}
		break;
	case TraceDqrProfiler::ICT_EXCEPTION:
		crFlag = TraceDqrProfiler::isException;
		break;
	case TraceDqrProfiler::ICT_INTERRUPT:
		crFlag = TraceDqrProfiler::isInterrupt;
		break;
	case TraceDqrProfiler::ICT_CONTEXT:
		crFlag = TraceDqrProfiler::isSwap;
		break;
	default:
		printf("Error: getCRBRFlags(): Invalid crsrc\n");

		status = TraceDqrProfiler::DQERR_ERR;
		return TraceDqrProfiler::DQERR_ERR;
	}

	return TraceDqrProfiler::DQERR_OK;
}

// Note: This next instruction only computes nextAddr for inferable calls. It does set the crFlag
// correctly for others.

TraceDqrProfiler::DQErr TraceProfiler::nextAddr(TraceDqrProfiler::ADDRESS addr, TraceDqrProfiler::ADDRESS& nextAddr, int& crFlag)
{
	int rc;
	TraceDqrProfiler::DQErr ec;
	uint32_t inst;
	int inst_size;
	TraceDqrProfiler::InstType inst_type;
	int32_t immediate;
	bool isBranch;
	TraceDqrProfiler::Reg rs1;
	TraceDqrProfiler::Reg rd;

	ec = elfReader->getInstructionByAddress(addr, inst);
	if (ec != TraceDqrProfiler::DQERR_OK) {
		printf("Error: nextAddr() failed\n");

		status = ec;
		return ec;
	}

	//	Need to get the destination of the call, which is in the immediate field

	crFlag = TraceDqrProfiler::isNone;
	nextAddr = 0;

	rc = decodeInstruction(inst, inst_size, inst_type, rs1, rd, immediate, isBranch);
	if (rc != 0) {
		printf("Error: Cann't decode size of instruction %04x\n", inst);

		status = TraceDqrProfiler::DQERR_ERR;
		return TraceDqrProfiler::DQERR_ERR;
	}

	switch (inst_type) {
	case TraceDqrProfiler::INST_JALR:
		if ((rd == TraceDqrProfiler::REG_1) || (rd == TraceDqrProfiler::REG_5)) { // rd == link
			if ((rs1 != TraceDqrProfiler::REG_1) && (rs1 != TraceDqrProfiler::REG_5)) { // rd == link; rs1 != link
				crFlag |= TraceDqrProfiler::isCall;
			}
			else if (rd != rs1) { // rd == link; rs1 == link; rd != rs1
				crFlag |= TraceDqrProfiler::isSwap;
			}
			else { // rd == link; rs1 == link; rd == rs1
				crFlag |= TraceDqrProfiler::isCall;
			}
		}
		else if ((rs1 == TraceDqrProfiler::REG_1) || (rs1 == TraceDqrProfiler::REG_5)) { // rd != link; rs1 == link
			crFlag |= TraceDqrProfiler::isReturn;
		}
		break;
	case TraceDqrProfiler::INST_JAL:
		if ((rd == TraceDqrProfiler::REG_1) || (rd == TraceDqrProfiler::REG_5)) { // rd == link
			crFlag = TraceDqrProfiler::isCall;
		}

		nextAddr = addr + immediate;
		break;
	case TraceDqrProfiler::INST_C_JAL:
		if ((rd == TraceDqrProfiler::REG_1) || (rd == TraceDqrProfiler::REG_5)) { // rd == link
			crFlag = TraceDqrProfiler::isCall;
		}

		nextAddr = addr + immediate;
		break;
	case TraceDqrProfiler::INST_C_JR:
		// pc = pc + rs1
		// not inferrable unconditional

		if ((rs1 == TraceDqrProfiler::REG_1) || (rs1 == TraceDqrProfiler::REG_5)) {
			crFlag |= TraceDqrProfiler::isReturn;
		}
		break;
	case TraceDqrProfiler::INST_C_JALR:
		if (rs1 == TraceDqrProfiler::REG_5) { // is it reg5 only, or also reg1 like non-compact JALR?
			crFlag |= TraceDqrProfiler::isSwap;
		}
		else {
			crFlag |= TraceDqrProfiler::isCall;
		}
		break;
	case TraceDqrProfiler::INST_EBREAK:
	case TraceDqrProfiler::INST_ECALL:
		crFlag = TraceDqrProfiler::isException;
		break;
	case TraceDqrProfiler::INST_MRET:
	case TraceDqrProfiler::INST_SRET:
	case TraceDqrProfiler::INST_URET:
		crFlag = TraceDqrProfiler::isExceptionReturn;
		break;
	default:
		printf("Error: TraceProfiler::nextAddr(): ProfilerInstruction at 0x%08x is not a JAL, JALR, C_JAL, C_JR, C_JALR, EBREAK, ECALL, MRET, SRET, or URET\n", addr);

#ifdef foodog
		printf("ProfilerInstruction type: %d\n", inst_type);

		// disassemble and display instruction

		Disassemble(addr);

		char dst[256];
		instructionInfo.addressToText(dst, sizeof dst, 0);

		if (instructionInfo.addressLabel != nullptr) {
			printf("<%s", instructionInfo.addressLabel);
			if (instructionInfo.addressLabelOffset != 0) {
				printf("+%x", instructionInfo.addressLabelOffset);
			}
			printf(">\n");
		}

		printf("    %s:    ", dst);

		instructionInfo.instructionToText(dst, sizeof dst, 2);
		printf("  %s\n", dst);
#endif // foodog

		status = TraceDqrProfiler::DQERR_ERR;
		return TraceDqrProfiler::DQERR_ERR;
	}

	return TraceDqrProfiler::DQERR_OK;
}

// this function takes the starting address and runs one instruction only!!
// The result is the address it stops at. It also consumes the counts (i-cnt,
// history, taken, not-taken) when appropriate!

TraceDqrProfiler::DQErr TraceProfiler::nextAddr(int core, TraceDqrProfiler::ADDRESS addr, TraceDqrProfiler::ADDRESS& pc, TraceDqrProfiler::TCode tcode, int& crFlag, TraceDqrProfiler::BranchFlags& brFlag)
{
	TraceDqrProfiler::CountType ct;
	uint32_t inst;
	int inst_size;
	TraceDqrProfiler::InstType inst_type;
	int32_t immediate;
	bool isBranch;
	int rc;
	TraceDqrProfiler::Reg rs1;
	TraceDqrProfiler::Reg rd;
	bool isTaken;

	status = elfReader->getInstructionByAddress(addr, inst);
	if (status != TraceDqrProfiler::DQERR_OK) {
		printf("Error: nextAddr(): getInstructionByAddress() failed\n");

		return status;
	}

	crFlag = TraceDqrProfiler::isNone;
	brFlag = TraceDqrProfiler::BRFLAG_none;

	// figure out how big the instruction is
	// Note: immediate will already be adjusted - don't need to mult by 2 before adding to address

	rc = decodeInstruction(inst, inst_size, inst_type, rs1, rd, immediate, isBranch);
	if (rc != 0) {
		printf("Error: nextAddr(): Cannot decode instruction %04x\n", inst);

		status = TraceDqrProfiler::DQERR_ERR;

		return status;
	}

	switch (inst_type) {
	case TraceDqrProfiler::INST_UNKNOWN:
		// btm and htm same

		pc = addr + inst_size / 8;
		break;
	case TraceDqrProfiler::INST_JAL:
		// btm and htm same

		// rd = pc+4 (rd can be r0)
		// pc = pc + (sign extended immediate offset)
		// plan unconditional jumps use rd -> r0
		// inferrable unconditional

		if ((rd == TraceDqrProfiler::REG_1) || (rd == TraceDqrProfiler::REG_5)) { // rd == link
			counts->push(core, addr + inst_size / 8);
			if (profiler_globalDebugFlag) printf("Debug: call: core %d, pushing address %08llx, %d item now on stack\n", core, addr + inst_size / 8, counts->getNumOnStack(core));
			crFlag |= TraceDqrProfiler::isCall;
		}

		pc = addr + immediate;
		break;
	case TraceDqrProfiler::INST_JALR:
		// btm: indirect branch; return pc = -1
		// htm: indirect branch with history; return pc = pop'd addr if possible, else -1

		// rd = pc+4 (rd can be r0)
		// pc = pc + ((sign extended immediate offset) + rs) & 0xffe
		// plain unconditional jumps use rd -> r0
		// not inferrable unconditional

//		printf("rd: %d, rs1: %d, reg_1: %d, reg_5: %d\n",rd,rs1,TraceDqrProfiler::REG_1,TraceDqrProfiler::REG_5);

		if ((rd == TraceDqrProfiler::REG_1) || (rd == TraceDqrProfiler::REG_5)) { // rd == link
			if ((rs1 != TraceDqrProfiler::REG_1) && (rs1 != TraceDqrProfiler::REG_5)) { // rd == link; rs1 != link
				counts->push(core, addr + inst_size / 8);
				if (profiler_globalDebugFlag) printf("Debug: indirect call: core %d, pushing address %08llx, %d item now on stack\n", core, addr + inst_size / 8, counts->getNumOnStack(core));
				pc = -1;
				crFlag |= TraceDqrProfiler::isCall;
			}
			else if (rd != rs1) { // rd == link; rs1 == link; rd != rs1
				pc = counts->pop(core);
				counts->push(core, addr + inst_size / 8);
				if (profiler_globalDebugFlag) printf("Debug: indirect call: core %d, pushing address %08llx, %d item now on stack\n", core, addr + inst_size / 8, counts->getNumOnStack(core));
				crFlag |= TraceDqrProfiler::isSwap;
			}
			else { // rd == link; rs1 == link; rd == rs1
				counts->push(core, addr + inst_size / 8);
				if (profiler_globalDebugFlag) printf("Debug: indirect call: core %d, pushing address %08llx, %d item now on stack\n", core, addr + inst_size / 8, counts->getNumOnStack(core));
				pc = -1;
				crFlag |= TraceDqrProfiler::isCall;
			}
		}
		else if ((rs1 == TraceDqrProfiler::REG_1) || (rs1 == TraceDqrProfiler::REG_5)) { // rd != link; rs1 == link
			pc = counts->pop(core);
			if (profiler_globalDebugFlag) printf("Debug: return: core %d, new address %08llx, %d item now on stack\n", core, pc, counts->getNumOnStack(core));
			crFlag |= TraceDqrProfiler::isReturn;
		}
		else {
			pc = -1;
		}

		// Try to tell if this is a btm or htm based on counts and isReturn | isSwap

		if (traceType == TraceDqrProfiler::TRACETYPE_BTM) {
			if (crFlag & (TraceDqrProfiler::isReturn | TraceDqrProfiler::isSwap)) {
				if (counts->consumeICnt(core, 0) > inst_size / 16) {
					traceType = TraceDqrProfiler::TRACETYPE_HTM;
					if (profiler_globalDebugFlag) printf("JALR: switching to HTM trace\n");
				}
			}
		}

		if (traceType == TraceDqrProfiler::TRACETYPE_BTM) {
			if (counts->consumeICnt(core, 0) > inst_size / 16) {
				// this handles the case of jumping to the instruction following the jump!

				pc = addr + inst_size / 8;
			}
			else {
				pc = -1;
			}
		}
		break;
	case TraceDqrProfiler::INST_BEQ:
	case TraceDqrProfiler::INST_BNE:
	case TraceDqrProfiler::INST_BLT:
	case TraceDqrProfiler::INST_BGE:
	case TraceDqrProfiler::INST_BLTU:
	case TraceDqrProfiler::INST_BGEU:
	case TraceDqrProfiler::INST_C_BEQZ:
	case TraceDqrProfiler::INST_C_BNEZ:
		// htm: follow history bits
		// btm: there will only be a trace record following this for taken branch. not taken branches are not
		// reported. If btm mode, we can look at i-count. If it is going to go to 0, branch was taken (direct branch message
		// will follow). If not going to 0, not taken

		// pc = pc + (sign extend immediate offset) (BLTU and BGEU are not sign extended)
		// inferrable conditional

		if (traceType == TraceDqrProfiler::TRACETYPE_HTM) {
			// htm mode
			ct = counts->getCurrentCountType(core);
			switch (ct) {
			case TraceDqrProfiler::COUNTTYPE_none:
				printf("Error: nextAddr(): instruction counts consumed\n");

				return TraceDqrProfiler::DQERR_ERR;
			case TraceDqrProfiler::COUNTTYPE_i_cnt:
				if (profiler_globalDebugFlag) printf("Debug: Conditional branch: No history. I-cnt: %d\n", counts->getICnt(core));

				// don't know if the branch is taken or not, so we don't know the next addr

				// This can happen with resource full messages where an i-cnt type resource full
				// may be emitted by the encoder due to i-cnt overflow, and it still have non-emitted
				// history bits. We will need to keep reading trace messages until we get a some
				// history. The current trace message should be retired.

				// this is not an error. Just keep retrying until we get a trace message that
				// kicks things loose again

				pc = -1;

				// The caller can detect this has happened and read a new trace message and retry, by
				// checking the brFlag for BRFLAG_unkown

				brFlag = TraceDqrProfiler::BRFLAG_unknown;
				break;
			case TraceDqrProfiler::COUNTTYPE_history:
				//consume history bit here and set pc accordingly

				if (profiler_globalDebugFlag) printf("Debug: Conditional branch: Have history, taken mask: %08x, bit %d, taken: %d\n", counts->getHistory(core), counts->getNumHistoryBits(core), counts->isTaken(core));

				rc = counts->consumeHistory(core, isTaken);
				if (rc != 0) {
					printf("Error: nextAddr(): consumeHistory() failed\n");

					status = TraceDqrProfiler::DQERR_ERR;

					return status;
				}

				if (isTaken) {
					pc = addr + immediate;
					brFlag = TraceDqrProfiler::BRFLAG_taken;
				}
				else {
					pc = addr + inst_size / 8;
					brFlag = TraceDqrProfiler::BRFLAG_notTaken;
				}
				break;
			case TraceDqrProfiler::COUNTTYPE_taken:
				if (profiler_globalDebugFlag) printf("Debug: Conditional branch: Have takenCount: %d, taken: %d\n", counts->getTakenCount(core), counts->getTakenCount(core) > 0);

				rc = counts->consumeTakenCount(core);
				if (rc != 0) {
					printf("Error: nextAddr(): consumeTakenCount() failed\n");

					status = TraceDqrProfiler::DQERR_ERR;

					return status;
				}

				pc = addr + immediate;
				brFlag = TraceDqrProfiler::BRFLAG_taken;
				break;
			case TraceDqrProfiler::COUNTTYPE_notTaken:
				if (profiler_globalDebugFlag) printf("Debug: Conditional branch: Have notTakenCount: %d, not taken: %d\n", counts->getNotTakenCount(core), counts->getNotTakenCount(core) > 0);

				rc = counts->consumeNotTakenCount(core);
				if (rc != 0) {
					printf("Error: nextAddr(): consumeTakenCount() failed\n");

					status = TraceDqrProfiler::DQERR_ERR;

					return status;
				}

				pc = addr + inst_size / 8;
				brFlag = TraceDqrProfiler::BRFLAG_notTaken;
				break;
			}
		}
		else {
			// btm mode

			// if i-cnts don't go to zero for this instruction, this branch is not taken in btmmode.
			// if i-cnts go to zero for this instruciotn, it might be a taken branch. Need to look
			// at the tcode for the current nexus message. If it is a direct branch with or without
			// sync, it is taken. Otherwise, not taken (it could be the result of i-cnt reaching the
			// limit, forcing a sync type message, but branch not taken).

			if (counts->consumeICnt(core, 0) > inst_size / 16) {
				// not taken

				pc = addr + inst_size / 8;

				brFlag = TraceDqrProfiler::BRFLAG_notTaken;
			}
			else if ((tcode == TraceDqrProfiler::TCODE_DIRECT_BRANCH) || (tcode == TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS)) {
				// taken

				pc = addr + immediate;

				brFlag = TraceDqrProfiler::BRFLAG_taken;
			}
			else {
				// not taken

				pc = addr + inst_size / 8;

				brFlag = TraceDqrProfiler::BRFLAG_notTaken;
			}
		}
		break;
	case TraceDqrProfiler::INST_C_J:
		// btm, htm same

		// pc = pc + (signed extended immediate offset)
		// inferrable unconditional

		pc = addr + immediate;
		break;
	case TraceDqrProfiler::INST_C_JAL:
		// btm, htm same

		// x1 = pc + 2
		// pc = pc + (signed extended immediate offset)
		// inferrable unconditional

		if ((rd == TraceDqrProfiler::REG_1) || (rd == TraceDqrProfiler::REG_5)) { // rd == link
			counts->push(core, addr + inst_size / 8);
			if (profiler_globalDebugFlag) printf("Debug: call: core %d, pushing address %08llx, %d item now on stack\n", core, addr + inst_size / 8, counts->getNumOnStack(core));
			crFlag |= TraceDqrProfiler::isCall;
		}

		pc = addr + immediate;
		break;
	case TraceDqrProfiler::INST_C_JR:
		// pc = pc + rs1
		// not inferrable unconditional

		if ((rs1 == TraceDqrProfiler::REG_1) || (rs1 == TraceDqrProfiler::REG_5)) {
			pc = counts->pop(core);
			if (profiler_globalDebugFlag) printf("Debug: return: core %d, new address %08llx, %d item now on stack\n", core, pc, counts->getNumOnStack(core));
			crFlag |= TraceDqrProfiler::isReturn;
		}
		else {
			pc = -1;
		}

		// Try to tell if this is a btm or htm based on counts and isReturn

		if (traceType == TraceDqrProfiler::TRACETYPE_BTM) {
			if (crFlag & TraceDqrProfiler::isReturn) {
				if (counts->consumeICnt(core, 0) > inst_size / 16) {
					traceType = TraceDqrProfiler::TRACETYPE_HTM;
					if (profiler_globalDebugFlag) printf("C_JR: switching to HTM trace\n");
				}
			}
		}

		if (traceType == TraceDqrProfiler::TRACETYPE_BTM) {
			if (counts->consumeICnt(core, 0) > inst_size / 16) {
				// this handles the case of jumping to the instruction following the jump!

				pc = addr + inst_size / 8;
			}
			else {
				pc = -1;
			}
		}
		break;
	case TraceDqrProfiler::INST_C_JALR:
		// x1 = pc + 2
		// pc = pc + rs1
		// not inferrble unconditional

		if (rs1 == TraceDqrProfiler::REG_5) {
			pc = counts->pop(core);
			counts->push(core, addr + inst_size / 8);
			if (profiler_globalDebugFlag) printf("Debug: return/call: core %d, new address %08llx, pushing %08xllx, %d item now on stack\n", core, pc, addr + inst_size / 8, counts->getNumOnStack(core));
			crFlag |= TraceDqrProfiler::isSwap;
		}
		else {
			counts->push(core, addr + inst_size / 8);
			if (profiler_globalDebugFlag) printf("Debug: call: core %d, new address %08llx (don't know dst yet), pushing %08llx, %d item now on stack\n", core, pc, addr + inst_size / 8, counts->getNumOnStack(core));
			pc = -1;
			crFlag |= TraceDqrProfiler::isCall;
		}

		// Try to tell if this is a btm or htm based on counts and isSwap

		if (traceType == TraceDqrProfiler::TRACETYPE_BTM) {
			if (crFlag & TraceDqrProfiler::isSwap) {
				if (counts->consumeICnt(core, 0) > inst_size / 16) {
					traceType = TraceDqrProfiler::TRACETYPE_HTM;
					if (profiler_globalDebugFlag) printf("C_JALR: switching to HTM trace\n");
				}
			}
		}

		if (traceType == TraceDqrProfiler::TRACETYPE_BTM) {
			if (counts->consumeICnt(core, 0) > inst_size / 16) {
				// this handles the case of jumping to the instruction following the jump!

				pc = addr + inst_size / 8;
			}
			else {
				pc = -1;
			}
		}
		break;
	case TraceDqrProfiler::INST_EBREAK:
	case TraceDqrProfiler::INST_ECALL:
		crFlag |= TraceDqrProfiler::isException;
		pc = -1;
		break;
	case TraceDqrProfiler::INST_MRET:
	case TraceDqrProfiler::INST_SRET:
	case TraceDqrProfiler::INST_URET:
		crFlag |= TraceDqrProfiler::isExceptionReturn;
		pc = -1;
		break;
	default:
		pc = addr + inst_size / 8;
		break;
	}

	// Always consume i-cnt unless brFlag == BRFLAG_unknown because we will retry computing next
	// addr for this instruction later

	if (brFlag != TraceDqrProfiler::BRFLAG_unknown) {
		counts->consumeICnt(core, inst_size / 16);
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr TraceProfiler::nextCAAddr(TraceDqrProfiler::ADDRESS& addr, TraceDqrProfiler::ADDRESS& savedAddr)
{
	uint32_t inst;
	int inst_size;
	TraceDqrProfiler::InstType inst_type;
	int32_t immediate;
	bool isBranch;
	int rc;
	TraceDqrProfiler::Reg rs1;
	TraceDqrProfiler::Reg rd;
	//	bool isTaken;

		// note: since saveAddr is a single address, we are only implementing a one address stack (not much of a stack)

	status = elfReader->getInstructionByAddress(addr, inst);
	if (status != TraceDqrProfiler::DQERR_OK) {
		printf("Error: nextCAAddr(): getInstructionByAddress() failed\n");

		return status;
	}

	// figure out how big the instruction is
	// Note: immediate will already be adjusted - don't need to mult by 2 before adding to address

	rc = decodeInstruction(inst, inst_size, inst_type, rs1, rd, immediate, isBranch);
	if (rc != 0) {
		printf("Error: nextCAAddr(): Cannot decode instruction %04x\n", inst);

		status = TraceDqrProfiler::DQERR_ERR;

		return status;
	}

	switch (inst_type) {
	case TraceDqrProfiler::INST_UNKNOWN:
		addr = addr + inst_size / 8;
		break;
	case TraceDqrProfiler::INST_JAL:
		if ((rd == TraceDqrProfiler::REG_1) || (rd == TraceDqrProfiler::REG_5)) { // rd == link
			savedAddr = addr + inst_size / 8;
		}

		addr = addr + immediate;
		break;
	case TraceDqrProfiler::INST_JALR:
		if ((rd == TraceDqrProfiler::REG_1) || (rd == TraceDqrProfiler::REG_5)) { // rd == link
			if ((rs1 != TraceDqrProfiler::REG_1) && (rs1 != TraceDqrProfiler::REG_5)) { // rd == link; rs1 != link
				savedAddr = addr + inst_size / 8;
				addr = -1;
			}
			else if (rd != rs1) { // rd == link; rs1 == link; rd != rs1
				addr = savedAddr;
				savedAddr = -1;
			}
			else { // rd == link; rs1 == link; rd == rs1
				savedAddr = addr + inst_size / 8;
				addr = -1;
			}
		}
		else if ((rs1 == TraceDqrProfiler::REG_1) || (rs1 == TraceDqrProfiler::REG_5)) { // rd != link; rs1 == link
			addr = savedAddr;
			savedAddr = -1;
		}
		else {
			addr = -1;
		}
		break;
	case TraceDqrProfiler::INST_BEQ:
	case TraceDqrProfiler::INST_BNE:
	case TraceDqrProfiler::INST_BLT:
	case TraceDqrProfiler::INST_BGE:
	case TraceDqrProfiler::INST_BLTU:
	case TraceDqrProfiler::INST_BGEU:
	case TraceDqrProfiler::INST_C_BEQZ:
	case TraceDqrProfiler::INST_C_BNEZ:
		if ((addr + inst_size / 8) == (addr + immediate)) {
			addr += immediate;
		}
		else {
			addr = -1;
		}
		break;
	case TraceDqrProfiler::INST_C_J:
		addr += immediate;
		break;
	case TraceDqrProfiler::INST_C_JAL:
		if ((rd == TraceDqrProfiler::REG_1) || (rd == TraceDqrProfiler::REG_5)) { // rd == link
			savedAddr = addr + inst_size / 8;
		}

		addr += immediate;
		break;
	case TraceDqrProfiler::INST_C_JR:
		if ((rs1 == TraceDqrProfiler::REG_1) || (rs1 == TraceDqrProfiler::REG_5)) {
			addr = savedAddr;
			savedAddr = -1;
		}
		else {
			addr = -1;
		}
		break;
	case TraceDqrProfiler::INST_C_JALR:
		if (rs1 == TraceDqrProfiler::REG_5) {
			TraceDqrProfiler::ADDRESS taddr;

			// swap addr, saveAddr
			taddr = addr;
			addr = savedAddr;
			savedAddr = taddr;
		}
		else {
			savedAddr = addr + inst_size / 8;
			addr = -1;
		}
		break;
	case TraceDqrProfiler::INST_EBREAK:
	case TraceDqrProfiler::INST_ECALL:
		addr = -1;
		break;
	case TraceDqrProfiler::INST_MRET:
	case TraceDqrProfiler::INST_SRET:
	case TraceDqrProfiler::INST_URET:
		addr = -1;
		break;
	default:
		addr += inst_size / 8;
		break;
	}

	if (addr == (TraceDqrProfiler::ADDRESS)-1) {
		return TraceDqrProfiler::DQERR_ERR;
	}

	return TraceDqrProfiler::DQERR_OK;
}

// adjust pc, faddr, timestamp based on faddr, uaddr, timestamp, and message type.
// Do not adjust counts! They are handled elsewhere
TraceDqrProfiler::DQErr TraceProfiler::PushTraceData(uint8_t *p_buff, const uint64_t size)
{
    return sfp ? sfp->PushTraceData(p_buff, size) : TraceDqrProfiler::DQERR_ERR;
}

void TraceProfiler::SetEndOfData()
{
   if(sfp)
       sfp->SetEndOfData();
}

TraceDqrProfiler::DQErr TraceProfiler::processTraceMessage(ProfilerNexusMessage& nm, TraceDqrProfiler::ADDRESS& pc, TraceDqrProfiler::ADDRESS& faddr, TraceDqrProfiler::TIMESTAMP& ts, bool& consumed)
{
	consumed = false;

	switch (nm.tcode) {
	case TraceDqrProfiler::TCODE_ERROR:
		if (nm.haveTimestamp) {
			ts = processTS(TraceDqrProfiler::TS_rel, ts, nm.timestamp);
		}

		// set addrs to 0 because we have dropped some messages and don't know what is going on

		faddr = 0;
		pc = 0;
		break;
	case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
		if (nm.haveTimestamp) {
			ts = processTS(TraceDqrProfiler::TS_rel, ts, nm.timestamp);
		}

		if (perfConverter != nullptr) { // or should this be a general itc process thing?? could we process all itc messages here?
			TraceDqrProfiler::DQErr rc;
			//rc = perfConverter->processITCPerf(nm.coreId, ts, nm.dataAcquisition.idTag, nm.dataAcquisition.data, consumed);
			//if (rc != TraceDqrProfiler::DQERR_OK) {
			//	return rc;
			//}
		}
		break;
	case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
	case TraceDqrProfiler::TCODE_RESOURCEFULL:
	case TraceDqrProfiler::TCODE_CORRELATION:
		if (nm.haveTimestamp) {
			ts = processTS(TraceDqrProfiler::TS_rel, ts, nm.timestamp);
		}
		break;
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
		if (nm.haveTimestamp) {
			ts = processTS(TraceDqrProfiler::TS_rel, ts, nm.timestamp);
		}
		faddr = faddr ^ (nm.indirectBranch.u_addr << 1);
		pc = faddr;
		break;
	case TraceDqrProfiler::TCODE_SYNC:
		if (nm.haveTimestamp) {
			ts = processTS(TraceDqrProfiler::TS_full, ts, nm.timestamp);
		}
		faddr = nm.sync.f_addr << 1;
		pc = faddr;
		counts->resetStack(nm.coreId);
		counts->resetCounts(nm.coreId);
		break;
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
		if (nm.haveTimestamp) {
			ts = processTS(TraceDqrProfiler::TS_full, ts, nm.timestamp);
		}
		faddr = nm.directBranchWS.f_addr << 1;
		pc = faddr;
		counts->resetStack(nm.coreId);
		counts->resetCounts(nm.coreId);
		break;
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
		if (nm.haveTimestamp) {
			ts = processTS(TraceDqrProfiler::TS_full, ts, nm.timestamp);
		}
		faddr = nm.indirectBranchWS.f_addr << 1;
		pc = faddr;
		counts->resetStack(nm.coreId);
		counts->resetCounts(nm.coreId);
		break;
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
		if (nm.haveTimestamp) {
			ts = processTS(TraceDqrProfiler::TS_rel, ts, nm.timestamp);
		}
		faddr = faddr ^ (nm.indirectHistory.u_addr << 1);
		pc = faddr;
		break;
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
		if (nm.haveTimestamp) {
			ts = processTS(TraceDqrProfiler::TS_full, ts, nm.timestamp);
		}
		faddr = nm.indirectHistoryWS.f_addr << 1;
		pc = faddr;
		counts->resetStack(nm.coreId);
		counts->resetCounts(nm.coreId);
		break;
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
		// for 8, 0; 14, 0 do not update pc, only faddr. 0, 0 has no address, so it never updates
		// this is because those message types all appear in instruction traces (non-event) and
		// do not want to update the current address because they have no icnt to say when to do it

		if (nm.haveTimestamp) {
			ts = processTS(TraceDqrProfiler::TS_rel, ts, nm.timestamp);
		}

		switch (nm.ict.cksrc) {
		case TraceDqrProfiler::ICT_EXT_TRIG:
			if (nm.ict.ckdf == 0) {
				faddr = faddr ^ (nm.ict.ckdata[0] << 1);
				// don't update pc

				//if (eventConverter != nullptr) {
				//	eventConverter->emitExtTrigEvent(nm.coreId, ts, nm.ict.ckdf, faddr, 0);
				//}
			}
			else if (nm.ict.ckdf == 1) {
				faddr = faddr ^ (nm.ict.ckdata[0] << 1);
				pc = faddr;

				//if (eventConverter != nullptr) {
				//	eventConverter->emitExtTrigEvent(nm.coreId, ts, nm.ict.ckdf, faddr, nm.ict.ckdata[1]);
				//}
			}
			else {
				printf("Error: processTraceMessage(): Invalid ckdf field: %d\n", nm.ict.ckdf);
				return TraceDqrProfiler::DQERR_ERR;
			}
			break;
		case TraceDqrProfiler::ICT_WATCHPOINT:
			if (nm.ict.ckdf == 0) {
				faddr = faddr ^ (nm.ict.ckdata[0] << 1);
				// don't update pc

				//if (eventConverter != nullptr) {
				//	eventConverter->emitWatchpoint(nm.coreId, ts, nm.ict.ckdf, faddr, 0);
				//}
			}
			else if (nm.ict.ckdf == 1) {
				faddr = faddr ^ (nm.ict.ckdata[0] << 1);
				pc = faddr;

				//if (eventConverter != nullptr) {
				//	eventConverter->emitWatchpoint(nm.coreId, ts, nm.ict.ckdf, faddr, nm.ict.ckdata[1]);
				//}
			}
			else {
				printf("Error: processTraceMessage(): Invalid ckdf field: %d\n", nm.ict.ckdf);
				return TraceDqrProfiler::DQERR_ERR;
			}
			break;
		case TraceDqrProfiler::ICT_INFERABLECALL:
			if (nm.ict.ckdf == 0) {
				pc = faddr ^ (nm.ict.ckdata[0] << 1);
				faddr = pc;

				TraceDqrProfiler::DQErr rc;
				TraceDqrProfiler::ADDRESS nextPC;
				int crFlags;

				rc = nextAddr(pc, nextPC, crFlags);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: processTraceMessage(): Could not compute next address for PROFILER_CTF conversion\n");
					return TraceDqrProfiler::DQERR_ERR;
				}

				// we will store the target address back in ckdata[1] in case it is needed later

				nm.ict.ckdata[1] = nextPC;

				if (ctf != nullptr) {
					//ctf->addCall(nm.coreId, pc, nextPC, ts);
				}

				//if (eventConverter != nullptr) {
				//	eventConverter->emitCallRet(nm.coreId, ts, nm.ict.ckdf, pc, nm.ict.ckdata[1], TraceDqrProfiler::isCall);
				//}
			}
			else if (nm.ict.ckdf == 1) {
				pc = faddr ^ (nm.ict.ckdata[0] << 1);
				faddr = pc ^ (nm.ict.ckdata[1] << 1);

				if ((ctf != nullptr) || (eventConverter != nullptr)) {
					TraceDqrProfiler::DQErr rc;
					TraceDqrProfiler::ADDRESS nextPC;
					int crFlags;

					rc = nextAddr(pc, nextPC, crFlags);
					if (rc != TraceDqrProfiler::DQERR_OK) {
						printf("Error: processTraceMessage(): Could not compute next address for PROFILER_CTF conversion\n");
						return TraceDqrProfiler::DQERR_ERR;
					}

					if (ctf != nullptr) {
						if (crFlags & TraceDqrProfiler::isCall) {
							//ctf->addCall(nm.coreId, pc, faddr, ts);
						}
						else if ((crFlags & TraceDqrProfiler::isReturn) || (crFlags & TraceDqrProfiler::isExceptionReturn)) {
							//ctf->addRet(nm.coreId, pc, faddr, ts);
						}
						else {
							printf("Error: processTraceMEssage(): Unsupported crFlags in PROFILER_CTF conversion\n");
							return TraceDqrProfiler::DQERR_ERR;
						}
					}

					//if (eventConverter != nullptr) {
					//	eventConverter->emitCallRet(nm.coreId, ts, nm.ict.ckdf, pc, faddr, crFlags);
					//}
				}
			}
			else {
				printf("Error: processTraceMessage(): Invalid ckdf field: %d\n", nm.ict.ckdf);
				return TraceDqrProfiler::DQERR_ERR;
			}
			break;
		case TraceDqrProfiler::ICT_EXCEPTION:
			if (nm.ict.ckdf == 1) {
				faddr = faddr ^ (nm.ict.ckdata[0] << 1);
				pc = faddr;
			}
			else {
				printf("Error: processTraceMessage(): Invalid ckdf field: %d\n", nm.ict.ckdf);
				return TraceDqrProfiler::DQERR_ERR;
			}

			if (eventConverter != nullptr) {
				//eventConverter->emitException(nm.coreId, ts, nm.ict.ckdf, pc, nm.ict.ckdata[1]);
			}
			break;
		case TraceDqrProfiler::ICT_INTERRUPT:
			if (nm.ict.ckdf == 1) {
				faddr = faddr ^ (nm.ict.ckdata[0] << 1);
				pc = faddr;
			}
			else {
				printf("Error: processTraceMessage(): Invalid ckdf field: %d\n", nm.ict.ckdf);
				return TraceDqrProfiler::DQERR_ERR;
			}

			if (eventConverter != nullptr) {
				//eventConverter->emitInterrupt(nm.coreId, ts, nm.ict.ckdf, pc, nm.ict.ckdata[1]);
			}
			break;
		case TraceDqrProfiler::ICT_CONTEXT:
			if (nm.ict.ckdf == 1) {
				faddr = faddr ^ (nm.ict.ckdata[0] << 1);
				pc = faddr;
			}
			else {
				printf("Error: processTraceMessage(): Invalid ckdf field: %d\n", nm.ict.ckdf);
				return TraceDqrProfiler::DQERR_ERR;
			}

			if (eventConverter != nullptr) {
				//eventConverter->emitContext(nm.coreId, ts, nm.ict.ckdf, pc, nm.ict.ckdata[1]);
			}
			break;
		case TraceDqrProfiler::ICT_PC_SAMPLE:
			if (nm.ict.ckdf == 0) {
				faddr = faddr ^ (nm.ict.ckdata[0] << 1);
				pc = faddr;
			}
			else {
				printf("Error: processTraceMessage(): Invalid ckdf field: %d\n", nm.ict.ckdf);
				return TraceDqrProfiler::DQERR_ERR;
			}

			if (eventConverter != nullptr) {
				//eventConverter->emitPeriodic(nm.coreId, ts, nm.ict.ckdf, pc);
			}
			break;
		case TraceDqrProfiler::ICT_CONTROL:
			if (nm.ict.ckdf == 0) {
				// nothing to do - no address
				// does not update faddr or pc!

				if (eventConverter != nullptr) {
					//eventConverter->emitControl(nm.coreId, ts, nm.ict.ckdf, nm.ict.ckdata[0], 0);
				}
			}
			else if (nm.ict.ckdf == 1) {
				faddr = faddr ^ (nm.ict.ckdata[0] << 1);
				pc = faddr;

				if (eventConverter != nullptr) {
					//eventConverter->emitControl(nm.coreId, ts, nm.ict.ckdf, nm.ict.ckdata[1], pc);
				}
			}
			else {
				printf("Error: processTraceMessage(): Invalid ckdf field: %d\n", nm.ict.ckdf);
				return TraceDqrProfiler::DQERR_ERR;
			}
			break;
		default:
			printf("Error: processTraceMessage(): Invalid ICT Event: %d\n", nm.ict.cksrc);
			return TraceDqrProfiler::DQERR_ERR;
		}
		break;
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS:
		// for 8, 0; 14, 0 do not update pc, only faddr. 0, 0 has no address, so it never updates
		// this is because those message types all apprear in instruction traces (non-event) and
		// do not want to update the current address because they have no icnt to say when to do it

		if (nm.haveTimestamp) {
			ts = processTS(TraceDqrProfiler::TS_full, ts, nm.timestamp);
		}

		switch (nm.ictWS.cksrc) {
		case TraceDqrProfiler::ICT_EXT_TRIG:
			if (nm.ictWS.ckdf == 0) {
				faddr = nm.ictWS.ckdata[0] << 1;
				// don't update pc

				if (eventConverter != nullptr) {
					//eventConverter->emitExtTrigEvent(nm.coreId, ts, nm.ictWS.ckdf, faddr, 0);
				}
			}
			else if (nm.ictWS.ckdf == 1) {
				faddr = nm.ictWS.ckdata[0] << 1;
				pc = faddr;

				if (eventConverter != nullptr) {
					//eventConverter->emitExtTrigEvent(nm.coreId, ts, nm.ictWS.ckdf, faddr, nm.ictWS.ckdata[1]);
				}
			}
			else {
				printf("Error: processTraceMessage(): Invalid ckdf field: %d\n", nm.ictWS.ckdf);
				return TraceDqrProfiler::DQERR_ERR;
			}
			break;
		case TraceDqrProfiler::ICT_WATCHPOINT:
			if (nm.ictWS.ckdf == 0) {
				faddr = nm.ictWS.ckdata[0] << 1;
				// don'tupdate pc

				if (eventConverter != nullptr) {
					//eventConverter->emitWatchpoint(nm.coreId, ts, nm.ictWS.ckdf, faddr, 0);
				}
			}
			else if (nm.ictWS.ckdf <= 1) {
				faddr = nm.ictWS.ckdata[0] << 1;
				pc = faddr;

				if (eventConverter != nullptr) {
					//eventConverter->emitWatchpoint(nm.coreId, ts, nm.ictWS.ckdf, faddr, nm.ictWS.ckdata[1]);
				}
			}
			else {
				printf("Error: processTraceMessage(): Invalid ckdf field: %d\n", nm.ictWS.ckdf);
				return TraceDqrProfiler::DQERR_ERR;
			}
			break;
		case TraceDqrProfiler::ICT_INFERABLECALL:
			if (nm.ictWS.ckdf == 0) {
				pc = nm.ictWS.ckdata[0] << 1;
				faddr = pc;

				TraceDqrProfiler::DQErr rc;
				TraceDqrProfiler::ADDRESS nextPC;
				int crFlags;

				rc = nextAddr(pc, nextPC, crFlags);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: processTraceMessage(): Could not compute next address for PROFILER_CTF conversion\n");
					return TraceDqrProfiler::DQERR_ERR;
				}

				// we will store the target address back in ckdata[1] in case it is needed later

				nm.ict.ckdata[1] = nextPC;

				if (ctf != nullptr) {
					//ctf->addCall(nm.coreId, pc, nextPC, ts);
				}

				if (eventConverter != nullptr) {
					//eventConverter->emitCallRet(nm.coreId, ts, nm.ictWS.ckdf, pc, faddr, TraceDqrProfiler::isCall);
				}
			}
			else if (nm.ictWS.ckdf == 1) {
				pc = nm.ictWS.ckdata[0] << 1;
				faddr = pc ^ (nm.ictWS.ckdata[1] << 1);

				if ((ctf != nullptr) || (eventConverter != nullptr)) {
					TraceDqrProfiler::DQErr rc;
					TraceDqrProfiler::ADDRESS nextPC;
					int crFlags;

					rc = nextAddr(pc, nextPC, crFlags);
					if (rc != TraceDqrProfiler::DQERR_OK) {
						printf("Error: processTraceMessage(): Could not compute next address for PROFILER_CTF conversion\n");
						return TraceDqrProfiler::DQERR_ERR;
					}

					if (ctf != nullptr) {
						if (crFlags & TraceDqrProfiler::isCall) {
							//ctf->addCall(nm.coreId, pc, faddr, ts);
						}
						else if ((crFlags & TraceDqrProfiler::isReturn) || (crFlags & TraceDqrProfiler::isExceptionReturn)) {
							//ctf->addRet(nm.coreId, pc, faddr, ts);
						}
						else {
							printf("Error: processTraceMEssage(): Unsupported crFlags in PROFILER_CTF conversion\n");
							return TraceDqrProfiler::DQERR_ERR;
						}
					}

					if (eventConverter != nullptr) {
						//eventConverter->emitCallRet(nm.coreId, ts, nm.ictWS.ckdf, pc, faddr, crFlags);
					}
				}
			}
			else {
				printf("Error: processTraceMessage(): Invalid ckdf field: %d\n", nm.ictWS.ckdf);
				return TraceDqrProfiler::DQERR_ERR;
			}
			break;
		case TraceDqrProfiler::ICT_EXCEPTION:
			if (nm.ictWS.ckdf == 1) {
				faddr = nm.ictWS.ckdata[0] << 1;
				pc = faddr;
			}
			else {
				printf("Error: processTraceMessage(): Invalid ckdf field: %d\n", nm.ictWS.ckdf);
				return TraceDqrProfiler::DQERR_ERR;
			}

			if (eventConverter != nullptr) {
				//eventConverter->emitException(nm.coreId, ts, nm.ictWS.ckdf, pc, nm.ictWS.ckdata[1]);
			}
			break;
		case TraceDqrProfiler::ICT_INTERRUPT:
			if (nm.ictWS.ckdf == 1) {
				faddr = nm.ictWS.ckdata[0] << 1;
				pc = faddr;
			}
			else {
				printf("Error: processTraceMessage(): Invalid ckdf field: %d\n", nm.ictWS.ckdf);
				return TraceDqrProfiler::DQERR_ERR;
			}

			if (eventConverter != nullptr) {
				//eventConverter->emitInterrupt(nm.coreId, ts, nm.ictWS.ckdf, pc, nm.ictWS.ckdata[1]);
			}
			break;
		case TraceDqrProfiler::ICT_CONTEXT:
			if (nm.ictWS.ckdf == 1) {
				faddr = nm.ictWS.ckdata[0] << 1;
				pc = faddr;
			}
			else {
				printf("Error: processTraceMessage(): Invalid ckdf field: %d\n", nm.ictWS.ckdf);
				return TraceDqrProfiler::DQERR_ERR;
			}

			if (eventConverter != nullptr) {
				//eventConverter->emitContext(nm.coreId, ts, nm.ictWS.ckdf, pc, nm.ictWS.ckdata[1]);
			}
			break;
		case TraceDqrProfiler::ICT_PC_SAMPLE:
			if (nm.ictWS.ckdf == 0) {
				faddr = nm.ictWS.ckdata[0] << 1;
				pc = faddr;
			}
			else {
				printf("Error: processTraceMessage(): Invalid ckdf field: %d\n", nm.ictWS.ckdf);
				return TraceDqrProfiler::DQERR_ERR;
			}

			if (eventConverter != nullptr) {
				//eventConverter->emitPeriodic(nm.coreId, ts, nm.ictWS.ckdf, pc);
			}
			break;
		case TraceDqrProfiler::ICT_CONTROL:
			if (nm.ictWS.ckdf == 0) {
				// nothing to do
				// does not update faddr or pc!

				if (eventConverter != nullptr) {
					//eventConverter->emitControl(nm.coreId, ts, nm.ictWS.ckdf, nm.ictWS.ckdata[0], 0);
				}
			}
			else if (nm.ictWS.ckdf == 1) {
				faddr = nm.ictWS.ckdata[0] << 1;
				pc = faddr;

				if (eventConverter != nullptr) {
					//eventConverter->emitControl(nm.coreId, ts, nm.ictWS.ckdf, nm.ictWS.ckdata[1], pc);
				}
			}
			else {
				printf("Error: processTraceMessage(): Invalid ckdf field: %d\n", nm.ictWS.ckdf);
				return TraceDqrProfiler::DQERR_ERR;
			}
			break;
		default:
			printf("Error: processTraceMessage(): Invalid ICT Event: %d\n", nm.ictWS.cksrc);
			return TraceDqrProfiler::DQERR_ERR;
		}
		break;
	case TraceDqrProfiler::TCODE_DEBUG_STATUS:
	case TraceDqrProfiler::TCODE_DEVICE_ID:
	case TraceDqrProfiler::TCODE_DATA_WRITE:
	case TraceDqrProfiler::TCODE_DATA_READ:
	case TraceDqrProfiler::TCODE_CORRECTION:
	case TraceDqrProfiler::TCODE_DATA_WRITE_WS:
	case TraceDqrProfiler::TCODE_DATA_READ_WS:
	case TraceDqrProfiler::TCODE_WATCHPOINT:
	case TraceDqrProfiler::TCODE_OUTPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_INPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_AUXACCESS_READ:
	case TraceDqrProfiler::TCODE_AUXACCESS_READNEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITENEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_RESPONSE:
	case TraceDqrProfiler::TCODE_REPEATBRANCH:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION_WS:
	case TraceDqrProfiler::TCODE_UNDEFINED:
	default:
		printf("Error: TraceProfiler::processTraceMessage(): Unsupported TCODE\n");

		return TraceDqrProfiler::DQERR_ERR;
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr TraceProfiler::getInstructionByAddress(TraceDqrProfiler::ADDRESS addr, ProfilerInstruction* instInfo, ProfilerSource* srcInfo, int* flags)
{
	TraceDqrProfiler::DQErr rc;

	rc = Disassemble(addr); // should error check disassembl() call!
	if (rc != TraceDqrProfiler::DQERR_OK) {
		return TraceDqrProfiler::DQERR_ERR;
	}

	*flags = 0;

	if (instInfo != nullptr) {
		instructionInfo.qDepth = 0;
		instructionInfo.arithInProcess = 0;
		instructionInfo.loadInProcess = 0;
		instructionInfo.storeInProcess = 0;

		instructionInfo.coreId = 0;
		*instInfo = instructionInfo;
		instInfo->CRFlag = TraceDqrProfiler::isNone;
		instInfo->brFlags = TraceDqrProfiler::BRFLAG_none;

		instInfo->timestamp = lastTime[currentCore];

		*flags |= TraceDqrProfiler::TRACE_HAVE_INSTINFO;
	}

	if (srcInfo != nullptr) {
		sourceInfo.coreId = 0;
		*srcInfo = sourceInfo;
		*flags |= TraceDqrProfiler::TRACE_HAVE_SRCINFO;
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr TraceProfiler::NextInstruction(ProfilerInstruction* instInfo, ProfilerNexusMessage* msgInfo, ProfilerSource* srcInfo, int* flags)
{
	TraceDqrProfiler::DQErr ec;

	ProfilerInstruction* instInfop = nullptr;
	ProfilerNexusMessage* msgInfop = nullptr;
	ProfilerSource* srcInfop = nullptr;

	ProfilerInstruction** instInfopp = nullptr;
	ProfilerNexusMessage** msgInfopp = nullptr;
	ProfilerSource** srcInfopp = nullptr;

	if (instInfo != nullptr) {
		instInfopp = &instInfop;
	}

	if (msgInfo != nullptr) {
		msgInfopp = &msgInfop;
	}

	if (srcInfo != nullptr) {
		srcInfopp = &srcInfop;
	}

	ec = NextInstruction(instInfopp, msgInfopp, srcInfopp);

	*flags = 0;

	if (ec == TraceDqrProfiler::DQERR_OK) {
		if (instInfo != nullptr) {
			if (instInfop != nullptr) {
				*instInfo = *instInfop;
				*flags |= TraceDqrProfiler::TRACE_HAVE_INSTINFO;
			}
		}

		if (msgInfo != nullptr) {
			if (msgInfop != nullptr) {
				*msgInfo = *msgInfop;
				*flags |= TraceDqrProfiler::TRACE_HAVE_MSGINFO;
			}
		}

		if (srcInfo != nullptr) {
			if (srcInfop != nullptr) {
				*srcInfo = *srcInfop;
				*flags |= TraceDqrProfiler::TRACE_HAVE_SRCINFO;
			}
		}

		if (itcPrint != nullptr) {
			if (itcPrint->haveITCPrintMsgs() != false) {
				*flags |= TraceDqrProfiler::TRACE_HAVE_ITCPRINTINFO;
			}
		}
	}

	return ec;
}
TraceDqrProfiler::DQErr TraceProfiler::NextInstruction(ProfilerInstruction** instInfo, ProfilerNexusMessage **nm_out, uint64_t& address_out)
{
	if (status != TraceDqrProfiler::DQERR_OK) 
	{
		return status;
	}

	TraceDqrProfiler::DQErr rc;
	TraceDqrProfiler::ADDRESS addr;
	int crFlag;
	TraceDqrProfiler::BranchFlags brFlags;
	uint32_t caFlags = 0;
	uint32_t pipeCycles = 0;
	uint32_t viStartCycles = 0;
	uint32_t viFinishCycles = 0;

	uint8_t qDepth = 0;
	uint8_t arithInProcess = 0;
	uint8_t loadInProcess = 0;
	uint8_t storeInProcess = 0;

	bool consumed = false;

	ProfilerInstruction** savedInstPtr = nullptr;
	ProfilerNexusMessage** savedMsgPtr = nullptr;
	ProfilerSource** savedSrcPtr = nullptr;

	//if (instInfo != nullptr) 
	//{
	//	*instInfo = nullptr;
	//}

	for (;;) {
		//		need to set readNewTraceMessage where it is needed! That includes
		//		staying in the same state that expects to get another message!!

		bool haveMsg;

		if (savedInstPtr != nullptr) {
			instInfo = savedInstPtr;
			savedInstPtr = nullptr;
		}

		if (readNewTraceMessage != false) 
		{
			do 
			{
				rc = sfp->readNextTraceMsg(nm, analytics, haveMsg);

				if (rc != TraceDqrProfiler::DQERR_OK) 
				{
					// have an error. either EOF, or error

					status = rc;

					if (status == TraceDqrProfiler::DQERR_EOF) {
						state[currentCore] = TRACE_STATE_DONE;
					}
					else {
						printf("Error: TraceProfiler file does not contain any trace messages, or is unreadable\n");

						state[currentCore] = TRACE_STATE_ERROR;
					}

					return status;
				}

				if (haveMsg == false) 
				{
					lastTime[currentCore] = 0;
					currentAddress[currentCore] = 0;
					lastFaddr[currentCore] = 0;

					state[currentCore] = TRACE_STATE_GETFIRSTSYNCMSG;
				}
			} while (haveMsg == false);

			readNewTraceMessage = false;
			currentCore = nm.coreId;
            *nm_out = &nm;

			// if set see if HTM trace message, switch to HTM mode

			if (traceType != TraceDqrProfiler::TRACETYPE_HTM) {
				switch (nm.tcode) {
				case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
				case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
				case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
				case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
				case TraceDqrProfiler::TCODE_ERROR:
				case TraceDqrProfiler::TCODE_SYNC:
				case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
				case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
				case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
				case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
				case TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS:
					break;
				case TraceDqrProfiler::TCODE_CORRELATION:
					if (nm.correlation.cdf == 1) {
						traceType = TraceDqrProfiler::TRACETYPE_HTM;
						if (profiler_globalDebugFlag) printf("TCODE_CORRELATION, cdf == 1: switching to HTM mode\n");
					}
					break;
				case TraceDqrProfiler::TCODE_RESOURCEFULL:
				case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
				case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
					traceType = TraceDqrProfiler::TRACETYPE_HTM;
					if (profiler_globalDebugFlag) printf("History/taken/not taken count TCODE: switching to HTM mode\n");
					break;
				case TraceDqrProfiler::TCODE_REPEATBRANCH:
				case TraceDqrProfiler::TCODE_REPEATINSTRUCTION:
				case TraceDqrProfiler::TCODE_REPEATINSTRUCTION_WS:
				case TraceDqrProfiler::TCODE_AUXACCESS_READNEXT:
				case TraceDqrProfiler::TCODE_AUXACCESS_WRITENEXT:
				case TraceDqrProfiler::TCODE_AUXACCESS_RESPONSE:
				case TraceDqrProfiler::TCODE_OUTPUT_PORTREPLACEMENT:
				case TraceDqrProfiler::TCODE_INPUT_PORTREPLACEMENT:
				case TraceDqrProfiler::TCODE_AUXACCESS_READ:
				case TraceDqrProfiler::TCODE_DATA_WRITE_WS:
				case TraceDqrProfiler::TCODE_DATA_READ_WS:
				case TraceDqrProfiler::TCODE_WATCHPOINT:
				case TraceDqrProfiler::TCODE_CORRECTION:
				case TraceDqrProfiler::TCODE_DATA_WRITE:
				case TraceDqrProfiler::TCODE_DATA_READ:
				case TraceDqrProfiler::TCODE_DEBUG_STATUS:
				case TraceDqrProfiler::TCODE_DEVICE_ID:
					printf("Error: NextInstruction(): Unsupported tcode type (%d)\n", nm.tcode);
					status = TraceDqrProfiler::DQERR_ERR;
					state[currentCore] = TRACE_STATE_ERROR;

					return status;
				case TraceDqrProfiler::TCODE_UNDEFINED:
					printf("Error: NextInstruction(): Undefined tcode type (%d)\n", nm.tcode);
					status = TraceDqrProfiler::DQERR_ERR;
					state[currentCore] = TRACE_STATE_ERROR;

					return status;
				}
			}

			// Check if this is a ICT Control message and if we are filtering them out
#if 0
			switch (nm.tcode) {
			case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
			case TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS:
				if ((nm.getCKSRC() == TraceDqrProfiler::ICT_CONTROL) && (eventFilterMask & (1 << PROFILER_CTF::et_controlIndex))) {
					savedInstPtr = instInfo;
					instInfo = nullptr;
				}
				break;
			default:
				break;
			}
#endif
		}

		switch (state[currentCore]) 
		{
		case TRACE_STATE_SYNCCATE:	// Looking for a CA trace sync
			// printf("TRACE_STATE_SYNCCATE\n");

			if (caTrace == nullptr) {
				// have an error! Should never have TRACE_STATE_SYNC without a caTrace ptr
				printf("Error: caTrace is null\n");
				status = TraceDqrProfiler::DQERR_ERR;
				state[currentCore] = TRACE_STATE_ERROR;
				return status;
			}

			// loop through trace messages until we find a sync of some kind. First sync should do it
			// sync reason must be correct (exit debug or start tracing) or we stay in this state

			TraceDqrProfiler::ADDRESS teAddr;

			switch (nm.tcode) 
			{
			case TraceDqrProfiler::TCODE_ERROR:
				// reset time. Messages have been missed. Address may not still be 0 if we have seen a sync
				// message without an exit debug or start trace sync reason, so reset address

				lastTime[currentCore] = 0;
				currentAddress[currentCore] = 0;
				lastFaddr[currentCore] = 0;


				readNewTraceMessage = true;

				status = TraceDqrProfiler::DQERR_OK;

				return status;
			case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
			case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
			case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
			case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
			case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
			case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
			case TraceDqrProfiler::TCODE_CORRELATION:
			case TraceDqrProfiler::TCODE_RESOURCEFULL:
			case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
			case TraceDqrProfiler::TCODE_REPEATBRANCH:
			case TraceDqrProfiler::TCODE_REPEATINSTRUCTION:
			case TraceDqrProfiler::TCODE_REPEATINSTRUCTION_WS:
			case TraceDqrProfiler::TCODE_AUXACCESS_READNEXT:
			case TraceDqrProfiler::TCODE_AUXACCESS_WRITENEXT:
			case TraceDqrProfiler::TCODE_AUXACCESS_RESPONSE:
			case TraceDqrProfiler::TCODE_OUTPUT_PORTREPLACEMENT:
			case TraceDqrProfiler::TCODE_INPUT_PORTREPLACEMENT:
			case TraceDqrProfiler::TCODE_AUXACCESS_READ:
				// here we return the trace messages before we have actually started tracing
				// this could be at the start of a trace, or after leaving a trace because of
				// a correlation message

						// we may have a valid address and time already if we saw a sync without an exit debug				        // or start trace sync reason. So call processTraceMessage()

				if (lastFaddr[currentCore] != 0) {
					rc = processTraceMessage(nm, currentAddress[currentCore], lastFaddr[currentCore], lastTime[currentCore], consumed);
					if (rc != TraceDqrProfiler::DQERR_OK) {
						printf("Error: NextInstruction(): state TRACE_STATE_SYNCCATE: processTraceMessage()\n");

						status = TraceDqrProfiler::DQERR_ERR;
						state[currentCore] = TRACE_STATE_ERROR;

						return status;
					}
				}

				readNewTraceMessage = true;

				status = TraceDqrProfiler::DQERR_OK;

				return status;
			case TraceDqrProfiler::TCODE_SYNC:
			case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
			case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
			case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
				// sync reason should be either EXIT_DEBUG or TRACE_ENABLE. Otherwise, keep looking

				TraceDqrProfiler::SyncReason sr;

				sr = nm.getSyncReason();
				switch (sr) {
				case TraceDqrProfiler::SYNC_EXIT_DEBUG:
				case TraceDqrProfiler::SYNC_TRACE_ENABLE:
					// only exit debug or trace enable allow proceeding. All others stay in this state and return

					teAddr = nm.getF_Addr() << 1;
					break;
				case TraceDqrProfiler::SYNC_EVTI:
				case TraceDqrProfiler::SYNC_EXIT_RESET:
				case TraceDqrProfiler::SYNC_T_CNT:
				case TraceDqrProfiler::SYNC_I_CNT_OVERFLOW:
				case TraceDqrProfiler::SYNC_WATCHPINT:
				case TraceDqrProfiler::SYNC_FIFO_OVERRUN:
				case TraceDqrProfiler::SYNC_EXIT_POWERDOWN:
				case TraceDqrProfiler::SYNC_MESSAGE_CONTENTION:
				case TraceDqrProfiler::SYNC_PC_SAMPLE:
					// here we return the trace messages before we have actually started tracing
					// this could be at the start of a trace, or after leaving a trace because of
					// a correlation message
					// probably should never get here when doing a CA trace.

					rc = processTraceMessage(nm, currentAddress[currentCore], lastFaddr[currentCore], lastTime[currentCore], consumed);
					if (rc != TraceDqrProfiler::DQERR_OK) {
						printf("Error: NextInstruction(): state TRACE_STATE_SYNCCATE: processTraceMessage()\n");

						status = TraceDqrProfiler::DQERR_ERR;
						state[currentCore] = TRACE_STATE_ERROR;

						return status;
					}



					readNewTraceMessage = true;

					status = TraceDqrProfiler::DQERR_OK;

					return status;
				case TraceDqrProfiler::SYNC_NONE:
				default:
					printf("Error: invalid sync reason\n");
					status = TraceDqrProfiler::DQERR_ERR;
					state[currentCore] = TRACE_STATE_ERROR;

					return status;
				}
				break;
#if 0
			case TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS:
				// INCIRCUTTRACE_WS messages do not have a sync reason, but control(0,1) has
				// the same info!

				TraceDqrProfiler::ICTReason itcr;

				itcr = nm.getCKSRC();

				switch (itcr) {
				case TraceDqrProfiler::ICT_INFERABLECALL:
				case TraceDqrProfiler::ICT_EXT_TRIG:
				case TraceDqrProfiler::ICT_EXCEPTION:
				case TraceDqrProfiler::ICT_INTERRUPT:
				case TraceDqrProfiler::ICT_CONTEXT:
				case TraceDqrProfiler::ICT_WATCHPOINT:
				case TraceDqrProfiler::ICT_PC_SAMPLE:
					rc = processTraceMessage(nm, currentAddress[currentCore], lastFaddr[currentCore], lastTime[currentCore], consumed);
					if (rc != TraceDqrProfiler::DQERR_OK) {
						printf("Error: NextInstruction(): state TRACE_STATE_SYNCCATE: processTraceMessage()\n");

						status = TraceDqrProfiler::DQERR_ERR;
						state[currentCore] = TRACE_STATE_ERROR;

						return status;
					}


					readNewTraceMessage = true;

					status = TraceDqrProfiler::DQERR_OK;

					return status;
				case TraceDqrProfiler::ICT_CONTROL:
					bool returnFlag;
					returnFlag = true;

					if (nm.ictWS.ckdf == 1) {
						switch (nm.ictWS.ckdata[1]) {
						case TraceDqrProfiler::ICT_CONTROL_TRACE_ON:
						case TraceDqrProfiler::ICT_CONTROL_EXIT_DEBUG:
							// only exit debug or trace enable allow proceeding. All others stay in this state and return

							teAddr = nm.getF_Addr() << 1;
							returnFlag = false;
							break;
						default:
							break;
						}
					}

					if (returnFlag) {
						rc = processTraceMessage(nm, currentAddress[currentCore], lastFaddr[currentCore], lastTime[currentCore], consumed);
						if (rc != TraceDqrProfiler::DQERR_OK) {
							printf("Error: NextInstruction(): state TRACE_STATE_SYNCCATE: processTraceMessage()\n");

							status = TraceDqrProfiler::DQERR_ERR;
							state[currentCore] = TRACE_STATE_ERROR;

							return status;
						}

	

						readNewTraceMessage = true;

						status = TraceDqrProfiler::DQERR_OK;

						return status;
					}
					break;
				case TraceDqrProfiler::ICT_NONE:
				default:
					printf("Error: invalid ICT reason\n");
					status = TraceDqrProfiler::DQERR_ERR;
					state[currentCore] = TRACE_STATE_ERROR;

					return status;
				}
				break;
#endif
			case TraceDqrProfiler::TCODE_DEBUG_STATUS:
			case TraceDqrProfiler::TCODE_DEVICE_ID:
			case TraceDqrProfiler::TCODE_DATA_WRITE:
			case TraceDqrProfiler::TCODE_DATA_READ:
			case TraceDqrProfiler::TCODE_CORRECTION:
			case TraceDqrProfiler::TCODE_DATA_WRITE_WS:
			case TraceDqrProfiler::TCODE_DATA_READ_WS:
			case TraceDqrProfiler::TCODE_WATCHPOINT:
			case TraceDqrProfiler::TCODE_UNDEFINED:
			default:
				printf("Error: nextInstruction(): state TRACE_STATE_SYNCCATE: unsupported or invalid TCODE\n");

				state[currentCore] = TRACE_STATE_ERROR;
				status = TraceDqrProfiler::DQERR_ERR;

				return status;
			}

			// run ca code until we get to the te trace address. only do 6 instructions a the most
#if 0
			caSyncAddr = caTrace->getCATraceStartAddr();

			//			printf("caSyncAddr: %08x, teAddr: %08x\n",caSyncAddr,teAddr);

			//			caTrace->dumpCurrentCARecord(1);

			TraceDqrProfiler::ADDRESS savedAddr;
			savedAddr = -1;

			bool fail;
			fail = false;

			for (int i = 0; (fail == false) && (teAddr != caSyncAddr) && (i < 30); i++) {
				rc = nextCAAddr(caSyncAddr, savedAddr);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					fail = true;
				}
				else {
					//					printf("caSyncAddr: %08x, teAddr: %08x\n",caSyncAddr,teAddr);

					rc = caTrace->consume(caFlags, TraceDqrProfiler::INST_SCALER, pipeCycles, viStartCycles, viFinishCycles, qDepth, arithInProcess, loadInProcess, storeInProcess);
					if (rc == TraceDqrProfiler::DQERR_EOF) {
						state[currentCore] = TRACE_STATE_DONE;

						status = rc;
						return rc;
					}

					if (rc != TraceDqrProfiler::DQERR_OK) {
						state[currentCore] = TRACE_STATE_ERROR;

						status = rc;
						return status;
					}
				}
			}

			//			if (teAddr == caSyncAddr) {
			//				printf("ca sync found at address %08x, cycles: %d\n",caSyncAddr,cycles);
			//			}

			if (teAddr != caSyncAddr) {
				// unable to sync by fast-forwarding the CA trace to match the instruction trace
				// so we will try to run the normal trace for a few instructions with the hope it
				// will sync up with the ca trace! We set the max number of instructions to run
				// the normal trace below, and turn tracing loose!

				syncCount = 16;
				caTrace->rewind();
				caSyncAddr = caTrace->getCATraceStartAddr();

				//				printf("starting normal trace to sync up; caSyncAddr: %08x\n",caSyncAddr);
			}

			// readnextmessage should be false. So, we want to process the message like a normal message here
			// if the addresses of the trace and the start of the ca trace sync later, it is handled in
			// the other states
#endif
			state[currentCore] = TRACE_STATE_GETFIRSTSYNCMSG;
			break;
		case TRACE_STATE_GETFIRSTSYNCMSG:
			// start here for normal traces

			// read trace messages until a sync is found. Should be the first message normally
			// unless the wrapped buffer

			// only exit this state when sync type message is found or EOF or error
			// Event messages will cause state to change to TRACE_STATE_EVENT

			switch (nm.tcode) {
			case TraceDqrProfiler::TCODE_SYNC:
			case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
			case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
			case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
				rc = processTraceMessage(nm, currentAddress[currentCore], lastFaddr[currentCore], lastTime[currentCore], consumed);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: NextInstruction(): state TRACE_STATE_GETFIRSTSYNCMSG: processTraceMessage()\n");

					status = TraceDqrProfiler::DQERR_ERR;
					state[currentCore] = TRACE_STATE_ERROR;

					return status;
				}


				state[currentCore] = TRACE_STATE_GETMSGWITHCOUNT;
				break;
#if 0
			case TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS:
				// this may set the timestamp, and and may set the address
				// all set the address except control(0,0) which is used just to set the timestamp at most

				rc = processTraceMessage(nm, currentAddress[currentCore], lastFaddr[currentCore], lastTime[currentCore], consumed);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: NextInstruction(): state TRACE_STATE_GETFIRSTSYNCMSG: processTraceMessage()\n");

					status = TraceDqrProfiler::DQERR_ERR;
					state[currentCore] = TRACE_STATE_ERROR;

					return status;
				}

				if (currentAddress[currentCore] == 0) {
					// for the get first sync state, we want currentAddress to be set
					// most incircuttrace_ws types will set it, but not 8,0; 14,0; 0,0

					currentAddress[currentCore] = lastFaddr[currentCore];
				}

				if ((nm.ictWS.cksrc == TraceDqrProfiler::ICT_CONTROL) && (nm.ictWS.ckdf == 0)) {
					// ICT_WS Control(0,0) only updates TS (if present). Does not change state or anything else
					// because it is the only incircuittrace message type with no address
				}
				else {
					if ((nm.getCKSRC() == TraceDqrProfiler::ICT_EXT_TRIG) && (nm.getCKDF() == 0)) {
						// no dasm or src for ext trigger in HTM instruction traces
					}
					else if ((nm.getCKSRC() == TraceDqrProfiler::ICT_WATCHPOINT) && (nm.getCKDF() == 0)) {
						// no dasm or src for ext trigger in HTM instruction traces
					}
					else if ((instInfo != nullptr)) {
						Disassemble(currentAddress[currentCore]);

						if (instInfo != nullptr) {
							instructionInfo.qDepth = 0;
							instructionInfo.arithInProcess = 0;
							instructionInfo.loadInProcess = 0;
							instructionInfo.storeInProcess = 0;

							instructionInfo.coreId = currentCore;
							*instInfo = &instructionInfo;
							//							(*instInfo)->CRFlag = TraceDqrProfiler::isNone;
							//							(*instInfo)->brFlags = TraceDqrProfiler::BRFLAG_none;
							getCRBRFlags(nm.getCKSRC(), currentAddress[currentCore], (*instInfo)->CRFlag, (*instInfo)->brFlags);

							(*instInfo)->timestamp = lastTime[currentCore];
						}

					}
					state[currentCore] = TRACE_STATE_GETMSGWITHCOUNT;
				}
				break;
#endif
			case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
				rc = processTraceMessage(nm, currentAddress[currentCore], lastFaddr[currentCore], lastTime[currentCore], consumed);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: NextInstruction(): state TRACE_STATE_GETFIRSTSYNCMSG: processTraceMessage()\n");

					status = TraceDqrProfiler::DQERR_ERR;
					state[currentCore] = TRACE_STATE_ERROR;

					return status;
				}
				break;
			case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
			case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
			case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
			case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
			case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
			case TraceDqrProfiler::TCODE_RESOURCEFULL:
			case TraceDqrProfiler::TCODE_CORRELATION:
				if (nm.timestamp) {
					lastTime[currentCore] = processTS(TraceDqrProfiler::TS_rel, lastTime[currentCore], nm.timestamp);
				}
				break;
			case TraceDqrProfiler::TCODE_ERROR:
				// reset time. Messages have been missed.
				lastTime[currentCore] = 0;
				break;
			case TraceDqrProfiler::TCODE_DEBUG_STATUS:
			case TraceDqrProfiler::TCODE_DEVICE_ID:
			case TraceDqrProfiler::TCODE_DATA_WRITE:
			case TraceDqrProfiler::TCODE_DATA_READ:
			case TraceDqrProfiler::TCODE_CORRECTION:
			case TraceDqrProfiler::TCODE_DATA_WRITE_WS:
			case TraceDqrProfiler::TCODE_DATA_READ_WS:
			case TraceDqrProfiler::TCODE_WATCHPOINT:
			default:
				printf("Error: nextInstructin(): state TRACE_STATE_GETFIRSTSYNCMSG: unsupported or invalid TCODE\n");

				state[currentCore] = TRACE_STATE_ERROR;
				status = TraceDqrProfiler::DQERR_ERR;

				return status;
			}

			// INCIRCUITTRACE or INCIRCUITTRACE_WS will have set state to TRACE_STATE_EVENT

			readNewTraceMessage = true;

			// here we return the trace messages before we have actually started tracing
			// this could be at the start of a trace, or after leaving a trace because of
			// a correlation message

			status = TraceDqrProfiler::DQERR_OK;
			return status;
		case TRACE_STATE_GETMSGWITHCOUNT:

			switch (nm.tcode) {
			case TraceDqrProfiler::TCODE_SYNC:
			case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
			case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
			case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
			case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
			case TraceDqrProfiler::TCODE_CORRELATION:
			case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
			case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
			case TraceDqrProfiler::TCODE_RESOURCEFULL:
				// don't update timestamp until messages are retired!

				// reset all counts before setting them. We have no valid counts before the second message.
				// first message is a sync-type message. Counts are for up to that message, nothing after.

				counts->resetCounts(currentCore);

				rc = counts->setCounts(&nm);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					state[currentCore] = TRACE_STATE_ERROR;
					status = rc;

					return status;
				}

				// only these TCODEs have counts and release from this state

				state[currentCore] = TRACE_STATE_GETNEXTINSTRUCTION;
				break;
#if 0
			case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
			case TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS:
				// these message have no counts so they will be retired immediately

				rc = processTraceMessage(nm, currentAddress[currentCore], lastFaddr[currentCore], lastTime[currentCore], consumed);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: NextInstruction(): state TRACE_STATE_GETMSGWITHCOUNT: processTraceMessage()\n");

					status = TraceDqrProfiler::DQERR_ERR;
					state[currentCore] = TRACE_STATE_ERROR;

					return status;
				}

				if ((nm.getCKSRC() == TraceDqrProfiler::ICT_CONTROL) && (nm.getCKDF() == 0)) {
					// ICT_WS Control(0,0) only updates TS (if present). Does not change state or anything else
					addr = currentAddress[currentCore];
				}
				else {
					if ((nm.getCKSRC() == TraceDqrProfiler::ICT_EXT_TRIG) && (nm.getCKDF() == 0)) {
						// no dasm or src for ext trigger in HTM instruction traces
						addr = lastFaddr[currentCore];
					}
					else if ((nm.getCKSRC() == TraceDqrProfiler::ICT_WATCHPOINT) && (nm.getCKDF() == 0)) {
						// no dasm or src for ext trigger in HTM instruction tracaes
						addr = lastFaddr[currentCore];
					}
					else if ((instInfo != nullptr)) {
						addr = currentAddress[currentCore];

						Disassemble(addr);

						if (instInfo != nullptr) {
							instructionInfo.qDepth = 0;
							instructionInfo.arithInProcess = 0;
							instructionInfo.loadInProcess = 0;
							instructionInfo.storeInProcess = 0;

							instructionInfo.coreId = currentCore;
							*instInfo = &instructionInfo;
							//							(*instInfo)->CRFlag = TraceDqrProfiler::isNone;
							//							(*instInfo)->brFlags = TraceDqrProfiler::BRFLAG_none;
							getCRBRFlags(nm.getCKSRC(), currentAddress[currentCore], (*instInfo)->CRFlag, (*instInfo)->brFlags);
							(*instInfo)->timestamp = lastTime[currentCore];
						}

					}
					state[currentCore] = TRACE_STATE_GETMSGWITHCOUNT;
				}



				readNewTraceMessage = true;

				return status;
#endif
			case TraceDqrProfiler::TCODE_ERROR:
				state[currentCore] = TRACE_STATE_GETFIRSTSYNCMSG;

				nm.timestamp = 0;	// clear time because we have lost time
				lastTime[currentCore] = 0;
				currentAddress[currentCore] = 0;
				lastFaddr[currentCore] = 0;

				readNewTraceMessage = true;

				return status;
			case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
				rc = processTraceMessage(nm, currentAddress[currentCore], lastFaddr[currentCore], lastTime[currentCore], consumed);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: NextInstruction(): state TRACE_STATE_GETMSGWITHCOUNT: processTraceMessage()\n");

					status = TraceDqrProfiler::DQERR_ERR;
					state[currentCore] = TRACE_STATE_ERROR;

					return status;
				}



				readNewTraceMessage = true;

				return status;
			case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
			case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
				// these message have no address or count info, so we still need to get
				// another message.

				// might want to keep track of process, but will add that later

				// for now, return message;

				if (nm.haveTimestamp) {
					lastTime[currentCore] = processTS(TraceDqrProfiler::TS_rel, lastTime[currentCore], nm.timestamp);
				}


				readNewTraceMessage = true;

				return status;
			default:
				printf("Error: bad tcode type in state TRACE_STATE_GETMSGWITHCOUNT. TCODE (%d)\n", nm.tcode);

				state[currentCore] = TRACE_STATE_ERROR;
				status = TraceDqrProfiler::DQERR_ERR;

				return status;
			}
			break;
		case TRACE_STATE_RETIREMESSAGE:
			switch (nm.tcode) {
				// sync type messages say where to set pc to
			case TraceDqrProfiler::TCODE_SYNC:
			case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
			case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
			case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
			case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
			case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
			case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
			case TraceDqrProfiler::TCODE_RESOURCEFULL:
				rc = processTraceMessage(nm, currentAddress[currentCore], lastFaddr[currentCore], lastTime[currentCore], consumed);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: NextInstruction(): state TRACE_STATE_RETIREMESSAGE: processTraceMessage()\n");

					status = TraceDqrProfiler::DQERR_ERR;
					state[currentCore] = TRACE_STATE_ERROR;

					return status;
				}

				// I don't think the b_type code below actaully does anything??? Remove??

				TraceDqrProfiler::BType b_type;
				b_type = TraceDqrProfiler::BTYPE_UNDEFINED;

				switch (nm.tcode) {
				case TraceDqrProfiler::TCODE_SYNC:
				case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
					break;
				case TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS:
					if ((nm.ictWS.cksrc == TraceDqrProfiler::ICT_EXCEPTION) || (nm.ictWS.cksrc == TraceDqrProfiler::ICT_INTERRUPT)) {
						b_type = TraceDqrProfiler::BTYPE_EXCEPTION;
					}
					break;
				case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
					if ((nm.ict.cksrc == TraceDqrProfiler::ICT_EXCEPTION) || (nm.ict.cksrc == TraceDqrProfiler::ICT_INTERRUPT)) {
						b_type = TraceDqrProfiler::BTYPE_EXCEPTION;
					}
					break;
				case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
					b_type = nm.indirectBranchWS.b_type;
					break;
				case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
					b_type = nm.indirectBranch.b_type;
					break;
				case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
					b_type = nm.indirectHistory.b_type;
					break;
				case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
					b_type = nm.indirectHistoryWS.b_type;
					break;
				case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
				case TraceDqrProfiler::TCODE_RESOURCEFULL:
					// fall through
				default:
					break;
				}

				if (b_type == TraceDqrProfiler::BTYPE_EXCEPTION) {
					enterISR[currentCore] = TraceDqrProfiler::isInterrupt;
				}

				readNewTraceMessage = true;
				state[currentCore] = TRACE_STATE_GETNEXTMSG;
				break;
			case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
			case TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS:
				// these messages should have been retired immediately

				printf("Error: unexpected tcode of INCIRCUTTRACE or INCIRCUTTRACE_WS in state TRACE_STATE_RETIREMESSAGE\n");
				state[currentCore] = TRACE_STATE_ERROR;

				status = TraceDqrProfiler::DQERR_ERR;
				return status;
			case TraceDqrProfiler::TCODE_CORRELATION:
				// correlation has i_cnt, but no address info

				if (nm.haveTimestamp) {
					lastTime[currentCore] = processTS(TraceDqrProfiler::TS_rel, lastTime[currentCore], nm.timestamp);
				}



				readNewTraceMessage = true;

				// leaving trace mode - need to get next sync

				state[currentCore] = TRACE_STATE_GETFIRSTSYNCMSG;
				break;
			case TraceDqrProfiler::TCODE_ERROR:
				printf("Error: Unexpected tcode TCODE_ERROR in state TRACE_STATE_RETIREMESSAGE\n");

				state[currentCore] = TRACE_STATE_ERROR;
				status = TraceDqrProfiler::DQERR_ERR;

				return status;
			case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
			case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
				// these messages have no address or i-cnt info and should have been
				// instantly retired when they were read.

				state[currentCore] = TRACE_STATE_ERROR;
				status = TraceDqrProfiler::DQERR_ERR;

				return status;
			default:
				printf("Error: bad tcode type in state TRACE_STATE_RETIREMESSAGE\n");

				state[currentCore] = TRACE_STATE_ERROR;
				status = TraceDqrProfiler::DQERR_ERR;

				return status;
			}

			status = TraceDqrProfiler::DQERR_OK;
			return status;
		case TRACE_STATE_GETNEXTMSG:
			//			printf("TRACE_STATE_GETNEXTMSG\n");

						// exit this state when message with i-cnt, history, taken, or not-taken is read

			switch (nm.tcode) {
			case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
			case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
			case TraceDqrProfiler::TCODE_SYNC:
			case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
			case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
			case TraceDqrProfiler::TCODE_CORRELATION:
			case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
			case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
			case TraceDqrProfiler::TCODE_RESOURCEFULL:
				rc = counts->setCounts(&nm);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: nextInstruction: state TRACE_STATE_GETNEXTMESSAGE Count::seteCounts()\n");

					state[currentCore] = TRACE_STATE_ERROR;

					status = rc;

					return status;
				}

				state[currentCore] = TRACE_STATE_GETNEXTINSTRUCTION;
				break;
#if 0
			case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
			case TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS:
				// these message have no counts so they will be retired immeadiately

				rc = processTraceMessage(nm, currentAddress[currentCore], lastFaddr[currentCore], lastTime[currentCore], consumed);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: NextInstruction(): state TRACE_STATE_GETMSGWITHCOUNT: processTraceMessage()\n");

					status = TraceDqrProfiler::DQERR_ERR;
					state[currentCore] = TRACE_STATE_ERROR;

					return status;
				}

				if ((nm.getCKSRC() == TraceDqrProfiler::ICT_CONTROL) && (nm.getCKDF() == 0)) {
					// ICT_WS Control(0,0) only updates TS (if present). Does not change state or anything else
					addr = currentAddress[currentCore];
				}
				else {
					if ((nm.getCKSRC() == TraceDqrProfiler::ICT_EXT_TRIG) && (nm.getCKDF() == 0)) {
						// no dasm or src for ext trigger in HTM instruction traces
						addr = lastFaddr[currentCore];
					}
					else if ((nm.getCKSRC() == TraceDqrProfiler::ICT_WATCHPOINT) && (nm.getCKDF() == 0)) {
						// no dasm or src for ext trigger in HTM instruction tracaes
						addr = lastFaddr[currentCore];
					}
					else if ((instInfo != nullptr)) {
						addr = currentAddress[currentCore];

						Disassemble(addr);

						if (instInfo != nullptr) {
							instructionInfo.qDepth = 0;
							instructionInfo.arithInProcess = 0;
							instructionInfo.loadInProcess = 0;
							instructionInfo.storeInProcess = 0;

							instructionInfo.coreId = currentCore;
							*instInfo = &instructionInfo;
							//							(*instInfo)->CRFlag = TraceDqrProfiler::isNone;
							//							(*instInfo)->brFlags = TraceDqrProfiler::BRFLAG_none;
							getCRBRFlags(nm.getCKSRC(), currentAddress[currentCore], (*instInfo)->CRFlag, (*instInfo)->brFlags);

							(*instInfo)->timestamp = lastTime[currentCore];
						}


					}
				}


				readNewTraceMessage = true;

				return status;
#endif
			case TraceDqrProfiler::TCODE_ERROR:
				state[currentCore] = TRACE_STATE_GETFIRSTSYNCMSG;

				nm.timestamp = 0;	// clear time because we have lost time
				currentAddress[currentCore] = 0;
				lastFaddr[currentCore] = 0;
				lastTime[currentCore] = 0;


				readNewTraceMessage = true;

				return status;
			case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
			case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
				rc = processTraceMessage(nm, currentAddress[currentCore], lastFaddr[currentCore], lastTime[currentCore], consumed);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: NextInstruction(): state TRACE_STATE_GETNXTMSG: processTraceMessage()\n");

					status = TraceDqrProfiler::DQERR_ERR;
					state[currentCore] = TRACE_STATE_ERROR;

					return status;
				}


				readNewTraceMessage = true;

				return status;
			case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
				// retire these instantly by returning them through msgInfo

				if (nm.haveTimestamp) {
					lastTime[currentCore] = processTS(TraceDqrProfiler::TS_rel, lastTime[currentCore], nm.timestamp);
				}


				// leave state along. Need to get another message with an i-cnt!

				readNewTraceMessage = true;

				return status;
			default:
				state[currentCore] = TRACE_STATE_ERROR;
				status = TraceDqrProfiler::DQERR_ERR;

				return status;
			}
			break;
		case TRACE_STATE_GETNEXTINSTRUCTION:
			if (counts->getCurrentCountType(currentCore) == TraceDqrProfiler::COUNTTYPE_none) {
				if (profiler_globalDebugFlag) {
					printf("NextInstruction(): counts are exhausted\n");
				}

				state[currentCore] = TRACE_STATE_RETIREMESSAGE;
				break;
			}

			addr = currentAddress[currentCore];
			address_out = addr;
			uint32_t inst;
			int inst_size;
			TraceDqrProfiler::InstType inst_type;
			int32_t immediate;
			bool isBranch;
			int rc;
			TraceDqrProfiler::Reg rs1;
			TraceDqrProfiler::Reg rd;

			// getInstrucitonByAddress() should cache last instrucioton/address because I thjink
			// it gets called a couple times for each address/insruction in a row
#if 0
			status = elfReader->getInstructionByAddress(addr, inst);
			if (status != TraceDqrProfiler::DQERR_OK) {
				printf("Error: getInstructionByAddress failed - looking for next sync message\n");

				lastTime[currentCore] = 0;
				currentAddress[currentCore] = 0;
				lastFaddr[currentCore] = 0;

				state[currentCore] = TRACE_STATE_GETFIRSTSYNCMSG;

				// the evil break below exits the switch statement - not the if statement!

				break;

				//				state[currentCore] = TRACE_STATE_ERROR;
				//
				//				return status;
			}

			// figure out how big the instruction is

//			decode instruction/decode instruction size should cache their results (at least last one)
//			because it gets called a few times here!

			rc = decodeInstruction(inst, inst_size, inst_type, rs1, rd, immediate, isBranch);
			if (rc != 0) {
				printf("Error: Cann't decode size of instruction %04x\n", inst);

				state[currentCore] = TRACE_STATE_ERROR;
				status = TraceDqrProfiler::DQERR_ERR;

				return status;
			}
#endif
#if 0
			Disassemble(addr);
#endif
			// compute next address (retire this instruction)

			// nextAddr() will also update counts
			//
			// nextAddr() computes next address if possible, consumes counts

			// nextAddr can usually compute the next address, but not always. If it can't, it returns
			// -1 as the next address.  This should never happen for conditional branches because we
			// should always have enough informatioon. But it can happen for indirect branches. For indirect
			// branches, retiring the current trace message (should be an indirect branch or indirect
			// brnach with sync) will set the next address correclty.

			status = nextAddr(currentCore, currentAddress[currentCore], addr, nm.tcode, crFlag, brFlags);
			if (status != TraceDqrProfiler::DQERR_OK) {
				printf("Error: nextAddr() failed\n");

				state[currentCore] = TRACE_STATE_GETFIRSTSYNCMSG;

				status = TraceDqrProfiler::DQERR_OK;
				return status;
			}

			// if addr == -1 and brFlags == BRFLAG_unknown, we need to read another trace message
			// which hopefully with have history bits. Do not return the instruciton yet - we will
			// retry it after getting another trace message

			// if addr == -1 and brflags != BRFLAG_unknown, and current counts type != none, we have an
			// error.

			// if addr == -1 and brflags != BRFLAG_unkonw and current count type == none, all should
			// be good. We will return the instruction and read another message

			if (addr == (TraceDqrProfiler::ADDRESS)-1) {
				if (brFlags == TraceDqrProfiler::BRFLAG_unknown) {
					// read another trace message and retry

					state[currentCore] = TRACE_STATE_RETIREMESSAGE;
					break; // this break exits trace_state_getnextinstruction!
				}
				else if (counts->getCurrentCountType(currentCore) != TraceDqrProfiler::COUNTTYPE_none) {
					// error
					// must have a JR/JALR or exception/exception return to get here, and the CR stack is empty

					//printf("Error: getCurrentCountType(core:%d) still has counts; have countType: %d\n", currentCore, counts->getCurrentCountType(currentCore));
					//char d[64];

					//instructionInfo.instructionToText(d, sizeof d, 2);
					//printf("%08llx:    %s\n", currentAddress[currentCore], d);

					//state[currentCore] = TRACE_STATE_ERROR;

					//status = TraceDqrProfiler::DQERR_ERR;
					//return status;

					// Profiling will return error in case there is an issue with a trace record.
					// This will lead to loss of data. In case the profiler is not able to continue,
					// we can reset the state to TRACE_STATE_GETFIRSTSYNCMSG which will restart
					// profiling at the next sync packet.
					state[currentCore] = TRACE_STATE_GETFIRSTSYNCMSG;

					status = TraceDqrProfiler::DQERR_OK;
					return status;
				}
			}

			currentAddress[currentCore] = addr;

			uint32_t prevCycle;
			prevCycle = 0;
#if 0
			if (caTrace != nullptr) {
				if (syncCount > 0) {
					if (caSyncAddr == instructionInfo.address) {
						//						printf("ca sync successful at addr %08x\n",caSyncAddr);

						syncCount = 0;
					}
					else {
						syncCount -= 1;
						if (syncCount == 0) {
							printf("Error: unable to sync CA trace and instruction trace\n");
							state[currentCore] = TRACE_STATE_ERROR;
							status = TraceDqrProfiler::DQERR_ERR;
							return status;
						}
					}
				}

				if (syncCount == 0) {
					status = caTrace->consume(caFlags, inst_type, pipeCycles, viStartCycles, viFinishCycles, qDepth, arithInProcess, loadInProcess, storeInProcess);
					if (status == TraceDqrProfiler::DQERR_EOF) {
						state[currentCore] = TRACE_STATE_DONE;
						return status;
					}

					if (status != TraceDqrProfiler::DQERR_OK) {
						state[currentCore] = TRACE_STATE_ERROR;
						return status;
					}

					prevCycle = lastCycle[currentCore];

					eCycleCount[currentCore] = pipeCycles - prevCycle;

					lastCycle[currentCore] = pipeCycles;
				}
			}
#endif

			if (instInfo != nullptr) 
			{
				instructionInfo.qDepth = qDepth;
				instructionInfo.arithInProcess = arithInProcess;
				instructionInfo.loadInProcess = loadInProcess;
				instructionInfo.storeInProcess = storeInProcess;

				qDepth = 0;
				arithInProcess = 0;
				loadInProcess = 0;
				storeInProcess = 0;

				instructionInfo.coreId = currentCore;
				*instInfo = &instructionInfo;
				(*instInfo)->CRFlag = (crFlag | enterISR[currentCore]);
				enterISR[currentCore] = TraceDqrProfiler::isNone;
				(*instInfo)->brFlags = brFlags;

				if ((caTrace != nullptr) && (syncCount == 0)) {
					// note: start signal is one cycle after execution begins. End signal is two cycles after end

					(*instInfo)->timestamp = pipeCycles;
					(*instInfo)->pipeCycles = eCycleCount[currentCore];

					(*instInfo)->VIStartCycles = viStartCycles - prevCycle;
					(*instInfo)->VIFinishCycles = viFinishCycles - prevCycle - 1;

					(*instInfo)->caFlags = caFlags;
				}
				else {
					(*instInfo)->timestamp = lastTime[currentCore];
				}
			}

			//			lastCycle[currentCore] = cycles;

#if 0
			status = analytics.updateInstructionInfo(currentCore, inst, inst_size, crFlag, brFlags);
			if (status != TraceDqrProfiler::DQERR_OK) {
				state[currentCore] = TRACE_STATE_ERROR;

				printf("Error: updateInstructionInfo() failed\n");
				return status;
			}
#endif

			if (counts->getCurrentCountType(currentCore) != TraceDqrProfiler::COUNTTYPE_none) {
				// still have valid counts. Keep running nextInstruction!

				return status;
			}

			// counts have expired. Retire this message and read next trace message and update. This should cause the
			// current process instruction (above) to be returned along with the retired trace message

			// if the instruction processed above in an indirect branch, counts should be zero and
			// retiring this trace message should set the next address (message should be an indirect
			// brnach type message)

			state[currentCore] = TRACE_STATE_RETIREMESSAGE;
			break;
		case TRACE_STATE_DONE:
			status = TraceDqrProfiler::DQERR_DONE;
			return status;
		case TRACE_STATE_ERROR:
			status = TraceDqrProfiler::DQERR_ERR;
			return status;
		default:
			printf("Error: TraceProfiler::NextInstruction():unknown\n");

			state[currentCore] = TRACE_STATE_ERROR;
			status = TraceDqrProfiler::DQERR_ERR;
			return status;
		}
	}

	status = TraceDqrProfiler::DQERR_OK;
	return TraceDqrProfiler::DQERR_OK;
}
//NextInstruction() want to return address, instruction, trace message if any, label+offset for instruction, target of instruciton
//		source code for instruction (file, function, line)
//
//		return instruction object (include label informatioon)
//		return message object
//		return source code object//
//
//				if instruction object ptr is null, don't return any instruction info
//				if message object ptr is null, don't return any message info
//				if source code object is null, don't return source code info

TraceDqrProfiler::DQErr TraceProfiler::NextInstruction(ProfilerInstruction** instInfo, ProfilerNexusMessage** msgInfo, ProfilerSource** srcInfo)
{
	if (sfp == nullptr) {
		printf("Error: TraceProfiler::NextInstructin(): Null sfp object\n");

		status = TraceDqrProfiler::DQERR_ERR;
		return status;
	}

	if (status != TraceDqrProfiler::DQERR_OK) {
		return status;
	}

	TraceDqrProfiler::DQErr rc;
	TraceDqrProfiler::ADDRESS addr;
	int crFlag;
	TraceDqrProfiler::BranchFlags brFlags;
	uint32_t caFlags = 0;
	uint32_t pipeCycles = 0;
	uint32_t viStartCycles = 0;
	uint32_t viFinishCycles = 0;

	uint8_t qDepth = 0;
	uint8_t arithInProcess = 0;
	uint8_t loadInProcess = 0;
	uint8_t storeInProcess = 0;

	bool consumed = false;

	ProfilerInstruction** savedInstPtr = nullptr;
	ProfilerNexusMessage** savedMsgPtr = nullptr;
	ProfilerSource** savedSrcPtr = nullptr;

	if (instInfo != nullptr) {
		*instInfo = nullptr;
	}

	if (msgInfo != nullptr) {
		*msgInfo = nullptr;
	}

	if (srcInfo != nullptr) {
		*srcInfo = nullptr;
	}

	for (;;) {
		//		need to set readNewTraceMessage where it is needed! That includes
		//		staying in the same state that expects to get another message!!

		bool haveMsg;

		if (savedInstPtr != nullptr) {
			instInfo = savedInstPtr;
			savedInstPtr = nullptr;
		}

		if (savedMsgPtr != nullptr) {
			msgInfo = savedMsgPtr;
			savedMsgPtr = nullptr;
		}

		if (savedSrcPtr != nullptr) {
			srcInfo = savedSrcPtr;
			savedSrcPtr = nullptr;
		}

		if (readNewTraceMessage != false) {
			do {
				rc = sfp->readNextTraceMsg(nm, analytics, haveMsg);

				if (rc != TraceDqrProfiler::DQERR_OK) {
					// have an error. either EOF, or error

					status = rc;

					if (status == TraceDqrProfiler::DQERR_EOF) {
						state[currentCore] = TRACE_STATE_DONE;
					}
					else {
						printf("Error: TraceProfiler file does not contain any trace messages, or is unreadable\n");

						state[currentCore] = TRACE_STATE_ERROR;
					}

					return status;
				}

				if (haveMsg == false) {
					lastTime[currentCore] = 0;
					currentAddress[currentCore] = 0;
					lastFaddr[currentCore] = 0;

					state[currentCore] = TRACE_STATE_GETFIRSTSYNCMSG;
				}
			} while (haveMsg == false);

			readNewTraceMessage = false;
			currentCore = nm.coreId;

			// if set see if HTM trace message, switch to HTM mode

			if (traceType != TraceDqrProfiler::TRACETYPE_HTM) {
				switch (nm.tcode) {
				case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
				case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
				case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
				case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
				case TraceDqrProfiler::TCODE_ERROR:
				case TraceDqrProfiler::TCODE_SYNC:
				case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
				case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
				case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
				case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
				case TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS:
					break;
				case TraceDqrProfiler::TCODE_CORRELATION:
					if (nm.correlation.cdf == 1) {
						traceType = TraceDqrProfiler::TRACETYPE_HTM;
						if (profiler_globalDebugFlag) printf("TCODE_CORRELATION, cdf == 1: switching to HTM mode\n");
					}
					break;
				case TraceDqrProfiler::TCODE_RESOURCEFULL:
				case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
				case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
					traceType = TraceDqrProfiler::TRACETYPE_HTM;
					if (profiler_globalDebugFlag) printf("History/taken/not taken count TCODE: switching to HTM mode\n");
					break;
				case TraceDqrProfiler::TCODE_REPEATBRANCH:
				case TraceDqrProfiler::TCODE_REPEATINSTRUCTION:
				case TraceDqrProfiler::TCODE_REPEATINSTRUCTION_WS:
				case TraceDqrProfiler::TCODE_AUXACCESS_READNEXT:
				case TraceDqrProfiler::TCODE_AUXACCESS_WRITENEXT:
				case TraceDqrProfiler::TCODE_AUXACCESS_RESPONSE:
				case TraceDqrProfiler::TCODE_OUTPUT_PORTREPLACEMENT:
				case TraceDqrProfiler::TCODE_INPUT_PORTREPLACEMENT:
				case TraceDqrProfiler::TCODE_AUXACCESS_READ:
				case TraceDqrProfiler::TCODE_DATA_WRITE_WS:
				case TraceDqrProfiler::TCODE_DATA_READ_WS:
				case TraceDqrProfiler::TCODE_WATCHPOINT:
				case TraceDqrProfiler::TCODE_CORRECTION:
				case TraceDqrProfiler::TCODE_DATA_WRITE:
				case TraceDqrProfiler::TCODE_DATA_READ:
				case TraceDqrProfiler::TCODE_DEBUG_STATUS:
				case TraceDqrProfiler::TCODE_DEVICE_ID:
					printf("Error: NextInstruction(): Unsupported tcode type (%d)\n", nm.tcode);
					status = TraceDqrProfiler::DQERR_ERR;
					state[currentCore] = TRACE_STATE_ERROR;

					return status;
				case TraceDqrProfiler::TCODE_UNDEFINED:
					printf("Error: NextInstruction(): Undefined tcode type (%d)\n", nm.tcode);
					status = TraceDqrProfiler::DQERR_ERR;
					state[currentCore] = TRACE_STATE_ERROR;

					return status;
				}
			}

			// Check if this is a ICT Control message and if we are filtering them out

			switch (nm.tcode) {
			case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
			case TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS:
				if ((nm.getCKSRC() == TraceDqrProfiler::ICT_CONTROL) && (eventFilterMask & (1 << PROFILER_CTF::et_controlIndex))) {
					savedInstPtr = instInfo;
					instInfo = nullptr;
					savedMsgPtr = msgInfo;
					msgInfo = nullptr;
					savedSrcPtr = srcInfo;
					srcInfo = nullptr;
				}
				break;
			default:
				break;
			}
		}

		switch (state[currentCore]) {
		case TRACE_STATE_SYNCCATE:	// Looking for a CA trace sync
			// printf("TRACE_STATE_SYNCCATE\n");

			if (caTrace == nullptr) {
				// have an error! Should never have TRACE_STATE_SYNC without a caTrace ptr
				printf("Error: caTrace is null\n");
				status = TraceDqrProfiler::DQERR_ERR;
				state[currentCore] = TRACE_STATE_ERROR;
				return status;
			}

			// loop through trace messages until we find a sync of some kind. First sync should do it
			// sync reason must be correct (exit debug or start tracing) or we stay in this state

			TraceDqrProfiler::ADDRESS teAddr;

			switch (nm.tcode) {
			case TraceDqrProfiler::TCODE_ERROR:
				// reset time. Messages have been missed. Address may not still be 0 if we have seen a sync
				// message without an exit debug or start trace sync reason, so reset address

				lastTime[currentCore] = 0;
				currentAddress[currentCore] = 0;
				lastFaddr[currentCore] = 0;

				if (msgInfo != nullptr) {
					messageInfo = nm;

					// currentAddresss should be 0 until we get a sync message. TS has been set to 0

					messageInfo.currentAddress = currentAddress[currentCore];
					messageInfo.time = lastTime[currentCore];

					if ((consumed == false) && (messageInfo.processITCPrintData(itcPrint) == false)) {
						*msgInfo = &messageInfo;
					}
				}

				readNewTraceMessage = true;

				status = TraceDqrProfiler::DQERR_OK;

				return status;
			case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
			case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
			case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
			case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
			case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
			case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
			case TraceDqrProfiler::TCODE_CORRELATION:
			case TraceDqrProfiler::TCODE_RESOURCEFULL:
			case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
			case TraceDqrProfiler::TCODE_REPEATBRANCH:
			case TraceDqrProfiler::TCODE_REPEATINSTRUCTION:
			case TraceDqrProfiler::TCODE_REPEATINSTRUCTION_WS:
			case TraceDqrProfiler::TCODE_AUXACCESS_READNEXT:
			case TraceDqrProfiler::TCODE_AUXACCESS_WRITENEXT:
			case TraceDqrProfiler::TCODE_AUXACCESS_RESPONSE:
			case TraceDqrProfiler::TCODE_OUTPUT_PORTREPLACEMENT:
			case TraceDqrProfiler::TCODE_INPUT_PORTREPLACEMENT:
			case TraceDqrProfiler::TCODE_AUXACCESS_READ:
				// here we return the trace messages before we have actually started tracing
				// this could be at the start of a trace, or after leaving a trace because of
				// a correlation message

						// we may have a valid address and time already if we saw a sync without an exit debug				        // or start trace sync reason. So call processTraceMessage()

				if (lastFaddr[currentCore] != 0) {
					rc = processTraceMessage(nm, currentAddress[currentCore], lastFaddr[currentCore], lastTime[currentCore], consumed);
					if (rc != TraceDqrProfiler::DQERR_OK) {
						printf("Error: NextInstruction(): state TRACE_STATE_SYNCCATE: processTraceMessage()\n");

						status = TraceDqrProfiler::DQERR_ERR;
						state[currentCore] = TRACE_STATE_ERROR;

						return status;
					}
				}

				if (msgInfo != nullptr) {
					messageInfo = nm;

					// currentAddresss should be 0 until we get a sync message. TS may
					// have been set by a ICT control WS message

					messageInfo.currentAddress = currentAddress[currentCore];
					messageInfo.time = lastTime[currentCore];

					if ((consumed == false) && (messageInfo.processITCPrintData(itcPrint) == false)) {
						*msgInfo = &messageInfo;
					}
				}

				readNewTraceMessage = true;

				status = TraceDqrProfiler::DQERR_OK;

				return status;
			case TraceDqrProfiler::TCODE_SYNC:
			case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
			case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
			case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
				// sync reason should be either EXIT_DEBUG or TRACE_ENABLE. Otherwise, keep looking

				TraceDqrProfiler::SyncReason sr;

				sr = nm.getSyncReason();
				switch (sr) {
				case TraceDqrProfiler::SYNC_EXIT_DEBUG:
				case TraceDqrProfiler::SYNC_TRACE_ENABLE:
					// only exit debug or trace enable allow proceeding. All others stay in this state and return

					teAddr = nm.getF_Addr() << 1;
					break;
				case TraceDqrProfiler::SYNC_EVTI:
				case TraceDqrProfiler::SYNC_EXIT_RESET:
				case TraceDqrProfiler::SYNC_T_CNT:
				case TraceDqrProfiler::SYNC_I_CNT_OVERFLOW:
				case TraceDqrProfiler::SYNC_WATCHPINT:
				case TraceDqrProfiler::SYNC_FIFO_OVERRUN:
				case TraceDqrProfiler::SYNC_EXIT_POWERDOWN:
				case TraceDqrProfiler::SYNC_MESSAGE_CONTENTION:
				case TraceDqrProfiler::SYNC_PC_SAMPLE:
					// here we return the trace messages before we have actually started tracing
					// this could be at the start of a trace, or after leaving a trace because of
					// a correlation message
					// probably should never get here when doing a CA trace.

					rc = processTraceMessage(nm, currentAddress[currentCore], lastFaddr[currentCore], lastTime[currentCore], consumed);
					if (rc != TraceDqrProfiler::DQERR_OK) {
						printf("Error: NextInstruction(): state TRACE_STATE_SYNCCATE: processTraceMessage()\n");

						status = TraceDqrProfiler::DQERR_ERR;
						state[currentCore] = TRACE_STATE_ERROR;

						return status;
					}

					if (msgInfo != nullptr) {
						messageInfo = nm;

						// if doing pc-sampling and msg type is INCIRCUITTRACE_WS, we want to use faddr
						// and not currentAddress

						messageInfo.currentAddress = nm.getF_Addr() << 1;

						if ((consumed == false) && (messageInfo.processITCPrintData(itcPrint) == false)) {
							*msgInfo = &messageInfo;
						}
					}

					readNewTraceMessage = true;

					status = TraceDqrProfiler::DQERR_OK;

					return status;
				case TraceDqrProfiler::SYNC_NONE:
				default:
					printf("Error: invalid sync reason\n");
					status = TraceDqrProfiler::DQERR_ERR;
					state[currentCore] = TRACE_STATE_ERROR;

					return status;
				}
				break;
			case TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS:
				// INCIRCUTTRACE_WS messages do not have a sync reason, but control(0,1) has
				// the same info!

				TraceDqrProfiler::ICTReason itcr;

				itcr = nm.getCKSRC();

				switch (itcr) {
				case TraceDqrProfiler::ICT_INFERABLECALL:
				case TraceDqrProfiler::ICT_EXT_TRIG:
				case TraceDqrProfiler::ICT_EXCEPTION:
				case TraceDqrProfiler::ICT_INTERRUPT:
				case TraceDqrProfiler::ICT_CONTEXT:
				case TraceDqrProfiler::ICT_WATCHPOINT:
				case TraceDqrProfiler::ICT_PC_SAMPLE:
					rc = processTraceMessage(nm, currentAddress[currentCore], lastFaddr[currentCore], lastTime[currentCore], consumed);
					if (rc != TraceDqrProfiler::DQERR_OK) {
						printf("Error: NextInstruction(): state TRACE_STATE_SYNCCATE: processTraceMessage()\n");

						status = TraceDqrProfiler::DQERR_ERR;
						state[currentCore] = TRACE_STATE_ERROR;

						return status;
					}

					if (msgInfo != nullptr) {
						messageInfo = nm;

						// if doing pc-sampling and msg type is INCIRCUITTRACE_WS, we want to use faddr
						// and not currentAddress

						messageInfo.currentAddress = nm.getF_Addr() << 1;

						if ((consumed == false) && (messageInfo.processITCPrintData(itcPrint) == false)) {
							*msgInfo = &messageInfo;
						}
					}

					readNewTraceMessage = true;

					status = TraceDqrProfiler::DQERR_OK;

					return status;
				case TraceDqrProfiler::ICT_CONTROL:
					bool returnFlag;
					returnFlag = true;

					if (nm.ictWS.ckdf == 1) {
						switch (nm.ictWS.ckdata[1]) {
						case TraceDqrProfiler::ICT_CONTROL_TRACE_ON:
						case TraceDqrProfiler::ICT_CONTROL_EXIT_DEBUG:
							// only exit debug or trace enable allow proceeding. All others stay in this state and return

							teAddr = nm.getF_Addr() << 1;
							returnFlag = false;
							break;
						default:
							break;
						}
					}

					if (returnFlag) {
						rc = processTraceMessage(nm, currentAddress[currentCore], lastFaddr[currentCore], lastTime[currentCore], consumed);
						if (rc != TraceDqrProfiler::DQERR_OK) {
							printf("Error: NextInstruction(): state TRACE_STATE_SYNCCATE: processTraceMessage()\n");

							status = TraceDqrProfiler::DQERR_ERR;
							state[currentCore] = TRACE_STATE_ERROR;

							return status;
						}

						if (msgInfo != nullptr) {
							messageInfo = nm;

							// if doing pc-sampling and msg type is INCIRCUITTRACE_WS, we want to use faddr
							// and not currentAddress

							messageInfo.currentAddress = nm.getF_Addr() << 1;

							if ((consumed == false) && (messageInfo.processITCPrintData(itcPrint) == false)) {
								*msgInfo = &messageInfo;
							}
						}

						readNewTraceMessage = true;

						status = TraceDqrProfiler::DQERR_OK;

						return status;
					}
					break;
				case TraceDqrProfiler::ICT_NONE:
				default:
					printf("Error: invalid ICT reason\n");
					status = TraceDqrProfiler::DQERR_ERR;
					state[currentCore] = TRACE_STATE_ERROR;

					return status;
				}
				break;
			case TraceDqrProfiler::TCODE_DEBUG_STATUS:
			case TraceDqrProfiler::TCODE_DEVICE_ID:
			case TraceDqrProfiler::TCODE_DATA_WRITE:
			case TraceDqrProfiler::TCODE_DATA_READ:
			case TraceDqrProfiler::TCODE_CORRECTION:
			case TraceDqrProfiler::TCODE_DATA_WRITE_WS:
			case TraceDqrProfiler::TCODE_DATA_READ_WS:
			case TraceDqrProfiler::TCODE_WATCHPOINT:
			case TraceDqrProfiler::TCODE_UNDEFINED:
			default:
				printf("Error: nextInstruction(): state TRACE_STATE_SYNCCATE: unsupported or invalid TCODE\n");

				state[currentCore] = TRACE_STATE_ERROR;
				status = TraceDqrProfiler::DQERR_ERR;

				return status;
			}

			// run ca code until we get to the te trace address. only do 6 instructions a the most

			caSyncAddr = caTrace->getCATraceStartAddr();

			//			printf("caSyncAddr: %08x, teAddr: %08x\n",caSyncAddr,teAddr);

			//			caTrace->dumpCurrentCARecord(1);

			TraceDqrProfiler::ADDRESS savedAddr;
			savedAddr = -1;

			bool fail;
			fail = false;

			for (int i = 0; (fail == false) && (teAddr != caSyncAddr) && (i < 30); i++) {
				rc = nextCAAddr(caSyncAddr, savedAddr);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					fail = true;
				}
				else {
					//					printf("caSyncAddr: %08x, teAddr: %08x\n",caSyncAddr,teAddr);

					rc = caTrace->consume(caFlags, TraceDqrProfiler::INST_SCALER, pipeCycles, viStartCycles, viFinishCycles, qDepth, arithInProcess, loadInProcess, storeInProcess);
					if (rc == TraceDqrProfiler::DQERR_EOF) {
						state[currentCore] = TRACE_STATE_DONE;

						status = rc;
						return rc;
					}

					if (rc != TraceDqrProfiler::DQERR_OK) {
						state[currentCore] = TRACE_STATE_ERROR;

						status = rc;
						return status;
					}
				}
			}

			//			if (teAddr == caSyncAddr) {
			//				printf("ca sync found at address %08x, cycles: %d\n",caSyncAddr,cycles);
			//			}

			if (teAddr != caSyncAddr) {
				// unable to sync by fast-forwarding the CA trace to match the instruction trace
				// so we will try to run the normal trace for a few instructions with the hope it
				// will sync up with the ca trace! We set the max number of instructions to run
				// the normal trace below, and turn tracing loose!

				syncCount = 16;
				caTrace->rewind();
				caSyncAddr = caTrace->getCATraceStartAddr();

				//				printf("starting normal trace to sync up; caSyncAddr: %08x\n",caSyncAddr);
			}

			// readnextmessage should be false. So, we want to process the message like a normal message here
			// if the addresses of the trace and the start of the ca trace sync later, it is handled in
			// the other states

			state[currentCore] = TRACE_STATE_GETFIRSTSYNCMSG;
			break;
		case TRACE_STATE_GETFIRSTSYNCMSG:
			// start here for normal traces

			// read trace messages until a sync is found. Should be the first message normally
			// unless the wrapped buffer

			// only exit this state when sync type message is found or EOF or error
			// Event messages will cause state to change to TRACE_STATE_EVENT

			switch (nm.tcode) {
			case TraceDqrProfiler::TCODE_SYNC:
			case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
			case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
			case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
				rc = processTraceMessage(nm, currentAddress[currentCore], lastFaddr[currentCore], lastTime[currentCore], consumed);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: NextInstruction(): state TRACE_STATE_GETFIRSTSYNCMSG: processTraceMessage()\n");

					status = TraceDqrProfiler::DQERR_ERR;
					state[currentCore] = TRACE_STATE_ERROR;

					return status;
				}

				if (srcInfo != nullptr) {
					Disassemble(currentAddress[currentCore]);

					sourceInfo.coreId = currentCore;
					*srcInfo = &sourceInfo;
				}

				state[currentCore] = TRACE_STATE_GETMSGWITHCOUNT;
				break;
			case TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS:
				// this may set the timestamp, and and may set the address
				// all set the address except control(0,0) which is used just to set the timestamp at most

				rc = processTraceMessage(nm, currentAddress[currentCore], lastFaddr[currentCore], lastTime[currentCore], consumed);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: NextInstruction(): state TRACE_STATE_GETFIRSTSYNCMSG: processTraceMessage()\n");

					status = TraceDqrProfiler::DQERR_ERR;
					state[currentCore] = TRACE_STATE_ERROR;

					return status;
				}

				if (currentAddress[currentCore] == 0) {
					// for the get first sync state, we want currentAddress to be set
					// most incircuttrace_ws types will set it, but not 8,0; 14,0; 0,0

					currentAddress[currentCore] = lastFaddr[currentCore];
				}

				if ((nm.ictWS.cksrc == TraceDqrProfiler::ICT_CONTROL) && (nm.ictWS.ckdf == 0)) {
					// ICT_WS Control(0,0) only updates TS (if present). Does not change state or anything else
					// because it is the only incircuittrace message type with no address
				}
				else {
					if ((nm.getCKSRC() == TraceDqrProfiler::ICT_EXT_TRIG) && (nm.getCKDF() == 0)) {
						// no dasm or src for ext trigger in HTM instruction traces
					}
					else if ((nm.getCKSRC() == TraceDqrProfiler::ICT_WATCHPOINT) && (nm.getCKDF() == 0)) {
						// no dasm or src for ext trigger in HTM instruction traces
					}
					else if ((instInfo != nullptr) || (srcInfo != nullptr)) {
						Disassemble(currentAddress[currentCore]);

						if (instInfo != nullptr) {
							instructionInfo.qDepth = 0;
							instructionInfo.arithInProcess = 0;
							instructionInfo.loadInProcess = 0;
							instructionInfo.storeInProcess = 0;

							instructionInfo.coreId = currentCore;
							*instInfo = &instructionInfo;
							//							(*instInfo)->CRFlag = TraceDqrProfiler::isNone;
							//							(*instInfo)->brFlags = TraceDqrProfiler::BRFLAG_none;
							getCRBRFlags(nm.getCKSRC(), currentAddress[currentCore], (*instInfo)->CRFlag, (*instInfo)->brFlags);

							(*instInfo)->timestamp = lastTime[currentCore];
						}

						if (srcInfo != nullptr) {
							sourceInfo.coreId = currentCore;
							*srcInfo = &sourceInfo;
						}
					}
					state[currentCore] = TRACE_STATE_GETMSGWITHCOUNT;
				}
				break;
			case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
				rc = processTraceMessage(nm, currentAddress[currentCore], lastFaddr[currentCore], lastTime[currentCore], consumed);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: NextInstruction(): state TRACE_STATE_GETFIRSTSYNCMSG: processTraceMessage()\n");

					status = TraceDqrProfiler::DQERR_ERR;
					state[currentCore] = TRACE_STATE_ERROR;

					return status;
				}
				break;
			case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
			case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
			case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
			case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
			case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
			case TraceDqrProfiler::TCODE_RESOURCEFULL:
			case TraceDqrProfiler::TCODE_CORRELATION:
				if (nm.timestamp) {
					lastTime[currentCore] = processTS(TraceDqrProfiler::TS_rel, lastTime[currentCore], nm.timestamp);
				}
				break;
			case TraceDqrProfiler::TCODE_ERROR:
				// reset time. Messages have been missed.
				lastTime[currentCore] = 0;
				break;
			case TraceDqrProfiler::TCODE_DEBUG_STATUS:
			case TraceDqrProfiler::TCODE_DEVICE_ID:
			case TraceDqrProfiler::TCODE_DATA_WRITE:
			case TraceDqrProfiler::TCODE_DATA_READ:
			case TraceDqrProfiler::TCODE_CORRECTION:
			case TraceDqrProfiler::TCODE_DATA_WRITE_WS:
			case TraceDqrProfiler::TCODE_DATA_READ_WS:
			case TraceDqrProfiler::TCODE_WATCHPOINT:
			default:
				printf("Error: nextInstructin(): state TRACE_STATE_GETFIRSTSYNCMSG: unsupported or invalid TCODE\n");

				state[currentCore] = TRACE_STATE_ERROR;
				status = TraceDqrProfiler::DQERR_ERR;

				return status;
			}

			// INCIRCUITTRACE or INCIRCUITTRACE_WS will have set state to TRACE_STATE_EVENT

			readNewTraceMessage = true;

			// here we return the trace messages before we have actually started tracing
			// this could be at the start of a trace, or after leaving a trace because of
			// a correlation message

			if (msgInfo != nullptr) {
				messageInfo = nm;

				messageInfo.currentAddress = currentAddress[currentCore];

				messageInfo.time = lastTime[currentCore];

				if ((consumed == false) && (messageInfo.processITCPrintData(itcPrint) == false)) {
					*msgInfo = &messageInfo;
				}
			}

			status = TraceDqrProfiler::DQERR_OK;
			return status;
		case TRACE_STATE_GETMSGWITHCOUNT:

			// think GETMSGWITHCOUNT and GETNEXTMSG state are the same!! If so, combine them!

//			printf("TRACE_STATE_GETMSGWITHCOUNT %08x\n",lastFaddr[currentCore]);
			// only message with i-cnt/hist/taken/notTaken will release from this state

			// return any message without a count (i-cnt or hist, taken/not taken)

			// do not return message with i-cnt/hist/taken/not taken; process them when counts expires

			switch (nm.tcode) {
			case TraceDqrProfiler::TCODE_SYNC:
			case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
			case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
			case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
			case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
			case TraceDqrProfiler::TCODE_CORRELATION:
			case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
			case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
			case TraceDqrProfiler::TCODE_RESOURCEFULL:
				// don't update timestamp until messages are retired!

				// reset all counts before setting them. We have no valid counts before the second message.
				// first message is a sync-type message. Counts are for up to that message, nothing after.

				counts->resetCounts(currentCore);

				rc = counts->setCounts(&nm);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					state[currentCore] = TRACE_STATE_ERROR;
					status = rc;

					return status;
				}

				// only these TCODEs have counts and release from this state

				state[currentCore] = TRACE_STATE_GETNEXTINSTRUCTION;
				break;
			case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
			case TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS:
				// these message have no counts so they will be retired immediately

				rc = processTraceMessage(nm, currentAddress[currentCore], lastFaddr[currentCore], lastTime[currentCore], consumed);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: NextInstruction(): state TRACE_STATE_GETMSGWITHCOUNT: processTraceMessage()\n");

					status = TraceDqrProfiler::DQERR_ERR;
					state[currentCore] = TRACE_STATE_ERROR;

					return status;
				}

				if ((nm.getCKSRC() == TraceDqrProfiler::ICT_CONTROL) && (nm.getCKDF() == 0)) {
					// ICT_WS Control(0,0) only updates TS (if present). Does not change state or anything else
					addr = currentAddress[currentCore];
				}
				else {
					if ((nm.getCKSRC() == TraceDqrProfiler::ICT_EXT_TRIG) && (nm.getCKDF() == 0)) {
						// no dasm or src for ext trigger in HTM instruction traces
						addr = lastFaddr[currentCore];
					}
					else if ((nm.getCKSRC() == TraceDqrProfiler::ICT_WATCHPOINT) && (nm.getCKDF() == 0)) {
						// no dasm or src for ext trigger in HTM instruction tracaes
						addr = lastFaddr[currentCore];
					}
					else if ((instInfo != nullptr) || (srcInfo != nullptr)) {
						addr = currentAddress[currentCore];

						Disassemble(addr);

						if (instInfo != nullptr) {
							instructionInfo.qDepth = 0;
							instructionInfo.arithInProcess = 0;
							instructionInfo.loadInProcess = 0;
							instructionInfo.storeInProcess = 0;

							instructionInfo.coreId = currentCore;
							*instInfo = &instructionInfo;
							//							(*instInfo)->CRFlag = TraceDqrProfiler::isNone;
							//							(*instInfo)->brFlags = TraceDqrProfiler::BRFLAG_none;
							getCRBRFlags(nm.getCKSRC(), currentAddress[currentCore], (*instInfo)->CRFlag, (*instInfo)->brFlags);
							(*instInfo)->timestamp = lastTime[currentCore];
						}

						if (srcInfo != nullptr) {
							sourceInfo.coreId = currentCore;
							*srcInfo = &sourceInfo;
						}
					}
					state[currentCore] = TRACE_STATE_GETMSGWITHCOUNT;
				}

				if (msgInfo != nullptr) {
					messageInfo = nm;
					messageInfo.time = lastTime[currentCore];
					messageInfo.currentAddress = addr;

					if ((consumed == false) && (messageInfo.processITCPrintData(itcPrint) == false)) {
						*msgInfo = &messageInfo;
					}
				}

				readNewTraceMessage = true;

				return status;
			case TraceDqrProfiler::TCODE_ERROR:
				state[currentCore] = TRACE_STATE_GETFIRSTSYNCMSG;

				// don't update timestamp because we have missed some
				//
				// if (nm.haveTimestamp) {
				//	lastTime[currentCore] = processTS(TraceDqrProfiler::TS_rel,lastTime[currentCore],nm.timestamp);
				// }

				nm.timestamp = 0;	// clear time because we have lost time
				lastTime[currentCore] = 0;
				currentAddress[currentCore] = 0;
				lastFaddr[currentCore] = 0;

				if (msgInfo != nullptr) {
					messageInfo = nm;
					messageInfo.time = lastTime[currentCore];
					messageInfo.currentAddress = currentAddress[currentCore];

					if (messageInfo.processITCPrintData(itcPrint) == false) {
						*msgInfo = &messageInfo;
					}
				}

				readNewTraceMessage = true;

				return status;
			case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
				rc = processTraceMessage(nm, currentAddress[currentCore], lastFaddr[currentCore], lastTime[currentCore], consumed);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: NextInstruction(): state TRACE_STATE_GETMSGWITHCOUNT: processTraceMessage()\n");

					status = TraceDqrProfiler::DQERR_ERR;
					state[currentCore] = TRACE_STATE_ERROR;

					return status;
				}

				// for now, return message;

				if (msgInfo != nullptr) {
					messageInfo = nm;
					messageInfo.time = lastTime[currentCore];
					messageInfo.currentAddress = currentAddress[currentCore];

					if ((consumed == false) && (messageInfo.processITCPrintData(itcPrint) == false)) {
						*msgInfo = &messageInfo;
					}
				}

				readNewTraceMessage = true;

				return status;
			case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
			case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
				// these message have no address or count info, so we still need to get
				// another message.

				// might want to keep track of process, but will add that later

				// for now, return message;

				if (nm.haveTimestamp) {
					lastTime[currentCore] = processTS(TraceDqrProfiler::TS_rel, lastTime[currentCore], nm.timestamp);
				}

				if (msgInfo != nullptr) {
					messageInfo = nm;
					messageInfo.time = lastTime[currentCore];
					messageInfo.currentAddress = currentAddress[currentCore];

					if ((consumed == false) && (messageInfo.processITCPrintData(itcPrint) == false)) {
						*msgInfo = &messageInfo;
					}
				}

				readNewTraceMessage = true;

				return status;
			default:
				printf("Error: bad tcode type in state TRACE_STATE_GETMSGWITHCOUNT. TCODE (%d)\n", nm.tcode);

				state[currentCore] = TRACE_STATE_ERROR;
				status = TraceDqrProfiler::DQERR_ERR;

				return status;
			}
			break;
		case TRACE_STATE_RETIREMESSAGE:
			//			printf("TRACE_STATE_RETIREMESSAGE\n");

						// Process message being retired (currently in nm) i_cnt/taken/not taken/history has gone to 0
						// compute next address

			//			set lastFaddr,currentAddress,lastTime.
			//			readNewTraceMessage = true;
			//			state = Trace_State_GetNextMsg;
			//			return messageInfo.

						// retire message should be run anytime any count expires - i-cnt, history, taken, not taken

			switch (nm.tcode) {
				// sync type messages say where to set pc to
			case TraceDqrProfiler::TCODE_SYNC:
			case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
			case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
			case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
			case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
			case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
			case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
			case TraceDqrProfiler::TCODE_RESOURCEFULL:
				rc = processTraceMessage(nm, currentAddress[currentCore], lastFaddr[currentCore], lastTime[currentCore], consumed);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: NextInstruction(): state TRACE_STATE_RETIREMESSAGE: processTraceMessage()\n");

					status = TraceDqrProfiler::DQERR_ERR;
					state[currentCore] = TRACE_STATE_ERROR;

					return status;
				}

				if (msgInfo != nullptr) {
					messageInfo = nm;
					messageInfo.time = lastTime[currentCore];

					messageInfo.currentAddress = currentAddress[currentCore];

					if ((consumed == false) && (messageInfo.processITCPrintData(itcPrint) == false)) {
						*msgInfo = &messageInfo;
					}
				}

				if ((srcInfo != nullptr) && (*srcInfo == nullptr)) {
					Disassemble(currentAddress[currentCore]);

					sourceInfo.coreId = currentCore;
					*srcInfo = &sourceInfo;
				}

				// I don't think the b_type code below actaully does anything??? Remove??

				TraceDqrProfiler::BType b_type;
				b_type = TraceDqrProfiler::BTYPE_UNDEFINED;

				switch (nm.tcode) {
				case TraceDqrProfiler::TCODE_SYNC:
				case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
					break;
				case TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS:
					if ((nm.ictWS.cksrc == TraceDqrProfiler::ICT_EXCEPTION) || (nm.ictWS.cksrc == TraceDqrProfiler::ICT_INTERRUPT)) {
						b_type = TraceDqrProfiler::BTYPE_EXCEPTION;
					}
					break;
				case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
					if ((nm.ict.cksrc == TraceDqrProfiler::ICT_EXCEPTION) || (nm.ict.cksrc == TraceDqrProfiler::ICT_INTERRUPT)) {
						b_type = TraceDqrProfiler::BTYPE_EXCEPTION;
					}
					break;
				case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
					b_type = nm.indirectBranchWS.b_type;
					break;
				case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
					b_type = nm.indirectBranch.b_type;
					break;
				case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
					b_type = nm.indirectHistory.b_type;
					break;
				case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
					b_type = nm.indirectHistoryWS.b_type;
					break;
				case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
				case TraceDqrProfiler::TCODE_RESOURCEFULL:
					// fall through
				default:
					break;
				}

				if (b_type == TraceDqrProfiler::BTYPE_EXCEPTION) {
					enterISR[currentCore] = TraceDqrProfiler::isInterrupt;
				}

				readNewTraceMessage = true;
				state[currentCore] = TRACE_STATE_GETNEXTMSG;
				break;
			case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
			case TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS:
				// these messages should have been retired immediately

				printf("Error: unexpected tcode of INCIRCUTTRACE or INCIRCUTTRACE_WS in state TRACE_STATE_RETIREMESSAGE\n");
				state[currentCore] = TRACE_STATE_ERROR;

				status = TraceDqrProfiler::DQERR_ERR;
				return status;
			case TraceDqrProfiler::TCODE_CORRELATION:
				// correlation has i_cnt, but no address info

				if (nm.haveTimestamp) {
					lastTime[currentCore] = processTS(TraceDqrProfiler::TS_rel, lastTime[currentCore], nm.timestamp);
				}

				if (msgInfo != nullptr) {
					messageInfo = nm;
					messageInfo.time = lastTime[currentCore];

					// leaving trace mode - currentAddress should be last faddr + i_cnt *2

					messageInfo.currentAddress = lastFaddr[currentCore] + nm.correlation.i_cnt * 2;

					if ((consumed == false) && (messageInfo.processITCPrintData(itcPrint) == false)) {
						*msgInfo = &messageInfo;
					}
				}

				readNewTraceMessage = true;

				// leaving trace mode - need to get next sync

				state[currentCore] = TRACE_STATE_GETFIRSTSYNCMSG;
				break;
			case TraceDqrProfiler::TCODE_ERROR:
				printf("Error: Unexpected tcode TCODE_ERROR in state TRACE_STATE_RETIREMESSAGE\n");

				state[currentCore] = TRACE_STATE_ERROR;
				status = TraceDqrProfiler::DQERR_ERR;

				return status;
			case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
			case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
				// these messages have no address or i-cnt info and should have been
				// instantly retired when they were read.

				state[currentCore] = TRACE_STATE_ERROR;
				status = TraceDqrProfiler::DQERR_ERR;

				return status;
			default:
				printf("Error: bad tcode type in state TRACE_STATE_RETIREMESSAGE\n");

				state[currentCore] = TRACE_STATE_ERROR;
				status = TraceDqrProfiler::DQERR_ERR;

				return status;
			}

			status = TraceDqrProfiler::DQERR_OK;
			return status;
		case TRACE_STATE_GETNEXTMSG:
			//			printf("TRACE_STATE_GETNEXTMSG\n");

						// exit this state when message with i-cnt, history, taken, or not-taken is read

			switch (nm.tcode) {
			case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
			case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
			case TraceDqrProfiler::TCODE_SYNC:
			case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
			case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
			case TraceDqrProfiler::TCODE_CORRELATION:
			case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
			case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
			case TraceDqrProfiler::TCODE_RESOURCEFULL:
				rc = counts->setCounts(&nm);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: nextInstruction: state TRACE_STATE_GETNEXTMESSAGE Count::seteCounts()\n");

					state[currentCore] = TRACE_STATE_ERROR;

					status = rc;

					return status;
				}

				state[currentCore] = TRACE_STATE_GETNEXTINSTRUCTION;
				break;
			case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
			case TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS:
				// these message have no counts so they will be retired immeadiately

				rc = processTraceMessage(nm, currentAddress[currentCore], lastFaddr[currentCore], lastTime[currentCore], consumed);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: NextInstruction(): state TRACE_STATE_GETMSGWITHCOUNT: processTraceMessage()\n");

					status = TraceDqrProfiler::DQERR_ERR;
					state[currentCore] = TRACE_STATE_ERROR;

					return status;
				}

				if ((nm.getCKSRC() == TraceDqrProfiler::ICT_CONTROL) && (nm.getCKDF() == 0)) {
					// ICT_WS Control(0,0) only updates TS (if present). Does not change state or anything else
					addr = currentAddress[currentCore];
				}
				else {
					if ((nm.getCKSRC() == TraceDqrProfiler::ICT_EXT_TRIG) && (nm.getCKDF() == 0)) {
						// no dasm or src for ext trigger in HTM instruction traces
						addr = lastFaddr[currentCore];
					}
					else if ((nm.getCKSRC() == TraceDqrProfiler::ICT_WATCHPOINT) && (nm.getCKDF() == 0)) {
						// no dasm or src for ext trigger in HTM instruction tracaes
						addr = lastFaddr[currentCore];
					}
					else if ((instInfo != nullptr) || (srcInfo != nullptr)) {
						addr = currentAddress[currentCore];

						Disassemble(addr);

						if (instInfo != nullptr) {
							instructionInfo.qDepth = 0;
							instructionInfo.arithInProcess = 0;
							instructionInfo.loadInProcess = 0;
							instructionInfo.storeInProcess = 0;

							instructionInfo.coreId = currentCore;
							*instInfo = &instructionInfo;
							//							(*instInfo)->CRFlag = TraceDqrProfiler::isNone;
							//							(*instInfo)->brFlags = TraceDqrProfiler::BRFLAG_none;
							getCRBRFlags(nm.getCKSRC(), currentAddress[currentCore], (*instInfo)->CRFlag, (*instInfo)->brFlags);

							(*instInfo)->timestamp = lastTime[currentCore];
						}

						if (srcInfo != nullptr) {
							sourceInfo.coreId = currentCore;
							*srcInfo = &sourceInfo;
						}
					}
				}

				if (msgInfo != nullptr) {
					messageInfo = nm;
					messageInfo.time = lastTime[currentCore];
					messageInfo.currentAddress = addr;

					if ((consumed == false) && (messageInfo.processITCPrintData(itcPrint) == false)) {
						*msgInfo = &messageInfo;
					}
				}

				readNewTraceMessage = true;

				return status;
			case TraceDqrProfiler::TCODE_ERROR:
				state[currentCore] = TRACE_STATE_GETFIRSTSYNCMSG;

				nm.timestamp = 0;	// clear time because we have lost time
				currentAddress[currentCore] = 0;
				lastFaddr[currentCore] = 0;
				lastTime[currentCore] = 0;

				if (msgInfo != nullptr) {
					messageInfo = nm;
					messageInfo.time = lastTime[currentCore];
					messageInfo.currentAddress = currentAddress[currentCore];

					if ((consumed == false) && (messageInfo.processITCPrintData(itcPrint) == false)) {
						*msgInfo = &messageInfo;
					}
				}

				readNewTraceMessage = true;

				return status;
			case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
			case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
				rc = processTraceMessage(nm, currentAddress[currentCore], lastFaddr[currentCore], lastTime[currentCore], consumed);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: NextInstruction(): state TRACE_STATE_GETNXTMSG: processTraceMessage()\n");

					status = TraceDqrProfiler::DQERR_ERR;
					state[currentCore] = TRACE_STATE_ERROR;

					return status;
				}

				// for now, return message;

				if (msgInfo != nullptr) {
					messageInfo = nm;
					messageInfo.time = lastTime[currentCore];
					messageInfo.currentAddress = currentAddress[currentCore];

					if ((consumed == false) && (messageInfo.processITCPrintData(itcPrint) == false)) {
						*msgInfo = &messageInfo;
					}
				}

				readNewTraceMessage = true;

				return status;
			case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
				// retire these instantly by returning them through msgInfo

				if (nm.haveTimestamp) {
					lastTime[currentCore] = processTS(TraceDqrProfiler::TS_rel, lastTime[currentCore], nm.timestamp);
				}

				if (msgInfo != nullptr) {
					messageInfo = nm;
					messageInfo.time = lastTime[currentCore];
					messageInfo.currentAddress = currentAddress[currentCore];

					if ((consumed == false) && (messageInfo.processITCPrintData(itcPrint) == false)) {
						*msgInfo = &messageInfo;
					}
				}

				// leave state along. Need to get another message with an i-cnt!

				readNewTraceMessage = true;

				return status;
			default:
				state[currentCore] = TRACE_STATE_ERROR;
				status = TraceDqrProfiler::DQERR_ERR;

				return status;
			}
			break;
		case TRACE_STATE_GETNEXTINSTRUCTION:
			if (counts->getCurrentCountType(currentCore) == TraceDqrProfiler::COUNTTYPE_none) {
				if (profiler_globalDebugFlag) {
					printf("NextInstruction(): counts are exhausted\n");
				}

				state[currentCore] = TRACE_STATE_RETIREMESSAGE;
				break;
			}

			//			printf("state TRACE_STATE_GETNEXTINSTRUCTION\n");

						// Should first process addr, and then compute next addr!!! If can't compute next addr, it is an error.
						// Should always be able to process instruction at addr and compute next addr when we get here.
						// After processing next addr, if there are no more counts, retire trace message and get another

			addr = currentAddress[currentCore];

			uint32_t inst;
			int inst_size;
			TraceDqrProfiler::InstType inst_type;
			int32_t immediate;
			bool isBranch;
			int rc;
			TraceDqrProfiler::Reg rs1;
			TraceDqrProfiler::Reg rd;

			// getInstrucitonByAddress() should cache last instrucioton/address because I thjink
			// it gets called a couple times for each address/insruction in a row

			status = elfReader->getInstructionByAddress(addr, inst);
			if (status != TraceDqrProfiler::DQERR_OK) {
				printf("Error: getInstructionByAddress failed - looking for next sync message\n");

				lastTime[currentCore] = 0;
				currentAddress[currentCore] = 0;
				lastFaddr[currentCore] = 0;

				state[currentCore] = TRACE_STATE_GETFIRSTSYNCMSG;

				// the evil break below exits the switch statement - not the if statement!

				break;

				//				state[currentCore] = TRACE_STATE_ERROR;
				//
				//				return status;
			}

			// figure out how big the instruction is

//			decode instruction/decode instruction size should cache their results (at least last one)
//			because it gets called a few times here!

			rc = decodeInstruction(inst, inst_size, inst_type, rs1, rd, immediate, isBranch);
			if (rc != 0) {
				printf("Error: Cann't decode size of instruction %04x\n", inst);

				state[currentCore] = TRACE_STATE_ERROR;
				status = TraceDqrProfiler::DQERR_ERR;

				return status;
			}

			Disassemble(addr);

			// compute next address (retire this instruction)

			// nextAddr() will also update counts
			//
			// nextAddr() computes next address if possible, consumes counts

			// nextAddr can usually compute the next address, but not always. If it can't, it returns
			// -1 as the next address.  This should never happen for conditional branches because we
			// should always have enough informatioon. But it can happen for indirect branches. For indirect
			// branches, retiring the current trace message (should be an indirect branch or indirect
			// brnach with sync) will set the next address correclty.

			status = nextAddr(currentCore, currentAddress[currentCore], addr, nm.tcode, crFlag, brFlags);
			if (status != TraceDqrProfiler::DQERR_OK) {
				printf("Error: nextAddr() failed\n");

				state[currentCore] = TRACE_STATE_ERROR;

				return status;
			}

			// if addr == -1 and brFlags == BRFLAG_unknown, we need to read another trace message
			// which hopefully with have history bits. Do not return the instruciton yet - we will
			// retry it after getting another trace message

			// if addr == -1 and brflags != BRFLAG_unknown, and current counts type != none, we have an
			// error.

			// if addr == -1 and brflags != BRFLAG_unkonw and current count type == none, all should
			// be good. We will return the instruction and read another message

			if (addr == (TraceDqrProfiler::ADDRESS)-1) {
				if (brFlags == TraceDqrProfiler::BRFLAG_unknown) {
					// read another trace message and retry

					state[currentCore] = TRACE_STATE_RETIREMESSAGE;
					break; // this break exits trace_state_getnextinstruction!
				}
				else if (counts->getCurrentCountType(currentCore) != TraceDqrProfiler::COUNTTYPE_none) {
					// error
					// must have a JR/JALR or exception/exception return to get here, and the CR stack is empty

					printf("Error: getCurrentCountType(core:%d) still has counts; have countType: %d\n", currentCore, counts->getCurrentCountType(currentCore));
					char d[64];

					instructionInfo.instructionToText(d, sizeof d, 2);
					printf("%08llx:    %s\n", currentAddress[currentCore], d);

					state[currentCore] = TRACE_STATE_ERROR;

					status = TraceDqrProfiler::DQERR_ERR;

					//					nm.dumpRawMessage();
					//					nm.dump();
					//
					//					rc = sfp->readNextTraceMsg(nm,analytics,haveMsg);
					//
					//					if (rc != TraceDqrProfiler::DQERR_OK) {
					//						printf("Error: TraceProfiler file does not contain any trace messages, or is unreadable\n");
					//					} else if (haveMsg != false) {
					//						nm.dumpRawMessage();
					//						nm.dump();
					//					}

					return status;
				}
			}

			currentAddress[currentCore] = addr;

			uint32_t prevCycle;
			prevCycle = 0;

			if (caTrace != nullptr) {
				if (syncCount > 0) {
					if (caSyncAddr == instructionInfo.address) {
						//						printf("ca sync successful at addr %08x\n",caSyncAddr);

						syncCount = 0;
					}
					else {
						syncCount -= 1;
						if (syncCount == 0) {
							printf("Error: unable to sync CA trace and instruction trace\n");
							state[currentCore] = TRACE_STATE_ERROR;
							status = TraceDqrProfiler::DQERR_ERR;
							return status;
						}
					}
				}

				if (syncCount == 0) {
					status = caTrace->consume(caFlags, inst_type, pipeCycles, viStartCycles, viFinishCycles, qDepth, arithInProcess, loadInProcess, storeInProcess);
					if (status == TraceDqrProfiler::DQERR_EOF) {
						state[currentCore] = TRACE_STATE_DONE;
						return status;
					}

					if (status != TraceDqrProfiler::DQERR_OK) {
						state[currentCore] = TRACE_STATE_ERROR;
						return status;
					}

					prevCycle = lastCycle[currentCore];

					eCycleCount[currentCore] = pipeCycles - prevCycle;

					lastCycle[currentCore] = pipeCycles;
				}
			}

			if (instInfo != nullptr) {
				instructionInfo.qDepth = qDepth;
				instructionInfo.arithInProcess = arithInProcess;
				instructionInfo.loadInProcess = loadInProcess;
				instructionInfo.storeInProcess = storeInProcess;

				qDepth = 0;
				arithInProcess = 0;
				loadInProcess = 0;
				storeInProcess = 0;

				instructionInfo.coreId = currentCore;
				*instInfo = &instructionInfo;
				(*instInfo)->CRFlag = (crFlag | enterISR[currentCore]);
				enterISR[currentCore] = TraceDqrProfiler::isNone;
				(*instInfo)->brFlags = brFlags;

				if ((caTrace != nullptr) && (syncCount == 0)) {
					// note: start signal is one cycle after execution begins. End signal is two cycles after end

					(*instInfo)->timestamp = pipeCycles;
					(*instInfo)->pipeCycles = eCycleCount[currentCore];

					(*instInfo)->VIStartCycles = viStartCycles - prevCycle;
					(*instInfo)->VIFinishCycles = viFinishCycles - prevCycle - 1;

					(*instInfo)->caFlags = caFlags;
				}
				else {
					(*instInfo)->timestamp = lastTime[currentCore];
				}
			}

			//			lastCycle[currentCore] = cycles;

			if (srcInfo != nullptr) {
				sourceInfo.coreId = currentCore;
				*srcInfo = &sourceInfo;
			}

			status = analytics.updateInstructionInfo(currentCore, inst, inst_size, crFlag, brFlags);
			if (status != TraceDqrProfiler::DQERR_OK) {
				state[currentCore] = TRACE_STATE_ERROR;

				printf("Error: updateInstructionInfo() failed\n");
				return status;
			}


			if (counts->getCurrentCountType(currentCore) != TraceDqrProfiler::COUNTTYPE_none) {
				// still have valid counts. Keep running nextInstruction!

				return status;
			}

			// counts have expired. Retire this message and read next trace message and update. This should cause the
			// current process instruction (above) to be returned along with the retired trace message

			// if the instruction processed above in an indirect branch, counts should be zero and
			// retiring this trace message should set the next address (message should be an indirect
			// brnach type message)

			state[currentCore] = TRACE_STATE_RETIREMESSAGE;
			break;
		case TRACE_STATE_DONE:
			status = TraceDqrProfiler::DQERR_DONE;
			return status;
		case TRACE_STATE_ERROR:
			status = TraceDqrProfiler::DQERR_ERR;
			return status;
		default:
			printf("Error: TraceProfiler::NextInstruction():unknown\n");

			state[currentCore] = TRACE_STATE_ERROR;
			status = TraceDqrProfiler::DQERR_ERR;
			return status;
		}
	}

	status = TraceDqrProfiler::DQERR_OK;
	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr TraceProfiler::GenerateHistogram()
{
	if (status != TraceDqrProfiler::DQERR_OK)
	{
		return status;
	}

	TraceDqrProfiler::DQErr rc;
	TraceDqrProfiler::ADDRESS addr;
	int crFlag;
	TraceDqrProfiler::BranchFlags brFlags;
	bool consumed = false;
	uint64_t prev_address = 0;
	const uint64_t update_offset = 1000000;
	uint64_t next_offset = update_offset;
	bool complete = false;
	uint64_t n_ins_cnt = 0;
	for (;;)
	{
		bool haveMsg;
		if (readNewTraceMessage != false)
		{
			do
			{
				if (n_ins_cnt > next_offset)
				{
					if (m_fp_hist_callback)
						m_fp_hist_callback(m_hist_map, (nm.offset + nm.size_message), n_ins_cnt);
					next_offset += update_offset;
				}
				if ((nm.offset + nm.size_message) >= m_flush_data_offset)
				{
					if (m_fp_hist_callback)
						m_fp_hist_callback(m_hist_map, (nm.offset + nm.size_message), n_ins_cnt);
				}
				rc = sfp->readNextTraceMsg(nm, analytics, haveMsg);
				if (rc != TraceDqrProfiler::DQERR_OK)
				{
					// have an error. either EOF, or error
					status = rc;
					
					if (status == TraceDqrProfiler::DQERR_EOF) {
						state[currentCore] = TRACE_STATE_DONE;
					}
					else {
						printf("Error: TraceProfiler file does not contain any trace messages, or is unreadable\n");
						state[currentCore] = TRACE_STATE_ERROR;
					}


					complete = true;
					m_flush_data_offset = 0xFFFFFFFFFFFFFFFF;
					if (m_fp_hist_callback)
						m_fp_hist_callback(m_hist_map, (nm.offset + nm.size_message), n_ins_cnt);
					return status;
				}
				complete = false;
				if (haveMsg == false)
				{
					lastTime[currentCore] = 0;
					currentAddress[currentCore] = 0;
					lastFaddr[currentCore] = 0;

					state[currentCore] = TRACE_STATE_GETFIRSTSYNCMSG;
				}
			} while (haveMsg == false);

			readNewTraceMessage = false;
			currentCore = nm.coreId;
		}

		switch (state[currentCore])
		{
		case TRACE_STATE_GETFIRSTSYNCMSG:
			switch (nm.tcode) {
			case TraceDqrProfiler::TCODE_SYNC:
			case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
			case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
			case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
			case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
				rc = processTraceMessage(nm, currentAddress[currentCore], lastFaddr[currentCore], lastTime[currentCore], consumed);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					status = TraceDqrProfiler::DQERR_ERR;
					state[currentCore] = TRACE_STATE_ERROR;
					return status;
				}
				state[currentCore] = TRACE_STATE_GETMSGWITHCOUNT;
				continue;
			case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
			case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
			case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
			case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
			case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
			case TraceDqrProfiler::TCODE_RESOURCEFULL:
			case TraceDqrProfiler::TCODE_CORRELATION:
			case TraceDqrProfiler::TCODE_ERROR:
				break;
			case TraceDqrProfiler::TCODE_DEBUG_STATUS:
			case TraceDqrProfiler::TCODE_DEVICE_ID:
			case TraceDqrProfiler::TCODE_DATA_WRITE:
			case TraceDqrProfiler::TCODE_DATA_READ:
			case TraceDqrProfiler::TCODE_CORRECTION:
			case TraceDqrProfiler::TCODE_DATA_WRITE_WS:
			case TraceDqrProfiler::TCODE_DATA_READ_WS:
			case TraceDqrProfiler::TCODE_WATCHPOINT:
			default:
				state[currentCore] = TRACE_STATE_ERROR;
				status = TraceDqrProfiler::DQERR_ERR;
				return status;
			}
			readNewTraceMessage = true;
			status = TraceDqrProfiler::DQERR_OK;
			continue;
		case TRACE_STATE_GETMSGWITHCOUNT:
			switch (nm.tcode) {
			case TraceDqrProfiler::TCODE_SYNC:
			case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
			case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
			case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
			case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
			case TraceDqrProfiler::TCODE_CORRELATION:
			case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
			case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
			case TraceDqrProfiler::TCODE_RESOURCEFULL:
				counts->resetCounts(currentCore);
				rc = counts->setCounts(&nm);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					state[currentCore] = TRACE_STATE_ERROR;
					status = rc;
					return status;
				}
				state[currentCore] = TRACE_STATE_GETNEXTINSTRUCTION;
				continue;
			case TraceDqrProfiler::TCODE_ERROR:
				state[currentCore] = TRACE_STATE_GETFIRSTSYNCMSG;

				nm.timestamp = 0;	// clear time because we have lost time
				lastTime[currentCore] = 0;
				currentAddress[currentCore] = 0;
				lastFaddr[currentCore] = 0;

				readNewTraceMessage = true;

				continue;
			case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
				rc = processTraceMessage(nm, currentAddress[currentCore], lastFaddr[currentCore], lastTime[currentCore], consumed);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: NextInstruction(): state TRACE_STATE_GETMSGWITHCOUNT: processTraceMessage()\n");

					status = TraceDqrProfiler::DQERR_ERR;
					state[currentCore] = TRACE_STATE_ERROR;

					return status;
				}
				readNewTraceMessage = true;
				continue;
			case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
			case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
				readNewTraceMessage = true;
				continue;
			default:
				printf("Error: bad tcode type in state TRACE_STATE_GETMSGWITHCOUNT. TCODE (%d)\n", nm.tcode);

				state[currentCore] = TRACE_STATE_ERROR;
				status = TraceDqrProfiler::DQERR_ERR;

				return status;
			}
			break;
		case TRACE_STATE_RETIREMESSAGE:
			switch (nm.tcode) {
				// sync type messages say where to set pc to
			case TraceDqrProfiler::TCODE_SYNC:
			case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
			case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
			case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
			case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
			case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
			case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
			case TraceDqrProfiler::TCODE_RESOURCEFULL:
				rc = processTraceMessage(nm, currentAddress[currentCore], lastFaddr[currentCore], lastTime[currentCore], consumed);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: NextInstruction(): state TRACE_STATE_RETIREMESSAGE: processTraceMessage()\n");
					status = TraceDqrProfiler::DQERR_ERR;
					state[currentCore] = TRACE_STATE_ERROR;
					return status;
				}
				readNewTraceMessage = true;
				state[currentCore] = TRACE_STATE_GETNEXTMSG;
				continue;
			case TraceDqrProfiler::TCODE_CORRELATION:
				readNewTraceMessage = true;
				state[currentCore] = TRACE_STATE_GETFIRSTSYNCMSG;
				continue;
			case TraceDqrProfiler::TCODE_ERROR:
			case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
			case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
			case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
			case TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS:
			default:
				printf("Error: bad tcode type in state TRACE_STATE_RETIREMESSAGE\n");
				state[currentCore] = TRACE_STATE_ERROR;
				status = TraceDqrProfiler::DQERR_ERR;
				return status;
			}

			status = TraceDqrProfiler::DQERR_OK;
			continue;
		case TRACE_STATE_GETNEXTMSG:
			switch (nm.tcode) {
			case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
			case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
			case TraceDqrProfiler::TCODE_SYNC:
			case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
			case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
			case TraceDqrProfiler::TCODE_CORRELATION:
			case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
			case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
			case TraceDqrProfiler::TCODE_RESOURCEFULL:
				rc = counts->setCounts(&nm);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					printf("Error: nextInstruction: state TRACE_STATE_GETNEXTMESSAGE Count::seteCounts()\n");
					state[currentCore] = TRACE_STATE_ERROR;
					status = rc;
					return status;
				}
				state[currentCore] = TRACE_STATE_GETNEXTINSTRUCTION;
				continue;
			case TraceDqrProfiler::TCODE_ERROR:
				state[currentCore] = TRACE_STATE_GETFIRSTSYNCMSG;

				nm.timestamp = 0;	// clear time because we have lost time
				currentAddress[currentCore] = 0;
				lastFaddr[currentCore] = 0;
				lastTime[currentCore] = 0;

				readNewTraceMessage = true;
				continue;
			case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
			case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
				rc = processTraceMessage(nm, currentAddress[currentCore], lastFaddr[currentCore], lastTime[currentCore], consumed);
				if (rc != TraceDqrProfiler::DQERR_OK) {
					status = TraceDqrProfiler::DQERR_ERR;
					state[currentCore] = TRACE_STATE_ERROR;
					return status;
				}
				readNewTraceMessage = true;
				return status;
			case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
				readNewTraceMessage = true;
				continue;
			default:
				state[currentCore] = TRACE_STATE_ERROR;
				status = TraceDqrProfiler::DQERR_ERR;
				return status;
			}
			break;
		case TRACE_STATE_GETNEXTINSTRUCTION:
			if (counts->getCurrentCountType(currentCore) == TraceDqrProfiler::COUNTTYPE_none)
			{
				if (profiler_globalDebugFlag)
				{
					printf("NextInstruction(): counts are exhausted\n");
				}
				state[currentCore] = TRACE_STATE_RETIREMESSAGE;
				continue;
			}
			while (1)
			{
				addr = currentAddress[currentCore];
				uint64_t address_out = (addr);

				if (prev_address != address_out)
				{
					m_hist_map[address_out] += 1;
					n_ins_cnt++;
				}
				prev_address = address_out;

				uint32_t inst;
				int inst_size;
				TraceDqrProfiler::InstType inst_type;
				int32_t immediate;
				bool isBranch;
				int rc;
				TraceDqrProfiler::Reg rs1;
				TraceDqrProfiler::Reg rd;

				status = nextAddr(currentCore, currentAddress[currentCore], addr, nm.tcode, crFlag, brFlags);
				if (status != TraceDqrProfiler::DQERR_OK)
				{
					state[currentCore] = TRACE_STATE_ERROR;
					return status;
				}

				if (addr == (TraceDqrProfiler::ADDRESS)-1)
				{
					if (brFlags == TraceDqrProfiler::BRFLAG_unknown)
					{
						state[currentCore] = TRACE_STATE_RETIREMESSAGE;
						break;
					}
					else if (counts->getCurrentCountType(currentCore) != TraceDqrProfiler::COUNTTYPE_none)
					{
						state[currentCore] = TRACE_STATE_GETFIRSTSYNCMSG;
						status = TraceDqrProfiler::DQERR_OK;
						break;
					}
				}


				currentAddress[currentCore] = addr;

				if (counts->getCurrentCountType(currentCore) == TraceDqrProfiler::COUNTTYPE_none)
				{
					// still have valid counts. Keep running nextInstruction!
					break;
				}

				//state[currentCore] = TRACE_STATE_RETIREMESSAGE;
				//break;
			}
			break;
		case TRACE_STATE_DONE:
			status = TraceDqrProfiler::DQERR_DONE;
			return status;
		case TRACE_STATE_ERROR:
			status = TraceDqrProfiler::DQERR_ERR;
			return status;
		default:
			state[currentCore] = TRACE_STATE_ERROR;
			status = TraceDqrProfiler::DQERR_ERR;
			return status;
		}
	}

	status = TraceDqrProfiler::DQERR_OK;
	return TraceDqrProfiler::DQERR_OK;
}
