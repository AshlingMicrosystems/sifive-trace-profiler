/* Copyright 2022 SiFive, Inc */
/* SPDX-License-Identifier: Apache-2.0 */

#include <iostream>
#include <iomanip>
#include <fstream>
#include <cstring>
#include <cstdint>
#include "unistd_profiler.h"
//#include <unistd.h>
#include <fcntl.h>
#ifdef WINDOWS
#include <winsock2.h>
#include <namedpipeapi.h>
#else // WINDOWS
//#include <netdb.h>
//#include <sys/ioctl.h>
#include <errno.h>
#include <sys/types.h>
 #include <sys/wait.h>
//#include <sys/wait.h>
#endif // WINDOWS

#include "dqr_profiler.h"
#include "dqr_trace_profiler.h"

//#define DQR_PROFILER_MAXCORES	8

int profiler_globalDebugFlag = 0;

// DECODER_VERSION is passed in from the Makefile, from version.mk in the root.
const char* const DQR_PROFILER_VERSION = "DECODER_VERSION";

// static C type helper functions

static int atoh(char a)
{
	if (a >= '0' && a <= '9') {
		return a - '0';
	}

	if (a >= 'a' && a <= 'f') {
		return a - 'a' + 10;
	}

	if (a >= 'A' && a <= 'F') {
		return a - 'A' + 10;
	}

	return -1;
}

// Section Class Methods
cachedInstInfo::cachedInstInfo(const char* file, int cutPathIndex, const char* func, int linenum, const char* lineTxt, const char* instText, TraceDqrProfiler::RV_INST inst, int instSize, const char* addresslabel, int addresslabeloffset)
{
	// Don't need to allocate and copy file and function. They will remain until trace object is deleted

	filename = file;
	this->cutPathIndex = cutPathIndex;
	functionname = func;
	linenumber = linenum;
	lineptr = lineTxt;

	instruction = inst;
	instsize = instSize;

	addressLabel = addresslabel;
	addressLabelOffset = addresslabeloffset;

	// Need to allocate and copy instruction. src changes every time an instruction is disassembled, so we need to save it

	if (instText != nullptr) {
		int	s = strlen(instText) + 1;
		instructionText = new char[s];
		strcpy(instructionText, instText);
	}
	else {
		instructionText = nullptr;
	}
}

cachedInstInfo::~cachedInstInfo()
{
	filename = nullptr;
	functionname = nullptr;
	lineptr = nullptr;
	addressLabel = nullptr;

	if (instructionText != nullptr) {
		delete[] instructionText;
		instructionText = nullptr;
	}
}

void cachedInstInfo::dump()
{
	printf("cachedInstInfo()\n");
	printf("filename: '%s'\n", filename);
	printf("fucntion: '%s'\n", functionname);
	printf("linenumber: %d\n", linenumber);
	printf("lineptr: '%s'\n", lineptr);
	printf("instructin: 0x%08x\n", instruction);
	printf("instruction size: %d\n", instsize);
	printf("instruction text: '%s'\n", instructionText);
	printf("addressLabel: '%s'\n", addressLabel);
	printf("addressLabelOffset: %d\n", addressLabelOffset);
}

// work with elf file sections

Section::Section()
{
	next = nullptr;
	name[0] = 0;
	flags = 0;
	size = 0;
	offset = 0;
	startAddr = (TraceDqrProfiler::ADDRESS)0;
	endAddr = (TraceDqrProfiler::ADDRESS)0;
	code = nullptr;
	fName = nullptr;
	line = nullptr;
	diss = nullptr;
	cachedInfo = nullptr;
}

Section::~Section()
{
	if (code != nullptr) {
		delete[] code;
		code = nullptr;
	}

	if (fName != nullptr) {
		// what fNameo[] points to will be deleted when deleting srcFileRoot object
		delete[] fName;
		fName = nullptr;
	}

	if (line != nullptr) {
		delete[] line;
		line = nullptr;
	}

	if (diss != nullptr) {
		for (unsigned int i = 0; i < size / 2; i++) {
			if (diss[i] != nullptr) {
				delete[] diss[i];
				diss[i] = nullptr;
			}
		}
		delete[] diss;
		diss = nullptr;
	}

	if (cachedInfo != nullptr) {
		for (unsigned int i = 0; i < size / 2; i++) {
			if (cachedInfo[i] != nullptr) {
				delete cachedInfo[i];
				cachedInfo[i] = nullptr;
			}
		}

		delete[] cachedInfo;
		cachedInfo = nullptr;
	}
}

void Section::dump()
{
	printf("section: %s 0x%08x - 0x%08x, size: %u, flags: 0x%08x\n", name, startAddr, endAddr, size, flags);

	if ((flags & Section::sect_CODE) && (fName != nullptr) && (line != nullptr)) {
		for (uint32_t i = 0; i < size / 2; i++) {
			printf("[%u]: addr: 0x%08llx, %s:%d\n", i, startAddr + i * 2, fName[i], line[i]);
		}
	}
}

Section* Section::getSectionByAddress(TraceDqrProfiler::ADDRESS addr)
{
	Section* sp = this;

	while (sp != nullptr) {
		if ((addr >= sp->startAddr) && (addr <= sp->endAddr)) {
			return sp;
		}

		sp = sp->next;
	}

	return nullptr;
}

Section* Section::getSectionByName(char* secName)
{
	Section* sp = this;

	while (sp != nullptr) {
		if (strcmp(sp->name,secName) == 0) {
			return sp;
		}

		sp = sp->next;
	}

	return nullptr;
}

cachedInstInfo* Section::setCachedInfo(TraceDqrProfiler::ADDRESS addr, const char* file, int cutPathIndex, const char* func, int linenum, const char* lineTxt, const char* instTxt, TraceDqrProfiler::RV_INST inst, int instSize, const char* addresslabel, int addresslabeloffset)
{
	if ((addr >= startAddr) && (addr <= endAddr)) {
		if (cachedInfo != nullptr) {

			int index = (addr - startAddr) >> 1;

			if (cachedInfo[index] != nullptr) {
				printf("Error: Section::setCachedInfo(): cachedInfo[%d] not null\n", index);
				return nullptr;
			}

			cachedInstInfo* cci;
			cci = new cachedInstInfo(file, cutPathIndex, func, linenum, lineTxt, instTxt, inst, instSize, addresslabel, addresslabeloffset);

			cachedInfo[index] = cci;

			return cci;
		}
	}

	return nullptr;
}

cachedInstInfo* Section::getCachedInfo(TraceDqrProfiler::ADDRESS addr)
{
	if ((addr >= startAddr) && (addr <= endAddr)) {
		if (cachedInfo != nullptr) {
			return cachedInfo[(addr - startAddr) >> 1];
		}
	}

	return nullptr;
}

int        ProfilerInstruction::addrSize;
uint32_t   ProfilerInstruction::addrDispFlags;
int        ProfilerInstruction::addrPrintWidth;

std::string ProfilerInstruction::addressToString(int labelLevel)
{
	char dst[128];

	addressToText(dst, sizeof dst, labelLevel);

	return std::string(dst);
}

void ProfilerInstruction::addressToText(char* dst, size_t len, int labelLevel)
{
	if (dst == nullptr) {
		printf("Error: ProfilerInstruction::addressToText(): Argument dst is null\n");
		return;
	}

	dst[0] = 0;

	if (addrDispFlags & TraceDqrProfiler::ADDRDISP_WIDTHAUTO) {
		while (address > (0xffffffffffffffffllu >> (64 - addrPrintWidth * 4))) {
			addrPrintWidth += 1;
		}
	}

	int n;

	if ((addrPrintWidth > 8) && (addrDispFlags & TraceDqrProfiler::ADDRDISP_SEP)) {
		n = snprintf(dst, len, "%0*x.%08x", addrPrintWidth - 8, (uint32_t)(address >> 32), (uint32_t)address);
	}
	else {
		n = snprintf(dst, len, "%0*llx", addrPrintWidth, address);
	}

	if ((labelLevel >= 1) && (addressLabel != nullptr)) {
		if (addressLabelOffset != 0) {
			snprintf(dst + n, len - n, " <%s+%x>", addressLabel, addressLabelOffset);
		}
		else {
			snprintf(dst + n, len - n, " <%s>", addressLabel);
		}
	}
}

std::string ProfilerInstruction::instructionToString(int labelLevel)
{
	char dst[128];

	instructionToText(dst, sizeof dst, labelLevel);

	return std::string(dst);
}

void ProfilerInstruction::instructionToText(char* dst, size_t len, int labelLevel)
{
	if (dst == nullptr) {
		printf("Error: ProfilerInstruction::instructionToText(): Argument dst is null\n");
		return;
	}

	dst[0] = 0;

	//	should cache this (as part of other instruction stuff cached)!!

	if (instSize == 32) {
		snprintf(dst, len, "%08x    %s", instruction, instructionText);
	}
	else {
		snprintf(dst, len, "%04x        %s", instruction, instructionText);
	}
}

std::string ProfilerInstruction::addressLabelToString()
{

	if (addressLabel != nullptr) {
		return std::string(addressLabel);
	}

	return std::string("");
}

const char* ProfilerSource::stripPath(const char* path)
{
	if (path == nullptr) {
		return sourceFile;
	}

	const char* s = sourceFile;

	if (s == nullptr) {
		return nullptr;
	}

	for (;;) {
		if (*path == 0) {
			return s;
		}

		if (tolower(*path) == tolower(*s)) {
			path += 1;
			s += 1;
		}
		else if (*path == '/') {
			if (*s != '\\') {
				return sourceFile;
			}
			path += 1;
			s += 1;
		}
		else if (*path == '\\') {
			if (*s != '/') {
				return sourceFile;
			}
			path += 1;
			s += 1;
		}
		else {
			return sourceFile;
		}
	}

	return nullptr;
}

std::string ProfilerSource::sourceFileToString(std::string path)
{
	if (sourceFile != nullptr) {
		// check for garbage in path/file name

		const char* sf = stripPath(path.c_str());
		if (sf == nullptr) {
			printf("Error: sourceFileToString(): stripPath() returned nullptr\n");
		}
		else {
			for (int i = 0; sf[i] != 0; i++) {
				switch (sf[i]) {
				case 'a':
				case 'b':
				case 'c':
				case 'd':
				case 'e':
				case 'f':
				case 'g':
				case 'h':
				case 'i':
				case 'j':
				case 'k':
				case 'l':
				case 'm':
				case 'n':
				case 'o':
				case 'p':
				case 'q':
				case 'r':
				case 's':
				case 't':
				case 'u':
				case 'v':
				case 'w':
				case 'x':
				case 'y':
				case 'z':
				case 'A':
				case 'B':
				case 'C':
				case 'D':
				case 'E':
				case 'F':
				case 'G':
				case 'H':
				case 'I':
				case 'J':
				case 'K':
				case 'L':
				case 'M':
				case 'N':
				case 'O':
				case 'P':
				case 'Q':
				case 'R':
				case 'S':
				case 'T':
				case 'U':
				case 'V':
				case 'W':
				case 'X':
				case 'Y':
				case 'Z':
				case '0':
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
				case '8':
				case '9':
				case '/':
				case '\\':
				case '.':
				case '_':
				case '-':
				case '+':
				case ':':
					break;
				default:
					printf("Error: source::srouceFileToSTring(): File name '%s' contains bogus char (0x%02x) in position %d!\n", sf, sf[i], i);
					break;
				}
			}
		}
	}

	if (sourceFile != nullptr) {

		const char* sf = stripPath(path.c_str());

		return std::string(sf);
	}

	return std::string("");
}

std::string ProfilerSource::sourceFileToString()
{
	if (sourceFile != nullptr) {
		return std::string(sourceFile);
	}

	return std::string("");
}

std::string ProfilerSource::sourceLineToString()
{
	if (sourceLine != nullptr) {
		return std::string(sourceLine);
	}

	return std::string("");
}

std::string ProfilerSource::sourceFunctionToString()
{
	if (sourceFunction != nullptr) {
		return std::string(sourceFunction);
	}

	return std::string("");
}

fileReader::fileReader(/*paths*/)
{
	lastFile = nullptr;
	files = nullptr;
	cutPath = nullptr;
	newRoot = nullptr;
}

fileReader::~fileReader()
{
	if (cutPath != nullptr) {
		delete[] cutPath;
		cutPath = nullptr;
	}

	if (newRoot != nullptr) {
		delete[] newRoot;
		newRoot = nullptr;
	}

	for (fileList* fl = files; fl != nullptr;) {
		fileList* nextFl = fl->next;

		for (funcList* func = fl->funcs; func != nullptr;) {
			funcList* nextFunc = func->next;
			if (func->func != nullptr) {
				delete[] func->func;
				func->func = nullptr;
			}
			delete func;
			func = nextFunc;
		}

		if (fl->name != nullptr) {
			delete[] fl->name;
			fl->name = nullptr;
		}

		if (fl->lines != nullptr) {
			if (fl->lines[0] != nullptr) {
				delete[] fl->lines[0];
			}
			delete fl->lines;
			fl->lines = nullptr;
		}

		fl = nextFl;
	}

	files = nullptr;
}

fileReader::fileList* fileReader::readFile(const char* file)
{
	if (file == nullptr) {
		printf("Error: fileReader::readFile(): No file specified\n");
		return nullptr;
	}

	std::ifstream  f;
	const char* original_file_name = file;
	int fi = 0; // file name inmdex

	if ((cutPath != nullptr) && (cutPath[0] != 0)) {
		// the plan is to strip off the cutpath portion of the file name and try to open the file
		// if that doesn't work, try the original file name
		// if that doesn't work, try just the file name with no path info

		char cpDrive = 0;
		char fnDrive = 0;
		int ci = 0; // cut path index

		// the tricky part is if this is windows and there is a drive designator, handle that
		// the cut path may or may not have a drive designator.
		// Unix-like OSs don't mess with such silly stuff

		// check for a drive designator on the cut path string

		if ((cutPath[0] != 0) && (cutPath[1] == ':')) {
			if ((cutPath[0] >= 'a') && (cutPath[0] <= 'z')) {
				cpDrive = 'A' + (cutPath[0] - 'a');
				ci = 2;
			}
			else if ((cutPath[0] >= 'A') && (cutPath[0] <= 'Z')) {
				cpDrive = cutPath[0];
				ci = 2;
			}
		}

		// check for a drive designator on the file name string

		if ((file[0] != 0) && (file[1] == ':')) {
			if ((file[0] >= 'a') && (file[0] <= 'z')) {
				fnDrive = 'A' + (file[0] - 'a');
				fi = 2;
			}
			else if ((file[0] >= 'A') && (file[0] <= 'Z')) {
				fnDrive = file[0];
				fi = 2;
			}
		}

		// if there are drive designators for both, they must match. If there are no drive
		// designators, they match. If there is a drive designators for file and none for cutpath
		// and the drive designtor for file is 'C:', they match.

		bool match = true;

		if (cpDrive == fnDrive) {
			// have a match. Either neither has a drive, or both have the same drive
		}
		else if ((cpDrive == 0) && (fnDrive == 'C')) {
			// have a match. Default to cpDrive of 'C' if nont specified.
		}
		else {
			// no match
			match = false;
		}

		/* \ matches /, / matches \ */

		while (match && (cutPath[ci] != 0) && (file[fi] != 0)) {
			if (cutPath[ci] == file[fi]) {
				ci += 1;
				fi += 1;
			}
			else if ((cutPath[ci] == '/') && (file[fi] == '\\')) {
				ci += 1;
				fi += 1;
			}
			else if ((cutPath[ci] == '\\') && (file[fi] == '/')) {
				ci += 1;
				fi += 1;
			}
			else {
				match = false;
			}
		}

		if (cutPath[ci] != 0) {
			match = false;
		}

		if (match == false) {
			fi = 0;
		}

		//		printf("cutPath: %s\n",cutPath);
		//		printf("file: %s\n",file);
		//
		//		if (match) {
		//			printf("match!\n");
		//
		//			printf("remaining path: %s\n",&file[fi]);
		//		}
		//		else {
		//			printf("no match!\n");
		//		}

		if ((match == true) && (newRoot != nullptr)) {
			int fl = strlen(&file[fi]);
			int rl = strlen(newRoot);
			char* newName;
			newName = new char[fl + rl + 1];

			strcpy(newName, newRoot);
			strcpy(&newName[rl], &file[fi]);

			//			printf("newName: %s\n",newName);

			f.open(newName, std::ifstream::binary);

			delete[] newName;
			newName = nullptr;
		}
		else {
			f.open(&file[fi], std::ifstream::binary);
		}
	}
	else {
		f.open(file, std::ifstream::binary);

		if (!f) {
			//		printf("Error: readFile(): could not open file %s for input\n",file);

					// try again after stripping off path

			int l = -1;

			for (int i = 0; file[i] != 0; i++) {
				if ((file[i] == '/') || (file[i] == '\\')) {
					l = i;
				}
			}

			if (l != -1) {
				file = &file[l + 1];
				f.open(file, std::ifstream::binary);
			}
		}
	}

	fileList* fl = new fileList;

	fl->next = files;
	fl->funcs = nullptr;
	files = fl;

	int len = strlen(original_file_name) + 1;
	char* name = new char[len];
	strcpy(name, original_file_name);

	fl->name = name;
	fl->cutPathIndex = fi;

	if (!f) {
		// always return a file list pointer, even if a file isn't found. If file not
		// found, lines will be null

		fl->lineCount = 0;
		fl->lines = nullptr;

		return fl;
	}

	// get length of file:

	f.seekg(0, f.end);
	int length = f.tellg();
	f.seekg(0, f.beg);

	// allocate memory:

	char* buffer = new char[length + 1]; // allocate an extra byte in case the file does not end with \n

	// read file into buffer

	f.read(buffer, length);

	f.close();

	// count lines

	int lc = 1;

	for (int i = 0; i < length; i++) {
		if (buffer[i] == '\n') {
			lc += 1;
		}
		else if (i == length - 1) {
			// last line does not have a \n
			lc += 1;
		}
	}

	// create array of line pointers

	char** lines = new char* [lc];

	// initialize arry of ptrs

	int l;
	int s;

	l = 0;
	s = 1;

	for (int i = 0; i < length; i++) {
		if (s != 0) {
			lines[l] = &buffer[i];
			l += 1;
			s = 0;
		}

		// strip out CRs and LFs

		if (buffer[i] == '\r') {
			buffer[i] = 0;
		}
		else if (buffer[i] == '\n') {
			buffer[i] = 0;
			s = 1;
		}
	}

	buffer[length] = 0;	// make sure last line is nul terminated

	if (l >= lc) {
		delete[] lines;
		delete[] buffer;

		fl->lineCount = 0;
		fl->lines = nullptr;

		printf("Error: readFile(): Error computing line count for file %s, l:%d, lc: %d\n", file, l, lc);

		return nullptr;
	}

	lines[l] = nullptr;

	fl->lineCount = l;
	fl->lines = lines;

	return fl;
}

fileReader::fileList* fileReader::findFile(const char* file)
{
	if (file == nullptr) {
		printf("Error: fileReader::findFile(): No file specified\n");
		return nullptr;
	}

	// first check if file is same as last one uesed

	if (lastFile != nullptr) {
		if (strcmp(lastFile->name,file) == 0) {
			// found file!
			return lastFile;
		}
	}

	struct fileList* fp;

	for (fp = files; fp != nullptr; fp = fp->next) {
		if (strcmp(fp->name,file) == 0) {
			lastFile = fp;
			return fp;
		}
	}

	// didn't find file. See if we can read it in

	fp = readFile(file);

	return fp;
}

TraceDqrProfiler::DQErr fileReader::subSrcPath(const char* cutPath, const char* newRoot)
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

	return TraceDqrProfiler::DQERR_OK;
}

static int symCompareFunc(const void* arg1, const void* arg2)
{
	if (arg1 == nullptr) {
		printf("Error: symCompareFunc(): Null first argument\n");
		return 0;
	}

	if (arg2 == nullptr) {
		printf("Error: symCompareFunc(): Null second argument\n");
		return 0;
	}

	Sym* first;
	Sym* second;

	first = *(Sym**)arg1;
	second = *(Sym**)arg2;

	int64_t cv;
	cv = first->address - second->address;

	int rv;

	// > 0: first comes after second, return 1
	// < 0: first comes before second, return -1
	// = 0: break tie:
	// 	if first is weak and second is not, first comes after second, return 1
	// 	if first is not weak and second is weak, first comes before second, return -1
	//
	// 	if first is debug and second is not, first comes after second, return 1
	// 	if first is not debug and second is debug, first comes before second, return -1
	//
	// 	if first is not global and second is global, first comes after second, return 1
	// 	if first is global and seoncd is not global, first comes before second, return -1
	//
	//	if first is not a function and second is a function, first comes after second, return 1
	//	if first is a function and second is not a function, first comes before second, return -1
	//
	// 	otherwise, return 0

	if (cv > 0) {
		rv = 1;
	}
	else if (cv < 0) {
		rv = -1;
	}
	else {
		// if addrs are same, use weak as the tie breaker, or global, or debug

		if ((first->flags & Sym::symWeak) && !(second->flags & Sym::symWeak)) {
			rv = 1;
		}
		else if (!(first->flags & Sym::symWeak) && (second->flags & Sym::symWeak)) {
			rv = -1;
		}
		else if ((first->flags & Sym::symDebug) && !(second->flags & Sym::symDebug)) {
			rv = 1;
		}
		else if (!(first->flags & Sym::symDebug) && (second->flags & Sym::symDebug)) {
			rv = -1;
		}
		else if (!(first->flags & Sym::symGlobal) && (second->flags & Sym::symGlobal)) {
			rv = 1;
		}
		else if ((first->flags & Sym::symGlobal) && !(second->flags & Sym::symGlobal)) {
			rv = -1;
		}
		else if (!(first->flags & Sym::symFunc) && (second->flags & Sym::symFunc)) {
			rv = 1;
		}
		else if ((first->flags & Sym::symFunc) && !(second->flags & Sym::symFunc)) {
			rv = -1;
		}
		else {
			// If we get here, the address and attributes are the same. So we do a
			// compare of the names, just to make this deterministic across platforms

       		rv = strcmp(first->name,second->name);
		}
	}

	return rv;
}

Symtab::Symtab(Sym* syms)
{
	status = TraceDqrProfiler::DQERR_OK;

	numSyms = 0;

	if (syms == nullptr) {
		printf("Info: No symbol information\n");

		symLst = nullptr;
		numSyms = 0;

		return;
	}

	cachedSymAddr = 0;
	cachedSymSize = 0;
	cachedSymIndex = -1;

	symLst = syms;

	Sym* symPtr;

	for (symPtr = syms; symPtr != nullptr; symPtr = symPtr->next) {
		numSyms += 1;
	}

	symPtrArray = new struct Sym* [numSyms];

	symPtr = syms;

	//        	make sure all symbols with no type info in code sections have function type added!

	for (int i = 0; i < numSyms; i++) {
		symPtrArray[i] = symPtr;

		symPtr = symPtr->next;
	}

	// note: qsort does not preserver order on equal items!

	qsort((void*)symPtrArray, (size_t)numSyms, sizeof symPtrArray[0], symCompareFunc);

	TraceDqrProfiler::DQErr rc;

	rc = fixupFunctionSizes();
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;
	}
}

Symtab::~Symtab()
{
	if (symLst != nullptr) {
		Sym* nextSym;
		nextSym = symLst;
		while (nextSym != nullptr) {
			Sym* tmpSymPtr;
			tmpSymPtr = nextSym->next;

			nextSym->srcFile = nullptr;

			if (nextSym->name != nullptr) {
				delete[] nextSym->name;
				nextSym->name = nullptr;
			}

			delete nextSym;
			nextSym = tmpSymPtr;
		}

		symLst = nullptr;
	}

	if (symPtrArray != nullptr) {
		delete[] symPtrArray;
		symPtrArray = nullptr;
	}
}

TraceDqrProfiler::DQErr Symtab::fixupFunctionSizes()
{
	bool haveStartSym;

	for (int s = 0; s < numSyms; s++) {
		haveStartSym = false;

		if (symPtrArray[s]->size == 0) {
			// compute size as distance to next symbol

			// if no section, don't have a start sym!
			// if debug, don't have a start sym!

			if (!(symPtrArray[s]->flags & Sym::symDebug) && (symPtrArray[s]->section != nullptr)) {
				haveStartSym = true;
			}
		}

		if (haveStartSym) {
			// look for following symbol - does not need to have a size of 0

			bool haveEndSym;
			haveEndSym = false;

			for (int e = s + 1; (e < numSyms) && !haveEndSym; e++) {
				if (symPtrArray[s]->section != symPtrArray[e]->section) {
					// went past end of section
					// size is from sym to end of section

					symPtrArray[s]->size = symPtrArray[s]->section->endAddr + 1 - symPtrArray[s]->address;

					haveEndSym = true;
				}
				else if (symPtrArray[e]->address != symPtrArray[s]->address) {
					if (!(symPtrArray[s]->flags & Sym::symDebug)) {
						symPtrArray[s]->size = symPtrArray[e]->address - symPtrArray[s]->address;

						haveEndSym = true;
					}
				}
			}
		}
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr Symtab::lookupSymbolByAddress(TraceDqrProfiler::ADDRESS addr, Sym*& sym) {
	if (addr == 0) {
		sym = nullptr;
		return TraceDqrProfiler::DQERR_ERR;
	}

	// check for a cache hit
	if ((addr >= cachedSymAddr) && (addr < (cachedSymAddr + cachedSymSize))) {
		if (cachedSymIndex < 0 || cachedSymIndex >= numSyms) {
			sym = nullptr;
			return TraceDqrProfiler::DQERR_ERR;
		}
		sym = symPtrArray[cachedSymIndex];
		return TraceDqrProfiler::DQERR_OK;
	}

	// not in cache, go look for it
	int found = -1;
	for (int i = 0; (found == -1) && (i < numSyms); i++) {
		if (symPtrArray[i] == nullptr) {
			continue;
		}
		if ((addr >= symPtrArray[i]->address) && (addr < (symPtrArray[i]->address + symPtrArray[i]->size))) {
			found = i;
		}
	}

	if (found >= 0) {
		// found - cache it
		cachedSymIndex = found;
		cachedSymAddr = symPtrArray[found]->address;
		sym = symPtrArray[found];
	}
	else {
		sym = nullptr;
	}

	return TraceDqrProfiler::DQERR_OK;
}


void Symtab::dump()
{
	printf("number_of_symbols: %ld\n", numSyms);

	for (int i = 0; i < numSyms; i++) {
		printf("sym[%d]: address: 0x%08llx, size: %8u ",
			i,
			symPtrArray[i]->address,
			(uint32_t)symPtrArray[i]->size);

		uint32_t flags = symPtrArray[i]->flags;

		if ((flags & (Sym::symLocal | Sym::symGlobal)) == (Sym::symLocal | Sym::symGlobal)) {
			printf("!");
		}
		else if (flags & Sym::symLocal) {
			printf("l");
		}
		else if (flags & Sym::symGlobal) {
			printf("g");
		}
		else {
			printf(" ");
		}

		if (flags & Sym::symWeak) {
			printf("w");
		}
		else {
			printf(" ");
		}

		if (flags & Sym::symConstructor) {
			printf("C");
		}
		else {
			printf(" ");
		}

		if (flags & Sym::symIndirect) {
			printf("I");
		}
		else if (flags & Sym::symIndirectFunc) {
			printf("i");
		}
		else {
			printf(" ");
		}

		if (flags & Sym::symDebug) {
			printf("d");
		}
		else if (flags & Sym::symDynamic) {
			printf("D");
		}
		else {
			printf(" ");
		}

		if (flags & Sym::symFunc) {
			printf("F");
		}
		else if (flags & Sym::symFile) {
			printf("f");
		}
		else if (flags & Sym::symObj) {
			printf("O");
		}
		else {
			printf(" ");
		}

		printf(" %s, ", symPtrArray[i]->name);

		if (symPtrArray[i]->section != nullptr) {
			printf(" section: %s\n", symPtrArray[i]->section->name);
		}
		else {
			printf(" section: no section\n");
		}
	}
}

ObjDump::ObjDump(const char* elfName, const char* objdumpPath, int& archSize, Section*& codeSectionLst, Sym*& syms, SrcFileRoot& srcFileRoot)
{
	TraceDqrProfiler::DQErr rc;

	status = TraceDqrProfiler::DQERR_OK;

	stdoutPipe = -1;
	objdumpPid = (int32_t)-1;
	fpipe = nullptr;

	pipeEOF = false;
	pipeIndex = 0;
	endOfBuffer = 0;

	rc = execObjDump(elfName, objdumpPath);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = TraceDqrProfiler::DQERR_ERR;
		pipeEOF = true;

		return;
	}

	rc = parseObjdump(archSize, codeSectionLst, syms, srcFileRoot);

#ifndef WINDOWS

	int status;
	status = 0;

	waitpid(objdumpPid, &status, 0);

#endif	// WINDOWS

	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = TraceDqrProfiler::DQERR_ERR;
	}
}

ObjDump::~ObjDump()
{
	if (stdoutPipe >= 0) {
		_close(stdoutPipe);
		stdoutPipe = -1;
	}

	if (fpipe != nullptr) {
		fclose(fpipe);
		fpipe = nullptr;
	}
}

#ifdef WINDOWS
#define PATH_SEP "\\"
#define PATH_SEG_SEP ';'
#else // WINDOWS
#define PATH_SEP "/"
#define PATH_SEG_SEP ':'
#endif // WINDOWS

static TraceDqrProfiler::DQErr findObjDump(char* objDump, bool& foundExec)
{
	//	printf("findObjDump(): %s\n",objDump);

	foundExec = false;

	if (objDump == nullptr) {
		return TraceDqrProfiler::DQERR_ERR;
	}

#ifdef WINDOWS
	// make sure there is a .exe extention on the name of objdump

	int l;
	l = strlen(objDump);
	if ((l < 4) || (strcasecmp(&objDump[l - 4], ".exe") != 0)) {
		strcat(objDump, ".exe");
	}
#endif // WINDOWS

	// see if a path was included in the name.

	bool hasPath;
	hasPath = false;

	for (int i = 0; (hasPath == false) && (objDump[i] != 0); i++) {
		if (objDump[i] == '/') {
			hasPath = true;
		}
		else if (objDump[i] == '\\') {
			hasPath = true;
		}
	}

	//	printf("hasPath: %d\n",hasPath);

	if (hasPath == true) {

		// has a path - don't mess with it

		// still need to see if it exists

#ifdef WINDOWS
		if (objDump[0] == '/') {
			if (((objDump[1] >= 'a') && (objDump[1] <= 'z')) ||
				((objDump[1] >= 'A') && (objDump[1] <= 'Z'))) {
				if (objDump[2] == '/') {
					objDump[0] = objDump[1];
					objDump[1] = ':';
				}
			}

		}
#endif // WINDOWS

		//		printf("try0: %s\n",objDump);

		if (access(objDump, X_OK) == 0) {
			foundExec = true;
		}

		//		printf("found: %d\n",foundExec);

		return TraceDqrProfiler::DQERR_OK;
	}

	char objdumpcmd[512];
	char* riscv_path;

	// try prepending the RISCV_PATH environment variable

	riscv_path = getenv("RISCV_PATH");
	if (riscv_path != nullptr) {
		bool unix_path;
		bool windows_path;
		char last_char;

		unix_path = false;
		windows_path = false;
		last_char = 0;

		strcpy(objdumpcmd, riscv_path);

		// see if there is a terminating path specifyer in the path

		for (int i = 0; riscv_path[i] != 0; i++) {
			if (riscv_path[i] == '/') {
				unix_path = true;
			}
			else if (riscv_path[i] == '\\') {
				windows_path = true;
			}
			else {
				last_char = riscv_path[i];
			}
		}

		if (windows_path == true) {
			if (unix_path == true) {
				printf("Error: findObjDump(): Conflicting path type\n");
				return TraceDqrProfiler::DQERR_ERR;
			}

			if (last_char != '\\') {
				strcat(objdumpcmd, "\\");
			}
		}
		else if (unix_path == true) {
			if (last_char != '/') {
				strcat(objdumpcmd, "/");
			}
		}

		strcat(objdumpcmd, objDump);

		//		printf("try1: %s\n",objdumpcmd);

		if (access(objdumpcmd, X_OK) == 0) {
			strcpy(objDump, objdumpcmd);

			foundExec = true;

			//			printf("found: %d\n",foundExec);

			return TraceDqrProfiler::DQERR_OK;
		}
	}

	// see if we can execute objdump with the given name (or path/name)

	char* path;
	path = getenv("PATH");

	if (path != nullptr) {
		int s;
		int e;
		bool path_sep;

		s = 0;
		while ((path[s] != 0) && (foundExec == false)) {
			path_sep = false;

			e = s;

			while ((path[e] != 0) && (path[e] != PATH_SEG_SEP)) {
				if ((path[e] == '/') || (path[e] == '\\')) {
					path_sep = true;
				}
				else {
					path_sep = false;
				}
				e += 1;
			}

			// try from start to finish

			char end;
			end = path[e];

			path[e] = 0;
			strcpy(objdumpcmd, &path[s]);

			//			printf("path seg: %s\n",objdumpcmd);

						// add name of objdump program to end

			if (path_sep == false) {
				strcat(objdumpcmd, PATH_SEP);
			}

			strcat(objdumpcmd, objDump);

			//			printf("trying path %s, %d\n",objdumpcmd,access(objdumpcmd,X_OK));

			if (access(objdumpcmd, X_OK) == 0) {
				strcpy(objDump, objdumpcmd);

				foundExec = true;

				//				printf("found: %d\n",foundExec);
			}

			if (end != 0) {
				s = e + 1;
			}
			else {
				s = e;
			}
		}

		if (foundExec == true) {
			strcpy(objDump, objdumpcmd);
			return TraceDqrProfiler::DQERR_OK;
		}
	}

	// try executing in the current working directory

#ifdef WINDOWS
	strcpy(objdumpcmd, ".\\");
#else // WINDOWS
	strcpy(objdumpcmd, "./");
#endif // WINDOWS

	strcat(objdumpcmd, objDump);

	//	printf("try3: %s\n",objdumpcmd);

	if (access(objdumpcmd, X_OK) == 0) {
		foundExec = true;

		strcpy(objDump, objdumpcmd);

		//		printf("found: %d\n",foundExec);

		return TraceDqrProfiler::DQERR_OK;
	}

	//	printf("give up: %d\n",foundExec);

	return TraceDqrProfiler::DQERR_OK;
}

#ifdef WINDOWS

TraceDqrProfiler::DQErr ObjDump::execObjDump(const char* elfName, const char* objdumpPath)
{
	char cmd[1024];
	char objdump[512];
	TraceDqrProfiler::DQErr rc;

	if (objdumpPath == nullptr) {
		strcpy(objdump, PROFILER_DEFAULTOBJDUMPNAME);
	}
	else {
		strcpy(objdump, objdumpPath);
	}

	bool foundExec;

	rc = findObjDump(objdump, foundExec);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		return TraceDqrProfiler::DQERR_ERR;
	}

	if (foundExec == false) {
		printf("Error: execObjDump(): Could not find objdump\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	sprintf(cmd, "\"%s\" -t -d -h -l \"%s\"", objdump, elfName);

	//  printf("cmd: '%s'\n",cmd);

#ifdef WINDOWS
	SECURITY_ATTRIBUTES sa;
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = TRUE;

	hStdOutPipeRead = NULL;
	hStdOutPipeWrite = NULL;
	if (CreatePipe(&hStdOutPipeRead, &hStdOutPipeWrite, &sa, 0) == FALSE)
	{
		return TraceDqrProfiler::DQERR_ERR;
	}


	STARTUPINFO si;
	DWORD flags = CREATE_NO_WINDOW;

	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	ZeroMemory(&si, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	si.dwFlags |= STARTF_USESTDHANDLES;
	si.hStdError = hStdOutPipeWrite;
	si.hStdOutput = hStdOutPipeWrite;
	si.hStdInput = NULL;

	if (CreateProcess(NULL, cmd, NULL, NULL, TRUE, flags, NULL, NULL, &si, &pi) == FALSE)
	{
		return TraceDqrProfiler::DQERR_ERR;
	}

	// Close pipes we do not need.
	CloseHandle(hStdOutPipeWrite);
	hStdOutPipeWrite = NULL;
#else
	fpipe = _popen(cmd, "rb");
	if (fpipe == NULL) {
		printf("Error: popen(): Failed\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	stdoutPipe = fileno(fpipe);
	if (stdoutPipe == -1) {
		printf("Error: fileno(): Failed\n");
		return TraceDqrProfiler::DQERR_ERR;
	}
#endif
	return TraceDqrProfiler::DQERR_OK;
}

#else // WINDOWS

TraceDqrProfiler::DQErr ObjDump::execObjDump(const char* elfName, const char* objdumpPath)
{
	int rc;
	bool foundExec;

	char objdump[512];

	if (objdumpPath == nullptr) {
		strcpy(objdump, PROFILER_DEFAULTOBJDUMPNAME);
	}
	else {
		strcpy(objdump, objdumpPath);
	}

	rc = findObjDump(objdump, foundExec);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		return TraceDqrProfiler::DQERR_ERR;
	}

	if (foundExec == false) {
		printf("Error: execObjDump(): Could not find objdump\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	pid_t pid;

	// pid == 0 for child process, for parent process, pid is pid of child

	int stdoutPipefd[2];

	rc = pipe(stdoutPipefd);
	if (rc < 0) {
		printf("Error: pipe(): failed\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	pid = fork();
	if (pid == -1) {
		printf("Error: fork(): failed\n");

		close(stdoutPipefd[0]);
		close(stdoutPipefd[1]);

		objdumpPid = (pid_t)-1;

		return TraceDqrProfiler::DQERR_ERR;
	}

	if (pid != 0) {
		// parent

		objdumpPid = pid;

		close(stdoutPipefd[1]);

		stdoutPipe = stdoutPipefd[0];

		return TraceDqrProfiler::DQERR_OK;
	}
	else {
		// child

		close(stdoutPipefd[0]);

		rc = dup2(stdoutPipefd[1], STDOUT_FILENO);
		if (rc < 0) {
			printf("Error: child: dup2(): failed\n");

			close(stdoutPipefd[1]);

			return TraceDqrProfiler::DQERR_ERR;
		}

		char command[512];
		char elf[512];

		strcpy(command, objdump);
		strcpy(elf, elfName);

		char* argument_list[] = { "-t", "-d", "-h", "-l", elf, NULL };

		execvp(command, argument_list);
		printf("Error: execv(): failed\n");

		close(stdoutPipefd[1]);

		return TraceDqrProfiler::DQERR_ERR;
	}

	// should never get here

	return TraceDqrProfiler::DQERR_ERR;
}

#endif // WINDOWS

#ifdef WINDOWS
TraceDqrProfiler::DQErr ObjDump::fillPipeBuffer()
{
	if (pipeEOF) {
		return TraceDqrProfiler::DQERR_OK;
	}

	if (hStdOutPipeRead == NULL) {
		printf("Error: fillPipeBuffer(): Invalid pipe\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	DWORD dwRead = 0;
	ReadFile(hStdOutPipeRead, pipeBuffer, sizeof pipeBuffer, &dwRead, NULL);
	if (dwRead < 0) {
		printf("Error: fillPipeBuffer(): read() failed\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	if (dwRead == 0) {
		pipeEOF = 0;
		WaitForSingleObject(pi.hProcess, INFINITE);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hStdOutPipeRead);
		hStdOutPipeRead = NULL;
	}

	endOfBuffer = dwRead;
	pipeIndex = 0;

	return TraceDqrProfiler::DQERR_OK;
}
#else
TraceDqrProfiler::DQErr ObjDump::fillPipeBuffer()
{
	int rc;

	if (pipeEOF) {
		return TraceDqrProfiler::DQERR_OK;
	}

	if (stdoutPipe < 0) {
		printf("Error: fillPipeBuffer(): Invalid pipe\n");

		return TraceDqrProfiler::DQERR_ERR;
	}

	rc = read(stdoutPipe, pipeBuffer, sizeof pipeBuffer);
	if (rc < 0) {
		printf("Error: fillPipeBuffer(): read() failed\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	if (rc == 0) {
		pipeEOF = 0;
	}

	//{
	//for (int i = 0; i < rc; i++) {
	//printf("%c",pipeBuffer[i]);
	//}
	//}

	endOfBuffer = rc;
	pipeIndex = 0;

	return TraceDqrProfiler::DQERR_OK;
}
#endif

bool ObjDump::isWSLookahead()
{
	if (pipeIndex >= endOfBuffer) {
		// fill buffer

		TraceDqrProfiler::DQErr rc;

		rc = fillPipeBuffer();
		if (rc != TraceDqrProfiler::DQERR_OK) {
			return odtt_error;
		}

		if (endOfBuffer == 0) {
			return false;
		}
	}

	switch (pipeBuffer[pipeIndex]) {
	case ' ':
	case '\t':
		return true;
	default:
		break;
	}

	return false;
}

ObjDump::objDumpTokenType ObjDump::getNextLex(char* lex, bool treat_space_as_lex)
{
	TraceDqrProfiler::DQErr rc;
	int haveWS = 1;

	lex[0] = 0;

	// strip WS

	do {
		while ((pipeIndex < endOfBuffer) && haveWS) {
			switch (pipeBuffer[pipeIndex]) {
			case ' ':
			case '\r':
			case '\t':
				pipeIndex += 1;
				break;
			default:
				haveWS = 0;
				break;
			}
		}

		if (haveWS) {
			// if haveWS is still true, we ran out of chars

			rc = fillPipeBuffer();
			if (rc != TraceDqrProfiler::DQERR_OK) {
				return odtt_error;
			}

			if (endOfBuffer == 0) {
				return odtt_eof;
			}
		}
	} while (haveWS);

	// at this point we have a non-ws char (which could be a '\n')

	// could be a \n, number, symbol, text

	switch (pipeBuffer[pipeIndex]) {
	case ',':
		pipeIndex += 1;
		return odtt_comma;
	case ':':
		pipeIndex += 1;
		return  odtt_colon;
	case '<':
		pipeIndex += 1;
		return  odtt_lt;
	case '>':
		pipeIndex += 1;
		return  odtt_gt;
	case '(':
		pipeIndex += 1;
		return  odtt_lp;
	case ')':
		pipeIndex += 1;
		return  odtt_rp;
	case '\n':
		pipeIndex += 1;
		return  odtt_eol;
	default:
		break;
	}

	int i = 0;

	int haveLex = 0;

	do {
		while ((pipeIndex < endOfBuffer) && (!haveLex)) {
			char c;
			c = pipeBuffer[pipeIndex];
			switch (c) {
			case ' ':
			{
				// Is space is not treated as lex
				// add the space character to lex buffer
				if (!treat_space_as_lex)
				{
					lex[i] = c;
					i += 1;
					pipeIndex += 1;
				}
				else
				{
					// If space is treated as lex token
					// set haveLex = 1 and break
					haveLex = 1;
				}
			}
			break;
			case '\t':
			case '\r':
			case '\n':
			case ':':
			case '<':
			case '>':
			case ',':
			case '(':
			case ')':
				haveLex = 1;
				break;
			default:
				lex[i] = c;
				i += 1;
				pipeIndex += 1;
				break;
			}
		}

		if (!haveLex) {
			// if haveLex is false, we ran out of chars

			rc = fillPipeBuffer();
			if (rc != TraceDqrProfiler::DQERR_OK) {
				lex[i] = 0;
				return odtt_error;
			}

			if (endOfBuffer == 0) {
				// this is an eof

				haveLex = 1;
			}
		}
	} while (!haveLex);

	lex[i] = 0;

	return odtt_string;
}

bool ObjDump::isStringAHexNumber(char* s, uint64_t& n)
{
	int validNumber;
	uint64_t val;

	validNumber = 1;
	val = 0;

	for (int i = 0; validNumber && (s[i] != 0); i++) {
		char c;

		c = s[i];

		switch (c) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			val = val * 16 + (c - '0');
			break;
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
			val = val * 16 + (c - 'a' + 10);
			break;
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
			val = val * 16 + (c - 'A' + 10);
			break;
		default:
			validNumber = 0;
			break;
		}
	}

	if (validNumber) {
		n = val;
		return true;
	}

	return false;
}

bool  ObjDump::isStringADecNumber(char* s, uint64_t& n)
{
	int validNumber;
	uint64_t val;

	validNumber = 1;
	val = 0;

	for (int i = 0; validNumber && (s[i] != 0); i++) {
		char c;

		c = s[i];

		switch (c) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			val = val * 10 + (c - '0');
			break;
		default:
			validNumber = 0;
			break;
		}
	}

	if (validNumber) {
		n = val;
		return true;
	}

	return false;
}

TraceDqrProfiler::DQErr ObjDump::parseElfName(char* elfName, enum elfType& et)
{
	objDumpTokenType type;

	// get the elf file name

	for (int scanning = 1; scanning; ) {
		type = getNextLex(elfName, false);

		switch (type) {
		case odtt_eol:
			break;
		case odtt_lt:
		case odtt_gt:
		case odtt_lp:
		case odtt_rp:
		case odtt_comma:
		case odtt_number:
		case odtt_error:
			printf("Error: parseElfName(): unexpected input\n");
			return TraceDqrProfiler::DQERR_ERR;
		case odtt_eof:
			printf("Error: parseElfName(): EOF encountered\n");
			return TraceDqrProfiler::DQERR_ERR;
		case odtt_colon:
			printf("Error: parseElfName(): unexpected input ':'\n");
			return TraceDqrProfiler::DQERR_ERR;
		case odtt_string:
			scanning = 0;
			break;
		}
	}

	char lex[256];

	type = getNextLex(lex, false);
	if (type != odtt_colon) {
		printf("Error: parseElfName(): expected ':', %d\n", type);
		return TraceDqrProfiler::DQERR_ERR;
	}

	// if the : is followed by white space, we shold look for "file".
	// Otherwise, continue collecting elf file name

	if (isWSLookahead() == false) {
		// The colon we found must be a drive specify. Get rest of elf name
		for (int scanning = 1; scanning; ) {
			type = getNextLex(lex, false);

			switch (type) {
			case odtt_eol:
				break;
			case odtt_lt:
			case odtt_gt:
			case odtt_lp:
			case odtt_rp:
			case odtt_comma:
			case odtt_number:
			case odtt_error:
				printf("Error: parseElfName(): unexpected input\n");
				return TraceDqrProfiler::DQERR_ERR;
			case odtt_eof:
				printf("Error: parseElfName(): EOF encountered\n");
				return TraceDqrProfiler::DQERR_ERR;
			case odtt_colon:
				printf("Error: parseElfName(): unexpected input ':'\n");
				return TraceDqrProfiler::DQERR_ERR;
			case odtt_string:
				scanning = 0;
				break;
			}
		}

		strcat(elfName, ":");
		strcat(elfName, lex);

		type = getNextLex(lex, false);
		if (type != odtt_colon) {
			printf("Error: parseElfName(): expected ':', %d\n", type);
			return TraceDqrProfiler::DQERR_ERR;
		}
	}

	// get the elf file format

	lex[0] = 0;

	type = getNextLex(lex);
	if ((type != odtt_string) || (strcasecmp("file", lex) != 0)) {
		printf("Error: parseElfName(): expected 'file'\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	type = getNextLex(lex);
	if ((type != odtt_string) || (strcasecmp("format", lex) != 0)) {
		printf("Error: parseElfName(): expected 'format'\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	type = getNextLex(lex);
	if (type != odtt_string) {
		printf("Error: parseElfName(): execpted elf file format specifier\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	if (strcasecmp("elf64-littleriscv", lex) == 0) {
		et = elfType_64_little;
	}
	else if (strcasecmp("elf32-littleriscv", lex) == 0) {
		et = elfType_32_little;
	}
	else {
		printf("Error: parseElfName(): invalid elf file type\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr ObjDump::parseSection(objDumpTokenType& nextType, char* nextLex, Section*& codeSection)
{
	objDumpTokenType type;
	char lex[256];
	char name[256];
	uint64_t n;

	// parse sequence number

	type = getNextLex(lex);
	if (type != odtt_string) {
		// this is not an error (yet). We may have reached the end of the section list

		nextType = type;
		strcpy(nextLex, lex);

		return TraceDqrProfiler::DQERR_OK;
	}

	if (isStringADecNumber(lex, n) == false) {
		// this is not an error (yet). We may have reached the end of the section list

		nextType = type;
		strcpy(nextLex, lex);

		return TraceDqrProfiler::DQERR_OK;
	}

	// parse section name

	type = getNextLex(name);
	if (type != odtt_string) {
		printf("Error: parseSection(): Expected section name\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	// parse section size

	type = getNextLex(lex);
	if (type != odtt_string) {
		printf("Error: parseSection(): Expected section size\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	if (isStringAHexNumber(lex, n) == false) {
		printf("Error: parseSection(): Expected section size. Not a valid hex number '%s'\n", lex);
		return TraceDqrProfiler::DQERR_ERR;
	}

	uint32_t sec_size;
	sec_size = (uint32_t)n;

	// parse section VMA

	type = getNextLex(lex);
	if (type != odtt_string) {
		printf("Error: parseSection(): Expected section VMA\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	if (isStringAHexNumber(lex, n) == false) {
		printf("Error: parseSection(): Expected section VMA. Not a valid hex number '%s'\n", lex);
		return TraceDqrProfiler::DQERR_ERR;
	}

	uint64_t vma = n;

	// parse section LMA

	type = getNextLex(lex);
	if (type != odtt_string) {
		printf("Error: parseSection(): Expected section LMA\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	if (isStringAHexNumber(lex, n) == false) {
		printf("Error: parseSection(): Expected section LMA. Not a valid hex number '%s'\n", lex);
		return TraceDqrProfiler::DQERR_ERR;
	}

	// parse section file offset

	type = getNextLex(lex);
	if (type != odtt_string) {
		printf("Error: parseSection(): Expected section file offset\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	if (isStringAHexNumber(lex, n) == false) {
		printf("Error: parseSection(): Expected section file offset. Not a valid hex number '%s'\n", lex);
		return TraceDqrProfiler::DQERR_ERR;
	}

	uint32_t file_offset;
	file_offset = (uint32_t)n;

	// parse section alignment

	type = getNextLex(lex);
	if (type != odtt_string) {
		printf("Error: parseSection(): Expected section file offset\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	// check for valid alignment

	uint32_t align;

    if (strcmp("2**0",lex) == 0) {
		align = 1 << 0;
	}
    else if (strcmp("2**1",lex) == 0) {
		align = 1 << 1;
	}
    else if (strcmp("2**2",lex) == 0) {
		align = 1 << 2;
	}
    else if (strcmp("2**3",lex) == 0) {
		align = 1 << 3;
	}
    else if (strcmp("2**4",lex) == 0) {
		align = 1 << 4;
	}
    else if (strcmp("2**5",lex) == 0) {
		align = 1 << 5;
	}
    else if (strcmp("2**6",lex) == 0) {
		align = 1 << 6;
	}
    else if (strcmp("2**7",lex) == 0) {
		align = 1 << 7;
	}
    else if (strcmp("2**8",lex) == 0) {
		align = 1 << 8;
	}
    else if (strcmp("2**9",lex) == 0) {
		align = 1 << 8;
	}
    else if (strcmp("2**10",lex) == 0) {
		align = 1 << 8;
	}
    else if (strcmp("2**11",lex) == 0) {
		align = 1 << 8;
	}
    else if (strcmp("2**12",lex) == 0) {
		align = 1 << 8;
	}
    else if (strcmp("2**13",lex) == 0) {
		align = 1 << 8;
	}
    else if (strcmp("2**14",lex) == 0) {
		align = 1 << 8;
	}
    else if (strcmp("2**15",lex) == 0) {
		align = 1 << 8;
	}
    else if (strcmp("2**16",lex) == 0) {
		align = 1 << 8;
	}
	else {
		printf("Error: parseSection(): Invalid section alignment: %s\n", lex);
		return TraceDqrProfiler::DQERR_ERR;
	}

	type = getNextLex(lex);
	if (type != odtt_eol) {
		printf("Error: parseSection(): Expected EOL\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	uint32_t flags = 0;

	do {
		type = getNextLex(lex);
		if (type != odtt_string) {
			printf("Error: parseSection(): Expected string\n");
			return TraceDqrProfiler::DQERR_ERR;
		}

		if (strcasecmp("CONTENTS", lex) == 0) {
			// set CONTENTS flag
			flags |= Section::sect_CONTENTS;
		}
		else if (strcasecmp("ALLOC", lex) == 0) {
			// set ALLOC flag
			flags |= Section::sect_ALLOC;
		}
		else if (strcasecmp("LOAD", lex) == 0) {
			// set LOAD flag
			flags |= Section::sect_LOAD;
		}
		else if (strcasecmp("READONLY", lex) == 0) {
			// set READONLY flag
			flags |= Section::sect_READONLY;
		}
		else if (strcasecmp("DATA", lex) == 0) {
			// set DATA flag
			flags |= Section::sect_DATA;
		}
		else if (strcasecmp("CODE", lex) == 0) {
			// set CODE flag
			flags |= Section::sect_CODE;
		}
		else if (strcasecmp("THREAD_LOCAL", lex) == 0) {
			// set THREAD_LOCAL flag
			flags |= Section::sect_THREADLOCAL;
		}
		else if (strcasecmp("DEBUGGING", lex) == 0) {
			// set DEBUGGING flag
			flags |= Section::sect_DEBUGGING;
		}
		else if (strcasecmp("OCTETS", lex) == 0) {
			// set OCTETS flag
			flags |= Section::sect_OCTETS;
		}
		else {
			printf("Error: parseSection(): Expected valid section flag: %s\n", lex);
			return TraceDqrProfiler::DQERR_ERR;
		}

		type = getNextLex(lex);
		if ((type != odtt_comma) && (type != odtt_eol)) {
			printf("Error: parseSection(): Expected comma or eol: %d\n", type);
			return TraceDqrProfiler::DQERR_ERR;
		}
	} while ((type != odtt_eol) && (type != odtt_eof));

    if ((flags & Section::sect_CODE) || (strcmp(".comment",name) == 0)) {
		// create new section
		Section* sp = new Section();

		strcpy(sp->name, name);
		sp->flags = flags;
		sp->size = sec_size;
		sp->offset = file_offset;
		sp->align = align;
		sp->startAddr = vma;
		sp->endAddr = vma + sec_size - 1;

		codeSection = sp;
	}
	else {
		codeSection = nullptr;
	}

	nextType = type;
	strcpy(nextLex, lex);

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr ObjDump::parseSectionList(ObjDump::objDumpTokenType& nextType, char* nextLex, Section*& codeSectionLst)
{
	objDumpTokenType type;
	char lex[256];

	// strip all EOLs

	do {
		type = getNextLex(lex);
	} while (type == odtt_eol);

	if ((type != odtt_string) || (strcasecmp("Sections", lex) != 0)) {
		// no sections: section

		nextType = type;
		strcpy(nextLex, lex);

		return TraceDqrProfiler::DQERR_OK;
	}

	type = getNextLex(lex);
	if (type != odtt_colon) {
		printf("Error: parseSectionList(): expected ':' on Sections line\n");

		return TraceDqrProfiler::DQERR_ERR;
	}

	type = getNextLex(lex);
	if (type != odtt_eol) {
		printf("Error: parseSectionList(): extra input on Sections line\n");

		return TraceDqrProfiler::DQERR_ERR;
	}

	const char* expected[] = {
		"Idx",
		"Name",
		"Size",
		"VMA",
		"LMA",
		"File",
		"off",
		"Algn"
	};

	for (int i = 0; i < (int)(sizeof expected / sizeof expected[0]); i++) {
		type = getNextLex(lex);

		if ((type != odtt_string) || (strcasecmp(expected[i], lex) != 0)) {
			printf("Error: parseSectionList(): expected '%s'\n", expected[i]);
			return TraceDqrProfiler::DQERR_ERR;
		}
	}

	type = getNextLex(lex);

	if (type != odtt_eol) {
		printf("Error: parseSectionList(): expected eol\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	do {
		Section* newSection;
		TraceDqrProfiler::DQErr rc;

		rc = parseSection(type, lex, newSection);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			printf("Error: parseSectionList(): parseSection() failed\n");
			return TraceDqrProfiler::DQERR_ERR;
		}

		if (newSection != nullptr) {
			newSection->next = codeSectionLst;
			codeSectionLst = newSection;
		}
	} while (type == odtt_eol);

	nextType = type;
	strcpy(nextLex, lex);

	return TraceDqrProfiler::DQERR_OK;
}

ObjDump::objDumpTokenType ObjDump::getRestOfLine(char* lex)
{
	TraceDqrProfiler::DQErr rc;
	int haveWS = 1;

	lex[0] = 0;

	// strip WS

	do {
		while ((pipeIndex < endOfBuffer) && haveWS) {
			switch (pipeBuffer[pipeIndex]) {
			case ' ':
			case '\r':
			case '\t':
				pipeIndex += 1;
				break;
			default:
				haveWS = 0;
				break;
			}
		}

		if (haveWS) {
			// if haveWS is still true, we ran out of chars

			rc = fillPipeBuffer();
			if (rc != TraceDqrProfiler::DQERR_OK) {
				return odtt_error;
			}

			if (endOfBuffer == 0) {
				return odtt_eof;
			}
		}
	} while (haveWS);

	// at this point we have a non-ws char (which could be a '\n')

	// copy chars until eof or eol

	if (pipeBuffer[pipeIndex] == '\n') {
		pipeIndex += 1;
		return  odtt_eol;
	}

	int i = 0;

	int haveLex = 0;

	do {
		while ((pipeIndex < endOfBuffer) && (!haveLex)) {
			char c;
			c = pipeBuffer[pipeIndex];
			switch (c) {
			case '\n':
				haveLex = 1;
				break;
			case '\r':
				pipeIndex += 1;
				break;
			default:
				lex[i] = c;
				i += 1;
				pipeIndex += 1;
				break;
			}
		}

		if (!haveLex) {
			// if haveLex is false, we ran out of chars

			rc = fillPipeBuffer();
			if (rc != TraceDqrProfiler::DQERR_OK) {
				lex[i] = 0;
				return odtt_error;
			}

			if (endOfBuffer == 0) {
				// this is an eof

				lex[i] = 0;
				return odtt_eof;
			}
		}
	} while (!haveLex);

	lex[i] = 0;

	return odtt_eol;
}

TraceDqrProfiler::DQErr ObjDump::parseFileOrLabelOrDisassembly(line_t& lineType, char* text, int& length, uint32_t& value)
{
	objDumpTokenType type;
	char lex[256];
	uint64_t n;

	// already have hex number

	//	could be:
	//
	// 2  address '<' label '>' ':'				<- Hstring '<' string '>' ':' EOL
	//
	// 3  address ':' instruction disassembly	<- Hstring ':' Hstring string2end EOL
	//
	// 4  drive ':' path-file ':' line			<- [H]string ':' string ':' Dstring EOL
	//
	// 5  name '(' ')' ':'						<- string '(' ')' ':' EOL

	type = getNextLex(lex);

	if (type == odtt_lt) {
		// case 2: address '<' label '>' ':'

		lineType = line_t_label;

		type = getNextLex(text);
		if (type != odtt_string) {
			printf("Error: parseFileOrLabelOrDisassembly(): expected label\n");
			return TraceDqrProfiler::DQERR_ERR;
		}

		type = getNextLex(lex);
		if (type != odtt_gt) {
			printf("Error: parseFileOrLabelOrDisassembly(): expected '>'\n");
			return TraceDqrProfiler::DQERR_ERR;
		}

		type = getNextLex(lex);
		if (type != odtt_colon) {
			printf("Error: parseFileOrLabelOrDisassembly(): expected ':'\n");
			return TraceDqrProfiler::DQERR_ERR;
		}

		type = getNextLex(lex);
	}
	else if (type == odtt_lp) {
		// case 5: name '(' ')' ':'

		lineType = line_t_func;

		type = getNextLex(lex);
		if (type != odtt_rp) {
			printf("Error: parseFileOrLabelOrDisassembly(): expected ')'\n");
			return TraceDqrProfiler::DQERR_ERR;
		}

		type = getNextLex(lex);
		if (type != odtt_colon) {
			printf("Error: parseFileOrLabelOrDisassembly(): expected ':'\n");
			return TraceDqrProfiler::DQERR_ERR;
		}

		type = getNextLex(lex);
	}
	else if (type == odtt_colon) {
		// need to look further to figure out what we have

		type = getNextLex(text);
		if (type != odtt_string) {
			printf("Error: parseFileOrLabelOrDisassembly(): Expected instruction or path\n");
			return TraceDqrProfiler::DQERR_ERR;
		}

		if (isStringAHexNumber(text, n) == false) {
			// have a filepath:line

			lineType = line_t_path;

			type = getNextLex(lex);
			if (type != odtt_colon) {
				printf("Error: parseFileOrLabelOrDisassembly(): Expected ':'\n");
				return TraceDqrProfiler::DQERR_ERR;
			}

			type = getNextLex(lex);
			if (type != odtt_string) {
				printf("Error: parseFileOrLabelOrDisassembly(): Expected line number\n");
				return TraceDqrProfiler::DQERR_ERR;
			}

			if (isStringADecNumber(lex, n) == false) {
				// this might be a weird objdump double path (thank you objdump - NOT).

				// Discard text and copy lex to text
				strcpy(text, lex);

				type = getNextLex(lex);
				if (type != odtt_colon) {
					printf("Error: parseFileOrLabelOrDisassembly(): Expected line number after double path\n");
					return TraceDqrProfiler::DQERR_ERR;
				}

				// need to get the line number

				type = getNextLex(lex);
				if (type != odtt_string) {
					printf("Error: parseFileOrLabelOrDisassembly(): Expected line number\n");
					return TraceDqrProfiler::DQERR_ERR;
				}

				if (isStringADecNumber(lex, n) == false) {
					printf("Error: parseFileOrLabelOrDisassembly(): Expected line number\n");
					return TraceDqrProfiler::DQERR_ERR;
				}
			}

			value = (uint32_t)n;

			// see if we have '(' discriminator n ')'

			type = getNextLex(lex);
			if (type == odtt_lp) {
				type = getNextLex(lex);
				if (type != odtt_string) {
					printf("Error: parseFileOrLabelOrDisassembly(): Expected discriminator\n");
					return TraceDqrProfiler::DQERR_ERR;
				}

				type = getNextLex(lex);
				if (type != odtt_string) {
					printf("Error: parseFileOrLabelOrDisassembly(): Expected discriminator number\n");
					return TraceDqrProfiler::DQERR_ERR;
				}

				type = getNextLex(lex);
				if (type != odtt_rp) {
					printf("Error: parseFileOrLabelOrDisassembly(): Expected discriminator ')'\n");
					return TraceDqrProfiler::DQERR_ERR;
				}

				type = getNextLex(lex);
			}
		}
		else {
			//  have a disassembly line

			lineType = line_t_diss;

			value = (uint32_t)n;

			int len;
			len = strlen(text);

			if (len == 4) {
				length = 16;
			}
			else if (len == 8) {
				length = 32;
			}
			else {
				printf("Error: pareFileOrLabelOrDisassembly(): Invalid instruction (%s,%d)\n", text, len);
				return TraceDqrProfiler::DQERR_ERR;
			}

			type = getRestOfLine(text);
			if ((type == odtt_eof) || (type == odtt_eol)) {
				return TraceDqrProfiler::DQERR_OK;
			}
		}
	}
	else {
		printf("Error: parseFileOrLabelOrDisassembly(): Unexpected input (%d, %s, %s)\n", type, text, lex);
		return TraceDqrProfiler::DQERR_ERR;
	}

	if ((type != odtt_eol) && (type != odtt_eof)) {
		printf("Error: parseFileOrLabelOrDisassembly(): Expected EOL\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr ObjDump::parseFileLine(uint32_t& line)
{
	enum objDumpTokenType type;
	char lex[256];
	uint64_t n;

	// already have filename when we enter this func

	type = getNextLex(lex);
	if (type != odtt_colon) {
		printf("Error: parseFileLine(): Expected ':'\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	type = getNextLex(lex);
	if ((type != odtt_string) || (isStringADecNumber(lex, n) == 0)) {
		printf("Error: parseFileLine(): Expected line number\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	line = (uint32_t)n;

	type = getNextLex(lex);

	// check for (discriminator n)

	if (type == odtt_lp) {
		// have (discriminator n)
		type = getNextLex(lex);
		if ((type != odtt_string) || (strcasecmp("discriminator", lex) != 0)) {
			printf("Error: parseFileLine(): Expected discriminator\n");
			return TraceDqrProfiler::DQERR_ERR;
		}

		type = getNextLex(lex);
		if ((type != odtt_string) || (isStringADecNumber(lex, n) == 0)) {
			printf("Error: parseFileLine(): Expected discriminator number\n");
			return TraceDqrProfiler::DQERR_ERR;
		}

		type = getNextLex(lex);
		if (type != odtt_rp) {
			printf("Error: parseFileLine(): Expected ')'\n");
			return TraceDqrProfiler::DQERR_ERR;
		}

		type = getNextLex(lex);
	}

	if ((type != odtt_eol) && (type != odtt_eof)) {
		printf("Error: parseFileLine(): Extra input on end of line. Expected EOL (%d)\n", type);
		return TraceDqrProfiler::DQERR_ERR;
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr ObjDump::parseFuncName()
{
	enum objDumpTokenType type;
	char lex[256];

	// should be string ( ^ ) : eol

	type = getNextLex(lex);
	if (type != odtt_rp) {
		printf("Error: parseFuncName(): Expected ')'\n");

		return TraceDqrProfiler::DQERR_ERR;
	}

	type = getNextLex(lex);
	if (type != odtt_colon) {
		printf("Error: parseFuncName(): Expected ':'\n");

		return TraceDqrProfiler::DQERR_ERR;
	}

	type = getNextLex(lex);
	if ((type != odtt_eol) && (type != odtt_eof)) {
		printf("Error: parseFuncName(): Expected EOL (%d)\n", type);

		return TraceDqrProfiler::DQERR_ERR;
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr ObjDump::parseDisassemblyList(objDumpTokenType& nextType, char* nextLex, Section* codeSectionLst, SrcFileRoot& srcFileRoot)
{
	objDumpTokenType type;
	char lex[1024];
	char lex2[1024];
	TraceDqrProfiler::DQErr rc;
	Section* sp;

	type = getNextLex(lex);
	if ((type != odtt_string) || (strcasecmp("of", lex) != 0)) {
		printf("Error: parseDisassemblyList(): Expected 'of'\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	type = getNextLex(lex);
	if ((type != odtt_string) || (strcasecmp("section", lex) != 0)) {
		printf("Error: parseDisassemblyList(): Expected 'section'\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	type = getNextLex(lex);
	if (type != odtt_string) {
		printf("Error: parseDisassemblyList(): Expected section name\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	sp = codeSectionLst->getSectionByName(lex);
	if (sp == nullptr) {
		printf("Error: parseDisassemblyList(): Section '%s' not found\n", lex);
		return TraceDqrProfiler::DQERR_ERR;
	}

	if (sp->code == nullptr) {
		sp->code = new uint16_t[(sp->size + 1) / 2]; // don't need to init to 0's
	}

	if (sp->diss == nullptr) {
		sp->diss = new char* [(sp->size + 1) / 2];
		for (int i = 0; i < (int)(sp->size + 1) / 2; i++) {
			sp->diss[i] = nullptr;
		}
	}

	if (sp->line == nullptr) {
		sp->line = new uint32_t[(sp->size + 1) / 2];
		for (int i = 0; i < (int)(sp->size + 1) / 2; i++) {
			sp->line[i] = 0;
		}
	}

	if (sp->fName == nullptr) {
		sp->fName = new char* [(sp->size + 1) / 2];
		for (int i = 0; i < (int)(sp->size + 1) / 2; i++) {
			sp->fName[i] = nullptr;
		}
	}

	type = getNextLex(lex);
	if (type != odtt_colon) {
		printf("Error: parseDisassemblyList(): Expected ':'\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	type = getNextLex(lex);
	if (type != odtt_eol) {
		printf("Error: parseDisassemblyList(): Expected EOL\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	// now at start of disassembly

	char* fName = nullptr;
	uint32_t line = 0;

	for (;;) {
		int eol_count = 0;

		while (type == odtt_eol) {
			eol_count += 1;
			type = getNextLex(lex);
		}

		if ((type != odtt_string) && (type != odtt_lt)) {
			nextType = type;
			strcpy(nextLex, lex);

			return TraceDqrProfiler::DQERR_OK;
		}

		line_t lineType;
		int length;
		uint32_t value;
		uint64_t addr;

		// have a string or '<' (case 2)

		// 1  ...									<- string EOL
		//
		// 2  '<' 'unknown' '>' ':' line			<- '<' string '>' ':' Dstring EOL
		//
		// 2.1 address '<' label '>' ':'			<- Hstring '<' string '>' ':' EOL
		//
		// 3  address ':' instruction disassembly	<- Hstring ':' Hstring string2end EOL
		//
		// 4  drive ':' path-file ':' line		<- [H]string ':' string ':' Dstring EOL
		//
		// 5  function '(' ')' ':'				<- string '(' ')' ':' EOL
		//
		// 6  disassembly of section label :		<- string string string string ':' EOL
		//
		// 7  symbol table ':'					<- string string ':' EOL
		//

		// want to only look ahead one lex!

		if (type == odtt_lt) { // case 2
			type = getNextLex(lex);
			if (type != odtt_string) {
				printf("Error: parseDisassemblyList(): Expected '<' to be followed by unknown\n");
				return TraceDqrProfiler::DQERR_ERR;
			}

          if (strcmp(lex,"unknown") != 0) {
				printf("Error: parseDisassemblyList(): Expected '<' to be followed by unknown\n");
				return TraceDqrProfiler::DQERR_ERR;
			}

			type = getNextLex(lex);
			if (type != odtt_gt) {
				printf("Error: parseDisassemblyList(): Expected '<unknown' to be followed by '>'\n");
				return TraceDqrProfiler::DQERR_ERR;
			}

			type = getNextLex(lex);
			if (type != odtt_colon) {
				printf("Error: parseDisassemblyList(): Expected '<unknown>' to be followed by ':'\n");
				return TraceDqrProfiler::DQERR_ERR;
			}

			type = getNextLex(lex);
			if (type != odtt_string) {
				printf("Error: parseDisassemblyList(): Expected '<unknown>:' to be followed by line number\n");
				return TraceDqrProfiler::DQERR_ERR;
			}

			uint64_t val;

			if (isStringADecNumber(lex, val) == false) {
				printf("Error: parseDisassemblyList(): Expected '<unknown>:' to be followed by line number\n");
				return TraceDqrProfiler::DQERR_ERR;
			}

			type = getNextLex(lex);
			if (type != odtt_eol) {
				printf("Error: parseDisassemblyList(): Expected '<unknown>:line' to be followed by EOL\n");
				return TraceDqrProfiler::DQERR_ERR;
			}

			fName = nullptr;
			line = 0;

			// just skip and do next line
		}
      else if (strcmp("...",lex) == 0) { // case 1
			type = getNextLex(lex);
			if (type != odtt_eol) {
				printf("Error: parseDisassemblyList(): Expected '...' to be folowed by EOL\n");
				return TraceDqrProfiler::DQERR_ERR;
			}

			fName = nullptr;
			line = 0;

			// just skip and do next line
		}
		else if (isStringAHexNumber(lex, addr) == true) { // cases 2.1, 3, and sometimes 4
			rc = parseFileOrLabelOrDisassembly(lineType, lex, length, value);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				printf("Error: parseDisassemblyList(): parseDisassembly() failed\n");
				return TraceDqrProfiler::DQERR_ERR;
			}

			switch (lineType) {
			case line_t_label:
				// currently, don't use anyting from address < label > :
				// but this information could be added to sym table in place of reading the sym table?
				fName = nullptr;
				line = 0;
				break;
			case line_t_diss:
				int index;
				index = (addr - sp->startAddr) / 2;

				sp->code[index] = (uint16_t)value;
				if (length == 32) {
					sp->code[index + 1] = (uint16_t)(value >> 16);
				}

				int len;
				len = strlen(lex) + 1;

				sp->diss[index] = new char[len];
				strcpy(sp->diss[index], lex);

				// save file and line here. They are set below and remain valid until they are updated

				sp->fName[index] = fName;
				sp->line[index] = line;
				break;
			case line_t_path:
				sprintf(lex2, "%X:%s", (uint32_t)addr, lex);
				fName = srcFileRoot.addFile(lex2);
				line = value;
				break;
			case line_t_func:
				// if we get here, function name could be interpreted as number, but it shouln't be (such as f1())
				fName = nullptr;
				line = 0;
				break;
			}
		}
		else if ((eol_count > 0) && ((strcasecmp("disassembly", lex) == 0) || (strcasecmp("symbol", lex) == 0))) {	// case 6, 7
			nextType = type;
			strcpy(nextLex, lex);

			return TraceDqrProfiler::DQERR_OK;
		}
		else if ((lex[0] == '/') || (lex[0] == '\\')) { // more case 4;
			rc = parseFileLine(line);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				printf("Error: parseDisassemblyList(): parseFileLine() failed\n");
				return TraceDqrProfiler::DQERR_ERR;
			}

			fName = srcFileRoot.addFile(lex);
		}
		else {	// case 5, reset of case 4
			// have a string. look ahead and see if it is a '(', ':' (case 5, rest of case 4)

			rc = parseFileOrLabelOrDisassembly(lineType, lex2, length, value);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				printf("Error: parseDisassemblyList(): parseDisassembly() failed\n");
				return TraceDqrProfiler::DQERR_ERR;
			}

			switch (lineType) {
			case line_t_label:
				printf("Error: parseDisassemblyList(): Bad label\n");
				return TraceDqrProfiler::DQERR_ERR;
			case line_t_diss:
				printf("Error: parseDisassemblyList(): Bad disassembly\n");
				return TraceDqrProfiler::DQERR_ERR;
			case line_t_path: // case 4
				strcat(lex, ":");
				strcat(lex, lex2);
				fName = srcFileRoot.addFile(lex2);
				line = value;
				break;
			case line_t_func: // case 5
				// nothing to do. If we saved the function, would we need to even collect the symtable? Probably.
				fName = nullptr;
				line = 0;
				break;
			}
		}

		type = getNextLex(lex);
	}

	// should never get here

	return TraceDqrProfiler::DQERR_ERR;
}

TraceDqrProfiler::DQErr ObjDump::parseFixedField(uint32_t& flags)
{
	TraceDqrProfiler::DQErr rc;

	flags = 0;

	// skip first space

	if (pipeIndex >= endOfBuffer) {
		rc = fillPipeBuffer();
		if (rc != TraceDqrProfiler::DQERR_OK) {
			printf("Error: parseFixedField(): fillPipeBuffer() failed\n");
			return TraceDqrProfiler::DQERR_ERR;
		}
	}

	if (endOfBuffer == 0) {
		// EOF

		return TraceDqrProfiler::DQERR_ERR;
	}

	if (pipeBuffer[pipeIndex] != ' ') {
		printf("Error: parseFixedField(): Expected ' '.\n");

		return TraceDqrProfiler::DQERR_ERR;
	}

	pipeIndex += 1;

	char flagChars[7];

	for (int i = 0; i < 7; i++) {
		if (pipeIndex >= endOfBuffer) {
			rc = fillPipeBuffer();
			if (rc != TraceDqrProfiler::DQERR_OK) {
				printf("Error: parseFixedField(): fillPipeBuffer() failed\n");
				return TraceDqrProfiler::DQERR_ERR;
			}
		}

		if (endOfBuffer == 0) {
			// EOF

			return TraceDqrProfiler::DQERR_ERR;
		}

		flagChars[i] = pipeBuffer[pipeIndex];
		pipeIndex += 1;
	}

	// group 1

	if (flagChars[0] == ' ') {
		// neither global or local
	}
	else if (flagChars[0] == 'l') {
		flags |= Sym::symLocal;
	}
	else if (flagChars[0] == 'g') {
		flags |= Sym::symGlobal;
	}
	else if (flagChars[0] == 'u') {
		flags |= Sym::symGlobal;
	}
	else if (flagChars[0] == '!') {
		flags |= Sym::symLocal | Sym::symGlobal;
	}
	else {
		printf("Error: parseFixedField(): Invalid sym flag '%c'\n", flagChars[0]);
		return TraceDqrProfiler::DQERR_ERR;
	}

	// group 2

	if (flagChars[1] == ' ') {
		// strong by default
	}
	else if (flagChars[1] == 'w') {
		flags |= Sym::symWeak;
	}
	else {
		printf("Error: parseFixedField(): Invalid sym flag '%c'\n", flagChars[1]);
		return TraceDqrProfiler::DQERR_ERR;
	}

	// group 3

	if (flagChars[2] == ' ') {
		// not a contstructor
	}
	else if (flagChars[2] == 'C') {
		flags |= Sym::symConstructor;
	}
	else {
		printf("Error: parseFixedField(): Invalid sym flag '%c'\n", flagChars[2]);
		return TraceDqrProfiler::DQERR_ERR;
	}

	// group 4

	if (flagChars[3] == ' ') {
		// nothing to do
	}
	else if (flagChars[3] == 'W') {
		// nothing to do
	}
	else {
		printf("Error: parseFixedField(): Invalid sym flag '%c'\n", flagChars[3]);
		return TraceDqrProfiler::DQERR_ERR;
	}

	// group 5

	if (flagChars[4] == ' ') {
		// not indirect or indirect func
	}
	else if (flagChars[4] == 'I') {
		flags |= Sym::symIndirect;
	}
	else if (flagChars[4] == 'i') {
		flags |= Sym::symIndirectFunc;
	}
	else {
		printf("Error: parseFixedField(): Invalid sym flag '%c'\n", flagChars[4]);
		return TraceDqrProfiler::DQERR_ERR;
	}

	// group 6

	if (flagChars[5] == ' ') {
		// nothing to do
	}
	else if (flagChars[5] == 'd') {
		flags |= Sym::symDebug;
	}
	else if (flagChars[5] == 'D') {
		flags |= Sym::symDynamic;
	}
	else {
		printf("Error: parseFixedField(): Invalid sym flag '%c'\n", flagChars[5]);
		return TraceDqrProfiler::DQERR_ERR;
	}

	// group 7

	if (flagChars[6] == ' ') {
		// nothing to do
	}
	else if (flagChars[6] == 'F') {
		flags |= Sym::symFunc;
	}
	else if (flagChars[6] == 'f') {
		flags |= Sym::symFile;
	}
	else if (flagChars[6] == 'O') {
		flags |= Sym::symObj;
	}
	else {
		printf("Error: parseFixedField(): Invalid sym flag '%c'\n", flagChars[6]);
		return TraceDqrProfiler::DQERR_ERR;
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr ObjDump::parseSymbol(bool& haveSym, char* secName, char* symName, uint32_t& symFlags, uint64_t& symSize)
{
	TraceDqrProfiler::DQErr rc;
	objDumpTokenType type;
	char lex[256];

	// we have already parsed the sym address

	// Get sym Flags

	haveSym = false;

	rc = parseFixedField(symFlags);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		return TraceDqrProfiler::DQERR_ERR;
	}

	// Get symbol section name

	type = getNextLex(secName);
	if (type != odtt_string) {
		printf("Error: parseSymbol(): Expected symbol section name\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	// Get symbol alignment or size

	type = getNextLex(lex);
	if (type != odtt_string) {
		printf("Error: parseSymbol(): Expected symbol alignment or size\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	if (isStringAHexNumber(lex, symSize) == false) {
		printf("Error: parseSymbol(): Expected a number for alignment or size\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	// Get symbol name or special flag

	type = getNextLex(symName);
	if (type != odtt_eol) { // if eol, there is no name, and we can skip
		if (type != odtt_string) {
			printf("Error: parseSymbol(): Expected symbol name or special type (%d)\n", type);
			return TraceDqrProfiler::DQERR_ERR;
		}

		// Get EOL or symbol name

		type = getNextLex(lex);
		if (type == odtt_string) {
			strcpy(symName, lex);
			type = getNextLex(lex);
			if (type != odtt_eol) {
				printf("Error: parseSymbol(): Expected EOL\n");
				return TraceDqrProfiler::DQERR_ERR;
			}
		}
		else if (type == odtt_colon) {
			type = getNextLex(lex);
			if (type != odtt_string) {
				printf("Error: parseSymbol(): Expected path string\n");
				return TraceDqrProfiler::DQERR_ERR;
			}

			strcat(symName, ":");
			strcat(symName, lex);

			type = getNextLex(lex);
			if (type != odtt_eol) {
				printf("Error: parseSymbol(): Expected EOL\n");
				return TraceDqrProfiler::DQERR_ERR;
			}
		}
		else if (type != odtt_eol) {
			printf("Error: parseSymbol(): Expected EOL\n");
			return TraceDqrProfiler::DQERR_ERR;
		}

		haveSym = true;
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr ObjDump::parseSymbolTable(objDumpTokenType& nextType, char* nextLex, Sym*& syms, Section*& codeSectionLst)
{
	objDumpTokenType type;
	char lex[256];
	TraceDqrProfiler::DQErr rc;

	type = getNextLex(lex);
	if (type != odtt_string) {
		printf("Error: parseSymboTable(): Expected 'TABLE'\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	if (strcasecmp("table", lex) != 0) {
		printf("Error: parseSymboTable(): Expected 'TABLE'\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	type = getNextLex(lex);
	if (type != odtt_colon) {
		printf("Error: parseSymboTable(): Expected ':'\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	type = getNextLex(lex);
	if (type != odtt_eol) {
		printf("Error: parseSymboTable(): Expected EOL\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	// now at start of symbols

	uint64_t addr;
	Sym* file;

	file = nullptr;

	for (;;) {
		// skip any extra eols

		do {
			type = getNextLex(lex);
		} while (type == odtt_eol);

		// Get Symbol address

		if (type != odtt_string) {
			printf("Error: parseSymbolTable(): Bad input found looking for symbol address\n");
			return TraceDqrProfiler::DQERR_ERR;
		}

		if (isStringAHexNumber(lex, addr) == false) {
			// end of symbols
			nextType = type;
			strcpy(nextLex, lex);

			return TraceDqrProfiler::DQERR_OK;
		}

		bool haveSym;
		char secName[256];
		char symName[256];
		uint64_t symSize;
		uint32_t symFlags;

		haveSym = false;

		rc = parseSymbol(haveSym, secName, symName, symFlags, symSize);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			return TraceDqrProfiler::DQERR_ERR;
		}

		if (haveSym) {
			Sym* sp;
			sp = new Sym();

			sp->next = syms;
			sp->name = new char[strlen(symName) + 1];
			strcpy(sp->name, symName);
			sp->flags = symFlags;
			sp->address = addr;
			sp->size = symSize;

			if (symFlags & Sym::symFile) {
				file = sp;
				sp->srcFile = nullptr;
			}
			else if ((symFlags != Sym::symLocal) && (symFlags != (Sym::symLocal | Sym::symFunc))) {
				// if not local flag, turn off srcFile setting
				file = nullptr;
			}
			else {
				sp->srcFile = file;
			}

			Section* sec;
			sec = codeSectionLst->getSectionByName(secName);
			sp->section = sec;

			syms = sp;
		}
		else if (symFlags & Sym::symFile) {
			file = nullptr;
		}
	}

	// should never get here

	return TraceDqrProfiler::DQERR_ERR;
}

TraceDqrProfiler::DQErr ObjDump::parseObjdump(int& archSize, Section*& codeSectionLst, Sym*& symLst, SrcFileRoot& srcFileRoot)
{
	TraceDqrProfiler::DQErr rc;
	objDumpTokenType type;
	char lex[256];
	char elfName[256];
	elfType et;

	rc = parseElfName(elfName, et);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		printf("Error: parseObjdump(): expected file name and type\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	switch (et) {
	case elfType_unknown:
		printf("Error: parseObjDump(): Unknown elf file type\n");
		return TraceDqrProfiler::DQERR_ERR;
	case elfType_64_little:
		archSize = 64;
		break;
	case elfType_32_little:
		archSize = 32;
		break;
	}

	rc = parseSectionList(type, lex, codeSectionLst);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		printf("Error: parseObjdump(): parseSectionList() failed\n");
		return TraceDqrProfiler::DQERR_ERR;
	}

	// strip out eols until we get something else

	while (type == odtt_eol) {
		type = getNextLex(lex);
	}

	// below should loop until error or eof

	while (type == odtt_string) {
		if (strcasecmp("disassembly", lex) == 0) {
			rc = parseDisassemblyList(type, lex, codeSectionLst, srcFileRoot);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				return TraceDqrProfiler::DQERR_ERR;
			}
		}
		else if (strcasecmp("symbol", lex) == 0) {
			rc = parseSymbolTable(type, lex, symLst, codeSectionLst);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				return TraceDqrProfiler::DQERR_ERR;
			}
		}
		else {
			printf("Error: parseObjdump(): Unexpected input in stream: '%s'\n", lex);
			return TraceDqrProfiler::DQERR_ERR;
		}
	}

	if (type != odtt_eof) {
		printf("Error: parseObjdump(): unexpected stuff in input %d\n", type);
		return TraceDqrProfiler::DQERR_ERR;
	}

	return TraceDqrProfiler::DQERR_OK;
}

SrcFile::SrcFile(char* fName, SrcFile* nxt)
{
	int len;
	len = strlen(fName) + 1;

	file = new char[len];
	strcpy(file, fName);

	next = nxt;
}

SrcFile::~SrcFile()
{
	if (file != nullptr) {
		delete[] file;
		file = nullptr;
	}

	next = nullptr;
}

SrcFileRoot::SrcFileRoot()
{
	fileRoot = nullptr;
}

SrcFileRoot::~SrcFileRoot()
{
	SrcFile* srcFile;

	srcFile = fileRoot;

	while (srcFile != nullptr) {
		SrcFile* next;
		next = srcFile->next;
		delete srcFile;
		srcFile = next;
	}

	fileRoot = nullptr;
}

char* SrcFileRoot::addFile(char* fName)
{
	if (fName == nullptr) {
		printf("Error: SrcFile::AddFile(): Null fName argument\n");
		return nullptr;
	}

	SrcFile* srcFile = fileRoot;

	for (bool found = false; (srcFile != nullptr) && (found == false);) {
		if (strcmp(srcFile->file,fName) == 0) {
			found = true;
		}
		else {
			srcFile = srcFile->next;
		}
	}

	if (srcFile == nullptr) {
		srcFile = new SrcFile(fName, fileRoot);
		fileRoot = srcFile;
	}

	return srcFile->file;
}

void SrcFileRoot::dump()
{
	for (SrcFile* sfp = fileRoot; sfp != nullptr; sfp = sfp->next) {
		printf("sfp: 0x%08llx, file: 0x%08llx %s, next: 0x%08llx\n", sfp, sfp->file, sfp->file, sfp->next);
	}
}

ElfReader::ElfReader(const char* elfname, const char* odExe)
{
	status = TraceDqrProfiler::DQERR_OK;
	symtab = nullptr;
	codeSectionLst = nullptr;
	elfName = nullptr;

	if (elfname == nullptr) {
		printf("Error: ElfReader::ElfReader(): No elf file name specified\n");
		status = TraceDqrProfiler::DQERR_ERR;
		return;
	}

	int len = strlen(elfname) + 1;
	elfName = new char[len];
	strcpy(elfName, elfname);

	Sym* symLst = nullptr;

	ObjDump* objdump = new ObjDump(elfname, odExe, archSize, codeSectionLst, symLst, srcFileRoot);
	if (objdump->getStatus() != TraceDqrProfiler::DQERR_OK) {
		delete objdump;
		objdump = nullptr;

		status = TraceDqrProfiler::DQERR_ERR;
		return;
	}

	delete objdump;
	objdump = nullptr;

	switch (archSize) {
	case 32:
		bitsPerAddress = 32;
		break;
	case 64:
		bitsPerAddress = 64;
		break;
	}

	symtab = new Symtab(symLst);

	TraceDqrProfiler::DQErr rc;

	rc = fixupSourceFiles(codeSectionLst, symLst);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = TraceDqrProfiler::DQERR_ERR;
		return;
	}

	status = TraceDqrProfiler::DQERR_OK;
}

ElfReader::~ElfReader()
{
	if (elfName != nullptr) {
		delete[] elfName;
		elfName = nullptr;
	}

	if (symtab != nullptr) {
		// elfReader is the only objet that really owns the Symtab, and is the only object that should
		// delete it!

		delete symtab;
		symtab = nullptr;
	}

	while (codeSectionLst != nullptr) {
		Section* nextSection = codeSectionLst->next;
		delete codeSectionLst;
		codeSectionLst = nextSection;
	}
}

TraceDqrProfiler::DQErr ElfReader::fixupSourceFiles(Section* sections, Sym* syms)
{
	// iterate through the symbols looking for non-null srcFile field and add it to fName[index].

	for (Sym* sym = syms; sym != nullptr; sym = sym->next) {
		if (sym->srcFile != nullptr) {
			Section* sp = sym->section;
			if ((sp != nullptr) && (sp->flags & Section::sect_CODE)) {
				int index;
				TraceDqrProfiler::ADDRESS addr;

				addr = sym->address;
				index = (addr - sp->startAddr) / 2;

				uint32_t i;

				i = 0;

				do { // do at least one
					if (sp->fName[index + i] == nullptr) {
						sp->fName[index + i] = sym->srcFile->name;
						sp->line[index + i] = 0;
					}
					i += 1;
				} while (i < (uint32_t)sym->size / 2);
			}
		}
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr ElfReader::getInstructionByAddress(TraceDqrProfiler::ADDRESS addr, TraceDqrProfiler::RV_INST& inst)
{
	// get instruction at addr

	// Address for code[0] is text->vma

	//don't forget base!!'

	// hmmm.. probably should cache section pointer, and not address/instruction! Or maybe not cache anything?

	Section* sp;
	if (codeSectionLst == nullptr) {
		status = TraceDqrProfiler::DQERR_ERR;
		return status;
	}

	sp = codeSectionLst->getSectionByAddress(addr);
	if (sp == nullptr) {
		status = TraceDqrProfiler::DQERR_ERR;
		return status;
	}

	if ((addr < sp->startAddr) || (addr > sp->endAddr)) {
		status = TraceDqrProfiler::DQERR_ERR;
		return status;
	}

	if (sp->code == NULL)
	{
		status = TraceDqrProfiler::DQERR_ERR;
		return status;
	}

	//	if ((addr < text->vma) || (addr >= text->vma + text->size)) {
	////			don't know instruction - not part of text segment. need to handle for os
	////			if we can't get the instruciton, get the next trace message and try again. or do
	////			we need the next sync message and the next trace message and try again?
	//
	//		// for now, just return an error
	//
	//		status = dqr::DQERR_ERR;
	//		return status;
	//	}

	int index;

	index = (addr - sp->startAddr) / 2;

	inst = sp->code[index];

	// if 32 bit instruction, get the second half

	switch (inst & 0x0003) {
	case 0x0000:	// quadrant 0, compressed
	case 0x0001:	// quadrant 1, compressed
	case 0x0002:	// quadrant 2, compressed
		status = TraceDqrProfiler::DQERR_OK;
		break;
	case 0x0003:	// not compressed. Assume RV32 for now
		if ((inst & 0x1f) == 0x1f) {
			fprintf(stderr, "Error: getInstructionByAddress(): cann't decode instructions longer than 32 bits\n");
			status = TraceDqrProfiler::DQERR_ERR;
			break;
		}

		inst = inst | (((uint32_t)sp->code[index + 1]) << 16);

		status = TraceDqrProfiler::DQERR_OK;
		break;
	}

	return status;
}

TraceDqrProfiler::DQErr ElfReader::parseNLSStrings(TraceDqrProfiler::nlStrings* nlsStrings)
{
	Section* sp;
	bool found = false;
	int rc;

	for (sp = codeSectionLst; (sp != NULL) && !found;) {
		if (strcmp(sp->name,".comment") == 0) {
			found = true;
		}
		else {
			sp = sp->next;
		}
	}

	if (!found) {
		return TraceDqrProfiler::DQERR_ERR;
	}

	int size = sp->size;
	char* data;

	data = new (std::nothrow) char[size];

	if (data == nullptr) {
		printf("Error: elfReader::parseNLSStrings(): Could not allocate data array\n");

		return TraceDqrProfiler::DQERR_ERR;
	}

	int fd;
	fd = _open(elfName, O_RDONLY);
	if (fd < 0) {
		printf("Error: elfReader::parseNLSStrings(): Could not open file %s for input\n", elfName);
		return TraceDqrProfiler::DQERR_ERR;
	}

	rc = lseek(fd, sp->offset, SEEK_SET);
	if (rc < 0) {
		printf("Error: ElfReder::parseNLSStrings(): Error seeking to .comment section");
		_close(fd);
		fd = -1;
		delete[] data;
		data = nullptr;

		return TraceDqrProfiler::DQERR_ERR;
	}

	rc = _read(fd, data, size);
	if (rc != size) {
		printf("Error: ElfReader::parseNLSStrings(): Error reading .comment section\n");
		_close(fd);
		fd = -1;
		delete[] data;
		data = nullptr;

		return TraceDqrProfiler::DQERR_ERR;
	}

	_close(fd);
	fd = -1;

	int index;

	for (int i = 0; i < 32; i++) {
		nlsStrings[i].nf = 0;
		nlsStrings[i].signedMask = 0;
		nlsStrings[i].format = nullptr;
	}

	for (int i = 0; i < size;) {
		char* end;

		index = strtol(&data[i], &end, 0);

		if (end != &data[i]) {
			// found an index

			i = end - data;

			if ((index >= 32) || (index < 0) || (data[i] != ':')) {
				// invalid format string - skip
				while ((i < size) && (data[i] != 0)) {
					i += 1;
				}
				i += 1;
			}
			else {
				// found a format string

				// need to find end of string
				int e;
				int nf = 0;
				int state = 0;

				for (e = i + 1; (data[e] != 0) && (e < size); e++) {
					// need to figure out if %s are signed or unsigned

					switch (state) {
					case 0:
						if (data[e] == '%') {
							state = 1;
						}
						break;
					case 1: // found a %, figure out format
						switch (data[e]) {
						case '%':
							state = 0;
							break;
							// signed cases
						case 'd':
						case 'i':
							nlsStrings[index].signedMask |= (1 << nf);
							nf += 1;
							state = 0;
							break;
							// unsigned cases
						case 'o':
						case 'u':
						case 'x':
						case 'X':
						case 'e':
						case 'E':
						case 'f':
						case 'F':
						case 'g':
						case 'G':
						case 'a':
						case 'A':
						case 'c':
						case 's':
						case 'p':
						case 'n':
						case 'M':
							state = 0;
							nf += 1;
							break;
						default:
							break;
						}
					}
				}

				if (data[e] != 0) {
					// invalid format string - not null terminated

					//should we delete here?

					for (int i = 0; i < 32; i++) {
						if (nlsStrings[i].format != nullptr) {
							delete[] nlsStrings[i].format;
							nlsStrings[i].format = nullptr;
						}
					}

					// don't delete nlsStrings here! We didn't allocate it!

					delete[] data;
					data = nullptr;

					return TraceDqrProfiler::DQERR_ERR;
				}

				nlsStrings[index].nf = nf;
				nlsStrings[index].format = new char[e - i + 1];

				strcpy(nlsStrings[index].format, &data[i + 1]);

				i = e + 1;
			}
		}
		else {
			// skip string, look for another
			while ((i < size) && (data[i] != 0)) {
				i += 1;
			}
			i += 1;
		}
	}

	//	for (int i = 0; i < 32; i++) {
	//		printf("nlsStrings[%d]: %d  %02x %s\n",i,nlsStrings[i].nf,nlsStrings[i].signedMask,nlsStrings[i].format);
	//	}

	delete[] data;
	data = nullptr;

	return TraceDqrProfiler::DQERR_OK;
}

Symtab* ElfReader::getSymtab()
{
	return symtab;
}

TraceDqrProfiler::DQErr ElfReader::dumpSyms()
{
	if (symtab == nullptr) {
		symtab = getSymtab();
	}

	symtab->dump();

	return TraceDqrProfiler::DQERR_OK;
}

TsList::TsList()
{
	prev = nullptr;
	next = nullptr;
	message = nullptr;
	terminated = false;

	startTime = (TraceDqrProfiler::TIMESTAMP)0;
	endTime = (TraceDqrProfiler::TIMESTAMP)0;
}

TsList::~TsList()
{
}

ITCPrint::ITCPrint(int itcPrintOpts, int numCores, int buffSize, int channel, TraceDqrProfiler::nlStrings* nlsStrings)
{
	if ((numCores <= 0) || (buffSize <= 0)) {
		printf("Error: ITCPrint::ITCPrint(): Bad numCores or bufSize argument\n");

		// just make some defaults and fly from there

		numCores = 1;
		buffSize = 1024;
	}

	this->numCores = numCores;
	this->buffSize = buffSize;
	this->printChannel = channel;
	this->nlsStrings = nlsStrings;

	itcOptFlags = itcPrintOpts;

	pbuff = new char* [numCores];

	for (int i = 0; i < numCores; i++) {
		pbuff[i] = new char[buffSize];
	}

	numMsgs = new int[numCores];

	for (int i = 0; i < numCores; i++) {
		numMsgs[i] = 0;
	}

	pbi = new int[numCores];

	for (int i = 0; i < numCores; i++) {
		pbi[i] = 0;
	}

	pbo = new int[numCores];

	for (int i = 0; i < numCores; i++) {
		pbo[i] = 0;
	}

	freeList = nullptr;

	tsList = new TsList * [numCores];

	for (int i = 0; i < numCores; i++) {
		tsList[i] = nullptr;
	}
}

ITCPrint::~ITCPrint()
{
	nlsStrings = nullptr; // don't delete this here - it is part of the trace object

	if (pbuff != nullptr) {
		for (int i = 0; i < numCores; i++) {
			if (pbuff[i] != nullptr) {
				delete[] pbuff[i];
				pbuff[i] = nullptr;
			}
		}

		delete[] pbuff;
		pbuff = nullptr;
	}

	if (numMsgs != nullptr) {
		delete[] numMsgs;
		numMsgs = nullptr;
	}

	if (pbi != nullptr) {
		delete[] pbi;
		pbi = nullptr;
	}

	if (pbo != nullptr) {
		delete[] pbo;
		pbo = nullptr;
	}

	if (freeList != nullptr) {
		TsList* tl = freeList;
		while (tl != nullptr) {
			TsList* tln = tl->next;
			delete tl;
			tl = tln;
		}
		freeList = nullptr;
	}

	if (tsList != nullptr) {
		for (int i = 0; i < numCores; i++) {
			TsList* tl = tsList[i];
			if (tl != nullptr) {
				do {
					TsList* tln = tl->next;
					delete tl;
					tl = tln;
				} while ((tl != tsList[i]) && (tl != nullptr));
			}
		}
		delete[] tsList;
		tsList = nullptr;
	}
}

int ITCPrint::roomInITCPrintQ(uint8_t core)
{
	if (core >= numCores) {
		return 0;
	}

	if (pbi[core] > pbo[core]) {
		return buffSize - pbi[core] + pbo[core] - 1;
	}

	if (pbi[core] < pbo[core]) {
		return pbo[core] - pbi[core] - 1;
	}

	return buffSize - 1;
}

bool ITCPrint::print(uint8_t core, uint32_t addr, uint32_t data, TraceDqrProfiler::TIMESTAMP tstamp)
{
	if (core >= numCores) {
		return false;
	}

	//	here we want to process nls!!!
	//	check is addr has an itc print format string (in nlsStrings)

	TsList* tlp;
	tlp = tsList[core];
	TsList* workingtlp;
	int channel;

	channel = addr / 4;

	if (itcOptFlags & TraceDqrProfiler::ITC_OPT_NLS) {
		if (((addr & 0x03) == 0) && (nlsStrings != nullptr) && (nlsStrings[channel].format != nullptr)) {
			int args[4];
			char dst[256];
			int dstLen = 0;

			// have a no-load-string print

			// need to get args for print

			switch (nlsStrings[channel].nf) {
			case 0:
				dstLen = sprintf(dst, nlsStrings[channel].format);
				break;
			case 1:
				dstLen = sprintf(dst, nlsStrings[channel].format, data);
				break;
			case 2:
				for (int i = 0; i < 2; i++) {
					if (nlsStrings[channel].signedMask & (1 << i)) {
						// signed
						args[i] = (int16_t)(data >> ((1 - i) * 16));
					}
					else {
						// unsigned
						args[i] = (uint16_t)(data >> ((1 - i) * 16));
					}
				}
				dstLen = sprintf(dst, nlsStrings[channel].format, args[0], args[1]);
				break;
			case 3:
				args[0] = (data >> (32 - 11)) & 0x7ff; // 10 bit
				args[1] = (data >> (32 - 22)) & 0x7ff; // 11 bit
				args[2] = (data >> (32 - 32)) & 0x3ff; // 11 bit

				if (nlsStrings[channel].signedMask & (1 << 0)) {
					if (args[0] & 0x400) {
						args[0] |= 0xfffff800;
					}
				}

				if (nlsStrings[channel].signedMask & (1 << 1)) {
					if (args[1] & 0x400) {
						args[1] |= 0xfffff800;
					}
				}

				if (nlsStrings[channel].signedMask & (1 << 2)) {
					if (args[2] & 0x200) {
						args[2] |= 0xfffffc00;
					}
				}

				dstLen = sprintf(dst, nlsStrings[channel].format, args[0], args[1], args[2]);
				break;
			case 4:
				for (int i = 0; i < 4; i++) {
					if (nlsStrings[channel].signedMask & (1 << i)) {
						// signed
						args[i] = (int8_t)(data >> ((3 - i) * 8));
					}
					else {
						// unsigned
						args[i] = (uint8_t)(data >> ((3 - i) * 8));
					}
				}
				dstLen = sprintf(dst, nlsStrings[channel].format, args[0], args[1], args[2], args[3]);
				break;
			default:
				dstLen = sprintf(dst, "Error: invalid number of args for format string %d, %s", channel, nlsStrings[channel].format);
				break;
			}

			if ((tsList[core] != nullptr) && (tsList[core]->terminated == false)) {
				// terminate the current message

				pbuff[core][pbi[core]] = 0;	// add a null termination after the eol
				pbi[core] += 1;

				if (pbi[core] >= buffSize) {
					pbi[core] = 0;
				}

				numMsgs[core] += 1;

				tsList[core]->terminated = true;
			}

			// check free list for available struct

			if (freeList != nullptr) {
				workingtlp = freeList;
				freeList = workingtlp->next;

				workingtlp->terminated = false;
				workingtlp->message = nullptr;
			}
			else {
				workingtlp = new TsList();
			}

			if (tlp == nullptr) {
				workingtlp->next = workingtlp;
				workingtlp->prev = workingtlp;
			}
			else {
				workingtlp->next = tlp;
				workingtlp->prev = tlp->prev;

				tlp->prev = workingtlp;
				workingtlp->prev->next = workingtlp;
			}

			workingtlp->startTime = tstamp;
			workingtlp->endTime = tstamp;
			workingtlp->message = &pbuff[core][pbi[core]];

			tsList[core] = workingtlp;

			// workingtlp now points to unterminated TSList object

			int room = roomInITCPrintQ(core);

			for (int i = 0; i < dstLen; i++) {
				if (room >= 2) { // 2 because we need to make sure there is room for the nul termination
					pbuff[core][pbi[core]] = dst[i];
					pbi[core] += 1;
					if (pbi[core] >= buffSize) {
						pbi[core] = 0;
					}
					room -= 1;
				}
			}

			pbuff[core][pbi[core]] = 0;
			pbi[core] += 1;
			if (pbi[core] >= buffSize) {
				pbi[core] = 0;
			}

			workingtlp->terminated = true;
			numMsgs[core] += 1;

			return true;
		}
	}

	if (itcOptFlags & TraceDqrProfiler::ITC_OPT_PRINT) {
		if ((addr < (uint32_t)printChannel * 4) || (addr >= (((uint32_t)printChannel + 1) * 4))) {
			// not writing to this itc channel

			return false;
		}

		if ((tlp == nullptr) || tlp->terminated == true) {
			// see if there is one on the free list before making a new one

			if (freeList != nullptr) {
				workingtlp = freeList;
				freeList = workingtlp->next;

				workingtlp->terminated = false;
				workingtlp->message = nullptr;
			}
			else {
				workingtlp = new TsList();
			}

			if (tlp == nullptr) {
				workingtlp->next = workingtlp;
				workingtlp->prev = workingtlp;
			}
			else {
				workingtlp->next = tlp;
				workingtlp->prev = tlp->prev;

				tlp->prev = workingtlp;
				workingtlp->prev->next = workingtlp;
			}

			workingtlp->terminated = false;
			workingtlp->startTime = tstamp;
			workingtlp->message = &pbuff[core][pbi[core]];

			tsList[core] = workingtlp;
		}
		else {
			workingtlp = tlp;
		}

		// workingtlp now points to unterminated TSList object (in progress)

		workingtlp->endTime = tstamp;

		char* p = (char*)&data;
		int room = roomInITCPrintQ(core);

		for (int i = 0; ((size_t)i < ((sizeof data) - (addr & 0x03))); i++) {
			if (room >= 2) {
				pbuff[core][pbi[core]] = p[i];
				pbi[core] += 1;
				if (pbi[core] >= buffSize) {
					pbi[core] = 0;
				}
				room -= 1;

				switch (p[i]) {
				case 0:
					numMsgs[core] += 1;

					workingtlp->terminated = true;
					break;
				case '\n':
				case '\r':
					pbuff[core][pbi[core]] = 0;	// add a null termination after the eol
					pbi[core] += 1;
					if (pbi[core] >= buffSize) {
						pbi[core] = 0;
					}
					room -= 1;
					numMsgs[core] += 1;

					workingtlp->terminated = true;
					break;
				default:
					break;
				}
			}
		}

		pbuff[core][pbi[core]] = 0; // make sure always null terminated. This may be a temporary null termination

		// returning true means it was an itc print msg and has been processed
		// false means it was not, and should be handled normally

		return true;
	}

	return false;
}

bool ITCPrint::haveITCPrintMsgs()
{
	for (int core = 0; core < numCores; core++) {
		if (numMsgs[core] != 0) {
			return true;
		}
	}

	return false;
}

int ITCPrint::getITCPrintMask()
{
	int mask = 0;

	for (int core = 0; core < numCores; core++) {
		if (numMsgs[core] != 0) {
			mask |= 1 << core;
		}
	}

	return mask;
}

int ITCPrint::getITCFlushMask()
{
	int mask = 0;

	for (int core = 0; core < numCores; core++) {
		if (numMsgs[core] > 0) {
			mask |= 1 << core;
		}
		else if (pbo[core] != pbi[core]) {
			mask |= 1 << core;
		}
	}

	return mask;
}

void ITCPrint::haveITCPrintData(int numMsgs[], bool havePrintData[])
{
	if (numMsgs != nullptr) {
		for (int i = 0; i < numCores; i++) {
			numMsgs[i] = this->numMsgs[i];
		}
	}

	if (havePrintData != nullptr) {
		for (int i = 0; i < numCores; i++) {
			havePrintData[i] = pbi[i] != pbo[i];
		}
	}
}

TsList* ITCPrint::consumeTerminatedTsList(int core)
{
	TsList* rv = nullptr;

	if (numMsgs[core] > 0) { // have stuff in the Q
		TsList* tsl = tsList[core];

		// tsl now points to the newest tslist object. We want the oldest, which will be tsl->prev

		if (tsl != nullptr) {
			tsl = tsl->prev;

			if (tsl->terminated == true) {
				rv = tsl;

				// unlink tsl (consume it)

				if (tsl->next == tsl) {
					// was the only one in list

					tsList[core] = nullptr;
				}
				else {
					tsList[core]->prev = tsl->prev;

					if (tsList[core]->next == tsl) {
						tsList[core]->next = tsl->next;
					}
				}

				tsl->next = freeList;
				tsl->prev = nullptr;
				freeList = tsl;
			}
		}
	}

	return rv;
}

TsList* ITCPrint::consumeOldestTsList(int core)
{
	TsList* rv;

	rv = consumeTerminatedTsList(core);
	if (rv == nullptr) {
		// no terminated itc prints. Look for one in progress

		TsList* tsl = tsList[core];

		if (tsl != nullptr) {
			// this must be an unterminated tsl. unlink tsl (consume it)

			rv = tsl;

			if (tsl->next == tsl) {
				// was the only one in the list!

				tsList[core] = nullptr;
			}
			else {
				tsList[core]->prev = tsl->prev;

				if (tsList[core]->next == tsl) {
					tsList[core]->next = tsl->next;
				}
			}

			tsl->next = freeList;
			tsl->prev = nullptr;
			freeList = tsl;
		}
	}

	return rv;
}

bool ITCPrint::getITCPrintMsg(uint8_t core, char* dst, int dstLen, TraceDqrProfiler::TIMESTAMP& startTime, TraceDqrProfiler::TIMESTAMP& endTime)
{
	bool rc = false;

	if (core >= numCores) {
		return false;
	}

	if ((dst == nullptr) || (dstLen <= 0)) {
		printf("Error: ITCPrint::getITCPrintMsg(): Bad dst argument or size\n");

		return false;
	}

	if (numMsgs[core] > 0) {
		TsList* tsl = consumeTerminatedTsList(core);

		if (tsl != nullptr) {
			startTime = tsl->startTime;
			endTime = tsl->endTime;
		}
		else if (tsl == nullptr) {
			printf("Error: ITCPrint::getITCPrintMsg(): tsl is null\n");
			return false;
		}

		rc = true;
		numMsgs[core] -= 1;

		while (pbuff[core][pbo[core]] && (dstLen > 1)) {
			*dst++ = pbuff[core][pbo[core]];
			dstLen -= 1;

			pbo[core] += 1;
			if (pbo[core] >= buffSize) {
				pbo[core] = 0;
			}
		}

		*dst = 0;

		// skip past null terminted end of message

		pbo[core] += 1;
		if (pbo[core] >= buffSize) {
			pbo[core] = 0;
		}
	}

	return rc;
}

bool ITCPrint::flushITCPrintMsg(uint8_t core, char* dst, int dstLen, TraceDqrProfiler::TIMESTAMP& startTime, TraceDqrProfiler::TIMESTAMP& endTime)
{
	if (core >= numCores) {
		printf("Error: ITCPrint::flushITCPringMsg(): Core out of range (%d)\n", core);
		return false;
	}

	if ((dst == nullptr) || (dstLen <= 0)) {
		printf("Error: ITCPrint::flushITCPrintMsg(): Bad dst argument\n");
		return false;
	}

	if (numMsgs[core] > 0) {
		return getITCPrintMsg(core, dst, dstLen, startTime, endTime);
	}

	if (pbo[core] != pbi[core]) {
		TsList* tsl = consumeOldestTsList(core);

		if ((tsl == nullptr) || (tsl->terminated != false)) {
			printf("Error: ITCPrint::flushITCPrintMsg(): bad tsl object\n");
			return false;
		}

		startTime = tsl->startTime;
		endTime = tsl->endTime;

		while (pbuff[core][pbo[core]] && (dstLen > 1)) {
			*dst++ = pbuff[core][pbo[core]];
			dstLen -= 1;

			pbo[core] += 1;
			if (pbo[core] >= buffSize) {
				pbo[core] = 0;
			}
		}
		return true;
	}

	return false;
}

bool ITCPrint::getITCPrintStr(uint8_t core, std::string& s, TraceDqrProfiler::TIMESTAMP& startTime, TraceDqrProfiler::TIMESTAMP& endTime)
{
	if (core >= numCores) {
		return false;
	}

	bool rc = false;

	if (numMsgs[core] > 0) { // stuff in the Q
		rc = true;

		TsList* tsl = consumeTerminatedTsList(core);

		if (tsl == nullptr) {
			printf("Error: ITCPrint::getITCPrintStr(): Bad tsl pointer\n");
			return false;
		}

		startTime = tsl->startTime;
		endTime = tsl->endTime;

		numMsgs[core] -= 1;

		while (pbuff[core][pbo[core]]) {
			s += pbuff[core][pbo[core]];

			pbo[core] += 1;
			if (pbo[core] >= buffSize) {
				pbo[core] = 0;
			}
		}

		pbo[core] += 1;
		if (pbo[core] >= buffSize) {
			pbo[core] = 0;
		}
	}

	return rc;
}

bool ITCPrint::flushITCPrintStr(uint8_t core, std::string& s, TraceDqrProfiler::TIMESTAMP& startTime, TraceDqrProfiler::TIMESTAMP& endTime)
{
	if (core >= numCores) {
		return false;
	}

	if (numMsgs[core] > 0) {
		return getITCPrintStr(core, s, startTime, endTime);
	}

	if (pbo[core] != pbi[core]) {
		TsList* tsl = consumeOldestTsList(core);

		if ((tsl == nullptr) || (tsl->terminated != false)) {
			printf("Error: ITCPrint::flushITCPrintStr(): Bad tsl pointer\n");
			return false;
		}

		startTime = tsl->startTime;
		endTime = tsl->endTime;

		s = "";
		while (pbuff[core][pbo[core]]) {
			s += pbuff[core][pbo[core]];

			pbo[core] += 1;
			if (pbo[core] >= buffSize) {
				pbo[core] = 0;
			}
		}
		return true;
	}

	return false;
}

ProfilerAnalytics::ProfilerAnalytics()
{
	cores = 0;
	num_trace_msgs_all_cores = 0;
	num_trace_bits_all_cores = 0;
	num_trace_bits_all_cores_max = 0;
	num_trace_bits_all_cores_min = 0;
	num_trace_mseo_bits_all_cores = 0;

	num_inst_all_cores = 0;
	num_inst16_all_cores = 0;
	num_inst32_all_cores = 0;

	num_branches_all_cores = 0;

	for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
		core[i].num_inst16 = 0;
		core[i].num_inst32 = 0;
		core[i].num_inst = 0;

		core[i].num_trace_msgs = 0;
		core[i].num_trace_syncs = 0;
		core[i].num_trace_dbranch = 0;
		core[i].num_trace_ibranch = 0;
		core[i].num_trace_ihistory = 0;
		core[i].num_trace_ihistoryws = 0;
		core[i].num_trace_resourcefull = 0;
		core[i].num_trace_incircuittraceWS = 0;
		core[i].num_trace_incircuittrace = 0;

		core[i].num_trace_dataacq = 0;
		core[i].num_trace_dbranchws = 0;
		core[i].num_trace_ibranchws = 0;
		core[i].num_trace_correlation = 0;
		core[i].num_trace_auxaccesswrite = 0;
		core[i].num_trace_ownership = 0;
		core[i].num_trace_error = 0;

		core[i].num_trace_ts = 0;
		core[i].num_trace_uaddr = 0;
		core[i].num_trace_faddr = 0;
		core[i].num_trace_ihistory_taken_branches = 0;
		core[i].num_trace_ihistory_nottaken_branches = 0;
		core[i].num_trace_resourcefull_i_cnt = 0;
		core[i].num_trace_resourcefull_hist = 0;
		core[i].num_trace_resourcefull_takenCount = 0;
		core[i].num_trace_resourcefull_notTakenCount = 0;
		core[i].num_trace_resourcefull_taken_branches = 0;
		core[i].num_trace_resourcefull_nottaken_branches = 0;

		core[i].trace_bits = 0;
		core[i].trace_bits_max = 0;
		core[i].trace_bits_min = 0;
		core[i].trace_bits_mseo = 0;

		core[i].max_hist_bits = 0;
		core[i].min_hist_bits = 0;
		core[i].max_notTakenCount = 0;
		core[i].min_notTakenCount = 0;
		core[i].max_takenCount = 0;
		core[i].min_takenCount = 0;

		core[i].trace_bits_sync = 0;
		core[i].trace_bits_dbranch = 0;
		core[i].trace_bits_ibranch = 0;
		core[i].trace_bits_dataacq = 0;
		core[i].trace_bits_dbranchws = 0;
		core[i].trace_bits_ibranchws = 0;
		core[i].trace_bits_ihistory = 0;
		core[i].trace_bits_ihistoryws = 0;
		core[i].trace_bits_resourcefull = 0;
		core[i].trace_bits_correlation = 0;
		core[i].trace_bits_auxaccesswrite = 0;
		core[i].trace_bits_ownership = 0;
		core[i].trace_bits_error = 0;
		core[i].trace_bits_incircuittrace = 0;
		core[i].trace_bits_incircuittraceWS = 0;

		core[i].trace_bits_ts = 0;
		core[i].trace_bits_ts_max = 0;
		core[i].trace_bits_ts_min = 0;

		core[i].trace_bits_uaddr = 0;
		core[i].trace_bits_uaddr_max = 0;
		core[i].trace_bits_uaddr_min = 0;

		core[i].trace_bits_faddr = 0;
		core[i].trace_bits_faddr_max = 0;
		core[i].trace_bits_faddr_min = 0;

		core[i].trace_bits_hist = 0;

		core[i].num_taken_branches = 0;
		core[i].num_notTaken_branches = 0;
		core[i].num_calls = 0;
		core[i].num_returns = 0;
		core[i].num_swaps = 0;
		core[i].num_exceptions = 0;
		core[i].num_exception_returns = 0;
		core[i].num_interrupts = 0;
	}

#ifdef DO_TIMES
	etimer = new Timer();
#endif // DO_TIMES

	status = TraceDqrProfiler::DQERR_OK;
}

ProfilerAnalytics::~ProfilerAnalytics()
{
#ifdef DO_TIMES
	if (etimer != nullptr) {
		delete etimer;
		etimer = nullptr;
	}
#endif // DO_TIMES
}

TraceDqrProfiler::DQErr ProfilerAnalytics::updateTraceInfo(ProfilerNexusMessage& nm, uint32_t bits, uint32_t mseo_bits, uint32_t ts_bits, uint32_t addr_bits)
{
	bool have_uaddr = false;
	bool have_faddr = false;

	num_trace_msgs_all_cores += 1;
	num_trace_bits_all_cores += bits;
	num_trace_mseo_bits_all_cores += mseo_bits;

	core[nm.coreId].num_trace_msgs += 1;

	if (bits > num_trace_bits_all_cores_max) {
		num_trace_bits_all_cores_max = bits;
	}

	if ((num_trace_bits_all_cores_min == 0) || (bits < num_trace_bits_all_cores_min)) {
		num_trace_bits_all_cores_min = bits;
	}

	core[nm.coreId].trace_bits_mseo += mseo_bits;
	core[nm.coreId].trace_bits += bits;

	if (bits > core[nm.coreId].trace_bits_max) {
		core[nm.coreId].trace_bits_max = bits;
	}

	if ((core[nm.coreId].trace_bits_min == 0) || (bits < core[nm.coreId].trace_bits_min)) {
		core[nm.coreId].trace_bits_min = bits;
	}

	cores |= (1 << nm.coreId);

	if (ts_bits > 0) {
		core[nm.coreId].num_trace_ts += 1;
		core[nm.coreId].trace_bits_ts += ts_bits;

		if (ts_bits > core[nm.coreId].trace_bits_ts_max) {
			core[nm.coreId].trace_bits_ts_max = ts_bits;
		}

		if ((core[nm.coreId].trace_bits_ts_min == 0) || (ts_bits < core[nm.coreId].trace_bits_ts_min)) {
			core[nm.coreId].trace_bits_ts_min = ts_bits;
		}
	}

	int msb;
	uint64_t mask;
	int taken;
	int nottaken;

	switch (nm.tcode) {
	case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
		core[nm.coreId].num_trace_ownership += 1;
		core[nm.coreId].trace_bits_ownership += bits;
		break;
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
		core[nm.coreId].num_trace_dbranch += 1;
		core[nm.coreId].trace_bits_dbranch += bits;
		num_branches_all_cores += 1;
		break;
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
		core[nm.coreId].num_trace_ibranch += 1;
		core[nm.coreId].trace_bits_ibranch += bits;
		num_branches_all_cores += 1;

		have_uaddr = true;
		break;
	case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
		core[nm.coreId].num_trace_dataacq += 1;
		core[nm.coreId].trace_bits_dataacq += bits;
		break;
	case TraceDqrProfiler::TCODE_ERROR:
		core[nm.coreId].num_trace_error += 1;
		core[nm.coreId].trace_bits_error += bits;
		break;
	case TraceDqrProfiler::TCODE_SYNC:
		core[nm.coreId].num_trace_syncs += 1;
		core[nm.coreId].trace_bits_sync += bits;

		have_faddr = true;
		break;
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
		core[nm.coreId].num_trace_dbranchws += 1;
		core[nm.coreId].trace_bits_dbranchws += bits;
		num_branches_all_cores += 1;

		have_faddr = true;
		break;
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
		core[nm.coreId].num_trace_ibranchws += 1;
		core[nm.coreId].trace_bits_ibranchws += bits;
		num_branches_all_cores += 1;

		have_faddr = true;
		break;
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
		core[nm.coreId].num_trace_auxaccesswrite += 1;
		core[nm.coreId].trace_bits_auxaccesswrite += bits;
		break;
	case TraceDqrProfiler::TCODE_CORRELATION:
		core[nm.coreId].num_trace_correlation += 1;
		core[nm.coreId].trace_bits_ibranchws += bits;
		break;
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
		core[nm.coreId].num_trace_ihistory += 1;
		core[nm.coreId].trace_bits_ihistory += bits;

		// need to find msb = 1

		msb = -1;
		mask = nm.indirectHistory.history;
		taken = -1;	// start at -1 to account for stop bit, which isn't a branch
		nottaken = 0;

		while (mask > 1) { // use > 1 because the most significant 1 is a stop bit which we don't want to count!
			msb += 1;
			if (mask & 1) {
				taken += 1;
			}
			else {
				nottaken += 1;
			}
			mask >>= 1;
		}

		core[nm.coreId].num_trace_ihistory_taken_branches += taken;
		core[nm.coreId].num_trace_ihistory_nottaken_branches += nottaken;

		if (msb >= 0) {
			core[nm.coreId].trace_bits_hist += msb + 1;

			if (msb >= (int32_t)core[nm.coreId].max_hist_bits) {
				core[nm.coreId].max_hist_bits = msb + 1;
			}
		}

		if ((msb + 1) < (int32_t)core[nm.coreId].min_hist_bits) {
			core[nm.coreId].min_hist_bits = msb + 1;
		}

		num_branches_all_cores += 1 + taken + nottaken;

		have_uaddr = true;
		break;
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
		core[nm.coreId].num_trace_ihistoryws += 1;
		core[nm.coreId].trace_bits_ihistoryws += bits;

		// need to find msb = 1

		msb = -1;
		mask = nm.indirectHistoryWS.history;
		taken = -1;	// start at -1 to account for stop bit, which isn't a branch
		nottaken = 0;

		while (mask > 1) {
			msb += 1;
			if (mask & 1) {
				taken += 1;
			}
			else {
				nottaken += 1;
			}
			mask >>= 1;
		}

		core[nm.coreId].num_trace_ihistory_taken_branches += taken;
		core[nm.coreId].num_trace_ihistory_nottaken_branches += nottaken;

		if (msb >= 0) {
			core[nm.coreId].trace_bits_hist += msb + 1;

			if (msb >= (int32_t)core[nm.coreId].max_hist_bits) {
				core[nm.coreId].max_hist_bits = msb + 1;
			}
		}

		if ((msb + 1) < (int32_t)core[nm.coreId].min_hist_bits) {
			core[nm.coreId].min_hist_bits = msb + 1;
		}

		num_branches_all_cores += 1 + taken + nottaken;

		have_faddr = true;
		break;
	case TraceDqrProfiler::TCODE_RESOURCEFULL:
		core[nm.coreId].num_trace_resourcefull += 1;
		core[nm.coreId].trace_bits_resourcefull += bits;

		switch (nm.resourceFull.rCode) {
		case 0:
			core[nm.coreId].num_trace_resourcefull_i_cnt += 1;
			break;
		case 1:
			core[nm.coreId].num_trace_resourcefull_hist += 1;

			// need to find msb = 1

			msb = -1;
			mask = nm.resourceFull.history;
			taken = -1;	// start at -1 to account for stop bit, which isn't a branch
			nottaken = 0;

			while (mask > 1) {
				msb += 1;
				if (mask & 1) {
					taken += 1;
				}
				else {
					nottaken += 1;
				}
				mask >>= 1;
			}

			core[nm.coreId].num_trace_ihistory_taken_branches += taken;
			core[nm.coreId].num_trace_ihistory_nottaken_branches += nottaken;

			if (msb >= 0) {
				core[nm.coreId].trace_bits_hist += msb + 1;

				if (msb >= (int32_t)core[nm.coreId].max_hist_bits) {
					core[nm.coreId].max_hist_bits = msb + 1;
				}
			}

			if ((msb + 1) < (int32_t)core[nm.coreId].min_hist_bits) {
				core[nm.coreId].min_hist_bits = msb + 1;
			}

			num_branches_all_cores += taken + nottaken;
			break;
		case 8:
			core[nm.coreId].num_trace_resourcefull_notTakenCount += 1;
			core[nm.coreId].num_trace_resourcefull_nottaken_branches += nm.resourceFull.notTakenCount;

			// compute avg/max/min not taken count

			if (nm.resourceFull.notTakenCount > (uint32_t)core[nm.coreId].max_notTakenCount) {
				core[nm.coreId].max_notTakenCount = nm.resourceFull.notTakenCount;
			}

			if ((core[nm.coreId].min_notTakenCount == 0) || (nm.resourceFull.notTakenCount < (uint32_t)core[nm.coreId].min_notTakenCount)) {
				core[nm.coreId].min_notTakenCount = nm.resourceFull.notTakenCount;
			}
			break;
		case 9:
			core[nm.coreId].num_trace_resourcefull_takenCount += 1;
			core[nm.coreId].num_trace_resourcefull_taken_branches += nm.resourceFull.takenCount;

			// compute avg/max/min taken count

			if (nm.resourceFull.takenCount > (uint32_t)core[nm.coreId].max_takenCount) {
				core[nm.coreId].max_takenCount = nm.resourceFull.takenCount;
			}

			if ((core[nm.coreId].min_takenCount == 0) || (nm.resourceFull.takenCount < (uint32_t)core[nm.coreId].min_takenCount)) {
				core[nm.coreId].min_takenCount = nm.resourceFull.takenCount;
			}
			break;
		default:
			printf("Error: ProfilerAnalytics::updateTraceInfo(): ResoureFull: unknown RDode: %d\n", nm.resourceFull.rCode);
			status = TraceDqrProfiler::DQERR_ERR;
			return status;
		}
		break;
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
		core[nm.coreId].num_trace_incircuittrace += 1;
		core[nm.coreId].trace_bits_incircuittrace += bits;
		have_uaddr = true;
		break;
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS:
		core[nm.coreId].num_trace_incircuittraceWS += 1;
		core[nm.coreId].trace_bits_incircuittraceWS += bits;
		have_faddr = true;
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
	default:
		status = TraceDqrProfiler::DQERR_ERR;
		return status;
	}

	if (have_uaddr) {
		core[nm.coreId].num_trace_uaddr += 1;
		core[nm.coreId].trace_bits_uaddr += addr_bits;

		if (addr_bits > core[nm.coreId].trace_bits_uaddr_max) {
			core[nm.coreId].trace_bits_uaddr_max = addr_bits;
		}

		if ((core[nm.coreId].trace_bits_uaddr_min == 0) || (addr_bits < core[nm.coreId].trace_bits_uaddr_min)) {
			core[nm.coreId].trace_bits_uaddr_min = addr_bits;
		}
	}
	else if (have_faddr) {
		core[nm.coreId].num_trace_faddr += 1;
		core[nm.coreId].trace_bits_faddr += addr_bits;

		if (addr_bits > core[nm.coreId].trace_bits_faddr_max) {
			core[nm.coreId].trace_bits_faddr_max = addr_bits;
		}

		if ((core[nm.coreId].trace_bits_faddr_min == 0) || (addr_bits < core[nm.coreId].trace_bits_faddr_min)) {
			core[nm.coreId].trace_bits_faddr_min = addr_bits;
		}
	}

	return status;
}

TraceDqrProfiler::DQErr ProfilerAnalytics::updateInstructionInfo(uint32_t core_id, uint32_t inst, int instSize, int crFlags, TraceDqrProfiler::BranchFlags brFlags)
{
	num_inst_all_cores += 1;
	core[core_id].num_inst += 1;

	switch (instSize) {
	case 16:
		num_inst16_all_cores += 1;
		core[core_id].num_inst16 += 1;
		break;
	case 32:
		num_inst32_all_cores += 1;
		core[core_id].num_inst32 += 1;
		break;
	default:
		status = TraceDqrProfiler::DQERR_ERR;
	}

	switch (brFlags) {
	case TraceDqrProfiler::BRFLAG_none:
	case TraceDqrProfiler::BRFLAG_unknown:
		break;
	case TraceDqrProfiler::BRFLAG_taken:
		core[core_id].num_taken_branches += 1;
		break;
	case TraceDqrProfiler::BRFLAG_notTaken:
		core[core_id].num_notTaken_branches += 1;
		break;
	}

	if (crFlags & TraceDqrProfiler::isCall) {
		core[core_id].num_calls += 1;
	}
	if (crFlags & TraceDqrProfiler::isReturn) {
		core[core_id].num_returns += 1;
	}
	if (crFlags & TraceDqrProfiler::isSwap) {
		core[core_id].num_swaps += 1;
	}
	if (crFlags & TraceDqrProfiler::isInterrupt) {
		core[core_id].num_interrupts += 1;
	}
	if (crFlags & TraceDqrProfiler::isException) {
		core[core_id].num_exceptions += 1;
	}
	if (crFlags & TraceDqrProfiler::isExceptionReturn) {
		core[core_id].num_exception_returns += 1;
	}

	return status;
}

static void updateDst(int n, char*& dst, int& dst_len)
{
	if (n >= dst_len) {
		dst += dst_len;
		dst_len = 0;
	}
	else {
		dst += n;
		dst_len -= n;
	}
}

void ProfilerAnalytics::toText(char* dst, int dst_len, int detailLevel)
{
	char tmp_dst[512];
	int n;
#ifdef DO_TIMES
	double etime = etimer->etime();
#endif // DO_TIMES

	if ((dst == nullptr) || (dst_len < 0)) {
		printf("Error: Anaylics::toText(): Bad dst pointer\n");
		return;
	}

	dst[0] = 0;

	if (detailLevel <= 0) {
		return;
	}

	uint32_t have_ts = 0;

	for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
		if (cores & (1 << i)) {
			if (core[i].num_trace_ts > 0) {
				have_ts |= (1 << i);
			}
		}
	}

	if (srcBits == 0) {
		n = snprintf(dst, dst_len, "TraceProfiler ProfilerAnalytics: Single core");
		updateDst(n, dst, dst_len);
	}
	else {
		n = snprintf(dst, dst_len, "TraceProfiler ProfilerAnalytics: Multi core (src field %d bits)", srcBits);
		updateDst(n, dst, dst_len);
	}

	if (have_ts == 0) {
		n = snprintf(dst, dst_len, "; TraceProfiler messages do not have timestamps\n");
		updateDst(n, dst, dst_len);
	}
	else if (have_ts == cores) {
		n = snprintf(dst, dst_len, "; TraceProfiler messages have timestamps\n");
		updateDst(n, dst, dst_len);
	}
	else {
		n = snprintf(dst, dst_len, "; Some trace messages have timestamps\n");
		updateDst(n, dst, dst_len);
	}

	if (detailLevel == 1) {
		n = snprintf(dst, dst_len, "\n");
		updateDst(n, dst, dst_len);

		n = snprintf(dst, dst_len, "Instructions             Compressed                   RV32\n");
		updateDst(n, dst, dst_len);

		if (num_inst_all_cores > 0) {
			n = snprintf(dst, dst_len, "  %10u    %10u (%0.2f%%)    %10u (%0.2f%%)\n", num_inst_all_cores, num_inst16_all_cores, ((float)num_inst16_all_cores) / num_inst_all_cores * 100.0, num_inst32_all_cores, ((float)num_inst32_all_cores) / num_inst_all_cores * 100.0);
		}
		else {
			n = snprintf(dst, dst_len, "          -");
		}
		updateDst(n, dst, dst_len);

		n = snprintf(dst, dst_len, "\n");
		updateDst(n, dst, dst_len);

		n = snprintf(dst, dst_len, "Number of TraceProfiler Msgs      Avg Length    Min Length    Max Length    Total Length\n");
		updateDst(n, dst, dst_len);

		n = snprintf(dst, dst_len, "          %10u          %6.2f    %10u    %10u      %10u\n", num_trace_msgs_all_cores, ((float)num_trace_bits_all_cores) / num_trace_msgs_all_cores, num_trace_bits_all_cores_min, num_trace_bits_all_cores_max, num_trace_bits_all_cores);
		updateDst(n, dst, dst_len);

		n = snprintf(dst, dst_len, "\n");
		updateDst(n, dst, dst_len);

		if (num_inst_all_cores > 0) {
			n = snprintf(dst, dst_len, "TraceProfiler bits per instruction:     %5.2f\n", ((float)num_trace_bits_all_cores) / num_inst_all_cores);
		}
		else {
			n = snprintf(dst, dst_len, "  --\n");
		}
		updateDst(n, dst, dst_len);

		n = snprintf(dst, dst_len, "Instructions per trace message: %5.2f\n", ((float)num_inst_all_cores) / num_trace_msgs_all_cores);
		updateDst(n, dst, dst_len);

		if (num_branches_all_cores > 0) {
			n = snprintf(dst, dst_len, "Instructions per taken branch:  %5.2f\n", ((float)num_inst_all_cores) / num_branches_all_cores);
		}
		else {
			n = snprintf(dst, dst_len, "--\n");
		}
		updateDst(n, dst, dst_len);

		if (srcBits > 0) {
			n = snprintf(dst, dst_len, "Src bits %% of message:          %5.2f%%\n", ((float)srcBits * num_trace_msgs_all_cores) / num_trace_bits_all_cores * 100.0);
			updateDst(n, dst, dst_len);
		}

		if (have_ts != 0 || 1) {
			int bits_ts = 0;

			for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
				if (cores & (1 << i)) {
					bits_ts += core[i].trace_bits_ts;
				}
			}
			n = snprintf(dst, dst_len, "Timestamp bits %% of message:    %5.2f%%\n", ((float)bits_ts) / num_trace_bits_all_cores * 100.0);
			updateDst(n, dst, dst_len);
		}
	}
	else if (detailLevel > 1) {
		int position;
		int tabs[] = { 19 + 21 * 0,19 + 21 * 1,19 + 21 * 2,19 + 21 * 3,19 + 21 * 4,19 + 21 * 5,19 + 21 * 6,19 + 21 * 7,19 + 21 * 8 };
		uint32_t t1, t2;
		int ts;

		n = sprintf(tmp_dst, "\n");
		n += sprintf(tmp_dst + n, "                 ");

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				n += sprintf(tmp_dst + n, "          Core %d", i);
			}
		}

		if (srcBits > 0) {
			n += sprintf(tmp_dst + n, "               Total");
		}

		n += sprintf(tmp_dst + n, "\n");

		n = snprintf(dst, dst_len, "%s", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "Instructions");

		t1 = 0;
		ts = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				position += sprintf(tmp_dst + position, "%10u", core[i].num_inst);
				t1 += core[i].num_inst;
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			position += sprintf(tmp_dst + position, "%10u", t1);
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "  Compressed");

		t2 = 0;
		ts = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				if (core[i].num_inst > 0) {
					position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", core[i].num_inst16, ((float)core[i].num_inst16) / core[i].num_inst * 100.0);
				}
				else {
					position += sprintf(tmp_dst + position, "          -");
				}
				t2 += core[i].num_inst16;
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			if (t1 > 0) {
				position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", t2, ((float)t2) / t1 * 100.0);
			}
			else {
				position += sprintf(tmp_dst + position, "          -");
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "  RV32");

		t2 = 0;
		ts = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				if (core[i].num_inst > 0) {
					position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", core[i].num_inst32, ((float)core[i].num_inst32) / core[i].num_inst * 100.0);
				}
				else {
					position += sprintf(tmp_dst + position, "          -");
				}
				t2 += core[i].num_inst32;
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			if (t1 > 0) {
				position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", t2, ((float)t2) / t1 * 100.0);
			}
			else {
				position += sprintf(tmp_dst + position, "          -");
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "TraceProfiler Msgs");

		t1 = 0;
		ts = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				position += sprintf(tmp_dst + position, "%10u", core[i].num_trace_msgs);
				t1 += core[i].num_trace_msgs;
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += printf(" "); }
			position += sprintf(tmp_dst + position, "%10u", t1);
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "  Sync");

		t2 = 0;
		ts = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				if (core[i].num_trace_msgs > 0) {
					position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", core[i].num_trace_syncs, ((float)core[i].num_trace_syncs) / core[i].num_trace_msgs * 100.0);
				}
				else {
					position += sprintf(tmp_dst + position, "          -");
				}
				t2 += core[i].num_trace_syncs;
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			if (t1 > 0) {
				position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", t2, ((float)t2) / t1 * 100.0);
			}
			else {
				position += sprintf(tmp_dst + position, "          -");
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "  DBranch");

		t2 = 0;
		ts = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				if (core[i].num_trace_msgs > 0) {
					position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", core[i].num_trace_dbranch, ((float)core[i].num_trace_dbranch) / core[i].num_trace_msgs * 100.0);
				}
				else {
					position += sprintf(tmp_dst + position, "          -");
				}
				t2 += core[i].num_trace_dbranch;
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			if (t1 > 0) {
				position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", t2, ((float)t2) / t1 * 100.0);
			}
			else {
				position += sprintf(tmp_dst + position, "          -");
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "  IBranch");

		ts = 0;
		t2 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				if (core[i].num_trace_msgs > 0) {
					position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", core[i].num_trace_ibranch, ((float)core[i].num_trace_ibranch) / core[i].num_trace_msgs * 100.0);
				}
				else {
					position += sprintf(tmp_dst + position, "          -");
				}
				t2 += core[i].num_trace_ibranch;
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			if (t1 > 0) {
				position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", t2, ((float)t2) / t1 * 100.0);
			}
			else {
				position += sprintf(tmp_dst + position, "          -");
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "  DBranch WS");

		ts = 0;
		t2 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				if (core[i].num_trace_msgs > 0) {
					position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", core[i].num_trace_dbranchws, ((float)core[i].num_trace_dbranchws) / core[i].num_trace_msgs * 100.0);
				}
				else {
					position += sprintf(tmp_dst + position, "          -");
				}
				t2 += core[i].num_trace_dbranchws;
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			if (t1 > 0) {
				position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", t2, ((float)t2) / t1 * 100.0);
			}
			else {
				position += sprintf(tmp_dst + position, "          -");
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "  IBranch WS");

		ts = 0;
		t2 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				if (core[i].num_trace_msgs > 0) {
					position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", core[i].num_trace_ibranchws, ((float)core[i].num_trace_ibranchws) / core[i].num_trace_msgs * 100.0);
				}
				else {
					position += sprintf(tmp_dst + position, "          -");
				}
				t2 += core[i].num_trace_ibranchws;
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			if (t1 > 0) {
				position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", t2, ((float)t2) / t1 * 100.0);
			}
			else {
				position += sprintf(tmp_dst + position, "          -");
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "  Data Acq");

		ts = 0;
		t2 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				if (core[i].num_trace_msgs > 0) {
					position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", core[i].num_trace_dataacq, ((float)core[i].num_trace_dataacq) / core[i].num_trace_msgs * 100.0);
				}
				else {
					position += sprintf(tmp_dst + position, "          -");
				}
				t2 += core[i].num_trace_dataacq;
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			if (t1 > 0) {
				position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", t2, ((float)t2) / t1 * 100.0);
			}
			else {
				position += sprintf(tmp_dst + position, "          -");
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "  Correlation");

		ts = 0;
		t2 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				if (core[i].num_trace_msgs > 0) {
					position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", core[i].num_trace_correlation, ((float)core[i].num_trace_correlation) / core[i].num_trace_msgs * 100.0);
				}
				else {
					position += sprintf(tmp_dst + position, "          -");
				}
				t2 += core[i].num_trace_correlation;
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			if (t1 > 0) {
				position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", t2, ((float)t2) / t1 * 100.0);
			}
			else {
				position += sprintf(tmp_dst + position, "          -");
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "  Aux Acc Write");

		ts = 0;
		t2 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				if (core[i].num_trace_msgs > 0) {
					position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", core[i].num_trace_auxaccesswrite, ((float)core[i].num_trace_auxaccesswrite) / core[i].num_trace_msgs * 100.0);
				}
				else {
					position += sprintf(tmp_dst + position, "          -");
				}
				t2 += core[i].num_trace_auxaccesswrite;
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			if (t1 > 0) {
				position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", t2, ((float)t2) / t1 * 100.0);
			}
			else {
				position += sprintf(tmp_dst + position, "          -");
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "  Ownership");

		ts = 0;
		t2 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				if (core[i].num_trace_msgs > 0) {
					position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", core[i].num_trace_ownership, ((float)core[i].num_trace_ownership) / core[i].num_trace_msgs * 100.0);
				}
				else {
					position += sprintf(tmp_dst + position, "          -");
				}
				t2 += core[i].num_trace_ownership;
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			if (t1 > 0) {
				position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", t2, ((float)t2) / t1 * 100.0);
			}
			else {
				position += sprintf(tmp_dst + position, "          -");
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "  Error");

		ts = 0;
		t2 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				if (core[i].num_trace_msgs > 0) {
					position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", core[i].num_trace_error, ((float)core[i].num_trace_error) / core[i].num_trace_msgs * 100.0);
				}
				else {
					position += sprintf(tmp_dst + position, "          -");
				}
				t2 += core[i].num_trace_error;
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			if (t1 > 0) {
				position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", t2, ((float)t2) / t1 * 100.0);
			}
			else {
				position += sprintf(tmp_dst + position, "          -");
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "  IHistory");

		ts = 0;
		t2 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				if (core[i].num_trace_msgs > 0) {
					position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", core[i].num_trace_ihistory, ((float)core[i].num_trace_ihistory) / core[i].num_trace_msgs * 100.0);
				}
				else {
					position += sprintf(tmp_dst + position, "          -");
				}
				t2 += core[i].num_trace_ihistory;
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			if (t1 > 0) {
				position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", t2, ((float)t2) / t1 * 100.0);
			}
			else {
				position += sprintf(tmp_dst + position, "          -");
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "  IHistory WS");

		ts = 0;
		t2 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				if (core[i].num_trace_msgs > 0) {
					position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", core[i].num_trace_ihistoryws, ((float)core[i].num_trace_ihistoryws) / core[i].num_trace_msgs * 100.0);
				}
				else {
					position += sprintf(tmp_dst + position, "          -");
				}
				t2 += core[i].num_trace_ihistoryws;
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			if (t1 > 0) {
				position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", t2, ((float)t2) / t1 * 100.0);
			}
			else {
				position += sprintf(tmp_dst + position, "          -");
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "  RFull ICNT");

		ts = 0;
		t2 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				if (core[i].num_trace_msgs > 0) {
					position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", core[i].num_trace_resourcefull_i_cnt, ((float)core[i].num_trace_resourcefull_i_cnt) / core[i].num_trace_msgs * 100.0);
				}
				else {
					position += sprintf(tmp_dst + position, "          -");
				}
				t2 += core[i].num_trace_resourcefull_i_cnt;
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			if (t1 > 0) {
				position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", t2, ((float)t2) / t1 * 100.0);
			}
			else {
				position += sprintf(tmp_dst + position, "          -");
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "  RFull HIST");

		ts = 0;
		t2 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				if (core[i].num_trace_msgs > 0) {
					position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", core[i].num_trace_resourcefull_hist, ((float)core[i].num_trace_resourcefull_hist) / core[i].num_trace_msgs * 100.0);
				}
				else {
					position += sprintf(tmp_dst + position, "          -");
				}
				t2 += core[i].num_trace_resourcefull_hist;
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			if (t1 > 0) {
				position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", t2, ((float)t2) / t1 * 100.0);
			}
			else {
				position += sprintf(tmp_dst + position, "          -");
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "  RFull Taken");

		ts = 0;
		t2 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				if (core[i].num_trace_msgs > 0) {
					position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", core[i].num_trace_resourcefull_takenCount, ((float)core[i].num_trace_resourcefull_takenCount) / core[i].num_trace_msgs * 100.0);
				}
				else {
					position += sprintf(tmp_dst + position, "          -");
				}
				t2 += core[i].num_trace_resourcefull_takenCount;
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			if (t1 > 0) {
				position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", t2, ((float)t2) / t1 * 100.0);
			}
			else {
				position += sprintf(tmp_dst + position, "          -");
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "  RFull NTaken");

		ts = 0;
		t2 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				if (core[i].num_trace_msgs > 0) {
					position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", core[i].num_trace_resourcefull_notTakenCount, ((float)core[i].num_trace_resourcefull_notTakenCount) / core[i].num_trace_msgs * 100.0);
				}
				else {
					position += sprintf(tmp_dst + position, "          -");
				}
				t2 += core[i].num_trace_resourcefull_notTakenCount;
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			if (t1 > 0) {
				position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", t2, ((float)t2) / t1 * 100.0);
			}
			else {
				position += sprintf(tmp_dst + position, "          -");
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "  ICT WS");

		ts = 0;
		t2 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				if (core[i].num_trace_msgs > 0) {
					position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", core[i].num_trace_incircuittraceWS, ((float)core[i].num_trace_incircuittraceWS) / core[i].num_trace_msgs * 100.0);
				}
				else {
					position += sprintf(tmp_dst + position, "          -");
				}
				t2 += core[i].num_trace_ihistoryws;
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			if (t1 > 0) {
				position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", t2, ((float)t2) / t1 * 100.0);
			}
			else {
				position += sprintf(tmp_dst + position, "          -");
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "  ICT");

		ts = 0;
		t2 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				if (core[i].num_trace_msgs > 0) {
					position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", core[i].num_trace_incircuittrace, ((float)core[i].num_trace_incircuittrace) / core[i].num_trace_msgs * 100.0);
				}
				else {
					position += sprintf(tmp_dst + position, "          -");
				}
				t2 += core[i].num_trace_ihistoryws;
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			if (t1 > 0) {
				position += sprintf(tmp_dst + position, "%10u (%0.2f%%)", t2, ((float)t2) / t1 * 100.0);
			}
			else {
				position += sprintf(tmp_dst + position, "          -");
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "TraceProfiler Bits Total");

		ts = 0;
		t1 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				position += sprintf(tmp_dst + position, "%10u", core[i].trace_bits);
				t1 += core[i].trace_bits;
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			position += sprintf(tmp_dst + position, "%10u", t1);
		}

		//		printf("\n");
		//		position = printf("TraceProfiler Bits MSEO");
		//
		//		ts = 0;
		//		t1 = 0;
		//
		//		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
		//			if (cores & (1<<i)) {
		//				while (position < tabs[ts]) { position += printf(" "); }
		//				position += printf("%10u",core[i].trace_bits_mseo);
		//				t1 += core[i].trace_bits_mseo;
		//				ts += 1;
		//			}
		//		}
		//
		//		if (srcBits > 0) {
		//			while (position < tabs[ts]) { position += printf(" "); }
		//			printf("%10u",t1);
		//		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "TraceProfiler Bits/Inst");

		ts = 0;
		t1 = 0;
		t2 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				if (core[i].num_inst > 0) {
					position += sprintf(tmp_dst + position, "%13.2f", ((float)core[i].trace_bits) / core[i].num_inst);
				}
				else {
					position += sprintf(tmp_dst + position, "          -");
				}
				t1 += core[i].trace_bits;
				t2 += core[i].num_inst;
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			if (t2 > 0) {
				position += sprintf(tmp_dst + position, "%13.2f", ((float)t1) / t2);
			}
			else {
				position += sprintf(tmp_dst + position, "          -");
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "Inst/TraceProfiler Msg");

		ts = 0;
		t1 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				if (core[i].num_trace_msgs > 0) {
					position += sprintf(tmp_dst + position, "%13.2f", ((float)core[i].num_inst) / core[i].num_trace_msgs);
				}
				else {
					position += sprintf(tmp_dst + position, "          -");
				}
				t1 += core[i].num_trace_msgs;
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			if (t1 > 0) {
				position += sprintf(tmp_dst + position, "%13.2f", ((float)t2) / t1);
			}
			else {
				position += sprintf(tmp_dst + position, "          -");
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "Inst/Taken Branch");

		ts = 0;
		t1 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				if ((core[i].num_trace_dbranch + core[i].num_trace_ibranch + core[i].num_trace_dbranchws + core[i].num_trace_ibranchws + core[i].num_trace_ihistory_taken_branches + core[i].num_trace_resourcefull_taken_branches) > 0) {
					position += sprintf(tmp_dst + position, "%13.2f", ((float)core[i].num_inst) / (core[i].num_trace_dbranch + core[i].num_trace_ibranch + core[i].num_trace_dbranchws + core[i].num_trace_ibranchws + core[i].num_trace_ihistory_taken_branches + core[i].num_trace_resourcefull_taken_branches));
				}
				else {
					position += sprintf(tmp_dst + position, "          -");
				}
				t1 += core[i].num_trace_dbranch + core[i].num_trace_ibranch + core[i].num_trace_dbranchws + core[i].num_trace_ibranchws;
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			if (t1 > 0) {
				position += sprintf(tmp_dst + position, "%13.2f", ((float)t2) / t1);
			}
			else {
				position += sprintf(tmp_dst + position, "          -");
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "Avg Msg Length");

		ts = 0;
		t1 = 0;
		t2 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				if (core[i].num_trace_msgs > 0) {
					position += sprintf(tmp_dst + position, "%13.2f", ((float)core[i].trace_bits) / core[i].num_trace_msgs);
				}
				else {
					position += sprintf(tmp_dst + position, "          -");
				}
				t1 += core[i].trace_bits;
				t2 += core[i].num_trace_msgs;
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			if (t2 > 0) {
				position += sprintf(tmp_dst + position, "%13.2f", ((float)t1) / t2);
			}
			else {
				position += sprintf(tmp_dst + position, "          -");
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "Min Msg Length");

		ts = 0;
		t1 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				position += sprintf(tmp_dst + position, "%10u", core[i].trace_bits_min);
				if ((t1 == 0) || (core[i].trace_bits_min < t1)) {
					t1 = core[i].trace_bits_min;
				}
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			position += sprintf(tmp_dst + position, "%10u", t1);
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "Max Msg Length");

		ts = 0;
		t1 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				position += sprintf(tmp_dst + position, "%10u", core[i].trace_bits_max);
				if (core[i].trace_bits_max > t1) {
					t1 = core[i].trace_bits_max;
				}
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			position += sprintf(tmp_dst + position, "%10u", t1);
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "Timestamp Counts");

		ts = 0;
		t1 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				position += sprintf(tmp_dst + position, "%10u", core[i].num_trace_ts);
				t1 += core[i].num_trace_ts;
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			position += sprintf(tmp_dst + position, "%10u", t1);
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "  TStamp Size Avg");

		ts = 0;
		t2 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				if (core[i].num_trace_ts > 0) {
					position += sprintf(tmp_dst + position, "%13.2f", ((float)core[i].trace_bits_ts) / core[i].num_trace_ts);
					t2 += core[i].trace_bits_ts;
				}
				else {
					position += sprintf(tmp_dst + position, "         0");
				}
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			if (t1 > 0) {
				position += sprintf(tmp_dst + position, "%13.2f", ((float)t2) / t1);
			}
			else {
				position += sprintf(tmp_dst + position, "         0");
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "  TStamp Size Min");

		ts = 0;
		t1 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				position += sprintf(tmp_dst + position, "%10u", core[i].trace_bits_ts_min);
				if ((t1 == 0) || (t1 > core[i].trace_bits_ts_min)) {
					t1 = core[i].trace_bits_ts_min;
				}
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			position += sprintf(tmp_dst + position, "%10u", t1);
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "  TStamp Size Max");

		ts = 0;
		t1 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				position += sprintf(tmp_dst + position, "%10u", core[i].trace_bits_ts_max);
				if (core[i].trace_bits_ts_max > t1) {
					t1 = core[i].trace_bits_ts_max;
				}
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			position += sprintf(tmp_dst + position, "%10u", t1);
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "Timestamp %% of Msg");

		ts = 0;
		t1 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				if (core[i].trace_bits > 0) {
					position += sprintf(tmp_dst + position, "%13.2f%%", ((float)core[i].trace_bits_ts) / core[i].trace_bits * 100.0);
				}
				else {
					position += sprintf(tmp_dst + position, "          -");
				}
				t1 += core[i].trace_bits;
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			if (t1 > 0) {
				position += sprintf(tmp_dst + position, "%13.2f%%", ((float)t2) / t1 * 100.0);
			}
			else {
				position += sprintf(tmp_dst + position, "          -");
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "UADDR Counts");

		ts = 0;
		t1 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				position += sprintf(tmp_dst + position, "%10u", core[i].num_trace_uaddr);
				t1 += core[i].num_trace_uaddr;
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			position += sprintf(tmp_dst + position, "%10u", t1);
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "  UADDR Size Avg");

		ts = 0;
		t2 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				if (core[i].num_trace_uaddr > 0) {
					position += sprintf(tmp_dst + position, "%13.2f", ((float)core[i].trace_bits_uaddr) / core[i].num_trace_uaddr);
					t2 += core[i].trace_bits_uaddr;
				}
				else {
					position += sprintf(tmp_dst + position, "        0");
				}
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			if (t1 > 0) {
				position += sprintf(tmp_dst + position, "%13.2f", ((float)t2) / t1);
			}
			else {
				position += sprintf(tmp_dst + position, "        0");
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "  UADDR Size Min");

		ts = 0;
		t1 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				position += sprintf(tmp_dst + position, "%10u", core[i].trace_bits_uaddr_min);
				if ((t1 == 0) || (core[i].trace_bits_uaddr_min < t1)) {
					t1 = core[i].trace_bits_uaddr_min;
				}
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			position += sprintf(tmp_dst + position, "%10u", t1);
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "  UADDR Size Max");

		ts = 0;
		t1 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				position += sprintf(tmp_dst + position, "%10u", core[i].trace_bits_uaddr_max);
				if (t1 < core[i].trace_bits_uaddr_max) {
					t1 = core[i].trace_bits_uaddr_max;
				}
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			position += sprintf(tmp_dst + position, "%10u", t1);
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "FADDR Counts");

		ts = 0;
		t1 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				position += sprintf(tmp_dst + position, "%10u", core[i].num_trace_faddr);
				t1 += core[i].num_trace_faddr;
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			position += sprintf(tmp_dst + position, "%10u", t1);
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "  FADDR Size Avg");

		ts = 0;
		t2 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				if (core[i].num_trace_faddr > 0) {
					position += sprintf(tmp_dst + position, "%13.2f", ((float)core[i].trace_bits_faddr) / core[i].num_trace_faddr);
					t2 = core[i].trace_bits_faddr;
				}
				else {
					position += sprintf(tmp_dst + position, "        0");
				}
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			if (t1 > 0) {
				position += sprintf(tmp_dst + position, "%13.2f", ((float)t2) / t1);
			}
			else {
				position += sprintf(tmp_dst + position, "        0");
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "  FADDR Size Min");

		ts = 0;
		t2 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				position += sprintf(tmp_dst + position, "%10u", core[i].trace_bits_faddr_min);
				if ((t2 == 0) || (core[i].trace_bits_faddr_min < t2)) {
					t2 = core[i].trace_bits_faddr_min;
				}
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			position += sprintf(tmp_dst + position, "%10u", t2);
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "  FADDR Size Max");

		ts = 0;
		t2 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				position += sprintf(tmp_dst + position, "%10u", core[i].trace_bits_faddr_max);
				if (core[i].trace_bits_faddr_max > t2) {
					t2 = core[i].trace_bits_faddr_max;
				}
				ts += 1;
			}
		}

		if (srcBits > 0) {
			while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
			position += sprintf(tmp_dst + position, "%10u", t2);
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "Taken Branches");

		ts = 0;
		t2 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				position += sprintf(tmp_dst + position, "%10u", core[i].num_taken_branches);
				ts += 1;
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "Not Taken Branches");

		ts = 0;
		t2 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				position += sprintf(tmp_dst + position, "%10u", core[i].num_notTaken_branches);
				ts += 1;
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "Calls");

		ts = 0;
		t2 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				position += sprintf(tmp_dst + position, "%10u", core[i].num_calls);
				ts += 1;
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "Returns");

		ts = 0;
		t2 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				position += sprintf(tmp_dst + position, "%10u", core[i].num_returns);
				ts += 1;
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "Swaps");

		ts = 0;
		t2 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				position += sprintf(tmp_dst + position, "%10u", core[i].num_swaps);
				ts += 1;
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "Exceptions");

		ts = 0;
		t2 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				position += sprintf(tmp_dst + position, "%10u", core[i].num_exceptions);
				ts += 1;
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "Exception Returns");

		ts = 0;
		t2 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				position += sprintf(tmp_dst + position, "%10u", core[i].num_exception_returns);
				ts += 1;
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);

		position = sprintf(tmp_dst, "Interrupts");

		ts = 0;
		t2 = 0;

		for (int i = 0; i < DQR_PROFILER_MAXCORES; i++) {
			if (cores & (1 << i)) {
				while (position < tabs[ts]) { position += sprintf(tmp_dst + position, " "); }
				position += sprintf(tmp_dst + position, "%10u", core[i].num_interrupts);
				ts += 1;
			}
		}

		n = snprintf(dst, dst_len, "%s\n", tmp_dst);
		updateDst(n, dst, dst_len);
	}

#ifdef DO_TIMES
	n = snprintf(dst, dst_len, "\nTime %f seconds\n", etime);
	updateDst(n, dst, dst_len);
	n = snprintf(dst, dst_len, "Instructions decoded per second: %0.2f\n", num_inst_all_cores / etime);
	updateDst(n, dst, dst_len);
	n = snprintf(dst, dst_len, "TraceProfiler messages decoded per second: %0.2f\n", num_trace_msgs_all_cores / etime);
	updateDst(n, dst, dst_len);
#endif // DO_TIMES
}

std::string ProfilerAnalytics::toString(int detailLevel)
{
	char dst[4096];

	dst[0] = 0;

	toText(dst, sizeof dst, detailLevel);

	return std::string(dst);
}

uint32_t ProfilerNexusMessage::targetFrequency = 0;

ProfilerNexusMessage::ProfilerNexusMessage()
{
	msgNum = 0;
	tcode = TraceDqrProfiler::TCODE_UNDEFINED;
	coreId = 0;
	haveTimestamp = false;
	timestamp = 0;
	currentAddress = 0;
	time = 0;
	offset = 0;
	for (int i = 0; (size_t)i < sizeof rawData / sizeof rawData[0]; i++) {
		rawData[i] = 0xff;
	}
}

int ProfilerNexusMessage::getI_Cnt()
{
	switch (tcode) {
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
		return directBranch.i_cnt;
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
		return indirectBranch.i_cnt;
	case TraceDqrProfiler::TCODE_SYNC:
		return sync.i_cnt;
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
		return directBranchWS.i_cnt;
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
		return indirectBranchWS.i_cnt;
	case TraceDqrProfiler::TCODE_CORRELATION:
		return correlation.i_cnt;
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
		return indirectHistory.i_cnt;
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
		return indirectHistoryWS.i_cnt;
	case TraceDqrProfiler::TCODE_RESOURCEFULL:
		if (resourceFull.rCode == 0) {
			return resourceFull.i_cnt;
		}
		break;
	case TraceDqrProfiler::TCODE_DEBUG_STATUS:
	case TraceDqrProfiler::TCODE_DEVICE_ID:
	case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
	case TraceDqrProfiler::TCODE_DATA_WRITE:
	case TraceDqrProfiler::TCODE_DATA_READ:
	case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
	case TraceDqrProfiler::TCODE_ERROR:
	case TraceDqrProfiler::TCODE_CORRECTION:
	case TraceDqrProfiler::TCODE_DATA_WRITE_WS:
	case TraceDqrProfiler::TCODE_DATA_READ_WS:
	case TraceDqrProfiler::TCODE_WATCHPOINT:
	case TraceDqrProfiler::TCODE_OUTPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_INPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_AUXACCESS_READ:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
	case TraceDqrProfiler::TCODE_AUXACCESS_READNEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITENEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_RESPONSE:
	case TraceDqrProfiler::TCODE_REPEATBRANCH:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION_WS:
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS:
	case TraceDqrProfiler::TCODE_UNDEFINED:
		break;
	default:
		break;
	}

	return 0;
}

TraceDqrProfiler::ADDRESS ProfilerNexusMessage::getU_Addr()
{
	switch (tcode) {
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
		return indirectBranch.u_addr;
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
		return indirectHistory.u_addr;
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
		switch (ict.cksrc) {
		case TraceDqrProfiler::ICT_EXT_TRIG:
			// ckdata0 is the address of the instruciton that retired before generating the exception
			return ict.ckdata[0];
		case TraceDqrProfiler::ICT_CONTROL:
			if (ict.ckdf == 1) {
				return ict.ckdata[0];
			}
			break;
		case TraceDqrProfiler::ICT_INFERABLECALL:
			if (ict.ckdf == 0) { // inferrable call
				// ckdata[0] is the address of the call instruction. destination determined form program image
				return ict.ckdata[0];
			}
			else if (ict.ckdf == 1) { // call/return
				// ckdata[0] is the address of the call instruction. destination is computed from ckdata[1]
				return ict.ckdata[0];
			}
			break;
		case TraceDqrProfiler::ICT_EXCEPTION:
			// ckdata0 the address of the next mainline instruction to execute (will execute after the return from except)
			return ict.ckdata[0];
		case TraceDqrProfiler::ICT_INTERRUPT:
			// ckdata0 is the address of the next instruction to execute in mainline code (will execute after the return from interrupt)
			return ict.ckdata[0];
		case TraceDqrProfiler::ICT_CONTEXT:
			// ckdata[0] is the address of the instruction prior to doing the context switch
			return ict.ckdata[0];
		case TraceDqrProfiler::ICT_WATCHPOINT:
			// ckdata0 is the address of the last instruction to retire??
			return ict.ckdata[0];
		case TraceDqrProfiler::ICT_PC_SAMPLE:
			// periodic pc sample. Address of last instruciton to retire??
			return ict.ckdata[0];
		case TraceDqrProfiler::ICT_NONE:
		default:
			break;
		}
		break;
	case TraceDqrProfiler::TCODE_DEBUG_STATUS:
	case TraceDqrProfiler::TCODE_DEVICE_ID:
	case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_DATA_WRITE:
	case TraceDqrProfiler::TCODE_DATA_READ:
	case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
	case TraceDqrProfiler::TCODE_ERROR:
	case TraceDqrProfiler::TCODE_SYNC:
	case TraceDqrProfiler::TCODE_CORRECTION:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
	case TraceDqrProfiler::TCODE_DATA_WRITE_WS:
	case TraceDqrProfiler::TCODE_DATA_READ_WS:
	case TraceDqrProfiler::TCODE_WATCHPOINT:
	case TraceDqrProfiler::TCODE_OUTPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_INPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_AUXACCESS_READ:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
	case TraceDqrProfiler::TCODE_AUXACCESS_READNEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITENEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_RESPONSE:
	case TraceDqrProfiler::TCODE_RESOURCEFULL:
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
	case TraceDqrProfiler::TCODE_REPEATBRANCH:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION_WS:
	case TraceDqrProfiler::TCODE_CORRELATION:
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS:
	case TraceDqrProfiler::TCODE_UNDEFINED:
	default:
		break;
	}

	return -1;
}

TraceDqrProfiler::ADDRESS ProfilerNexusMessage::getF_Addr()
{
	switch (tcode) {
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
		return directBranchWS.f_addr;
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
		return indirectBranchWS.f_addr;
	case TraceDqrProfiler::TCODE_SYNC:
		return sync.f_addr;
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
		return indirectHistoryWS.f_addr;
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS:
		switch (ictWS.cksrc) {
		case TraceDqrProfiler::ICT_EXT_TRIG:
			// ckdata0 is the address of the instruciton that retired before generating the exception
			return ictWS.ckdata[0];
		case TraceDqrProfiler::ICT_CONTROL:
			if (ictWS.ckdf == 1) {
				return ictWS.ckdata[0];
			}
			break;
		case TraceDqrProfiler::ICT_INFERABLECALL:
			if (ictWS.ckdf == 0) { // inferrable call
				// ckdata[0] is the address of the call instruction. destination determined form program image
				return ictWS.ckdata[0];
			}
			else if (ictWS.ckdf == 1) { // call/return
				// ckdata[0] is the address of the call instruction. destination is computed from ckdata[1]
				// for now, just return the faddr
				return ictWS.ckdata[0];
			}
			break;
		case TraceDqrProfiler::ICT_EXCEPTION:
			// ckdata0 the address of the next mainline instruction to execute (will execute after the return from except)
			return ictWS.ckdata[0];
		case TraceDqrProfiler::ICT_INTERRUPT:
			// ckdata0 is the address of the next instruction to execute in mainline code (will execute after the return from interrupt)
			return ictWS.ckdata[0];
		case TraceDqrProfiler::ICT_CONTEXT:
			// ckdata[0] is the address of the instruction prior to doing the context switch
			return ictWS.ckdata[0];
		case TraceDqrProfiler::ICT_WATCHPOINT:
			// ckdata0 is the address of the last instruction to retire??
			return ictWS.ckdata[0];
		case TraceDqrProfiler::ICT_PC_SAMPLE:
			// periodic pc sample. Address of last instruciton to retire??
			return ictWS.ckdata[0];
		case TraceDqrProfiler::ICT_NONE:
		default:
			break;
		}
		break;
	case TraceDqrProfiler::TCODE_DEBUG_STATUS:
	case TraceDqrProfiler::TCODE_DEVICE_ID:
	case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_DATA_WRITE:
	case TraceDqrProfiler::TCODE_DATA_READ:
	case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
	case TraceDqrProfiler::TCODE_ERROR:
	case TraceDqrProfiler::TCODE_CORRECTION:
	case TraceDqrProfiler::TCODE_DATA_WRITE_WS:
	case TraceDqrProfiler::TCODE_DATA_READ_WS:
	case TraceDqrProfiler::TCODE_WATCHPOINT:
	case TraceDqrProfiler::TCODE_OUTPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_INPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_AUXACCESS_READ:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
	case TraceDqrProfiler::TCODE_AUXACCESS_READNEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITENEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_RESPONSE:
	case TraceDqrProfiler::TCODE_RESOURCEFULL:
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
	case TraceDqrProfiler::TCODE_REPEATBRANCH:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION_WS:
	case TraceDqrProfiler::TCODE_CORRELATION:
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
	case TraceDqrProfiler::TCODE_UNDEFINED:
		break;
	default:
		break;
	}

	return -1;
}

//TraceDqrProfiler::ADDRESS ProfilerNexusMessage::getNextAddr()
//{
//	TraceDqrProfiler::ADDRESS addr;
//
//	addr = getF_Addr();
//	if (addr != (TraceDqrProfiler::ADDRESS)-1) {
//		addr = addr << 1;
//	}
//
//	return addr;
//}

// Note: for this function to return the correct target address, processTraceMessage() must have already
// been called for this messages if it is a TCODE_INCIRCUITTRACE message. If it is a TCODE_INCIRCUIRCIUTTRACE_WS,
// it will work either way

TraceDqrProfiler::ADDRESS    ProfilerNexusMessage::getICTCallReturnTarget()
{
	switch (tcode) {
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
		if (ict.cksrc == TraceDqrProfiler::ICT_INFERABLECALL) {
			if (ict.ckdf == 0) {
				return ict.ckdata[1];
			}
			else {
				return currentAddress ^ (ict.ckdata[1] << 1);
			}
		}
		break;
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS:
		if (ictWS.cksrc == TraceDqrProfiler::ICT_INFERABLECALL) {
			if (ictWS.ckdf == 0) {
				return ictWS.ckdata[1];
			}
			else {
				return currentAddress ^ (ict.ckdata[1] << 1);
			}
		}
		break;
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
	case TraceDqrProfiler::TCODE_DEBUG_STATUS:
	case TraceDqrProfiler::TCODE_DEVICE_ID:
	case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_DATA_WRITE:
	case TraceDqrProfiler::TCODE_DATA_READ:
	case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
	case TraceDqrProfiler::TCODE_ERROR:
	case TraceDqrProfiler::TCODE_SYNC:
	case TraceDqrProfiler::TCODE_CORRECTION:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
	case TraceDqrProfiler::TCODE_DATA_WRITE_WS:
	case TraceDqrProfiler::TCODE_DATA_READ_WS:
	case TraceDqrProfiler::TCODE_WATCHPOINT:
	case TraceDqrProfiler::TCODE_OUTPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_INPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_AUXACCESS_READ:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
	case TraceDqrProfiler::TCODE_AUXACCESS_READNEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITENEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_RESPONSE:
	case TraceDqrProfiler::TCODE_RESOURCEFULL:
	case TraceDqrProfiler::TCODE_REPEATBRANCH:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION_WS:
	case TraceDqrProfiler::TCODE_CORRELATION:
	case TraceDqrProfiler::TCODE_UNDEFINED:
		break;
	default:
		break;
	}

	return -1;
}

TraceDqrProfiler::BType ProfilerNexusMessage::getB_Type()
{
	switch (tcode) {
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
		return indirectBranch.b_type;
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
		return indirectBranchWS.b_type;
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
		return indirectHistory.b_type;
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
		return indirectHistoryWS.b_type;
	case TraceDqrProfiler::TCODE_DEBUG_STATUS:
	case TraceDqrProfiler::TCODE_DEVICE_ID:
	case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_DATA_WRITE:
	case TraceDqrProfiler::TCODE_DATA_READ:
	case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
	case TraceDqrProfiler::TCODE_ERROR:
	case TraceDqrProfiler::TCODE_SYNC:
	case TraceDqrProfiler::TCODE_CORRECTION:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
	case TraceDqrProfiler::TCODE_DATA_WRITE_WS:
	case TraceDqrProfiler::TCODE_DATA_READ_WS:
	case TraceDqrProfiler::TCODE_WATCHPOINT:
	case TraceDqrProfiler::TCODE_OUTPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_INPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_AUXACCESS_READ:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
	case TraceDqrProfiler::TCODE_AUXACCESS_READNEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITENEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_RESPONSE:
	case TraceDqrProfiler::TCODE_RESOURCEFULL:
	case TraceDqrProfiler::TCODE_REPEATBRANCH:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION_WS:
	case TraceDqrProfiler::TCODE_CORRELATION:
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS:
	case TraceDqrProfiler::TCODE_UNDEFINED:
		break;
	default:
		break;
	}

	return TraceDqrProfiler::BTYPE_UNDEFINED;
}

TraceDqrProfiler::SyncReason ProfilerNexusMessage::getSyncReason()
{
	switch (tcode) {
	case TraceDqrProfiler::TCODE_SYNC:
		return sync.sync;
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
		return directBranchWS.sync;
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
		return indirectBranchWS.sync;
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
		return indirectHistoryWS.sync;
	case TraceDqrProfiler::TCODE_DEBUG_STATUS:
	case TraceDqrProfiler::TCODE_DEVICE_ID:
	case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_DATA_WRITE:
	case TraceDqrProfiler::TCODE_DATA_READ:
	case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
	case TraceDqrProfiler::TCODE_ERROR:
	case TraceDqrProfiler::TCODE_CORRECTION:
	case TraceDqrProfiler::TCODE_DATA_WRITE_WS:
	case TraceDqrProfiler::TCODE_DATA_READ_WS:
	case TraceDqrProfiler::TCODE_WATCHPOINT:
	case TraceDqrProfiler::TCODE_OUTPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_INPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_AUXACCESS_READ:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
	case TraceDqrProfiler::TCODE_AUXACCESS_READNEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITENEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_RESPONSE:
	case TraceDqrProfiler::TCODE_RESOURCEFULL:
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
	case TraceDqrProfiler::TCODE_REPEATBRANCH:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION_WS:
	case TraceDqrProfiler::TCODE_CORRELATION:
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
	case TraceDqrProfiler::TCODE_UNDEFINED:
		break;
	default:
		break;
	}

	return TraceDqrProfiler::SYNC_NONE;
}

uint8_t ProfilerNexusMessage::getEType()
{
	switch (tcode) {
	case TraceDqrProfiler::TCODE_ERROR:
		return error.etype;
	case TraceDqrProfiler::TCODE_DEBUG_STATUS:
	case TraceDqrProfiler::TCODE_DEVICE_ID:
	case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_DATA_WRITE:
	case TraceDqrProfiler::TCODE_DATA_READ:
	case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
	case TraceDqrProfiler::TCODE_SYNC:
	case TraceDqrProfiler::TCODE_CORRECTION:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
	case TraceDqrProfiler::TCODE_DATA_WRITE_WS:
	case TraceDqrProfiler::TCODE_DATA_READ_WS:
	case TraceDqrProfiler::TCODE_WATCHPOINT:
	case TraceDqrProfiler::TCODE_OUTPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_INPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_AUXACCESS_READ:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
	case TraceDqrProfiler::TCODE_AUXACCESS_READNEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITENEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_RESPONSE:
	case TraceDqrProfiler::TCODE_RESOURCEFULL:
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
	case TraceDqrProfiler::TCODE_REPEATBRANCH:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION_WS:
	case TraceDqrProfiler::TCODE_CORRELATION:
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
	case TraceDqrProfiler::TCODE_UNDEFINED:
		break;
	default:
		break;
	}

	return 0;
}

uint8_t ProfilerNexusMessage::getCKDF()
{
	switch (tcode) {
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
		return ict.ckdf;
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS:
		return ictWS.ckdf;
	case TraceDqrProfiler::TCODE_CORRELATION:
	case TraceDqrProfiler::TCODE_DEBUG_STATUS:
	case TraceDqrProfiler::TCODE_DEVICE_ID:
	case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_DATA_WRITE:
	case TraceDqrProfiler::TCODE_DATA_READ:
	case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
	case TraceDqrProfiler::TCODE_ERROR:
	case TraceDqrProfiler::TCODE_SYNC:
	case TraceDqrProfiler::TCODE_CORRECTION:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
	case TraceDqrProfiler::TCODE_DATA_WRITE_WS:
	case TraceDqrProfiler::TCODE_DATA_READ_WS:
	case TraceDqrProfiler::TCODE_WATCHPOINT:
	case TraceDqrProfiler::TCODE_OUTPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_INPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_AUXACCESS_READ:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
	case TraceDqrProfiler::TCODE_AUXACCESS_READNEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITENEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_RESPONSE:
	case TraceDqrProfiler::TCODE_RESOURCEFULL:
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
	case TraceDqrProfiler::TCODE_REPEATBRANCH:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION_WS:
	case TraceDqrProfiler::TCODE_UNDEFINED:
		break;
	default:
		break;
	}

	return 0;
}

TraceDqrProfiler::ICTReason ProfilerNexusMessage::getCKSRC()
{
	switch (tcode) {
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
		return ict.cksrc;
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS:
		return ictWS.cksrc;
	case TraceDqrProfiler::TCODE_CORRELATION:
	case TraceDqrProfiler::TCODE_DEBUG_STATUS:
	case TraceDqrProfiler::TCODE_DEVICE_ID:
	case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_DATA_WRITE:
	case TraceDqrProfiler::TCODE_DATA_READ:
	case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
	case TraceDqrProfiler::TCODE_ERROR:
	case TraceDqrProfiler::TCODE_SYNC:
	case TraceDqrProfiler::TCODE_CORRECTION:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
	case TraceDqrProfiler::TCODE_DATA_WRITE_WS:
	case TraceDqrProfiler::TCODE_DATA_READ_WS:
	case TraceDqrProfiler::TCODE_WATCHPOINT:
	case TraceDqrProfiler::TCODE_OUTPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_INPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_AUXACCESS_READ:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
	case TraceDqrProfiler::TCODE_AUXACCESS_READNEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITENEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_RESPONSE:
	case TraceDqrProfiler::TCODE_RESOURCEFULL:
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
	case TraceDqrProfiler::TCODE_REPEATBRANCH:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION_WS:
	case TraceDqrProfiler::TCODE_UNDEFINED:
		break;
	default:
		break;
	}

	return TraceDqrProfiler::ICT_NONE;
}

TraceDqrProfiler::ADDRESS ProfilerNexusMessage::getCKData(int i)
{
	switch (tcode) {
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
		return ict.ckdata[i];
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS:
		return ictWS.ckdata[i];
	case TraceDqrProfiler::TCODE_CORRELATION:
	case TraceDqrProfiler::TCODE_DEBUG_STATUS:
	case TraceDqrProfiler::TCODE_DEVICE_ID:
	case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_DATA_WRITE:
	case TraceDqrProfiler::TCODE_DATA_READ:
	case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
	case TraceDqrProfiler::TCODE_ERROR:
	case TraceDqrProfiler::TCODE_SYNC:
	case TraceDqrProfiler::TCODE_CORRECTION:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
	case TraceDqrProfiler::TCODE_DATA_WRITE_WS:
	case TraceDqrProfiler::TCODE_DATA_READ_WS:
	case TraceDqrProfiler::TCODE_WATCHPOINT:
	case TraceDqrProfiler::TCODE_OUTPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_INPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_AUXACCESS_READ:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
	case TraceDqrProfiler::TCODE_AUXACCESS_READNEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITENEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_RESPONSE:
	case TraceDqrProfiler::TCODE_RESOURCEFULL:
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
	case TraceDqrProfiler::TCODE_REPEATBRANCH:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION_WS:
	case TraceDqrProfiler::TCODE_UNDEFINED:
		break;
	default:
		break;
	}

	return 0;
}

uint8_t ProfilerNexusMessage::getCDF()
{
	switch (tcode) {
	case TraceDqrProfiler::TCODE_CORRELATION:
		return correlation.cdf;
	case TraceDqrProfiler::TCODE_DEBUG_STATUS:
	case TraceDqrProfiler::TCODE_DEVICE_ID:
	case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_DATA_WRITE:
	case TraceDqrProfiler::TCODE_DATA_READ:
	case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
	case TraceDqrProfiler::TCODE_ERROR:
	case TraceDqrProfiler::TCODE_SYNC:
	case TraceDqrProfiler::TCODE_CORRECTION:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
	case TraceDqrProfiler::TCODE_DATA_WRITE_WS:
	case TraceDqrProfiler::TCODE_DATA_READ_WS:
	case TraceDqrProfiler::TCODE_WATCHPOINT:
	case TraceDqrProfiler::TCODE_OUTPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_INPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_AUXACCESS_READ:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
	case TraceDqrProfiler::TCODE_AUXACCESS_READNEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITENEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_RESPONSE:
	case TraceDqrProfiler::TCODE_RESOURCEFULL:
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
	case TraceDqrProfiler::TCODE_REPEATBRANCH:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION_WS:
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
	case TraceDqrProfiler::TCODE_UNDEFINED:
		break;
	default:
		break;
	}

	return 0;
}

uint8_t ProfilerNexusMessage::getEVCode()
{
	switch (tcode) {
	case TraceDqrProfiler::TCODE_CORRELATION:
		return correlation.evcode;
	case TraceDqrProfiler::TCODE_DEBUG_STATUS:
	case TraceDqrProfiler::TCODE_DEVICE_ID:
	case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_DATA_WRITE:
	case TraceDqrProfiler::TCODE_DATA_READ:
	case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
	case TraceDqrProfiler::TCODE_ERROR:
	case TraceDqrProfiler::TCODE_SYNC:
	case TraceDqrProfiler::TCODE_CORRECTION:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
	case TraceDqrProfiler::TCODE_DATA_WRITE_WS:
	case TraceDqrProfiler::TCODE_DATA_READ_WS:
	case TraceDqrProfiler::TCODE_WATCHPOINT:
	case TraceDqrProfiler::TCODE_OUTPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_INPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_AUXACCESS_READ:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
	case TraceDqrProfiler::TCODE_AUXACCESS_READNEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITENEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_RESPONSE:
	case TraceDqrProfiler::TCODE_RESOURCEFULL:
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
	case TraceDqrProfiler::TCODE_REPEATBRANCH:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION_WS:
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
		break;
	case TraceDqrProfiler::TCODE_UNDEFINED:
		break;
	default:
		break;
	}

	return 0;
}

uint32_t ProfilerNexusMessage::getData()
{
	switch (tcode) {
	case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
		return dataAcquisition.data;
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
		return auxAccessWrite.data;
	case TraceDqrProfiler::TCODE_DEBUG_STATUS:
	case TraceDqrProfiler::TCODE_DEVICE_ID:
	case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_DATA_WRITE:
	case TraceDqrProfiler::TCODE_DATA_READ:
	case TraceDqrProfiler::TCODE_ERROR:
	case TraceDqrProfiler::TCODE_SYNC:
	case TraceDqrProfiler::TCODE_CORRECTION:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
	case TraceDqrProfiler::TCODE_DATA_WRITE_WS:
	case TraceDqrProfiler::TCODE_DATA_READ_WS:
	case TraceDqrProfiler::TCODE_WATCHPOINT:
	case TraceDqrProfiler::TCODE_OUTPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_INPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_AUXACCESS_READ:
	case TraceDqrProfiler::TCODE_AUXACCESS_READNEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITENEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_RESPONSE:
	case TraceDqrProfiler::TCODE_RESOURCEFULL:
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
	case TraceDqrProfiler::TCODE_REPEATBRANCH:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION_WS:
	case TraceDqrProfiler::TCODE_CORRELATION:
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
	case TraceDqrProfiler::TCODE_UNDEFINED:
		break;
	default:
		break;
	}

	return 0;
}

uint32_t ProfilerNexusMessage::getAddr()
{
	switch (tcode) {
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
		return auxAccessWrite.data;
	case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
	case TraceDqrProfiler::TCODE_DEBUG_STATUS:
	case TraceDqrProfiler::TCODE_DEVICE_ID:
	case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_DATA_WRITE:
	case TraceDqrProfiler::TCODE_DATA_READ:
	case TraceDqrProfiler::TCODE_ERROR:
	case TraceDqrProfiler::TCODE_SYNC:
	case TraceDqrProfiler::TCODE_CORRECTION:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
	case TraceDqrProfiler::TCODE_DATA_WRITE_WS:
	case TraceDqrProfiler::TCODE_DATA_READ_WS:
	case TraceDqrProfiler::TCODE_WATCHPOINT:
	case TraceDqrProfiler::TCODE_OUTPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_INPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_AUXACCESS_READ:
	case TraceDqrProfiler::TCODE_AUXACCESS_READNEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITENEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_RESPONSE:
	case TraceDqrProfiler::TCODE_RESOURCEFULL:
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
	case TraceDqrProfiler::TCODE_REPEATBRANCH:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION_WS:
	case TraceDqrProfiler::TCODE_CORRELATION:
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
	case TraceDqrProfiler::TCODE_UNDEFINED:
		break;
	default:
		break;
	}

	return 0;
}

uint32_t ProfilerNexusMessage::getIdTag()
{
	switch (tcode) {
	case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
		return dataAcquisition.idTag;
	case TraceDqrProfiler::TCODE_DEBUG_STATUS:
	case TraceDqrProfiler::TCODE_DEVICE_ID:
	case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_DATA_WRITE:
	case TraceDqrProfiler::TCODE_DATA_READ:
	case TraceDqrProfiler::TCODE_ERROR:
	case TraceDqrProfiler::TCODE_SYNC:
	case TraceDqrProfiler::TCODE_CORRECTION:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
	case TraceDqrProfiler::TCODE_DATA_WRITE_WS:
	case TraceDqrProfiler::TCODE_DATA_READ_WS:
	case TraceDqrProfiler::TCODE_WATCHPOINT:
	case TraceDqrProfiler::TCODE_OUTPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_INPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_AUXACCESS_READ:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
	case TraceDqrProfiler::TCODE_AUXACCESS_READNEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITENEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_RESPONSE:
	case TraceDqrProfiler::TCODE_RESOURCEFULL:
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
	case TraceDqrProfiler::TCODE_REPEATBRANCH:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION_WS:
	case TraceDqrProfiler::TCODE_CORRELATION:
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
	case TraceDqrProfiler::TCODE_UNDEFINED:
		break;
	default:
		break;
	}

	return 0;
}

uint32_t ProfilerNexusMessage::getProcess()
{
	switch (tcode) {
	case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
		return ownership.process;
	case TraceDqrProfiler::TCODE_DEBUG_STATUS:
	case TraceDqrProfiler::TCODE_DEVICE_ID:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_DATA_WRITE:
	case TraceDqrProfiler::TCODE_DATA_READ:
	case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
	case TraceDqrProfiler::TCODE_ERROR:
	case TraceDqrProfiler::TCODE_SYNC:
	case TraceDqrProfiler::TCODE_CORRECTION:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
	case TraceDqrProfiler::TCODE_DATA_WRITE_WS:
	case TraceDqrProfiler::TCODE_DATA_READ_WS:
	case TraceDqrProfiler::TCODE_WATCHPOINT:
	case TraceDqrProfiler::TCODE_OUTPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_INPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_AUXACCESS_READ:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
	case TraceDqrProfiler::TCODE_AUXACCESS_READNEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITENEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_RESPONSE:
	case TraceDqrProfiler::TCODE_RESOURCEFULL:
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
	case TraceDqrProfiler::TCODE_REPEATBRANCH:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION_WS:
	case TraceDqrProfiler::TCODE_CORRELATION:
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
	case TraceDqrProfiler::TCODE_UNDEFINED:
		break;
	default:
		break;
	}

	return 0;
}

uint32_t ProfilerNexusMessage::getRCode()
{
	switch (tcode) {
	case TraceDqrProfiler::TCODE_RESOURCEFULL:
		return resourceFull.rCode;
	case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
	case TraceDqrProfiler::TCODE_DEBUG_STATUS:
	case TraceDqrProfiler::TCODE_DEVICE_ID:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_DATA_WRITE:
	case TraceDqrProfiler::TCODE_DATA_READ:
	case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
	case TraceDqrProfiler::TCODE_ERROR:
	case TraceDqrProfiler::TCODE_SYNC:
	case TraceDqrProfiler::TCODE_CORRECTION:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
	case TraceDqrProfiler::TCODE_DATA_WRITE_WS:
	case TraceDqrProfiler::TCODE_DATA_READ_WS:
	case TraceDqrProfiler::TCODE_WATCHPOINT:
	case TraceDqrProfiler::TCODE_OUTPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_INPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_AUXACCESS_READ:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
	case TraceDqrProfiler::TCODE_AUXACCESS_READNEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITENEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_RESPONSE:
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
	case TraceDqrProfiler::TCODE_REPEATBRANCH:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION_WS:
	case TraceDqrProfiler::TCODE_CORRELATION:
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
	case TraceDqrProfiler::TCODE_UNDEFINED:
		break;
	default:
		break;
	}

	return 0;
}

uint64_t ProfilerNexusMessage::getRData()
{
	switch (tcode) {
	case TraceDqrProfiler::TCODE_RESOURCEFULL:
		switch (resourceFull.rCode) {
		case 0:
			return (uint64_t)resourceFull.i_cnt;
		case 1:
			return resourceFull.history;
		case 8:
			return (uint64_t)resourceFull.notTakenCount;
		case 9:
			return (uint64_t)resourceFull.takenCount;
		default:
			break;
		}
		return 0;
	case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
	case TraceDqrProfiler::TCODE_DEBUG_STATUS:
	case TraceDqrProfiler::TCODE_DEVICE_ID:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_DATA_WRITE:
	case TraceDqrProfiler::TCODE_DATA_READ:
	case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
	case TraceDqrProfiler::TCODE_ERROR:
	case TraceDqrProfiler::TCODE_SYNC:
	case TraceDqrProfiler::TCODE_CORRECTION:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
	case TraceDqrProfiler::TCODE_DATA_WRITE_WS:
	case TraceDqrProfiler::TCODE_DATA_READ_WS:
	case TraceDqrProfiler::TCODE_WATCHPOINT:
	case TraceDqrProfiler::TCODE_OUTPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_INPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_AUXACCESS_READ:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
	case TraceDqrProfiler::TCODE_AUXACCESS_READNEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITENEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_RESPONSE:
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
	case TraceDqrProfiler::TCODE_REPEATBRANCH:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION_WS:
	case TraceDqrProfiler::TCODE_CORRELATION:
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
	case TraceDqrProfiler::TCODE_UNDEFINED:
		break;
	default:
		break;
	}

	return 0;
}

uint64_t ProfilerNexusMessage::getHistory()
{
	switch (tcode) {
	case TraceDqrProfiler::TCODE_RESOURCEFULL:
		if (resourceFull.rCode == 1) {
			return resourceFull.history;
		}
		break;
	case TraceDqrProfiler::TCODE_CORRELATION:
		return correlation.history;
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
		return indirectHistory.history;
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
		return indirectHistoryWS.history;
	case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
	case TraceDqrProfiler::TCODE_DEBUG_STATUS:
	case TraceDqrProfiler::TCODE_DEVICE_ID:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
	case TraceDqrProfiler::TCODE_DATA_WRITE:
	case TraceDqrProfiler::TCODE_DATA_READ:
	case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
	case TraceDqrProfiler::TCODE_ERROR:
	case TraceDqrProfiler::TCODE_SYNC:
	case TraceDqrProfiler::TCODE_CORRECTION:
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
	case TraceDqrProfiler::TCODE_DATA_WRITE_WS:
	case TraceDqrProfiler::TCODE_DATA_READ_WS:
	case TraceDqrProfiler::TCODE_WATCHPOINT:
	case TraceDqrProfiler::TCODE_OUTPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_INPUT_PORTREPLACEMENT:
	case TraceDqrProfiler::TCODE_AUXACCESS_READ:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
	case TraceDqrProfiler::TCODE_AUXACCESS_READNEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITENEXT:
	case TraceDqrProfiler::TCODE_AUXACCESS_RESPONSE:
	case TraceDqrProfiler::TCODE_REPEATBRANCH:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION:
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION_WS:
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
	case TraceDqrProfiler::TCODE_UNDEFINED:
		break;
	default:
		break;
	}

	return 0;
}

bool ProfilerNexusMessage::processITCPrintData(ITCPrint* itcPrint)
{
	bool rc = false;

	// need to only do this once per message! Return true if the message is an itc print or itc perf message
	// and it has been consumed. Otherwise, false

	if (itcPrint != nullptr) {
		switch (tcode) {
		case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
			rc = itcPrint->print(coreId, dataAcquisition.idTag, dataAcquisition.data, time);
			break;
		case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
			rc = itcPrint->print(coreId, auxAccessWrite.addr, auxAccessWrite.data, time);
			break;
		default:
			break;
		}
	}

	return rc;
}

std::string ProfilerNexusMessage::messageToString(int detailLevel)
{
	char dst[512];

	messageToText(dst, sizeof dst, detailLevel);

	return std::string(dst);
}

void  ProfilerNexusMessage::messageToText(char* dst, size_t dst_len, int level)
{
	if ((dst == nullptr) || (dst_len <= 0)) {
		printf("Error: ProfilerNexusMessage::messageToText(): Bad dst pointer\n");
		return;
	}

	const char* sr;
	const char* bt;
	int n;

	// level = 0, itcprint (always process itc print info)
	// level = 1, timestamp + target + itcprint
	// level = 2, message info + timestamp + target + itcprint
	// level = 3, message info + timestamp + target + itcprint + raw trace data

	if (level <= 0) {
		dst[0] = 0;
		return;
	}

	n = snprintf(dst, dst_len, "Msg # %d, ", msgNum);

	if (level >= 3) {
		n += snprintf(dst + n, dst_len - n, "Offset %d, ", offset);

		int i = 0;

		do {
			if (i > 0) {
				n += snprintf(dst + n, dst_len - n, ":%02x", rawData[i]);
			}
			else {
				n += snprintf(dst + n, dst_len - n, "%02x", rawData[i]);
			}
			i += 1;
		} while (((size_t)i < sizeof rawData / sizeof rawData[0]) && ((rawData[i - 1] & 0x3) != TraceDqrProfiler::MSEO_END));
		n += snprintf(dst + n, dst_len - n, ", ");
	}

	if (haveTimestamp) {
		if (ProfilerNexusMessage::targetFrequency != 0) {
			n += snprintf(dst + n, dst_len - n, "time: %0.8f, ", ((double)time) / ProfilerNexusMessage::targetFrequency);
		}
		else {
			n += snprintf(dst + n, dst_len - n, "Tics: %llu, ", time);
		}
	}

	if ((tcode != TraceDqrProfiler::TCODE_INCIRCUITTRACE) && (tcode != TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS)) {
		n += snprintf(dst + n, dst_len - n, "NxtAddr: %08llx, TCode: ", currentAddress);
	}

	switch (tcode) {
	case TraceDqrProfiler::TCODE_DEBUG_STATUS:
		snprintf(dst + n, dst_len - n, "DEBUG STATUS (%d)", tcode);
		break;
	case TraceDqrProfiler::TCODE_DEVICE_ID:
		snprintf(dst + n, dst_len - n, "DEVICE ID (%d)", tcode);
		break;
	case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
		n += snprintf(dst + n, dst_len - n, "OWNERSHIP TRACE (%d)", tcode);

		if (level >= 2) {
			snprintf(dst + n, dst_len - n, " process: %d", ownership.process);
		}
		break;
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
		n += snprintf(dst + n, dst_len - n, "DIRECT BRANCH (%d)", tcode);
		if (level >= 2) {
			snprintf(dst + n, dst_len - n, " I-CNT: %d", directBranch.i_cnt);
		}
		break;
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
		n += snprintf(dst + n, dst_len - n, "INDIRECT BRANCH (%d)", tcode);

		if (level >= 2) {
			switch (indirectBranch.b_type) {
			case TraceDqrProfiler::BTYPE_INDIRECT:
				bt = "Indirect";
				break;
			case TraceDqrProfiler::BTYPE_EXCEPTION:
				bt = "Exception";
				break;
			case TraceDqrProfiler::BTYPE_HARDWARE:
				bt = "Hardware";
				break;
			case TraceDqrProfiler::BTYPE_UNDEFINED:
				bt = "Undefined";
				break;
			default:
				bt = "Bad Branch Type";
				break;
			}

			snprintf(dst + n, dst_len - n, " Branch Type: %s (%d) I-CNT: %d U-ADDR: 0x%08llx ", bt, indirectBranch.b_type, indirectBranch.i_cnt, indirectBranch.u_addr);
		}
		break;
	case TraceDqrProfiler::TCODE_DATA_WRITE:
		snprintf(dst + n, dst_len - n, "DATA WRITE (%d)", tcode);
		break;
	case TraceDqrProfiler::TCODE_DATA_READ:
		snprintf(dst + n, dst_len - n, "DATA READ (%d)", tcode);
		break;
	case TraceDqrProfiler::TCODE_ERROR:
		n += snprintf(dst + n, dst_len - n, "ERROR (%d)", tcode);
		if (level >= 2) {
			snprintf(dst + n, dst_len - n, " Error Type %d", error.etype);
		}
		break;
	case TraceDqrProfiler::TCODE_SYNC:
		n += snprintf(dst + n, dst_len - n, "SYNC (%d)", tcode);

		if (level >= 2) {
			switch (sync.sync) {
			case TraceDqrProfiler::SYNC_EVTI:
				sr = "EVTI";
				break;
			case TraceDqrProfiler::SYNC_EXIT_RESET:
				sr = "Exit Reset";
				break;
			case TraceDqrProfiler::SYNC_T_CNT:
				sr = "T Count";
				break;
			case TraceDqrProfiler::SYNC_EXIT_DEBUG:
				sr = "Exit Debug";
				break;
			case TraceDqrProfiler::SYNC_I_CNT_OVERFLOW:
				sr = "I-Count Overflow";
				break;
			case TraceDqrProfiler::SYNC_TRACE_ENABLE:
				sr = "TraceProfiler Enable";
				break;
			case TraceDqrProfiler::SYNC_WATCHPINT:
				sr = "Watchpoint";
				break;
			case TraceDqrProfiler::SYNC_FIFO_OVERRUN:
				sr = "FIFO Overrun";
				break;
			case TraceDqrProfiler::SYNC_EXIT_POWERDOWN:
				sr = "Exit Powerdown";
				break;
			case TraceDqrProfiler::SYNC_MESSAGE_CONTENTION:
				sr = "Message Contention";
				break;
			case TraceDqrProfiler::SYNC_PC_SAMPLE:
				sr = "PC Sample";
				break;
			case TraceDqrProfiler::SYNC_NONE:
				sr = "None";
				break;
			default:
				sr = "Bad Sync Reason";
				break;
			}

			snprintf(dst + n, dst_len - n, " Reason: (%d) %s I-CNT: %d F-Addr: 0x%08llx", sync.sync, sr, sync.i_cnt, sync.f_addr);
		}
		break;
	case TraceDqrProfiler::TCODE_CORRECTION:
		snprintf(dst + n, dst_len - n, "Correction (%d)", tcode);
		break;
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
		n += snprintf(dst + n, dst_len - n, "DIRECT BRANCH WS (%d)", tcode);

		if (level >= 2) {
			switch (directBranchWS.sync) {
			case TraceDqrProfiler::SYNC_EVTI:
				sr = "EVTI";
				break;
			case TraceDqrProfiler::SYNC_EXIT_RESET:
				sr = "Exit Reset";
				break;
			case TraceDqrProfiler::SYNC_T_CNT:
				sr = "T Count";
				break;
			case TraceDqrProfiler::SYNC_EXIT_DEBUG:
				sr = "Exit Debug";
				break;
			case TraceDqrProfiler::SYNC_I_CNT_OVERFLOW:
				sr = "I-Count Overflow";
				break;
			case TraceDqrProfiler::SYNC_TRACE_ENABLE:
				sr = "TraceProfiler Enable";
				break;
			case TraceDqrProfiler::SYNC_WATCHPINT:
				sr = "Watchpoint";
				break;
			case TraceDqrProfiler::SYNC_FIFO_OVERRUN:
				sr = "FIFO Overrun";
				break;
			case TraceDqrProfiler::SYNC_EXIT_POWERDOWN:
				sr = "Exit Powerdown";
				break;
			case TraceDqrProfiler::SYNC_MESSAGE_CONTENTION:
				sr = "Message Contention";
				break;
			case TraceDqrProfiler::SYNC_PC_SAMPLE:
				sr = "PC Sample";
				break;
			case TraceDqrProfiler::SYNC_NONE:
				sr = "None";
				break;
			default:
				sr = "Bad Sync Reason";
				break;
			}

			snprintf(dst + n, dst_len - n, " Reason: (%d) %s I-CNT: %d F-Addr: 0x%08llx", directBranchWS.sync, sr, directBranchWS.i_cnt, directBranchWS.f_addr);
		}
		break;
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
		n += snprintf(dst + n, dst_len - n, "INDIRECT BRANCH WS (%d)", tcode);

		if (level >= 2) {
			switch (indirectBranchWS.sync) {
			case TraceDqrProfiler::SYNC_EVTI:
				sr = "EVTI";
				break;
			case TraceDqrProfiler::SYNC_EXIT_RESET:
				sr = "Exit Reset";
				break;
			case TraceDqrProfiler::SYNC_T_CNT:
				sr = "T Count";
				break;
			case TraceDqrProfiler::SYNC_EXIT_DEBUG:
				sr = "Exit Debug";
				break;
			case TraceDqrProfiler::SYNC_I_CNT_OVERFLOW:
				sr = "I-Count Overflow";
				break;
			case TraceDqrProfiler::SYNC_TRACE_ENABLE:
				sr = "TraceProfiler Enable";
				break;
			case TraceDqrProfiler::SYNC_WATCHPINT:
				sr = "Watchpoint";
				break;
			case TraceDqrProfiler::SYNC_FIFO_OVERRUN:
				sr = "FIFO Overrun";
				break;
			case TraceDqrProfiler::SYNC_EXIT_POWERDOWN:
				sr = "Exit Powerdown";
				break;
			case TraceDqrProfiler::SYNC_MESSAGE_CONTENTION:
				sr = "Message Contention";
				break;
			case TraceDqrProfiler::SYNC_PC_SAMPLE:
				sr = "PC Sample";
				break;
			case TraceDqrProfiler::SYNC_NONE:
				sr = "None";
				break;
			default:
				sr = "Bad Sync Reason";
				break;
			}

			switch (indirectBranchWS.b_type) {
			case TraceDqrProfiler::BTYPE_INDIRECT:
				bt = "Indirect";
				break;
			case TraceDqrProfiler::BTYPE_EXCEPTION:
				bt = "Exception";
				break;
			case TraceDqrProfiler::BTYPE_HARDWARE:
				bt = "Hardware";
				break;
			case TraceDqrProfiler::BTYPE_UNDEFINED:
				bt = "Undefined";
				break;
			default:
				bt = "Bad Branch Type";
				break;
			}

			snprintf(dst + n, dst_len - n, " Reason: (%d) %s Branch Type %s (%d) I-CNT: %d F-Addr: 0x%08llx", indirectBranchWS.sync, sr, bt, indirectBranchWS.b_type, indirectBranchWS.i_cnt, indirectBranchWS.f_addr);
		}
		break;
	case TraceDqrProfiler::TCODE_DATA_WRITE_WS:
		snprintf(dst + n, dst_len - n, "DATA WRITE WS (%d)", tcode);
		break;
	case TraceDqrProfiler::TCODE_DATA_READ_WS:
		snprintf(dst + n, dst_len - n, "DATA READ WS (%d)", tcode);
		break;
	case TraceDqrProfiler::TCODE_WATCHPOINT:
		snprintf(dst + n, dst_len - n, "TCode: WATCHPOINT (%d)", tcode);
		break;
	case TraceDqrProfiler::TCODE_OUTPUT_PORTREPLACEMENT:
		snprintf(dst + n, dst_len - n, "OUTPUT PORT REPLACEMENT (%d)", tcode);
		break;
	case TraceDqrProfiler::TCODE_INPUT_PORTREPLACEMENT:
		snprintf(dst + n, dst_len - n, "INPUT PORT REPLACEMENT (%d)", tcode);
		break;
	case TraceDqrProfiler::TCODE_AUXACCESS_READ:
		snprintf(dst + n, dst_len - n, "AUX ACCESS READ (%d)", tcode);
		break;
	case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
		n += snprintf(dst + n, dst_len - n, "DATA ACQUISITION (%d)", tcode);

		if (level >= 2) { // here, if addr not on word boudry, have a partial write!
			switch (dataAcquisition.idTag & 0x03) {
			case 0:
			case 1:
				snprintf(dst + n, dst_len - n, " idTag: 0x%08x Data: 0x%08x", dataAcquisition.idTag, dataAcquisition.data);
				break;
			case 2:
				snprintf(dst + n, dst_len - n, " idTag: 0x%08x Data: 0x%04x", dataAcquisition.idTag, (uint16_t)dataAcquisition.data);
				break;
			case 3:
				snprintf(dst + n, dst_len - n, " idTag: 0x%08x Data: 0x%02x", dataAcquisition.idTag, (uint8_t)dataAcquisition.data);
				break;
			}
		}
		break;
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
		n += snprintf(dst + n, dst_len - n, "AUX ACCESS WRITE (%d)", tcode);

		if (level >= 2) { // here, if addr not on word boudry, have a partial write!
			switch (auxAccessWrite.addr & 0x03) {
			case 0:
			case 1:
				snprintf(dst + n, dst_len - n, " Addr: 0x%08x Data: 0x%08x", auxAccessWrite.addr, auxAccessWrite.data);
				break;
			case 2:
				snprintf(dst + n, dst_len - n, " Addr: 0x%08x Data: 0x%04x", auxAccessWrite.addr, (uint16_t)auxAccessWrite.data);
				break;
			case 3:
				snprintf(dst + n, dst_len - n, " Addr: 0x%08x Data: 0x%02x", auxAccessWrite.addr, (uint8_t)auxAccessWrite.data);
				break;
			}
		}
		break;
	case TraceDqrProfiler::TCODE_AUXACCESS_READNEXT:
		snprintf(dst + n, dst_len - n, "AUX ACCESS READNEXT (%d)", tcode);
		break;
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITENEXT:
		snprintf(dst + n, dst_len - n, "AUX ACCESS WRITENEXT (%d)", tcode);
		break;
	case TraceDqrProfiler::TCODE_AUXACCESS_RESPONSE:
		snprintf(dst + n, dst_len - n, "AUXACCESS RESPOINSE (%d)", tcode);
		break;
	case TraceDqrProfiler::TCODE_RESOURCEFULL:
		n += snprintf(dst + n, dst_len - n, "RESOURCE FULL (%d)", tcode);

		if (level >= 2) { // here, if addr not on word boudry, have a partial write!
			n += snprintf(dst + n, dst_len - n, " RCode: %d", resourceFull.rCode);

			switch (resourceFull.rCode) {
			case 0:
				snprintf(dst + n, dst_len - n, " I-CNT: %d", resourceFull.i_cnt);
				break;
			case 1:
				snprintf(dst + n, dst_len - n, " History: 0x%08llx", resourceFull.history);
				break;
			case 8:
				snprintf(dst + n, dst_len - n, " Not Taken Count: %u", resourceFull.notTakenCount);
				break;
			case 9:
				snprintf(dst + n, dst_len - n, " Taken Count: %u", resourceFull.takenCount);
				break;
			default:
				snprintf(dst + n, dst_len - n, " Invalid rCode");
				break;
			}
		}
		break;
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
		n += snprintf(dst + n, dst_len - n, "INDIRECT BRANCH HISTORY (%d)", tcode);

		if (level >= 2) {
			switch (indirectHistory.b_type) {
			case TraceDqrProfiler::BTYPE_INDIRECT:
				bt = "Indirect";
				break;
			case TraceDqrProfiler::BTYPE_EXCEPTION:
				bt = "Exception";
				break;
			case TraceDqrProfiler::BTYPE_HARDWARE:
				bt = "Hardware";
				break;
			case TraceDqrProfiler::BTYPE_UNDEFINED:
				bt = "Undefined";
				break;
			default:
				bt = "Bad Branch Type";
				break;
			}

			snprintf(dst + n, dst_len - n, " Branch Type: %s (%d) I-CNT: %d U-ADDR: 0x%08llx History: 0x%08llx", bt, indirectHistory.b_type, indirectHistory.i_cnt, indirectHistory.u_addr, indirectHistory.history);
		}
		break;
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
		n += snprintf(dst + n, dst_len - n, "INDIRECT BRANCH HISTORY WS (%d)", tcode);

		if (level >= 2) {
			switch (indirectHistoryWS.sync) {
			case TraceDqrProfiler::SYNC_EVTI:
				sr = "EVTI";
				break;
			case TraceDqrProfiler::SYNC_EXIT_RESET:
				sr = "Exit Reset";
				break;
			case TraceDqrProfiler::SYNC_T_CNT:
				sr = "T Count";
				break;
			case TraceDqrProfiler::SYNC_EXIT_DEBUG:
				sr = "Exit Debug";
				break;
			case TraceDqrProfiler::SYNC_I_CNT_OVERFLOW:
				sr = "I-Count Overflow";
				break;
			case TraceDqrProfiler::SYNC_TRACE_ENABLE:
				sr = "TraceProfiler Enable";
				break;
			case TraceDqrProfiler::SYNC_WATCHPINT:
				sr = "Watchpoint";
				break;
			case TraceDqrProfiler::SYNC_FIFO_OVERRUN:
				sr = "FIFO Overrun";
				break;
			case TraceDqrProfiler::SYNC_EXIT_POWERDOWN:
				sr = "Exit Powerdown";
				break;
			case TraceDqrProfiler::SYNC_MESSAGE_CONTENTION:
				sr = "Message Contention";
				break;
			case TraceDqrProfiler::SYNC_PC_SAMPLE:
				sr = "PC Sample";
				break;
			case TraceDqrProfiler::SYNC_NONE:
				sr = "None";
				break;
			default:
				sr = "Bad Sync Reason";
				break;
			}

			switch (indirectHistoryWS.b_type) {
			case TraceDqrProfiler::BTYPE_INDIRECT:
				bt = "Indirect";
				break;
			case TraceDqrProfiler::BTYPE_EXCEPTION:
				bt = "Exception";
				break;
			case TraceDqrProfiler::BTYPE_HARDWARE:
				bt = "Hardware";
				break;
			case TraceDqrProfiler::BTYPE_UNDEFINED:
				bt = "Undefined";
				break;
			default:
				bt = "Bad Branch Type";
				break;
			}

			snprintf(dst + n, dst_len - n, " Reason: (%d) %s Branch Type %s (%d) I-CNT: %d F-Addr: 0x%08llx History: 0x%08llx", indirectHistoryWS.sync, sr, bt, indirectHistoryWS.b_type, indirectHistoryWS.i_cnt, indirectHistoryWS.f_addr, indirectHistoryWS.history);
		}
		break;
	case TraceDqrProfiler::TCODE_REPEATBRANCH:
		snprintf(dst + n, dst_len - n, "REPEAT BRANCH (%d)", tcode);
		break;
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION:
		snprintf(dst + n, dst_len - n, "REPEAT INSTRUCTION (%d)", tcode);
		break;
	case TraceDqrProfiler::TCODE_REPEATINSTRUCTION_WS:
		snprintf(dst + n, dst_len - n, "REPEAT INSTRUCTIN WS (%d)", tcode);
		break;
	case TraceDqrProfiler::TCODE_CORRELATION:
		n += snprintf(dst + n, dst_len - n, "CORRELATION (%d)", tcode);

		if (level >= 2) {
			n += snprintf(dst + n, dst_len - n, " EVCODE: %d CDF: %d I-CNT: %d", correlation.evcode, correlation.cdf, correlation.i_cnt);
			if (correlation.cdf > 0) {
				snprintf(dst + n, dst_len - n, " History: 0x%08llx", correlation.history);
			}
		}
		break;
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
		if ((ict.cksrc == TraceDqrProfiler::ICT_CONTROL) && (ict.ckdf == 0)) {
			n += snprintf(dst + n, dst_len - n, "TCode: INCIRCUITTRACE (%d)", tcode);
		}
		else {
			n += snprintf(dst + n, dst_len - n, "Address: %08llx TCode: INCIRCUITTRACE (%d)", currentAddress, tcode);
		}

		if (level >= 2) {
			switch (ict.cksrc) {
			case TraceDqrProfiler::ICT_EXT_TRIG:
				if (ict.ckdf == 0) {
					snprintf(dst + n, dst_len - n, " ICT Reason: External Trigger (%d) U-ADDR: 0x%08llx", ict.cksrc, ict.ckdata[0]);
				}
				else if (ict.ckdf == 1) {
					snprintf(dst + n, dst_len - n, " ICT Reason: External Trigger + ID (%d) Trigger ID %d U-ADDR: 0x%08llx", ict.cksrc, (int)ict.ckdata[1], ict.ckdata[0]);
				}
				else {
					printf("Error: messageToText(): ICT_EXTERNAL_TRIG: invalid ict.ckdf value: %d\n", ict.ckdf);
					snprintf(dst + n, dst_len - n, " Error: messageToText(): ICT_EXTERNAL_TRIG: invalid ict.ckdf value: %d", ict.ckdf);
				}
				break;
			case TraceDqrProfiler::ICT_WATCHPOINT:
				if (ict.ckdf == 0) {
					snprintf(dst + n, dst_len - n, " ICT Reason: Watchpoint (%d) U-ADDR: 0x%08llx", ict.cksrc, ict.ckdata[0]);
				}
				else if (ict.ckdf == 1) {
					snprintf(dst + n, dst_len - n, " ICT Reason: Watchpoint + ID (%d) Trigger ID %d U-ADDR: 0x%08llx", ict.cksrc, (int)ict.ckdata[1], ict.ckdata[0]);
				}
				else {
					printf("Error: messageToText(): ICT_WATCHPOINT: invalid ict.ckdf value: %d\n", ict.ckdf);
					snprintf(dst + n, dst_len - n, " Error: messageToText(): ICT_WATCHPOINT: invalid ict.ckdf value: %d", ict.ckdf);
				}
				break;
			case TraceDqrProfiler::ICT_INFERABLECALL:
				if (ict.ckdf == 0) {
					snprintf(dst + n, dst_len - n, " ICT Reason: Inferable Call (%d) U-ADDR: 0x%08llx", ict.cksrc, ict.ckdata[0]);
				}
				else if (ict.ckdf == 1) {
					snprintf(dst + n, dst_len - n, " ICT Reason: Call/Return (%d) U-ADDR: 0x%08llx PCdest 0x%08llx", ict.cksrc, ict.ckdata[0], currentAddress ^ (ict.ckdata[1] << 1));
				}
				else {
					printf("Error: messageToText(): ICT_INFERABLECALL: invalid ict.ckdf value: %d\n", ict.ckdf);
					snprintf(dst + n, dst_len - n, " Error: messageToText(): ICT_INFERABLECALL: invalid ict.ckdf value: %d", ict.ckdf);
				}
				break;
			case TraceDqrProfiler::ICT_EXCEPTION:
				snprintf(dst + n, dst_len - n, " ICT Reason: Exception (%d) Cause %d U-ADDR: 0x%08llx", ict.cksrc, (int)ict.ckdata[1], ict.ckdata[0]);
				break;
			case TraceDqrProfiler::ICT_INTERRUPT:
				snprintf(dst + n, dst_len - n, " ICT Reason: Interrupt (%d) Cause %d U-ADDR: 0x%08llx", ict.cksrc, (int)ict.ckdata[1], ict.ckdata[0]);
				break;
			case TraceDqrProfiler::ICT_CONTEXT:
				snprintf(dst + n, dst_len - n, " ICT Reason: Context (%d) Context %d U-ADDR: 0x%08llx", ict.cksrc, (int)ict.ckdata[1], ict.ckdata[0]);
				break;
			case TraceDqrProfiler::ICT_PC_SAMPLE:
				snprintf(dst + n, dst_len - n, " ICT Reason: Periodic (%d) U-ADDR: 0x%08llx", ict.cksrc, ict.ckdata[0]);
				break;
			case TraceDqrProfiler::ICT_CONTROL:
				if (ict.ckdf == 0) {
					snprintf(dst + n, dst_len - n, " ICT Reason: Control (%d) Control %d", ict.cksrc, (int)ict.ckdata[0]);
				}
				else if (ict.ckdf == 1) {
					snprintf(dst + n, dst_len - n, " ICT Reason: Control (%d) Control %d U-ADDR: 0x%08llx", ict.cksrc, (int)ict.ckdata[1], ict.ckdata[0]);
				}
				else {
					printf("Error: messageToText(): ICT_CONTROL: invalid ict.ckdf value: %d\n", ict.ckdf);
					snprintf(dst + n, dst_len - n, " Error: messageToText(): ICT_CONTROL: invalid ict.ckdf value: %d", ict.ckdf);
				}
				break;
			default:
				printf("Error: messageToText(): Invalid ICT Event: %d\n", ict.cksrc);
				snprintf(dst + n, dst_len - n, " Error: messageToText(): Invalid ICT Event: %d", ict.cksrc);
				break;
			}
		}
		break;
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS:
		if ((ictWS.cksrc == TraceDqrProfiler::ICT_CONTROL) && (ictWS.ckdf == 0)) {
			n += snprintf(dst + n, dst_len - n, "TCode: INCIRCUITTRACE WS (%d)", tcode);
		}
		else {
			n += snprintf(dst + n, dst_len - n, "Address: %08llx TCode: INCIRCUITTRACE WS (%d)", currentAddress, tcode);
		}

		if (level >= 2) {
			switch (ictWS.cksrc) {
			case TraceDqrProfiler::ICT_EXT_TRIG:
				if (ictWS.ckdf == 0) {
					snprintf(dst + n, dst_len - n, " ICT Reason: External Trigger (%d) F-ADDR: 0x%08llx", ictWS.cksrc, ictWS.ckdata[0]);
				}
				else if (ictWS.ckdf == 1) {
					snprintf(dst + n, dst_len - n, " ICT Reason: External Trigger + ID (%d) Trigger ID %d F-ADDR: 0x%08llx", ictWS.cksrc, (int)ictWS.ckdata[1], ictWS.ckdata[0]);
				}
				else {
					printf("Error: messageToText(): ICT_EXTERNAL_TRIG: invalid ictWS.ckdf value: %d\n", ictWS.ckdf);
					snprintf(dst + n, dst_len - n, " Error: messageToText(): ICT_EXTERNAL_TRIG: invalid ictWS.ckdf value: %d", ictWS.ckdf);
				}
				break;
			case TraceDqrProfiler::ICT_WATCHPOINT:
				if (ictWS.ckdf == 0) {
					snprintf(dst + n, dst_len - n, " ICT Reason: Watchpoint (%d) U-ADDR: 0x%08llx", ictWS.cksrc, ictWS.ckdata[0]);
				}
				else if (ictWS.ckdf == 1) {
					snprintf(dst + n, dst_len - n, " ICT Reason: Watchpoint + ID (%d) Trigger ID %d F-ADDR: 0x%08llx", ictWS.cksrc, (int)ictWS.ckdata[1], ictWS.ckdata[0]);
				}
				else {
					printf("Error: messageToText(): ICT_WATCHPOINT: invalid ictWS.ckdf value: %d\n", ictWS.ckdf);
					snprintf(dst + n, dst_len - n, " Error: messageToText(): ICT_WATCHPOINT: invalid ictWS.ckdf value: %d", ictWS.ckdf);
				}
				break;
			case TraceDqrProfiler::ICT_INFERABLECALL:
				if (ictWS.ckdf == 0) {
					snprintf(dst + n, dst_len - n, " ICT Reason: Inferable Call (%d) F-ADDR: 0x%08llx", ictWS.cksrc, ictWS.ckdata[0]);
				}
				else if (ictWS.ckdf == 1) {
					snprintf(dst + n, dst_len - n, " ICT Reason: Call/Return (%d) F-ADDR: 0x%08llx PCdest 0x%08llx", ictWS.cksrc, ictWS.ckdata[0], currentAddress ^ (ictWS.ckdata[1] << 1));
				}
				else {
					printf("Error: messageToText(): ICT_INFERABLECALL: invalid ictWS.ckdf value: %d\n", ictWS.ckdf);
					snprintf(dst + n, dst_len - n, " Error: messageToText(): ICT_INFERABLECALL: invalid ictWS.ckdf value: %d", ictWS.ckdf);
				}
				break;
			case TraceDqrProfiler::ICT_EXCEPTION:
				snprintf(dst + n, dst_len - n, " ICT Reason: Exception (%d) Cause %d F-ADDR: 0x%08llx", ictWS.cksrc, (int)ictWS.ckdata[1], ictWS.ckdata[0]);
				break;
			case TraceDqrProfiler::ICT_INTERRUPT:
				snprintf(dst + n, dst_len - n, " ICT Reason: Interrupt (%d) Cause %d F-ADDR: 0x%08llx", ictWS.cksrc, (int)ictWS.ckdata[1], ictWS.ckdata[0]);
				break;
			case TraceDqrProfiler::ICT_CONTEXT:
				snprintf(dst + n, dst_len - n, " ICT Reason: Context (%d) Context %d F-ADDR: 0x%08llx", ictWS.cksrc, (int)ictWS.ckdata[1], ictWS.ckdata[0]);
				break;
			case TraceDqrProfiler::ICT_PC_SAMPLE:
				snprintf(dst + n, dst_len - n, " ICT Reason: Periodic (%d) F-ADDR: 0x%08llx", ictWS.cksrc, ictWS.ckdata[0]);
				break;
			case TraceDqrProfiler::ICT_CONTROL:
				if (ictWS.ckdf == 0) {
					snprintf(dst + n, dst_len - n, " ICT Reason: Control (%d) Control %d", ictWS.cksrc, (int)ictWS.ckdata[0]);
				}
				else if (ictWS.ckdf == 1) {
					snprintf(dst + n, dst_len - n, " ICT Reason: Control (%d) Control %d F-ADDR: 0x%08llx", ictWS.cksrc, (int)ictWS.ckdata[1], ictWS.ckdata[0]);
				}
				else {
					printf("Error: messageToText(): ICT_CONTROL: invalid ictWS.ckdf value: %d\n", ictWS.ckdf);
					snprintf(dst + n, dst_len - n, " Error: messageToText(): ICT_CONTROL: invalid ictWS.ckdf value: %d", ictWS.ckdf);
				}
				break;
			default:
				printf("Error: messageToText(): Invalid ICT Event: %d\n", ictWS.cksrc);
				snprintf(dst + n, dst_len - n, " Error: messageToText(): Invalid ICT Event: %d", ictWS.cksrc);
				break;
			}
		}
		break;
	case TraceDqrProfiler::TCODE_UNDEFINED:
		snprintf(dst + n, dst_len - n, "UNDEFINED (%d)", tcode);
		break;
	default:
		snprintf(dst + n, dst_len - n, "BAD TCODE (%d)", tcode);
		break;
	}
}

double ProfilerNexusMessage::seconds()
{
	if (haveTimestamp == false) {
		return 0.0;
	}

	if (targetFrequency != 0) {
		return ((double)time) / targetFrequency;
	}

	return (double)time;
}

void ProfilerNexusMessage::dumpRawMessage()
{
	int i;

	printf("Raw Message # %d: ", msgNum);

	for (i = 0; ((size_t)i < sizeof rawData / sizeof rawData[0]) && ((rawData[i] & 0x03) != TraceDqrProfiler::MSEO_END); i++) {
		printf("%02x ", rawData[i]);
	}

	if ((size_t)i < sizeof rawData / sizeof rawData[0]) {
		printf("%02x\n", rawData[i]);
	}
	else {
		printf("no end of message\n");
	}
}

void ProfilerNexusMessage::dump()
{
	switch (tcode) {
	case TraceDqrProfiler::TCODE_DEBUG_STATUS:
		std::cout << "unsupported debug status trace message\n";
		break;
	case TraceDqrProfiler::TCODE_DEVICE_ID:
		std::cout << "unsupported device id trace message\n";
		break;
	case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
		std::cout << "  # TraceProfiler Message(" << msgNum << "): Ownership, process=" << ownership.process << std::endl; // << ", TS=0x" << hex << timestamp << dec; // << endl;
		break;
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
		//		cout << "(" << traceNum << ") ";
		//		cout << "  | Direct Branch | TYPE=DBM, ICNT=" << i_cnt << ", TS=0x" << hex << timestamp << dec; // << endl;
		std::cout << "  # TraceProfiler Message(" << msgNum << "): Direct Branch, ICNT=" << directBranch.i_cnt << std::endl; // << ", TS=0x" << hex << timestamp << dec; // << endl;
		break;
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
		//		cout << "(" << traceNum << ") ";
		//		cout << "  | Indirect Branch | TYPE=IBM, BTYPE=" << b_type << ", ICNT=" << i_cnt << ", UADDR=0x" << hex << u_addr << ", TS=0x" << timestamp << dec;// << endl;
		std::cout << "  # TraceProfiler Message(" << msgNum << "): Indirect Branch, BTYPE=" << indirectBranch.b_type << ", ICNT=" << indirectBranch.i_cnt << ", UADDR=0x" << std::hex << indirectBranch.u_addr << std::dec << std::endl; // << ", TS=0x" << timestamp << dec;// << endl;
		break;
	case TraceDqrProfiler::TCODE_RESOURCEFULL:
		switch (resourceFull.rCode) {
		case 0:
			std::cout << "  # TraceProfiler Message(" << msgNum << "): Resource Full, rCode=" << resourceFull.rCode << ", ICNT=" << resourceFull.i_cnt << std::endl; // << ", TS=0x" << timestamp << dec;// << endl;
			break;
		case 1:
			std::cout << "  # TraceProfiler Message(" << msgNum << "): Resource Full, rCode=" << resourceFull.rCode << ", History=0x" << std::hex << resourceFull.history << std::dec << std::endl; // << ", TS=0x" << timestamp << dec;// << endl;
			break;
		case 8:
			std::cout << "  # TraceProfiler Message(" << msgNum << "): Resource Full, rCode=" << resourceFull.rCode << ", Not taken=" << resourceFull.notTakenCount << std::endl; // << ", TS=0x" << timestamp << dec;// << endl;
			break;
		case 9:
			std::cout << "  # TraceProfiler Message(" << msgNum << "): Resource Full, rCode=" << resourceFull.rCode << ", Taken=" << resourceFull.takenCount << std::endl; // << ", TS=0x" << timestamp << dec;// << endl;
			break;
		default:
			std::cout << "  # TraceProfiler Message(" << msgNum << "): Resource Full, Invalid or unsupported rCode for reourceFull TCODE" << std::endl;
			break;
		}
		break;
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
		std::cout << "  # TraceProfiler Message(" << msgNum << "): Indirect Branch History, ICNT=" << indirectHistory.i_cnt << ", BTYPE=" << indirectHistory.b_type << ", UADDR=0x" << std::hex << indirectHistory.u_addr << std::dec << ", history=0x" << std::hex << indirectHistory.history << std::dec << std::endl;
		break;
		//	case TCODE_INDIRECTBRANCHHISTORY_WS:
		//	case TCODE_CORRELATION:
		//	case TCODE_INCIRCUITTRACE:
		//	case TCODE_INCIRCUITTRACE_WS:
		//		break;
	case TraceDqrProfiler::TCODE_DATA_WRITE:
		std::cout << "unsupported data write trace message\n";
		break;
	case TraceDqrProfiler::TCODE_DATA_READ:
		std::cout << "unsupported data read trace message\n";
		break;
	case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
		std::cout << "unsupported data acquisition trace message\n";
		break;
	case TraceDqrProfiler::TCODE_ERROR:
		std::cout << "  # TraceProfiler Message(" << msgNum << "): Error, ETYPE=" << (uint32_t)error.etype << std::endl; // << ", TS=0x" << timestamp << dec;// << endl;
		break;
	case TraceDqrProfiler::TCODE_SYNC:
		//		cout << "(" << traceNum << "," << syncNum << ") ";
		//		cout << "  | Sync | TYPE=SYNC, SYNC=" << sync << ", ICNT=" << i_cnt << ", FADDR=0x" << hex << f_addr << ", TS=0x" << timestamp << dec;// << endl;
		std::cout << "  # TraceProfiler Message(" << msgNum << "): Sync, SYNCREASON=" << sync.sync << ", ICNT=" << sync.i_cnt << ", FADDR=0x" << std::hex << sync.f_addr << std::dec << std::endl; // << ", TS=0x" << timestamp << dec;// << endl;
		break;
	case TraceDqrProfiler::TCODE_CORRECTION:
		std::cout << "unsupported correction trace message\n";
		break;
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
		//		cout << "(" << traceNum << "," << syncNum << ") ";
		//		cout << "  | Direct Branch With Sync | TYPE=DBWS, SYNC=" << sync << ", ICNT=" << i_cnt << ", FADDR=0x" << hex << f_addr << ", TS=0x" << timestamp << dec;// << endl;
		std::cout << "  # TraceProfiler Message(" << msgNum << "): Direct Branch With Sync, SYNCTYPE=" << directBranchWS.sync << ", ICNT=" << directBranchWS.i_cnt << ", FADDR=0x" << std::hex << directBranchWS.f_addr << std::dec << std::endl; // << ", TS=0x" << timestamp << dec;// << endl;
		break;
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
		//		cout << "(" << traceNum << "," << syncNum << ") ";
		//		cout << "  | Indirect Branch With Sync | TYPE=IBWS, SYNC=" << sync << ", BTYPE=" << b_type << ", ICNT=" << i_cnt << ", FADDR=0x" << hex << f_addr << ", TS=0x" << timestamp << dec;// << endl;
		std::cout << "  # TraceProfiler Message(" << msgNum << "): Indirect Branch With sync, SYNCTYPE=" << indirectBranchWS.sync << ", BTYPE=" << indirectBranchWS.b_type << ", ICNT=" << indirectBranchWS.i_cnt << ", FADDR=0x" << std::hex << indirectBranchWS.f_addr << std::dec << std::endl; // << ", TS=0x" << timestamp << dec;// << endl;
		break;
	case TraceDqrProfiler::TCODE_DATA_WRITE_WS:
		std::cout << "unsupported data write with sync trace message\n";
		break;
	case TraceDqrProfiler::TCODE_DATA_READ_WS:
		std::cout << "unsupported data read with sync trace message\n";
		break;
	case TraceDqrProfiler::TCODE_WATCHPOINT:
		std::cout << "unsupported watchpoint trace message\n";
		break;
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
		std::cout << "  # TraceProfiler Message(" << msgNum << "): Auxillary Access Write, address=" << std::hex << auxAccessWrite.addr << std::dec << ", data=" << std::hex << auxAccessWrite.data << std::dec << std::endl; // << ", TS=0x" << hex << timestamp << dec; // << endl;
		break;
	case TraceDqrProfiler::TCODE_CORRELATION:
		std::cout << "  # TraceProfiler Message(" << msgNum << "): Correlation, EVCODE=" << (uint32_t)correlation.evcode << ", CDF=" << (int)correlation.cdf << ", ICNT=" << correlation.i_cnt << "\n"; // << ", TS=0x" << timestamp << dec;// << endl;
		break;
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
		switch (ict.cksrc) {
		case TraceDqrProfiler::ICT_EXT_TRIG:
			std::cout << "  # TraceProfiler Message(" << msgNum << "): In Circuit TraceProfiler External Trigger, cksrc=" << ict.cksrc << ", ckdf=" << (int)ict.ckdf << ", PC=0x" << std::hex << ict.ckdata[0] << std::dec;
			if (ict.ckdf > 0) {
				std::cout << ", ID=" << ict.ckdata[1];
			}
			std::cout << std::endl;
			break;
		case TraceDqrProfiler::ICT_CONTROL:
			std::cout << "  # TraceProfiler Message(" << msgNum << "): In Circuit TraceProfiler Control, cksrc=" << ict.cksrc << ", ckdf=" << (int)ict.ckdf;
			if (ict.ckdf > 0) {
				std::cout << ", PC=0x" << std::hex << ict.ckdata[0] << std::dec << ", Control=" << ict.ckdata[1] << std::endl;
			}
			else {
				std::cout << ", Control=" << ict.ckdata[0] << std::endl;
			}
			break;
		case TraceDqrProfiler::ICT_INFERABLECALL:
			std::cout << "  # TraceProfiler Message(" << msgNum << "): In Circuit TraceProfiler Call/Return, cksrc=" << ict.cksrc << ", ckdf=" << (int)ict.ckdf << ", PC=0x" << std::hex << ict.ckdata[0] << std::dec;
			if (ict.ckdf > 0) {
				std::cout << ", PCDest=0x" << std::hex << ict.ckdata[1] << std::dec;
			}
			std::cout << std::endl;
			break;
		case TraceDqrProfiler::ICT_EXCEPTION:
			std::cout << "  # TraceProfiler Message(" << msgNum << "): In Circuit TraceProfiler Exception, cksrc=" << ict.cksrc << ", ckdf=" << (int)ict.ckdf << ", PC=0x" << std::hex << ict.ckdata[0] << std::dec << ", Cause=" << ict.ckdata[1] << std::endl;
			break;
		case TraceDqrProfiler::ICT_INTERRUPT:
			std::cout << "  # TraceProfiler Message(" << msgNum << "): In Circuit TraceProfiler Interrupt, cksrc=" << ict.cksrc << ", ckdf=" << (int)ict.ckdf << ", PC=0x" << std::hex << ict.ckdata[0] << std::dec << ", Cause=" << ict.ckdata[1] << std::endl;
			break;
		case TraceDqrProfiler::ICT_CONTEXT:
			std::cout << "  # TraceProfiler Message(" << msgNum << "): In Circuit TraceProfiler Context, cksrc=" << ict.cksrc << ", ckdf=" << (int)ict.ckdf << ", PC=0x" << std::hex << ict.ckdata[0] << std::dec << ", Context=0x" << std::hex << ict.ckdata[1] << std::dec << std::endl;
			break;
		case TraceDqrProfiler::ICT_WATCHPOINT:
			std::cout << "  # TraceProfiler Message(" << msgNum << "): In Circuit TraceProfiler Watchpoint, cksrc=" << ict.cksrc << ", ckdf=" << (int)ict.ckdf << ", PC=0x" << std::hex << ict.ckdata[0] << std::dec;
			if (ict.ckdf > 0) {
				std::cout << ", ID=" << ict.ckdata[1];
			}
			std::cout << std::endl;
			break;
		case TraceDqrProfiler::ICT_PC_SAMPLE:
			std::cout << "  # TraceProfiler Message(" << msgNum << "): In Circuit TraceProfiler PC Sample, cksrc=" << ict.cksrc << ", ckdf=" << (int)ict.ckdf << ", PC=0x" << std::hex << ict.ckdata[0] << std::dec << std::endl;
			break;
		case TraceDqrProfiler::ICT_NONE:
			break;
		}
		break;
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS:
		switch (ictWS.cksrc) {
		case TraceDqrProfiler::ICT_EXT_TRIG:
			std::cout << "  # TraceProfiler Message(" << msgNum << "): In Circuit TraceProfiler WS External Trigger, cksrc=" << ictWS.cksrc << ", ckdf=" << (int)ictWS.ckdf << ", PC=0x" << std::hex << ictWS.ckdata[0] << std::dec;
			if (ictWS.ckdf > 0) {
				std::cout << ", ID=" << ictWS.ckdata[1];
			}
			std::cout << std::endl;
			break;
		case TraceDqrProfiler::ICT_CONTROL:
			std::cout << "  # TraceProfiler Message(" << msgNum << "): In Circuit TraceProfiler WS Control, cksrc=" << ictWS.cksrc << ", ckdf=" << (int)ictWS.ckdf;
			if (ictWS.ckdf > 0) {
				std::cout << ", PC=0x" << std::hex << ictWS.ckdata[0] << std::dec << ", Control=" << ictWS.ckdata[1] << std::endl;
			}
			else {
				std::cout << ", Control=" << ictWS.ckdata[0] << std::endl;
			}
			break;
		case TraceDqrProfiler::ICT_INFERABLECALL:
			std::cout << "  # TraceProfiler Message(" << msgNum << "): In Circuit TraceProfiler WS Call/Return, cksrc=" << ictWS.cksrc << ", ckdf=" << (int)ictWS.ckdf << ", PC=0x" << std::hex << ictWS.ckdata[0] << std::dec;
			if (ictWS.ckdf > 0) {
				std::cout << ", PCDest=0x" << std::hex << ictWS.ckdata[1] << std::dec;
			}
			std::cout << std::endl;
			break;
		case TraceDqrProfiler::ICT_EXCEPTION:
			std::cout << "  # TraceProfiler Message(" << msgNum << "): In Circuit TraceProfiler WS Exception, cksrc=" << ictWS.cksrc << ", ckdf=" << (int)ictWS.ckdf << ", PC=0x" << std::hex << ictWS.ckdata[0] << std::dec << ", Cause=" << ictWS.ckdata[1] << std::endl;
			break;
		case TraceDqrProfiler::ICT_INTERRUPT:
			std::cout << "  # TraceProfiler Message(" << msgNum << "): In Circuit TraceProfiler WS Interrupt, cksrc=" << ictWS.cksrc << ", ckdf=" << (int)ictWS.ckdf << ", PC=0x" << std::hex << ictWS.ckdata[0] << std::dec << ", Cause=" << ictWS.ckdata[1] << std::endl;
			break;
		case TraceDqrProfiler::ICT_CONTEXT:
			std::cout << "  # TraceProfiler Message(" << msgNum << "): In Circuit TraceProfiler WS Context, cksrc=" << ictWS.cksrc << ", ckdf=" << (int)ictWS.ckdf << ", PC=0x" << std::hex << ictWS.ckdata[0] << std::dec << ", Context=0x" << std::hex << ictWS.ckdata[1] << std::dec << std::endl;
			break;
		case TraceDqrProfiler::ICT_WATCHPOINT:
			std::cout << "  # TraceProfiler Message(" << msgNum << "): In Circuit TraceProfiler WS Watchpoint, cksrc=" << ictWS.cksrc << ", ckdf=" << (int)ictWS.ckdf << ", PC=0x" << std::hex << ictWS.ckdata[0] << std::dec;
			if (ictWS.ckdf > 0) {
				std::cout << ", ID=" << ictWS.ckdata[1];
			}
			std::cout << std::endl;
			break;
		case TraceDqrProfiler::ICT_PC_SAMPLE:
			std::cout << "  # TraceProfiler Message(" << msgNum << "): In Circuit TraceProfiler WS PC Sample, cksrc=" << ictWS.cksrc << ", ckdf=" << (int)ictWS.ckdf << ", PC=0x" << std::hex << ictWS.ckdata[0] << std::dec << std::endl;
			break;
		case TraceDqrProfiler::ICT_NONE:
			break;
		}
		break;
	default:
		std::cout << "Error: ProfilerNexusMessage::dump(): Unknown TCODE " << tcode << " (0x" << std::hex << tcode << std::dec << "), msgnum: " << msgNum << std::endl;
	}
}

Count::Count()
{
	for (int i = 0; i < (int)(sizeof i_cnt / sizeof i_cnt[0]); i++) {
		i_cnt[i] = 0;
	}

	for (int i = 0; i < (int)(sizeof history / sizeof history[0]); i++) {
		history[i] = 0;
	}

	for (int i = 0; i < (int)(sizeof histBit / sizeof histBit[0]); i++) {
		histBit[i] = -1;
	}

	for (int i = 0; i < (int)(sizeof takenCount / sizeof takenCount[0]); i++) {
		takenCount[i] = 0;
	}

	for (int i = 0; i < (int)(sizeof notTakenCount / sizeof notTakenCount[0]); i++) {
		notTakenCount[i] = 0;
	}
}

Count::~Count()
{
	// nothing to do here!
}

void Count::resetCounts(int core)
{
	i_cnt[core] = 0;
	histBit[core] = -1;
	takenCount[core] = 0;
	notTakenCount[core] = 0;
}

TraceDqrProfiler::CountType Count::getCurrentCountType(int core)
{
	// types are prioritized! Order is important

	if (histBit[core] >= 0) {
		return TraceDqrProfiler::COUNTTYPE_history;
	}

	if (takenCount[core] > 0) {
		return TraceDqrProfiler::COUNTTYPE_taken;
	}

	if (notTakenCount[core] > 0) {
		return TraceDqrProfiler::COUNTTYPE_notTaken;
	}

	// i-cnt is the lowest priority

	if (i_cnt[core] > 0) {
		return TraceDqrProfiler::COUNTTYPE_i_cnt;
	}

	//	printf("count type: hist: %d taken:%d not taken:%d i_cnt: %d\n",histBit[core],takenCount[core],notTakenCount[core],i_cnt[core]);

	return TraceDqrProfiler::COUNTTYPE_none;
}

TraceDqrProfiler::DQErr Count::setICnt(int core, int count)
{
	i_cnt[core] += count;

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr Count::setHistory(int core, uint64_t hist)
{
	TraceDqrProfiler::DQErr rc = TraceDqrProfiler::DQERR_OK;

	if (histBit[core] >= 0) {
		rc = TraceDqrProfiler::DQERR_ERR;
	}
	else if (takenCount[core] != 0) {
		rc = TraceDqrProfiler::DQERR_ERR;
	}
	else if (notTakenCount[core] != 0) {
		rc = TraceDqrProfiler::DQERR_ERR;
	}
	else if (hist == 0) {
		history[core] = 0;
		histBit[core] = -1;
	}
	else {
		history[core] = hist;

		int i;

		for (i = sizeof hist * 8 - 1; i >= 0; i -= 1) {
			if (hist & (((uint64_t)1) << i)) {
				histBit[core] = i - 1;
				break;
			}
		}

		if (i < 0) {
			histBit[core] = -1;
		}
	}

	return rc;
}

TraceDqrProfiler::DQErr Count::setHistory(int core, uint64_t hist, int count)
{
	TraceDqrProfiler::DQErr rc;

	rc = setICnt(core, count);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		return rc;
	}

	rc = setHistory(core, hist);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		return rc;
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr Count::setTakenCount(int core, int takenCnt)
{
	TraceDqrProfiler::DQErr rc;

	if (histBit[core] >= 0) {
		rc = TraceDqrProfiler::DQERR_ERR;
	}
	else if (takenCount[core] != 0) {
		rc = TraceDqrProfiler::DQERR_ERR;
	}
	else if (notTakenCount[core] != 0) {
		rc = TraceDqrProfiler::DQERR_ERR;
	}
	else {
		takenCount[core] = takenCnt;
		rc = TraceDqrProfiler::DQERR_OK;
	}

	return rc;
}

TraceDqrProfiler::DQErr Count::setNotTakenCount(int core, int notTakenCnt)
{
	TraceDqrProfiler::DQErr rc;

	if (histBit[core] >= 0) {
		rc = TraceDqrProfiler::DQERR_ERR;
	}
	else if (takenCount[core] != 0) {
		rc = TraceDqrProfiler::DQERR_ERR;
	}
	else if (notTakenCount[core] != 0) {
		rc = TraceDqrProfiler::DQERR_ERR;
	}
	else {
		notTakenCount[core] = notTakenCnt;
		rc = TraceDqrProfiler::DQERR_OK;
	}

	return rc;
}

TraceDqrProfiler::DQErr Count::setCounts(ProfilerNexusMessage* nm)
{
	TraceDqrProfiler::DQErr rc;
	int tmp_i_cnt = 0;
	uint64_t tmp_history = 0;
	int tmp_taken = 0;
	int tmp_notTaken = 0;

	switch (nm->tcode) {
	case TraceDqrProfiler::TCODE_DEBUG_STATUS:
	case TraceDqrProfiler::TCODE_DEVICE_ID:
	case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
	case TraceDqrProfiler::TCODE_DATA_WRITE:
	case TraceDqrProfiler::TCODE_DATA_READ:
	case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
	case TraceDqrProfiler::TCODE_ERROR:
	case TraceDqrProfiler::TCODE_CORRECTION:
	case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
	case TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS:
		// no counts, do nothing
		return TraceDqrProfiler::DQERR_OK;
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
		tmp_i_cnt = nm->directBranch.i_cnt;
		break;
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
		tmp_i_cnt = nm->indirectBranch.i_cnt;
		break;
	case TraceDqrProfiler::TCODE_SYNC:
		tmp_i_cnt = nm->sync.i_cnt;
		break;
	case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
		tmp_i_cnt = nm->directBranchWS.i_cnt;
		break;
	case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
		tmp_i_cnt = nm->indirectBranchWS.i_cnt;
		break;
	case TraceDqrProfiler::TCODE_RESOURCEFULL:
		switch (nm->resourceFull.rCode) {
		case 0:
			tmp_i_cnt = nm->resourceFull.i_cnt;
			break;
		case 1:
			tmp_history = nm->resourceFull.history;
			break;
		case 8:
			tmp_notTaken = nm->resourceFull.notTakenCount;
			break;
		case 9:
			tmp_taken = nm->resourceFull.takenCount;
			break;
		default:
			printf("Error: Count::setCount(): invalid or unsupported rCode for reourceFull TCODE\n");

			return TraceDqrProfiler::DQERR_ERR;
		}
		break;
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
		tmp_i_cnt = nm->indirectHistory.i_cnt;
		tmp_history = nm->indirectHistory.history;
		break;
	case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
		tmp_i_cnt = nm->indirectHistoryWS.i_cnt;
		tmp_history = nm->indirectHistoryWS.history;
		break;
	case TraceDqrProfiler::TCODE_CORRELATION:
		tmp_i_cnt = nm->correlation.i_cnt;
		if (nm->correlation.cdf == 1) {
			tmp_history = nm->correlation.history;
		}
		break;
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
		printf("Error: Count::setCount(): invalid or unsupported TCODE\n");

		return TraceDqrProfiler::DQERR_ERR;
	}

	if (tmp_i_cnt != 0) {
		rc = setICnt(nm->coreId, tmp_i_cnt);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			return rc;
		}
	}

	if (tmp_history != 0) {
		rc = setHistory(nm->coreId, tmp_history);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			return rc;
		}
	}

	if (tmp_taken != 0) {
		rc = setTakenCount(nm->coreId, tmp_taken);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			return rc;
		}
	}

	if (tmp_notTaken != 0) {
		rc = setNotTakenCount(nm->coreId, tmp_notTaken);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			return rc;
		}
	}

	return TraceDqrProfiler::DQERR_OK;
}

int Count::consumeICnt(int core, int numToConsume)
{
	i_cnt[core] -= numToConsume;

	return i_cnt[core];
}

int Count::consumeHistory(int core, bool& taken)
{
	if (histBit[core] < 0) {
		return 1;
	}

	taken = (history[core] & (1 << histBit[core])) != 0;

	histBit[core] -= 1;

	return 0;
}

int Count::consumeTakenCount(int core)
{
	if (takenCount[core] <= 0) {
		return 1;
	}

	takenCount[core] -= 1;

	return 0;
}

int Count::consumeNotTakenCount(int core)
{
	if (notTakenCount[core] <= 0) {
		return 1;
	}

	notTakenCount[core] -= 1;

	return 0;
}

void Count::dumpCounts(int core)
{
	printf("Count::dumpCounts(): core: %d, i_cnt: %d, history: 0x%08llx, histBit: %d, takenCount: %d, notTakenCount: %d\n", core, i_cnt[core], history[core], histBit[core], takenCount[core], notTakenCount[core]);
}

SliceFileParser::SliceFileParser(char* filename, int srcBits)
{
	//if (filename == nullptr) {
	//	printf("Error: SliceFileParser::SliceFaileParser(): No filename specified\n");
	//	status = TraceDqrProfiler::DQERR_OK;
	//	return;
	//}

	srcbits = srcBits;

	msgSlices = 0;
	bitIndex = 0;

	pendingMsgIndex = 0;

	tfSize = 0;
	bufferInIndex = 0;
	bufferOutIndex = 0;

	eom = false;
    {
        std::lock_guard<std::mutex> msg_eod_guard(m_end_of_data_mutex);
        m_end_of_data = false;
    }

	int i;

	// first lets see if it is a windows path

	bool havePath = true;

	//for (i = 0; (filename[i] != 0) && (filename[i] != ':'); i++) { /* empty */ }

	//if (filename[i] == ':') {
	//	// see if this is a disk designator or port designator

	//	int j;
	//	int numAlpha = 0;

	//	// look for drive : (not a foolproof test, but should work

	//	for (j = 0; j < i; j++) {
	//		if ((filename[j] >= 'a' && filename[j] <= 'z') || (filename[j] >= 'A' && filename[j] <= 'Z')) {
	//			numAlpha += 1;
	//		}
	//	}

	//	if (numAlpha != 1) {
	//		havePath = false;
	//	}
	//}
	if (havePath == false) {
#if 0
		// have a server:port address

		int rc;
		char* sn = nullptr;
		int port = 0;

		sn = new char[i];
		strncpy(sn, filename, i);
		sn[i] = 0;

		port = atoi(&filename[i + 1]);

		// create socket

#ifdef WINDOWS
		WORD wVersionRequested;
		WSADATA wsaData;

		wVersionRequested = MAKEWORD(2, 2);
		rc = WSAStartup(wVersionRequested, &wsaData);
		if (rc != 0) {
			printf("Error: WSAStartUP() failed with error %d\n", rc);
			delete[] sn;
			sn = nullptr;
			status = TraceDqrProfiler::DQERR_ERR;
			return;
		}
#endif // WINDOWS

		SWTsock = socket(AF_INET, SOCK_STREAM, 0);
		if (SWTsock < 0) {
			printf("Error: SliceFileParser::SliceFileParser(); socket() failed\n");
			delete[] sn;
			sn = nullptr;
			status = TraceDqrProfiler::DQERR_ERR;
			return;
		}

		struct sockaddr_in serv_addr;
		struct hostent* server;

		server = gethostbyname(sn);

		delete[] sn;
		sn = nullptr;

		memset((char*)&serv_addr, 0, sizeof(serv_addr));
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_port = htons(port);
		memcpy((char*)&serv_addr.sin_addr.s_addr, (char*)server->h_addr, server->h_length);

		rc = connect(SWTsock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
		if (rc < 0) {
			printf("Error: SliceFileParser::SliceFileParser(): connect() failed: %d\n", rc);

#ifdef WINDOWS
			closesocket(SWTsock);
#else // WINDOWS
			close(SWTsock);
#endif // WINDOWS

			SWTsock = -1;

			server = nullptr;

			status = TraceDqrProfiler::DQERR_ERR;

			return;
		}

		// put socket in non-blocking mode
#ifdef WINDOWS
		unsigned long on = 1L;
		rc = ioctlsocket(SWTsock, FIONBIO, &on);
		if (rc != NO_ERROR) {
			printf("Error: SliceFileParser::SliceFileParser(): Failed to put socket into non-blocking mode\n");
			status = TraceDqrProfiler::DQERR_ERR;
			return;
		}
#else // WINDOWS
//		long on = 1L;
//		rc = ioctl(SWTsock,(int)FIONBIO,(char*)&on);
//		if (rc < 0) {
//			printf("Error: SliceFileParser::SliceFileParser(): Failed to put socket into non-blocking mode\n");
//			status = TraceDqrProfiler::DQERR_ERR;
//			return;
//		}
#endif // WINDOWS

		tfSize = 0;
#endif
	}
	else {
		//tf.open(filename, std::ios::in | std::ios::binary);
		//if (!tf) {
		//	printf("Error: SliceFileParder(): could not open file %s for input\n", filename);
		//	status = TraceDqrProfiler::DQERR_OPEN;
		//	return;
		//}
		//else {
		//	status = TraceDqrProfiler::DQERR_OK;
		//}

		//tf.seekg(0, tf.end);
		//tfSize = tf.tellg();
		//tf.seekg(0, tf.beg);

		msgOffset = 0;

		SWTsock = -1;
	}

	status = TraceDqrProfiler::DQERR_OK;
}

SliceFileParser::~SliceFileParser()
{
	if (tf.is_open()) {
		tf.close();
	}
	std::lock_guard<std::mutex> msg_queue_guard(m_msg_queue_mutex);
	m_msg_queue.clear();

//	if (SWTsock >= 0) {
//#ifdef WINDOWS
//		closesocket(SWTsock);
//		WSACleanup();
//#else  // WINDOWS
//		close(SWTsock);
//#endif // WINDOWS
//
//		SWTsock = -1;
//	}
}

TraceDqrProfiler::DQErr SliceFileParser::getNumBytesInSWTQ(int& numBytes)
{
	TraceDqrProfiler::DQErr rc;

	//if (SWTsock < 0) {
	//	return TraceDqrProfiler::DQERR_ERR;
	//}

	//rc = bufferSWT();
	//if (rc != TraceDqrProfiler::DQERR_OK) {
	//	return rc;
	//}

	//if (bufferInIndex == bufferOutIndex) {
	//	numBytes = 0;
	//}
	//else if (bufferInIndex < bufferOutIndex) {
	//	numBytes = (sizeof sockBuffer / sizeof sockBuffer[0]) - bufferOutIndex + bufferInIndex;
	//}
	//else { // bufferInIndex > bufferOutIndex
	//	numBytes = bufferInIndex - bufferOutIndex;
	//}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr SliceFileParser::getFileOffset(int& size, int& offset)
{
	if (!tf.is_open()) {
		return TraceDqrProfiler::DQERR_ERR;
	}

	size = tfSize;
	offset = tf.tellg();

	return TraceDqrProfiler::DQERR_OK;
}

void SliceFileParser::dump()
{
	//msg and msgSlices

	for (int i = 0; i < msgSlices; i++) {
		std::cout << std::setw(2) << i + 1;
		std::cout << " | ";
		std::cout << std::setfill('0');
		std::cout << std::setw(2) << std::hex << int(msg[i] >> 2) << std::dec;
		std::cout << std::setfill(' ');
		std::cout << " | ";
		std::cout << int((msg[i] >> 1) & 1);
		std::cout << " ";
		std::cout << int(msg[i] & 1);
		std::cout << std::endl;
	}
}

TraceDqrProfiler::DQErr SliceFileParser::parseICT(ProfilerNexusMessage& nm, ProfilerAnalytics& analytics)
{
	TraceDqrProfiler::DQErr rc;
	uint64_t   tmp;
	int        width;
	int        bits = 6;	// start bits at 6 to account for tcode
	int        ts_bits = 0;
	int        addr_bits;

	nm.tcode = TraceDqrProfiler::TCODE_INCIRCUITTRACE;

	if (srcbits > 0) {
		rc = parseFixedField(srcbits, &tmp);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return status;
		}

		bits += srcbits;

		nm.coreId = (uint8_t)tmp;
	}
	else {
		nm.coreId = 0;
	}

	// parse the four bit CKSRC (reason for ICT)

	rc = parseFixedField(4, &tmp);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += 4;

	nm.ict.cksrc = (TraceDqrProfiler::ICTReason)tmp;

	// parse the 2 bit CKDF field (number of CKDATA fields: 0 means 1, etc)

	rc = parseFixedField(2, &tmp);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += 2;

	if (tmp > 1) {
		status = TraceDqrProfiler::DQERR_ERR;

		return status;
	}

	nm.ict.ckdf = (uint8_t)tmp;

	for (int i = 0; i <= nm.ict.ckdf; i++) {
		// parse the variable length CKDATA field

		rc = parseVarField(&tmp, &width);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return status;
		}

		bits += width;
		addr_bits = width;

		nm.ict.ckdata[i] = (TraceDqrProfiler::ADDRESS)tmp;
	}

	if (eom == true) {
		nm.haveTimestamp = false;
		nm.timestamp = 0;
	}
	else {
		rc = parseVarField(&tmp, &width); // this field is optional - check err
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return status;
		}

		bits += width;
		ts_bits = width;

		// check if entire message has been consumed

		if (eom != true) {
			status = TraceDqrProfiler::DQERR_BM;

			return status;
		}

		nm.haveTimestamp = true;
		nm.timestamp = (TraceDqrProfiler::TIMESTAMP)tmp;
	}

	status = analytics.updateTraceInfo(nm, bits + msgSlices * 2, msgSlices * 2, ts_bits, addr_bits);

	nm.msgNum = analytics.currentTraceMsgNum();

	return status;
}

TraceDqrProfiler::DQErr SliceFileParser::parseICTWS(ProfilerNexusMessage& nm, ProfilerAnalytics& analytics)
{
	TraceDqrProfiler::DQErr rc;
	uint64_t   tmp;
	int        width;
	int        bits = 6;	// start bits at 6 to account for tcode
	int        ts_bits = 0;
	int        addr_bits;

	nm.tcode = TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS;

	if (srcbits > 0) {
		rc = parseFixedField(srcbits, &tmp);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return status;
		}

		bits += srcbits;

		nm.coreId = (uint8_t)tmp;
	}
	else {
		nm.coreId = 0;
	}

	// parse the four bit CKSRC (reason for ICT)

	rc = parseFixedField(4, &tmp);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += 4;

	nm.ictWS.cksrc = (TraceDqrProfiler::ICTReason)tmp;

	// parse the 2 bit CKDF field (number of CKDATA fields: 0 means 1, etc)

	rc = parseFixedField(2, &tmp);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += 2;

	if (tmp > 1) {
		status = TraceDqrProfiler::DQERR_ERR;

		return status;
	}

	nm.ictWS.ckdf = (uint8_t)tmp;

	for (int i = 0; i <= nm.ictWS.ckdf; i++) {
		// parse the variable length CKDATA field

		rc = parseVarField(&tmp, &width);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return status;
		}

		bits += width;
		addr_bits = width;

		nm.ictWS.ckdata[i] = (TraceDqrProfiler::ADDRESS)tmp;
	}

	if (eom == true) {
		nm.haveTimestamp = false;
		nm.timestamp = 0;
	}
	else {
		rc = parseVarField(&tmp, &width); // this field is optional - check err
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return status;
		}

		bits += width;
		ts_bits = width;

		// check if entire message has been consumed

		if (eom != true) {
			status = TraceDqrProfiler::DQERR_BM;

			return status;
		}

		nm.haveTimestamp = true;
		nm.timestamp = (TraceDqrProfiler::TIMESTAMP)tmp;
	}

	status = analytics.updateTraceInfo(nm, bits + msgSlices * 2, msgSlices * 2, ts_bits, addr_bits);

	nm.msgNum = analytics.currentTraceMsgNum();

	return status;
}

TraceDqrProfiler::DQErr SliceFileParser::parseIndirectHistory(ProfilerNexusMessage& nm, ProfilerAnalytics& analytics)
{
	TraceDqrProfiler::DQErr rc;
	uint64_t   tmp;
	int        width;
	int        bits = 6;	// start bits at 6 to account for tcode
	int        ts_bits = 0;
	int        addr_bits;

	nm.tcode = TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY;

	if (srcbits > 0) {
		rc = parseFixedField(srcbits, &tmp);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return status;
		}

		bits += srcbits;

		nm.coreId = (uint8_t)tmp;
	}
	else {
		nm.coreId = 0;
	}

	// parse the two bit b-type

	rc = parseFixedField(2, &tmp);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += 2;

	nm.indirectHistory.b_type = (TraceDqrProfiler::BType)tmp;

	// parse the variable length the i-cnt

	rc = parseVarField(&tmp, &width);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += width;

	nm.indirectHistory.i_cnt = (int)tmp;

	// parse the u-addr field

	rc = parseVarField(&tmp, &width);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += width;
	addr_bits = width;

	nm.indirectHistory.u_addr = (TraceDqrProfiler::ADDRESS)tmp;

	// parse the variable lenght history field

	rc = parseVarField(&tmp, &width);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += width;

	nm.indirectHistory.history = tmp;

	if (eom == true) {
		nm.haveTimestamp = false;
		nm.timestamp = 0;
	}
	else {
		rc = parseVarField(&tmp, &width); // this field is optional - check err
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return status;
		}

		bits += width;
		ts_bits = width;

		// check if entire message has been consumed

		if (eom != true) {
			status = TraceDqrProfiler::DQERR_BM;

			return status;
		}

		nm.haveTimestamp = true;
		nm.timestamp = (TraceDqrProfiler::TIMESTAMP)tmp;
	}

	status = analytics.updateTraceInfo(nm, bits + msgSlices * 2, msgSlices * 2, ts_bits, addr_bits);

	nm.msgNum = analytics.currentTraceMsgNum();

	return status;
}

TraceDqrProfiler::DQErr SliceFileParser::parseIndirectHistoryWS(ProfilerNexusMessage& nm, ProfilerAnalytics& analytics)
{
	TraceDqrProfiler::DQErr rc;
	uint64_t   tmp;
	int        width;
	int        bits = 6;	// start bits at 6 to account for tcode
	int        ts_bits = 0;
	int        addr_bits;

	nm.tcode = TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS;

	// if multicore, parse src field

	if (srcbits > 0) {
		rc = parseFixedField(srcbits, &tmp);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return status;
		}

		bits += srcbits;

		nm.coreId = (uint8_t)tmp;
	}
	else {
		nm.coreId = 0;
	}

	// parse the fixed length sync reason field

	rc = parseFixedField(4, &tmp);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += 4;

	nm.indirectHistoryWS.sync = (TraceDqrProfiler::SyncReason)tmp;

	// parse the two bit b-type

	rc = parseFixedField(2, &tmp);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += 2;

	nm.indirectHistoryWS.b_type = (TraceDqrProfiler::BType)tmp;

	// parse the variable length the i-cnt

	rc = parseVarField(&tmp, &width);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += width;

	nm.indirectHistoryWS.i_cnt = (int)tmp;

	// parse the f-addr field

	rc = parseVarField(&tmp, &width);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += width;
	addr_bits = width;

	nm.indirectHistoryWS.f_addr = (TraceDqrProfiler::ADDRESS)tmp;

	// parse the variable length history field

	rc = parseVarField(&tmp, &width);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += width;

	nm.indirectHistoryWS.history = tmp;

	if (eom == true) {
		nm.haveTimestamp = false;
		nm.timestamp = 0;
	}
	else {
		rc = parseVarField(&tmp, &width); // this field is optional - check err
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return status;
		}

		bits += width;
		ts_bits = width;

		// check if entire message has been consumed

		if (eom != true) {
			status = TraceDqrProfiler::DQERR_BM;

			return status;
		}

		nm.haveTimestamp = true;
		nm.timestamp = (TraceDqrProfiler::TIMESTAMP)tmp;
	}

	status = analytics.updateTraceInfo(nm, bits + msgSlices * 2, msgSlices * 2, ts_bits, addr_bits);

	nm.msgNum = analytics.currentTraceMsgNum();

	return status;
}

TraceDqrProfiler::DQErr SliceFileParser::parseResourceFull(ProfilerNexusMessage& nm, ProfilerAnalytics& analytics)
{
	TraceDqrProfiler::DQErr rc;
	uint64_t   tmp;
	int        width;
	int        bits = 6;	// start bits at 6 to account for tcode
	int        ts_bits = 0;

	nm.tcode = TraceDqrProfiler::TCODE_RESOURCEFULL;

	// if multicore, parse src field

	if (srcbits > 0) {
		rc = parseFixedField(srcbits, &tmp);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return status;
		}

		bits += srcbits;

		nm.coreId = (uint8_t)tmp;
	}
	else {
		nm.coreId = 0;
	}

	// parse the 4 bit RCODE

	rc = parseFixedField(4, &tmp);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += 4;

	nm.resourceFull.rCode = (int)tmp;

	// parse the vairable length rdata field

	rc = parseVarField(&tmp, &width);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += width;

	switch (nm.resourceFull.rCode) {
	case 0:
		nm.resourceFull.i_cnt = (int)tmp;
		break;
	case 1:
		nm.resourceFull.history = tmp;
		break;
	case 8:
		nm.resourceFull.notTakenCount = (int)tmp;
		break;
	case 9:
		nm.resourceFull.takenCount = (int)tmp;
		break;
	default:
		printf("Error: parseResourceFull(): unknown rCode: %d\n", nm.resourceFull.rCode);

		status = TraceDqrProfiler::DQERR_ERR;
		return status;
	}

	if (eom == true) {
		nm.haveTimestamp = false;
		nm.timestamp = 0;
	}
	else {
		rc = parseVarField(&tmp, &width); // this field is optional - check err
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return status;
		}

		bits += width;
		ts_bits = width;

		// check if entire message has been consumed

		if (eom != true) {
			status = TraceDqrProfiler::DQERR_BM;

			return status;
		}

		nm.haveTimestamp = true;
		nm.timestamp = (TraceDqrProfiler::TIMESTAMP)tmp;
	}

	status = analytics.updateTraceInfo(nm, bits + msgSlices * 2, msgSlices * 2, ts_bits, 0);

	nm.msgNum = analytics.currentTraceMsgNum();

	return status;
}

TraceDqrProfiler::DQErr SliceFileParser::parseDirectBranch(ProfilerNexusMessage& nm, ProfilerAnalytics& analytics)
{
	TraceDqrProfiler::DQErr rc;
	uint64_t   tmp;
	int        width;
	int        bits = 6;	// start bits at 6 to account for tcode
	int        ts_bits = 0;

	nm.tcode = TraceDqrProfiler::TCODE_DIRECT_BRANCH;

	// if multicore, parse src field

	if (srcbits > 0) {
		rc = parseFixedField(srcbits, &tmp);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return status;
		}

		bits += srcbits;

		nm.coreId = (uint8_t)tmp;
	}
	else {
		nm.coreId = 0;
	}

	// parse the variable length the i-cnt

	rc = parseVarField(&tmp, &width);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += width;

	nm.directBranch.i_cnt = (int)tmp;

	if (eom == true) {
		nm.haveTimestamp = false;
		nm.timestamp = 0;
	}
	else {
		rc = parseVarField(&tmp, &width); // this field is optional - check err
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return status;
		}

		bits += width;
		ts_bits = width;

		// check if entire message has been consumed

		if (eom != true) {
			status = TraceDqrProfiler::DQERR_BM;

			return status;
		}

		nm.haveTimestamp = true;
		nm.timestamp = (TraceDqrProfiler::TIMESTAMP)tmp;
	}

	status = analytics.updateTraceInfo(nm, bits + msgSlices * 2, msgSlices * 2, ts_bits, 0);

	nm.msgNum = analytics.currentTraceMsgNum();

	return status;
}

TraceDqrProfiler::DQErr SliceFileParser::parseDirectBranchWS(ProfilerNexusMessage& nm, ProfilerAnalytics& analytics)
{
	TraceDqrProfiler::DQErr rc;
	uint64_t   tmp;
	int        width;
	int        bits = 6;
	int        ts_bits = 0;
	int        addr_bits;

	nm.tcode = TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS;

	// if multicore, parse src field

	if (srcbits > 0) {
		rc = parseFixedField(srcbits, &tmp);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return status;
		}

		bits += srcbits;

		nm.coreId = (uint8_t)tmp;
	}
	else {
		nm.coreId = 0;
	}

	// parse the fixed length sync reason field

	rc = parseFixedField(4, &tmp);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += 4;

	nm.directBranchWS.sync = (TraceDqrProfiler::SyncReason)tmp;

	// parse the variable length the i-cnt

	rc = parseVarField(&tmp, &width);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += width;

	nm.directBranchWS.i_cnt = (int)tmp;

	rc = parseVarField(&tmp, &width);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += width;
	addr_bits = width;

	nm.directBranchWS.f_addr = (TraceDqrProfiler::ADDRESS)tmp;

	if (eom == true) {
		nm.haveTimestamp = false;
		nm.timestamp = 0;
	}
	else {
		rc = parseVarField(&tmp, &width); // this field is optional - check err
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return status;
		}

		bits += width;
		ts_bits = width;

		// check if entire message has been consumed

		if (eom != true) {
			status = TraceDqrProfiler::DQERR_BM;

			return status;
		}

		nm.haveTimestamp = true;
		nm.timestamp = (TraceDqrProfiler::TIMESTAMP)tmp;
	}

	status = analytics.updateTraceInfo(nm, bits + msgSlices * 2, msgSlices * 2, ts_bits, addr_bits);

	nm.msgNum = analytics.currentTraceMsgNum();

	return status;
}

TraceDqrProfiler::DQErr SliceFileParser::parseIndirectBranch(ProfilerNexusMessage& nm, ProfilerAnalytics& analytics)
{
	TraceDqrProfiler::DQErr rc;
	uint64_t   tmp;
	int        width;
	int        bits = 6;
	int        ts_bits = 0;
	int        addr_bits;

	nm.tcode = TraceDqrProfiler::TCODE_INDIRECT_BRANCH;

	// if multicore, parse src field

	if (srcbits > 0) {
		rc = parseFixedField(srcbits, &tmp);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			//            printf("Error: parseIndirectBranch(): parseFixedField() for srcbits failed\n");

			return status;
		}

		bits += srcbits;

		nm.coreId = (uint8_t)tmp;
	}
	else {
		nm.coreId = 0;
	}

	//	if (profiler_globalDebugFlag) {
	//		printf("parseIndirectBranch(): coreId: %d\n",nm.coreId);
	//	}

		// parse the fixed length b-type

	rc = parseFixedField(2, &tmp);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		//        printf("Error: parseIndirectBranch(): parseFixedField() for b-type failed\n");

		return status;
	}

	bits += 2;

	nm.indirectBranch.b_type = (TraceDqrProfiler::BType)tmp;

	//	if (profiler_globalDebugFlag) {
	//		printf("parseIndirectBranch(): b_type: %d\n",nm.indirectBranch.b_type);
	//	}

		// parse the variable length the i-cnt

	rc = parseVarField(&tmp, &width);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		//        printf("Error: parseIndirectBranch(): parseVarField() for i-cnt failed\n");

		return status;
	}

	bits += width;

	nm.indirectBranch.i_cnt = (int)tmp;

	//	if (profiler_globalDebugFlag) {
	//		printf("parseIndirectBranch(): i_cnt: %d\n",nm.indirectBranch.i_cnt);
	//	}

	rc = parseVarField(&tmp, &width);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		//        printf("Error: parseIndirectBranch(): parseVarField() for address failed\n");

		return status;
	}

	bits += width;
	addr_bits = width;

	nm.indirectBranch.u_addr = (TraceDqrProfiler::ADDRESS)tmp;

	//	if (profiler_globalDebugFlag) {
	//		printf("parseIndirectBranch(): u_addr: 0x%08llx\n",nm.indirectBranch.u_addr);
	//	}

	if (eom == true) {
		nm.haveTimestamp = false;
		nm.timestamp = 0;

		//		if (profiler_globalDebugFlag) {
		//			printf("parseIndirectBranch(): no timestamp\n");
		//		}
	}
	else {
		rc = parseVarField(&tmp, &width); // this field is optional - check err
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			//	        printf("Error: parseIndirectBranch(): parseFixedField() for timestamp failed\n");

			return status;
		}

		bits += width;
		ts_bits = width;

		// check if entire message has been consumed

		if (eom != true) {
			status = TraceDqrProfiler::DQERR_BM;

			printf("Error: parseIndirectBranch(): End of message expected\n");

			return status;
		}

		nm.haveTimestamp = true;
		nm.timestamp = (TraceDqrProfiler::TIMESTAMP)tmp;

		//		if (profiler_globalDebugFlag) {
		//			printf("parseIndirectBranch(): timestamp: %llu\n",nm.timestamp);
		//		}
	}

	status = analytics.updateTraceInfo(nm, bits + msgSlices * 2, msgSlices * 2, ts_bits, addr_bits);

	nm.msgNum = analytics.currentTraceMsgNum();

	return status;
}

TraceDqrProfiler::DQErr SliceFileParser::parseIndirectBranchWS(ProfilerNexusMessage& nm, ProfilerAnalytics& analytics)
{
	TraceDqrProfiler::DQErr rc;
	uint64_t   tmp;
	int        width;
	int        bits = 6;
	int        ts_bits = 0;
	int        addr_bits;

	nm.tcode = TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS;

	// if multicore, parse src field

	if (srcbits > 0) {
		rc = parseFixedField(srcbits, &tmp);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return status;
		}

		bits += srcbits;

		nm.coreId = (uint8_t)tmp;
	}
	else {
		nm.coreId = 0;
	}

	// parse the fixed length sync field

	rc = parseFixedField(4, &tmp);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += 4;

	nm.indirectBranchWS.sync = (TraceDqrProfiler::SyncReason)tmp;

	// parse the fixed length b-type

	rc = parseFixedField(2, &tmp);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += 2;

	nm.indirectBranchWS.b_type = (TraceDqrProfiler::BType)tmp;

	// parse the variable length the i-cnt

	rc = parseVarField(&tmp, &width);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += width;

	nm.indirectBranchWS.i_cnt = (int)tmp;

	rc = parseVarField(&tmp, &width);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += width;
	addr_bits = width;

	nm.indirectBranchWS.f_addr = (TraceDqrProfiler::ADDRESS)tmp;

	if (eom == true) {
		nm.haveTimestamp = false;
		nm.timestamp = 0;
	}
	else {
		rc = parseVarField(&tmp, &width); // this field is optional - check err
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return status;
		}

		// check if entire message has been consumed

		if (eom != true) {
			status = TraceDqrProfiler::DQERR_BM;

			return status;
		}

		bits += width;
		ts_bits = width;

		nm.haveTimestamp = true;
		nm.timestamp = (TraceDqrProfiler::TIMESTAMP)tmp;
	}

	status = analytics.updateTraceInfo(nm, bits + msgSlices * 2, msgSlices * 2, ts_bits, addr_bits);

	nm.msgNum = analytics.currentTraceMsgNum();

	return status;
}

TraceDqrProfiler::DQErr SliceFileParser::parseSync(ProfilerNexusMessage& nm, ProfilerAnalytics& analytics)
{
	TraceDqrProfiler::DQErr rc;
	uint64_t   tmp;
	int        width;
	int        bits = 6;
	int        ts_bits = 0;
	int        addr_bits;

	nm.tcode = TraceDqrProfiler::TCODE_SYNC;

	// if multicore, parse src field

	if (srcbits > 0) {
		rc = parseFixedField(srcbits, &tmp);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return status;
		}

		bits += srcbits;

		nm.coreId = (uint8_t)tmp;
	}
	else {
		nm.coreId = 0;
	}

	// parse the sync resons

	rc = parseFixedField(4, &tmp);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += 4;

	nm.sync.sync = (TraceDqrProfiler::SyncReason)tmp;

	rc = parseVarField(&tmp, &width);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += width;

	nm.sync.i_cnt = (int)tmp;

	rc = parseVarField(&tmp, &width);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += width;
	addr_bits = width;

	nm.sync.f_addr = (TraceDqrProfiler::ADDRESS)tmp;

	if (eom == true) {
		nm.haveTimestamp = false;
		nm.timestamp = 0;
	}
	else {
		rc = parseVarField(&tmp, &width); // this field is optional - check err
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return status;
		}

		// check if entire message has been consumed

		if (eom != true) {
			status = TraceDqrProfiler::DQERR_BM;

			return status;
		}

		bits += width;
		ts_bits = width;

		nm.haveTimestamp = true;
		nm.timestamp = (TraceDqrProfiler::TIMESTAMP)tmp;
	}

	status = analytics.updateTraceInfo(nm, bits + msgSlices * 2, msgSlices * 2, ts_bits, addr_bits);

	nm.msgNum = analytics.currentTraceMsgNum();

	return status;
}

TraceDqrProfiler::DQErr SliceFileParser::parseCorrelation(ProfilerNexusMessage& nm, ProfilerAnalytics& analytics)
{
	TraceDqrProfiler::DQErr rc;
	uint64_t   tmp;
	int        width;
	int        bits = 6;
	int        ts_bits = 0;

	nm.tcode = TraceDqrProfiler::TCODE_CORRELATION;

	//	printf("parse correlation\n");

		// if multicore, parse src field

	if (srcbits > 0) {
		rc = parseFixedField(srcbits, &tmp);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return status;
		}

		bits += srcbits;

		nm.coreId = (uint8_t)tmp;
	}
	else {
		nm.coreId = 0;
	}

	// parse the 4-bit evcode field

	rc = parseFixedField(4, &tmp);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += 4;

	nm.correlation.evcode = (uint8_t)tmp;

	// parse the 2-bit cdf field.

	rc = parseFixedField(2, &tmp);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += 2;

	nm.correlation.cdf = (uint8_t)tmp;

	// parse the variable length i-cnt field

	rc = parseVarField(&tmp, &width);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += width;

	nm.correlation.i_cnt = (int)tmp;

	switch (nm.correlation.cdf) {
	case 0:
		break;
	case 1:
		rc = parseVarField(&tmp, &width);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return status;
		}

		bits += width;

		nm.correlation.history = tmp;

		break;
	default:
		printf("Error: parseCorrelation(): invalid CDF field: %d\n", nm.correlation.cdf);

		status = TraceDqrProfiler::DQERR_ERR;
		return status;
	}

	if (eom == true) {
		nm.haveTimestamp = false;
		nm.timestamp = 0;
	}
	else {
		rc = parseVarField(&tmp, &width); // this field is optional - check err
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return status;
		}

		// check if entire message has been consumed

		if (eom != true) {
			status = TraceDqrProfiler::DQERR_BM;

			return status;
		}

		bits += width;
		ts_bits = width;

		nm.haveTimestamp = true;
		nm.timestamp = (TraceDqrProfiler::TIMESTAMP)tmp;
	}

	status = analytics.updateTraceInfo(nm, bits + msgSlices * 2, msgSlices * 2, ts_bits, 0);

	nm.msgNum = analytics.currentTraceMsgNum();

	return status;
}

TraceDqrProfiler::DQErr SliceFileParser::parseError(ProfilerNexusMessage& nm, ProfilerAnalytics& analytics)
{
	TraceDqrProfiler::DQErr rc;
	uint64_t   tmp;
	int        width;
	int        bits = 6;
	int        ts_bits = 0;

	nm.tcode = TraceDqrProfiler::TCODE_ERROR;

	// if multicore, parse src field

	if (srcbits > 0) {
		rc = parseFixedField(srcbits, &tmp);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return status;
		}

		bits += srcbits;

		nm.coreId = (uint8_t)tmp;
	}
	else {
		nm.coreId = 0;
	}

	// parse the 4 bit ETYPE field

	rc = parseFixedField(4, &tmp);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += 4;

	nm.error.etype = (uint8_t)tmp;

	// parse the variable sized padd field

	rc = parseVarField(&tmp, &width);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += width;

	if (eom == true) {
		nm.haveTimestamp = false;
		nm.timestamp = 0;
	}
	else {
		rc = parseVarField(&tmp, &width); // this field is optional - check err
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return status;
		}

		// check if entire message has been consumed

		if (eom != true) {
			status = TraceDqrProfiler::DQERR_BM;

			return status;
		}

		bits += width;
		ts_bits = width;

		nm.haveTimestamp = true;
		nm.timestamp = (TraceDqrProfiler::TIMESTAMP)tmp;
	}

	status = analytics.updateTraceInfo(nm, bits + msgSlices * 2, msgSlices * 2, ts_bits, 0);

	nm.msgNum = analytics.currentTraceMsgNum();

	return status;
}

TraceDqrProfiler::DQErr SliceFileParser::parseOwnershipTrace(ProfilerNexusMessage& nm, ProfilerAnalytics& analytics)
{
	TraceDqrProfiler::DQErr rc;
	uint64_t   tmp;
	int        width;
	int        bits = 6;
	int        ts_bits = 0;

	nm.tcode = TraceDqrProfiler::TCODE_OWNERSHIP_TRACE;

	// if multicore, parse src field

	if (srcbits > 0) {
		rc = parseFixedField(srcbits, &tmp);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return status;
		}

		bits += srcbits;

		nm.coreId = (uint8_t)tmp;
	}
	else {
		nm.coreId = 0;
	}

	// parse the variable length process ID field

	rc = parseVarField(&tmp, &width);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += width;

	nm.ownership.process = (int)tmp;

	if (eom == true) {
		nm.haveTimestamp = false;
		nm.timestamp = 0;
	}
	else {
		rc = parseVarField(&tmp, &width); // this field is optional - check err
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return status;
		}

		// check if entire message has been consumed

		if (eom != true) {
			status = TraceDqrProfiler::DQERR_BM;

			return status;
		}

		bits += width;
		ts_bits = width;

		nm.haveTimestamp = true;
		nm.timestamp = (TraceDqrProfiler::TIMESTAMP)tmp;
	}

	status = analytics.updateTraceInfo(nm, bits + msgSlices * 2, msgSlices * 2, ts_bits, 0);

	nm.msgNum = analytics.currentTraceMsgNum();

	return status;
}

TraceDqrProfiler::DQErr SliceFileParser::parseAuxAccessWrite(ProfilerNexusMessage& nm, ProfilerAnalytics& analytics)
{
	TraceDqrProfiler::DQErr rc;
	uint64_t   tmp;
	int        width;
	int        bits = 6;
	int        ts_bits = 0;

	nm.tcode = TraceDqrProfiler::TCODE_AUXACCESS_WRITE;

	// if multicore, parse src field

	if (srcbits > 0) {
		rc = parseFixedField(srcbits, &tmp);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return status;
		}

		bits += srcbits;

		nm.coreId = (uint8_t)tmp;
	}
	else {
		nm.coreId = 0;
	}

	// parse the ADDR field

	rc = parseVarField(&tmp, &width);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += width;

	nm.auxAccessWrite.addr = (uint32_t)tmp;

	// parse the data field

	rc = parseVarField(&tmp, &width);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += width;

	nm.auxAccessWrite.data = (uint32_t)tmp;

	if (eom == true) {
		nm.haveTimestamp = false;
		nm.timestamp = 0;
	}
	else {
		rc = parseVarField(&tmp, &width); // this field is optional - check err
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return status;
		}

		// check if entire message has been consumed

		if (eom != true) {
			status = TraceDqrProfiler::DQERR_BM;

			return status;
		}

		bits += width;
		ts_bits = width;

		nm.haveTimestamp = true;
		nm.timestamp = (TraceDqrProfiler::TIMESTAMP)tmp;
	}

	status = analytics.updateTraceInfo(nm, bits + msgSlices * 2, msgSlices * 2, ts_bits, 0);

	nm.msgNum = analytics.currentTraceMsgNum();

	return status;
}

TraceDqrProfiler::DQErr SliceFileParser::parseDataAcquisition(ProfilerNexusMessage& nm, ProfilerAnalytics& analytics)
{
	TraceDqrProfiler::DQErr rc;
	uint64_t   tmp;
	int        width;
	int        bits = 6;
	int        ts_bits = 0;

	nm.tcode = TraceDqrProfiler::TCODE_DATA_ACQUISITION;

	// if multicore, parse src field

	if (srcbits > 0) {
		rc = parseFixedField(srcbits, &tmp);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return status;
		}

		bits += srcbits;

		nm.coreId = (uint8_t)tmp;
	}
	else {
		nm.coreId = 0;
	}

	// parse the idTag field

	rc = parseVarField(&tmp, &width);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += width;

	nm.dataAcquisition.idTag = (uint32_t)tmp;

	// parse the data field

	rc = parseVarField(&tmp, &width);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = rc;

		return status;
	}

	bits += width;

	nm.dataAcquisition.data = (uint32_t)tmp;

	if (eom == true) {
		nm.haveTimestamp = false;
		nm.timestamp = 0;
	}
	else {
		rc = parseVarField(&tmp, &width); // this field is optional - check err
		if (rc != TraceDqrProfiler::DQERR_OK) {
			status = rc;

			return status;
		}

		// check if entire message has been consumed

		if (eom != true) {
			status = TraceDqrProfiler::DQERR_BM;

			return status;
		}

		bits += width;
		ts_bits = width;

		nm.haveTimestamp = true;
		nm.timestamp = (TraceDqrProfiler::TIMESTAMP)tmp;
	}

	status = analytics.updateTraceInfo(nm, bits + msgSlices * 2, msgSlices * 2, ts_bits, 0);

	nm.msgNum = analytics.currentTraceMsgNum();

	return status;
}

TraceDqrProfiler::DQErr SliceFileParser::parseFixedField(int width, uint64_t* val)
{
	if ((width <= 0) || (val == nullptr)) {
		printf("Error: SliceFileParser::parseFixedField(): Bad width or val argument\n");

		status = TraceDqrProfiler::DQERR_ERR;
		return status;
	}

	uint64_t tmp_val = 0;

	int i;
	int b;

	i = bitIndex / 6;
	b = bitIndex % 6;

	//	printf("parseFixedField(): bitIndex:%d, i:%d, b:%d, width: %d\n",bitIndex,i,b,width);

	bitIndex += width;

	// for read error checking we should make sure that the MSEO bits are
	// correct for this field. But for now, we don't

	if (bitIndex >= msgSlices * 6) {
		// read past end of message

		status = TraceDqrProfiler::DQERR_EOM;

		return TraceDqrProfiler::DQERR_EOM;
	}

	if (b + width > 6) {
		// fixed field crossed byte boundry - get the bits at msg[i]

		// work from lsb's to msb's

		tmp_val = (uint64_t)(msg[i] >> (b + 2));	// add 2 because of the mseo bits

		int consumed = 6 - b;
		int remainingWidth = width - consumed;

		i += 1;

		//		b = 0; comment this line out because we jsut don't use b anymore. It is 0 for the rest of the call

				// get the middle bits

		while (remainingWidth >= 6) {
			tmp_val |= ((uint64_t)(msg[i] >> 2)) << consumed;
			i += 1;
			remainingWidth -= 6;
			consumed += 6;
		}

		// now get the last bits

		if (remainingWidth > 0) {
			tmp_val |= ((uint64_t)(((uint8_t)(msg[i] << (6 - remainingWidth))) >> (6 - remainingWidth + 2))) << consumed;
		}

		*val = tmp_val;
	}
	else {
		uint8_t v;

		// strip off upper and lower bits not part of field

		v = msg[i] << (6 - (b + width));
		v = v >> ((6 - (b + width)) + b + 2);

		*val = uint64_t(v);
	}

	if ((msg[i] & 0x03) == TraceDqrProfiler::MSEO_END) {
		eom = true;
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr SliceFileParser::parseVarField(uint64_t* val, int* width)
{
	if (val == nullptr) {
		printf("SliceFileParser::parseVarField(): Bad val argument\n");
		status = TraceDqrProfiler::DQERR_ERR;
		return status;
	}

	int i;
	int b;
	int w = 0;

	i = bitIndex / 6;
	b = bitIndex % 6;

	if (i >= msgSlices) {
		// read past end of message

		status = TraceDqrProfiler::DQERR_EOM;

		return TraceDqrProfiler::DQERR_EOM;
	}

	uint64_t v;

	// strip off upper and lower bits not part of field

	w = 6 - b;

	//	printf("parseVarField(): bitIndex:%d, (byte index)i:%d, (bit index)b:%d, width: %d, slices: %d\n",bitIndex,i,b,w,msgSlices);

	v = ((uint64_t)msg[i]) >> (b + 2);

	while ((msg[i] & 0x03) == TraceDqrProfiler::MSEO_NORMAL) {
		i += 1;

		if (i >= msgSlices) {
			// read past end of message

			status = TraceDqrProfiler::DQERR_ERR;

			return TraceDqrProfiler::DQERR_ERR;
		}

		v = v | ((((uint64_t)msg[i]) >> 2) << w);
		w += 6;
	}

	// The check for overflow is a bit tricky. A 64 bit number will be encoded as a 66 bit number
	// because each slice holds 6 bits of data. So a 64 bit number will take 11 slices, and
	// at first this looks like a 66 bit number, not 64. Bit if the upper two bits of the last slice
	// are 0, it is a 66 bit number.

	if ((w > (int)sizeof(v) * 8) && ((msg[i] & 0xc0) != 0)) {
		// variable field overflowed size of v

		status = TraceDqrProfiler::DQERR_ERR;

		return TraceDqrProfiler::DQERR_ERR;
	}

	if ((msg[i] & 0x03) == TraceDqrProfiler::MSEO_END) {
		eom = true;
	}

	bitIndex += w;

	*width = w;
	*val = v;

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr SliceFileParser::bufferSWT()
{
	int br = 0;
	int bytesToRead;
#if 0
	// compute room in buffer for read

	if (bufferInIndex == bufferOutIndex) {
		// buffer is empty

		bytesToRead = (sizeof sockBuffer) - 1;

#ifdef WINDOWS
		br = recv(SWTsock, (char*)sockBuffer, bytesToRead, 0);
#else // WINDOWS
		br = recv(SWTsock, (char*)sockBuffer, bytesToRead, MSG_DONTWAIT);

		if (br < 0) {
			if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
				perror("SliceFileParser::bufferSWT(): recv() error");
			}
		}
#endif // WINDOWS

		if (br > 0) {
			bufferInIndex = br;
			bufferOutIndex = 0;
		}
	}
	else if (bufferInIndex < bufferOutIndex) {
		// empty bytes is (bufferOutIndex - bufferInIndex) - 1

		bytesToRead = bufferOutIndex - bufferInIndex - 1;

		if (bytesToRead > 0) {
#ifdef WINDOWS
			br = recv(SWTsock, (char*)sockBuffer + bufferInIndex, bytesToRead, 0);
#else // WINDOWS
			br = recv(SWTsock, (char*)sockBuffer + bufferInIndex, bytesToRead, MSG_DONTWAIT);

			if (br < 0) {
				if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
					perror("SlicFileParser::bufferSWT(): recv() error");
				}
			}
#endif // WINDOWS

			if (br > 0) {
				bufferInIndex += br;
			}
		}
	}
	else if (bufferInIndex > bufferOutIndex) {
		// empty bytes is bufferInIndex to end of buffer + bufferOutIndex - 1
		// first read to end of buffer

		if (bufferOutIndex == 0) {
			// don't want to completely fill up tail of buffer, because can't set bufferInIndex to 0!

			bytesToRead = (sizeof sockBuffer) - bufferInIndex - 1;
		}
		else {
			bytesToRead = (sizeof sockBuffer) - bufferInIndex;
		}

		if (bytesToRead > 0) {
#ifdef WINDOWS
			br = recv(SWTsock, (char*)sockBuffer + bufferInIndex, bytesToRead, 0);
#else // WINDOWS
			br = recv(SWTsock, (char*)sockBuffer + bufferInIndex, bytesToRead, MSG_DONTWAIT);

			if (br < 0) {
				if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
					perror("SizeFileParser::bufferSWT(): recv() error");
				}
			}
#endif // WINDOWS

			if (br > 0) {
				if ((bufferInIndex + br) >= (int)(sizeof sockBuffer)) {
					bufferInIndex = 0;

					bytesToRead = bufferOutIndex - 1;

					if (bytesToRead > 0) {
#ifdef WINDOWS
						br = recv(SWTsock, (char*)sockBuffer, bytesToRead, 0);
#else // WINDOWS
						br = recv(SWTsock, (char*)sockBuffer, bytesToRead, MSG_DONTWAIT);

						if (br < 0) {
							if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
								perror("SliceFileParser::bufferSWT(): recv() error");
							}
						}
#endif // WINDOWS
						if (br > 0) {
							bufferInIndex = br;
						}
					}
				}
				else {
					bufferInIndex += br;
				}
			}
		}
	}

#ifdef WINDOWS
	if ((br == -1) && (WSAGetLastError() != WSAEWOULDBLOCK)) {
		printf("Error: bufferSWT(): read socket failed\n");
		status = TraceDqrProfiler::DQERR_ERR;
		return status;
	}
#else // WINDOWS
	if ((br == -1) && ((errno != EAGAIN) && (errno != EWOULDBLOCK))) {
		printf("Error: bufferSWT(): read socket failed\n");
		status = TraceDqrProfiler::DQERR_ERR;
		return status;
	}
#endif // WINDOWS
#endif
	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr SliceFileParser::readBinaryMsg(bool& haveMsg)
{
    // start by stripping off end of message or end of var bytes. These would be here in the case
    // of a wrapped buffer, or some kind of corruption
    msgOffset = prev_offset;
	haveMsg = false;

	// if doing SWT, we may have ran out of data last time before getting an entire message
	// and pendingMsgIndex may not be 0. If not 0, pick up where we left off

	if (pendingMsgIndex == 0) {
		do {
			if (SWTsock >= 0) {
				//// need a buffer to read from.

				//status = bufferSWT();

				//if (status != TraceDqrProfiler::DQERR_OK) {
				//	return status;
				//}

				//if (bufferInIndex == bufferOutIndex) {
				//	return status;
				//}

				//msg[0] = sockBuffer[bufferOutIndex];
				//bufferOutIndex += 1;
				//if ((size_t)bufferOutIndex >= sizeof sockBuffer) {
				//	bufferOutIndex = 0;
				//}
			}
			else {

                // If the queue is empty, wait till we receive new trace data
                while (1)
                {
                    std::lock_guard<std::mutex> msg_queue_guard(m_msg_queue_mutex);
                    {
                        if (m_msg_queue.empty())
                        {
                            // If end of data flag is set, exit the loop
                            std::lock_guard<std::mutex> end_of_data_guard(m_end_of_data_mutex);
                            if (m_end_of_data == true)
                                return TraceDqrProfiler::DQERR_EOF;
                        }
                        else
                        {
                            // We have some data in queue
                            // Get the first byte
                            msg[0] = m_msg_queue.front();
                            m_msg_queue.pop_front();
                            prev_offset++;
                            break;
                        }
                    }
                }


				//tf.read((char*)&msg[0], sizeof msg[0]);
				//if (!tf) {
				//	if (tf.eof()) {
				//		status = TraceDqrProfiler::DQERR_EOF;
				//	}
				//	else {
				//		status = TraceDqrProfiler::DQERR_ERR;

				//		std::cout << "Error reading trace file\n";
				//	}

				//	tf.close();

				//	return status;
				//}
			}

			if ((msg[0] == 0x00) || (((msg[0] & 0x3) != TraceDqrProfiler::MSEO_NORMAL) && (msg[0] != 0xff))) {
				printf("Info: SliceFileParser::readBinaryMsg(): Skipping: %02x\n", msg[0]);
			}
		} while ((msg[0] == 0x00) || ((msg[0] & 0x3) != TraceDqrProfiler::MSEO_NORMAL));

		pendingMsgIndex = 1;
	}

	//if (SWTsock >= 0) {
	//	msgOffset = 0;
	//}
	//else {
	//	msgOffset = ((uint32_t)tf.tellg()) - 1;

	//}

	bool done = false;

	while (!done) {
#if 0
		if (pendingMsgIndex >= (int)(sizeof msg / sizeof msg[0])) {
			if (SWTsock >= 0) {
//#ifdef WINDOWS
//				closesocket(SWTsock);
//#else // WINDOWS
//				close(SWTsock);
//#endif // WINDOWS
//				SWTsock = -1;
			}
			else {
				tf.close();
			}

			std::cout << "Error: SliceFileParser::readBinaryMsg(): msg buffer overflow" << std::endl;

			pendingMsgIndex = 0;

			status = TraceDqrProfiler::DQERR_ERR;

			return TraceDqrProfiler::DQERR_ERR;
		}
#endif
		if (SWTsock >= 0) {
			status = bufferSWT();

			if (status != TraceDqrProfiler::DQERR_OK) {
				return status;
			}

			if (bufferInIndex == bufferOutIndex) {
				return status;
			}

			msg[pendingMsgIndex] = sockBuffer[bufferOutIndex];

			bufferOutIndex += 1;
			if ((size_t)bufferOutIndex >= sizeof sockBuffer) {
				bufferOutIndex = 0;
			}
		}
		else
        {
            while (1)
            {
                std::lock_guard<std::mutex> msg_queue_guard(m_msg_queue_mutex);
                {
                    if (m_msg_queue.empty())
                    {
                        // If end of data flag is set, exit the loop
                        std::lock_guard<std::mutex> end_of_data_guard(m_end_of_data_mutex);
                        if (m_end_of_data == true)
                            return TraceDqrProfiler::DQERR_EOF;
                    }
                    else
                    {
                        // We have some data in queue
                        // Get the first byte
                        msg[pendingMsgIndex] = m_msg_queue.front();
                        m_msg_queue.pop_front();
                        prev_offset++;
                        break;
                    }
                }
            }

			//tf.read((char*)&msg[pendingMsgIndex], sizeof msg[0]);
			//if (!tf) {
			//	if (tf.eof()) {
			//		printf("Info: SliceFileParser::readBinaryMsg(): Last message in trace file is incomplete\n");
			//		if (profiler_globalDebugFlag) {
			//			printf("Debug: Raw msg:");
			//			for (int i = 0; i < pendingMsgIndex; i++) {
			//				printf(" %02x", msg[i]);
			//			}
			//			printf("\n");
			//		}
			//		status = TraceDqrProfiler::DQERR_EOF;
			//	}
			//	else {
			//		status = TraceDqrProfiler::DQERR_ERR;

			//		std::cout << "Error reading trace file\n";
			//	}

			//	tf.close();

				//return status;
			//}
		}

		if ((msg[pendingMsgIndex] & 0x03) == TraceDqrProfiler::MSEO_END) {
			done = true;
			msgSlices = pendingMsgIndex + 1;
		}

		pendingMsgIndex += 1;
	}

	eom = false;
	bitIndex = 0;

	haveMsg = true;
	pendingMsgIndex = 0;

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr SliceFileParser::readNextByte(uint8_t* byte)
{
	char c;

	// strip white space, comments, cr, and lf

	enum {
		STRIPPING_WHITESPACE,
		STRIPPING_COMMENT,
		STRIPPING_DONE
	} ss = STRIPPING_WHITESPACE;

	do {
		tf.read((char*)&c, sizeof c);
		if (!tf) {
			tf.close();

			status = TraceDqrProfiler::DQERR_EOF;

			return TraceDqrProfiler::DQERR_EOF;
		}

		switch (ss) {
		case STRIPPING_WHITESPACE:
			switch (c) {
			case '#':
				ss = STRIPPING_COMMENT;
				break;
			case '\n':
			case '\r':
			case ' ':
			case '\t':
				break;
			default:
				ss = STRIPPING_DONE;
			}
			break;
		case STRIPPING_COMMENT:
			switch (c) {
			case '\n':
				ss = STRIPPING_WHITESPACE;
				break;
			}
			break;
		default:
			break;
		}
	} while (ss != STRIPPING_DONE);

	// now try to get two hex digits

	tf.read((char*)&c, sizeof c);
	if (!tf) {
		tf.close();

		status = TraceDqrProfiler::DQERR_EOF;

		return TraceDqrProfiler::DQERR_EOF;
	}

	int hd;
	uint8_t hn;

	hd = atoh(c);
	if (hd < 0) {
		status = TraceDqrProfiler::DQERR_ERR;

		return TraceDqrProfiler::DQERR_ERR;
	}

	hn = hd << 4;

	hd = atoh(c);
	if (hd < 0) {
		status = TraceDqrProfiler::DQERR_ERR;

		return TraceDqrProfiler::DQERR_ERR;
	}

	hn = hn | hd;

	*byte = hn;

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr SliceFileParser::readNextTraceMsg(ProfilerNexusMessage& nm, ProfilerAnalytics& analytics, bool& haveMsg)	// generator to read trace messages one at a time
{
	haveMsg = false;

	if (status != TraceDqrProfiler::DQERR_OK) {
		return status;
	}

	TraceDqrProfiler::DQErr rc;
	uint64_t   val;
	uint8_t    tcode;

	status = TraceDqrProfiler::DQERR_OK;

	// read from file, store in object, compute and fill out full fields, such as address and more later

	rc = readBinaryMsg(haveMsg);
	if (rc != TraceDqrProfiler::DQERR_OK) {

		// all errors from readBinaryMsg() are non-recoverable.

		if (rc != TraceDqrProfiler::DQERR_EOF) {
			std::cout << "Error: (): readNextTraceMsg() returned error " << rc << std::endl;
		}

		status = rc;

		return status;
	}

	if (haveMsg == false) {
		return TraceDqrProfiler::DQERR_OK;
	}

	nm.offset = msgOffset;

	int i = 0;

	do {
		nm.rawData[i] = msg[i];
		i += 1;
	} while (((size_t)i < sizeof nm.rawData / sizeof nm.rawData[0]) && ((msg[i - 1] & 0x03) != TraceDqrProfiler::MSEO_END));
	nm.size_message = i;

	rc = parseFixedField(6, &val);
	if (rc == TraceDqrProfiler::DQERR_OK) {
		tcode = (uint8_t)val;

		switch (tcode) {
		case TraceDqrProfiler::TCODE_DEBUG_STATUS:
			std::cout << "Unsupported debug status trace message\n";
			rc = TraceDqrProfiler::DQERR_ERR;
			break;
		case TraceDqrProfiler::TCODE_DEVICE_ID:
			std::cout << "Unsupported device id trace message\n";
			rc = TraceDqrProfiler::DQERR_ERR;
			break;
		case TraceDqrProfiler::TCODE_OWNERSHIP_TRACE:
			rc = parseOwnershipTrace(nm, analytics);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				std::cout << "Error: parseOwnershipTrace()\n";
			}
			break;
		case TraceDqrProfiler::TCODE_DIRECT_BRANCH:
			rc = parseDirectBranch(nm, analytics);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				std::cout << "Error: parseDirectBranch()\n";
			}
			break;
		case TraceDqrProfiler::TCODE_INDIRECT_BRANCH:
			rc = parseIndirectBranch(nm, analytics);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				std::cout << "Error: parseIndirectBranch()\n";
			}
			break;
		case TraceDqrProfiler::TCODE_DATA_WRITE:
			std::cout << "unsupported data write trace message\n";
			rc = TraceDqrProfiler::DQERR_ERR;
			break;
		case TraceDqrProfiler::TCODE_DATA_READ:
			std::cout << "unsupported data read trace message\n";
			rc = TraceDqrProfiler::DQERR_ERR;
			break;
		case TraceDqrProfiler::TCODE_DATA_ACQUISITION:
			rc = parseDataAcquisition(nm, analytics);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				std::cout << "Error: parseDataAcquisition()\n";
			}
			break;
		case TraceDqrProfiler::TCODE_ERROR:
			rc = parseError(nm, analytics);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				std::cout << "Error: parseError()\n";
			}
			break;
		case TraceDqrProfiler::TCODE_SYNC:
			rc = parseSync(nm, analytics);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				std::cout << "Error: parseSync()\n";
			}
			break;
		case TraceDqrProfiler::TCODE_CORRECTION:
			std::cout << "Unsupported correction trace message\n";
			rc = TraceDqrProfiler::DQERR_ERR;
			break;
		case TraceDqrProfiler::TCODE_DIRECT_BRANCH_WS:
			rc = parseDirectBranchWS(nm, analytics);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				std::cout << "Error: parseDirectBranchWS()\n";
			}
			break;
		case TraceDqrProfiler::TCODE_INDIRECT_BRANCH_WS:
			rc = parseIndirectBranchWS(nm, analytics);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				std::cout << "Error: parseDirectIndirectBranchWS()\n";
			}
			break;
		case TraceDqrProfiler::TCODE_DATA_WRITE_WS:
			std::cout << "unsupported data write with sync trace message\n";
			rc = TraceDqrProfiler::DQERR_ERR;
			break;
		case TraceDqrProfiler::TCODE_DATA_READ_WS:
			std::cout << "unsupported data read with sync trace message\n";
			rc = TraceDqrProfiler::DQERR_ERR;
			break;
		case TraceDqrProfiler::TCODE_WATCHPOINT:
			std::cout << "unsupported watchpoint trace message\n";
			rc = TraceDqrProfiler::DQERR_ERR;
			break;
		case TraceDqrProfiler::TCODE_CORRELATION:
			rc = parseCorrelation(nm, analytics);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				std::cout << "Error: parseCorrelation()\n";
			}
			break;
		case TraceDqrProfiler::TCODE_AUXACCESS_WRITE:
			rc = parseAuxAccessWrite(nm, analytics);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				std::cout << "Error: parseAuxAccessWrite()\n";
			}
			break;
		case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY:
			rc = parseIndirectHistory(nm, analytics);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				std::cout << "Error: parseIndirectHistory()\n";
			}
			break;
		case TraceDqrProfiler::TCODE_INDIRECTBRANCHHISTORY_WS:
			rc = parseIndirectHistoryWS(nm, analytics);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				std::cout << "Error: parseIndirectHisotryWS()\n";
			}
			break;
		case TraceDqrProfiler::TCODE_INCIRCUITTRACE:
			rc = parseICT(nm, analytics);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				std::cout << "Error: parseICT()\n";
			}
			break;
		case TraceDqrProfiler::TCODE_INCIRCUITTRACE_WS:
			rc = parseICTWS(nm, analytics);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				std::cout << "Error: parseICTWS()\n";
			}
			break;
		case TraceDqrProfiler::TCODE_RESOURCEFULL:
			rc = parseResourceFull(nm, analytics);
			if (rc != TraceDqrProfiler::DQERR_OK) {
				std::cout << "Error: parseResourceFull()\n";
			}
			break;
		default:
			std::cout << "Error: readNextTraceMsg(): Unknown TCODE " << std::hex << int(tcode) << std::dec << std::endl;
			rc = TraceDqrProfiler::DQERR_ERR;
		}
	}

	if (rc != TraceDqrProfiler::DQERR_OK) {
		std::cout << "Error possibly due to corrupted message in trace - skipping message" << std::endl;
		if (profiler_globalDebugFlag) {
			nm.msgNum += 1;
			nm.dumpRawMessage();
		}

		haveMsg = false;
	}

	status = TraceDqrProfiler::DQERR_OK;

	return status;
}

ProfilerObjFile::ProfilerObjFile(char* ef_name, const char* odExe)
{
	elfReader = nullptr;
	//	symtab = nullptr;
	disassembler = nullptr;

	if (ef_name == nullptr) {
		printf("Error: ProfilerObjFile::ProfilerObjFile(): null of_name argument\n");

		status = TraceDqrProfiler::DQERR_ERR;

		return;
	}

	elfReader = new (std::nothrow) ElfReader(ef_name, odExe);

	if (elfReader == nullptr) {
		printf("Error: ProfilerObjFile::Objfile(): Could not create elfRedaer object\n");
		status = TraceDqrProfiler::DQERR_ERR;
		return;
	}

	if (elfReader->getStatus() != TraceDqrProfiler::DQERR_OK) {
		delete elfReader;
		elfReader = nullptr;

		status = TraceDqrProfiler::DQERR_ERR;

		return;
	}

	Symtab* symtab;
	Section* sections;

	symtab = elfReader->getSymtab();
	if (symtab == nullptr) {
		delete elfReader;
		elfReader = nullptr;

		printf("Error: Objfile::Objfile(): Could not get symtab\n");
		status = TraceDqrProfiler::DQERR_ERR;
		return;
	}

	sections = elfReader->getSections();
	if (sections == nullptr) {
		delete elfReader;
		elfReader = nullptr;

		printf("Error: Objfile::Objfile(): coult not get sections\n");
		status = TraceDqrProfiler::DQERR_ERR;
		return;
	}

	int archSize;
	archSize = elfReader->getArchSize();

	disassembler = new (std::nothrow) Disassembler(symtab, sections, archSize);

	if (disassembler == nullptr) {
		delete elfReader;
		elfReader = nullptr;

		printf("ProfilerObjFile::ProfilerObjFile(): Coudl not create disassembler object\n");
		status = TraceDqrProfiler::DQERR_ERR;
		return;
	}

	if (disassembler->getStatus() != TraceDqrProfiler::DQERR_OK) {
		if (elfReader != nullptr) {
			delete elfReader;
			elfReader = nullptr;
		}

		delete disassembler;
		disassembler = nullptr;

		status = TraceDqrProfiler::DQERR_ERR;

		return;
	}

	cutPath = nullptr;
	newRoot = nullptr;

	status = TraceDqrProfiler::DQERR_OK;
}

ProfilerObjFile::~ProfilerObjFile()
{
	cleanUp();
}

void ProfilerObjFile::cleanUp()
{
	if (cutPath != nullptr) {
		delete[] cutPath;
		cutPath = nullptr;
	}

	if (newRoot != nullptr) {
		delete[] newRoot;
		newRoot = nullptr;
	}

	if (elfReader != nullptr) {
		delete elfReader;
		elfReader = nullptr;
	}

	if (disassembler != nullptr) {
		delete disassembler;
		disassembler = nullptr;
	}
}

TraceDqrProfiler::DQErr ProfilerObjFile::subSrcPath(const char* cutPath, const char* newRoot)
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

	return TraceDqrProfiler::DQERR_ERR;
}

TraceDqrProfiler::DQErr ProfilerObjFile::sourceInfo(TraceDqrProfiler::ADDRESS addr, ProfilerInstruction& instInfo, ProfilerSource& srcInfo)
{
	TraceDqrProfiler::DQErr s;

	if (disassembler == nullptr) {
		printf("Error: ProfilerObjFile::sourceInfo(): Disassembler object null\n");
		status = TraceDqrProfiler::DQERR_ERR;
		return status;
	}

	s = disassembler->disassemble(addr);
	if (s != TraceDqrProfiler::DQERR_OK) {
		status = s;
		return s;
	}

	//	instructionInfo = disassembler->getInstructionInfo();
	srcInfo = disassembler->getSourceInfo();
	instInfo = disassembler->getInstructionInfo();

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr ProfilerObjFile::setPathType(TraceDqrProfiler::pathType pt)
{
	if (disassembler != nullptr) {
		disassembler->setPathType(pt);

		return TraceDqrProfiler::DQERR_OK;
	}

	return TraceDqrProfiler::DQERR_ERR;
}

TraceDqrProfiler::DQErr ProfilerObjFile::parseNLSStrings(TraceDqrProfiler::nlStrings(&nlsStrings)[32])
{
	if (elfReader == nullptr) {
		status = TraceDqrProfiler::DQERR_ERR;
		return TraceDqrProfiler::DQERR_ERR;
	}

	return elfReader->parseNLSStrings(nlsStrings);
}

TraceDqrProfiler::DQErr ProfilerObjFile::dumpSyms()
{
	if (elfReader == nullptr) {
		printf("elfReader is null\n");

		status = TraceDqrProfiler::DQERR_ERR;
		return TraceDqrProfiler::DQERR_ERR;
	}

	return elfReader->dumpSyms();
}

Disassembler::Disassembler(Symtab* stp, Section* sp, int archsize)
{
	status = TraceDqrProfiler::DQERR_OK;

	if (stp == nullptr) {
		printf("Error: Disassembler::Disassembler(): stp argument is null\n");

		status = TraceDqrProfiler::DQERR_ERR;
		return;
	}

	if (sp == nullptr) {
		printf("Error: Disassembler::Disassembler(): sp argument is null\n");

		status = TraceDqrProfiler::DQERR_ERR;
		return;
	}

	archSize = archsize;

	pType = TraceDqrProfiler::PATH_TO_UNIX;

	cachedAddr = 0;
	cachedSecPtr = nullptr;
	cachedIndex = -1;

	symtab = stp;
	sectionLst = sp;

	fileReader = new class fileReader();

	status = TraceDqrProfiler::DQERR_OK;
}

Disassembler::~Disassembler()
{
	// the following three pointers point to objects owned by the elfReader object, and the
	// elfReader object will delete.

	sectionLst = nullptr;
	symtab = nullptr;
	cachedSecPtr = nullptr;

	if (fileReader != nullptr) {
		delete fileReader;
		fileReader = nullptr;
	}
}

TraceDqrProfiler::DQErr Disassembler::setPathType(TraceDqrProfiler::pathType pt)
{
	TraceDqrProfiler::DQErr rc;
	rc = TraceDqrProfiler::DQERR_OK;

	switch (pt) {
	case TraceDqrProfiler::PATH_TO_WINDOWS:
		pType = TraceDqrProfiler::PATH_TO_WINDOWS;
		break;
	case TraceDqrProfiler::PATH_TO_UNIX:
		pType = TraceDqrProfiler::PATH_TO_UNIX;
		break;
	case TraceDqrProfiler::PATH_RAW:
		pType = TraceDqrProfiler::PATH_RAW;
		break;
	default:
		pType = TraceDqrProfiler::PATH_TO_UNIX;
		rc = TraceDqrProfiler::DQERR_ERR;
		break;
	}

	return rc;
}

TraceDqrProfiler::DQErr Disassembler::subSrcPath(const char* cutPath, const char* newRoot)
{
	if (fileReader != nullptr) {
		TraceDqrProfiler::DQErr rc;

		rc = fileReader->subSrcPath(cutPath, newRoot);

		status = rc;
		return rc;
	}

	return TraceDqrProfiler::DQERR_ERR;
}

TraceDqrProfiler::DQErr Disassembler::lookupInstructionByAddress(TraceDqrProfiler::ADDRESS addr, uint32_t& ins, int& insSize)
{
	uint32_t inst;
	int size;
	TraceDqrProfiler::DQErr rc;

	// need to support multiple code sections and do some error checking on the address!

	if (sectionLst == nullptr) {
		status = TraceDqrProfiler::DQERR_ERR;

		return TraceDqrProfiler::DQERR_ERR;
	}

	if (addr != cachedAddr) {
		TraceDqrProfiler::DQErr rc;

		rc = cacheSrcInfo(addr);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			return TraceDqrProfiler::DQERR_ERR;;
		}
	}


	if (cachedSecPtr == nullptr) {
		status = TraceDqrProfiler::DQERR_ERR;

		return TraceDqrProfiler::DQERR_ERR;
	}

	inst = (uint32_t)cachedSecPtr->code[cachedIndex];

	rc = decodeInstructionSize(inst, size);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = TraceDqrProfiler::DQERR_ERR;

		return TraceDqrProfiler::DQERR_ERR;
	}

	insSize = size;

	if (size == 16) {
		ins = inst;
	}
	else {
		ins = (((uint32_t)cachedSecPtr->code[cachedIndex + 1]) << 16) | inst;
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr Disassembler::decodeInstructionSize(uint32_t inst, int& inst_size)
{
	switch (inst & 0x0003) {
	case 0x0000:	// quadrant 0, compressed
		inst_size = 16;
		return TraceDqrProfiler::DQERR_OK;
	case 0x0001:	// quadrant 1, compressed
		inst_size = 16;
		return TraceDqrProfiler::DQERR_OK;
	case 0x0002:	// quadrant 2, compressed
		inst_size = 16;
		return TraceDqrProfiler::DQERR_OK;
	case 0x0003:	// not compressed. Assume RV32 for now
		if ((inst & 0x1f) == 0x1f) {
			fprintf(stderr, "Error: decode_instruction(): cann't decode instructions longer than 32 bits\n");
			return TraceDqrProfiler::DQERR_ERR;
		}

		inst_size = 32;
		return TraceDqrProfiler::DQERR_OK;
	}

	// error return

	return TraceDqrProfiler::DQERR_ERR;
}

#define MOVE_BIT(bits,s,d)	(((bits)&(1<<(s)))?(1<<(d)):0)

int Disassembler::decodeRV32Q0Instruction(uint32_t instruction, int& inst_size, TraceDqrProfiler::InstType& inst_type, TraceDqrProfiler::Reg& rs1, TraceDqrProfiler::Reg& rd, int32_t& immediate, bool& is_branch)
{
	// no branch or jump instruction in quadrant 0

	inst_size = 16;
	is_branch = false;
	immediate = 0;

	if ((instruction & 0x0003) != 0x0000) {
		return 1;
	}

	// we only crare about rs1 and rd for branch instructions, so just set them to unknown for now
	rs1 = TraceDqrProfiler::REG_unknown;
	rd = TraceDqrProfiler::REG_unknown;

	inst_type = TraceDqrProfiler::INST_UNKNOWN;

	return 0;
}

int Disassembler::decodeRV32Q1Instruction(uint32_t instruction, int& inst_size, TraceDqrProfiler::InstType& inst_type, TraceDqrProfiler::Reg& rs1, TraceDqrProfiler::Reg& rd, int32_t& immediate, bool& is_branch)
{
	// Q1 compressed instruction

	uint32_t t;

	inst_size = 16;

	switch (instruction >> 13) {
	case 0x1:
		inst_type = TraceDqrProfiler::INST_C_JAL;
		is_branch = true;

		t = MOVE_BIT(instruction, 3, 1);
		t |= MOVE_BIT(instruction, 4, 2);
		t |= MOVE_BIT(instruction, 5, 3);
		t |= MOVE_BIT(instruction, 11, 4);
		t |= MOVE_BIT(instruction, 2, 5);
		t |= MOVE_BIT(instruction, 7, 6);
		t |= MOVE_BIT(instruction, 6, 7);
		t |= MOVE_BIT(instruction, 9, 8);
		t |= MOVE_BIT(instruction, 10, 9);
		t |= MOVE_BIT(instruction, 8, 10);
		t |= MOVE_BIT(instruction, 12, 11);

		if (t & (1 << 11)) { // sign extend offset
			t |= 0xfffff000;
		}

		immediate = t;

		rs1 = TraceDqrProfiler::REG_unknown;
		rd = TraceDqrProfiler::REG_1;
		break;
	case 0x5:
		inst_type = TraceDqrProfiler::INST_C_J;
		is_branch = true;

		t = MOVE_BIT(instruction, 3, 1);
		t |= MOVE_BIT(instruction, 4, 2);
		t |= MOVE_BIT(instruction, 5, 3);
		t |= MOVE_BIT(instruction, 11, 4);
		t |= MOVE_BIT(instruction, 2, 5);
		t |= MOVE_BIT(instruction, 7, 6);
		t |= MOVE_BIT(instruction, 6, 7);
		t |= MOVE_BIT(instruction, 9, 8);
		t |= MOVE_BIT(instruction, 10, 9);
		t |= MOVE_BIT(instruction, 8, 10);
		t |= MOVE_BIT(instruction, 12, 11);

		if (t & (1 << 11)) { // sign extend offset
			t |= 0xfffff000;
		}

		rs1 = TraceDqrProfiler::REG_unknown;
		rd = TraceDqrProfiler::REG_0;

		immediate = t;
		break;
	case 0x6:
		inst_type = TraceDqrProfiler::INST_C_BEQZ;
		is_branch = true;

		t = MOVE_BIT(instruction, 3, 1);
		t |= MOVE_BIT(instruction, 4, 2);
		t |= MOVE_BIT(instruction, 10, 3);
		t |= MOVE_BIT(instruction, 11, 4);
		t |= MOVE_BIT(instruction, 2, 5);
		t |= MOVE_BIT(instruction, 5, 6);
		t |= MOVE_BIT(instruction, 6, 7);
		t |= MOVE_BIT(instruction, 12, 8);

		if (t & (1 << 8)) { // sign extend offset
			t |= 0xfffffe00;
		}

		rs1 = (TraceDqrProfiler::Reg)((instruction >> 7) & 0x03);
		rd = TraceDqrProfiler::REG_unknown;

		immediate = t;
		break;
	case 0x7:
		inst_type = TraceDqrProfiler::INST_C_BNEZ;
		is_branch = true;

		t = MOVE_BIT(instruction, 3, 1);
		t |= MOVE_BIT(instruction, 4, 2);
		t |= MOVE_BIT(instruction, 10, 3);
		t |= MOVE_BIT(instruction, 11, 4);
		t |= MOVE_BIT(instruction, 2, 5);
		t |= MOVE_BIT(instruction, 5, 6);
		t |= MOVE_BIT(instruction, 6, 7);
		t |= MOVE_BIT(instruction, 12, 8);

		if (t & (1 << 8)) { // sign extend offset
			t |= 0xfffffe00;
		}

		rs1 = (TraceDqrProfiler::Reg)((instruction >> 7) & 0x03);
		rd = TraceDqrProfiler::REG_unknown;

		immediate = t;
		break;
	default:
		rs1 = TraceDqrProfiler::REG_unknown;
		rd = TraceDqrProfiler::REG_unknown;
		inst_type = TraceDqrProfiler::INST_UNKNOWN;
		immediate = 0;
		is_branch = 0;
		break;
	}

	return 0;
}

int Disassembler::decodeRV32Q2Instruction(uint32_t instruction, int& inst_size, TraceDqrProfiler::InstType& inst_type, TraceDqrProfiler::Reg& rs1, TraceDqrProfiler::Reg& rd, int32_t& immediate, bool& is_branch)
{
	// Q1 compressed instruction

	inst_size = 16;

	inst_type = TraceDqrProfiler::INST_UNKNOWN;
	is_branch = false;
	rs1 = TraceDqrProfiler::REG_unknown;
	rd = TraceDqrProfiler::REG_unknown;

	switch (instruction >> 13) {
	case 0x4:
		if (instruction & (1 << 12)) {
			if ((instruction & 0x007c) == 0x0000) {
				if ((instruction & 0x0f80) != 0x0000) {
					inst_type = TraceDqrProfiler::INST_C_JALR;
					is_branch = true;

					rs1 = (TraceDqrProfiler::Reg)((instruction >> 7) & 0x1f);
					rd = TraceDqrProfiler::REG_1;
					immediate = 0;
				}
				else {
					inst_type = TraceDqrProfiler::INST_C_EBREAK;
					immediate = 0;
					is_branch = true;
				}
			}
		}
		else {
			if ((instruction & 0x007c) == 0x0000) {
				if ((instruction & 0x0f80) != 0x0000) {
					inst_type = TraceDqrProfiler::INST_C_JR;
					is_branch = true;

					rs1 = (TraceDqrProfiler::Reg)((instruction >> 7) & 0x1f);
					rd = TraceDqrProfiler::REG_0;
					immediate = 0;
				}
			}
		}
		break;
	default:
		break;
	}

	return 0;
}

int Disassembler::decodeRV32Instruction(uint32_t instruction, int& inst_size, TraceDqrProfiler::InstType& inst_type, TraceDqrProfiler::Reg& rs1, TraceDqrProfiler::Reg& rd, int32_t& immediate, bool& is_branch)
{
	if ((instruction & 0x1f) == 0x1f) {
		fprintf(stderr, "Error: decodeBranch(): cann't decode instructions longer than 32 bits\n");
		return 1;
	}

	uint32_t t;

	inst_size = 32;

	switch (instruction & 0x7f) {
	case 0x6f:
		inst_type = TraceDqrProfiler::INST_JAL;
		is_branch = true;

		t = MOVE_BIT(instruction, 21, 1);
		t |= MOVE_BIT(instruction, 22, 2);
		t |= MOVE_BIT(instruction, 23, 3);
		t |= MOVE_BIT(instruction, 24, 4);
		t |= MOVE_BIT(instruction, 25, 5);
		t |= MOVE_BIT(instruction, 26, 6);
		t |= MOVE_BIT(instruction, 27, 7);
		t |= MOVE_BIT(instruction, 28, 8);
		t |= MOVE_BIT(instruction, 29, 9);
		t |= MOVE_BIT(instruction, 30, 10);
		t |= MOVE_BIT(instruction, 20, 11);
		t |= MOVE_BIT(instruction, 12, 12);
		t |= MOVE_BIT(instruction, 13, 13);
		t |= MOVE_BIT(instruction, 14, 14);
		t |= MOVE_BIT(instruction, 15, 15);
		t |= MOVE_BIT(instruction, 16, 16);
		t |= MOVE_BIT(instruction, 17, 17);
		t |= MOVE_BIT(instruction, 18, 18);
		t |= MOVE_BIT(instruction, 19, 19);
		t |= MOVE_BIT(instruction, 31, 20);

		if (t & (1 << 20)) { // sign extend offset
			t |= 0xffe00000;
		}

		immediate = t;
		rd = (TraceDqrProfiler::Reg)((instruction >> 7) & 0x1f);
		rs1 = TraceDqrProfiler::REG_unknown;
		break;
	case 0x67:
		if ((instruction & 0x7000) == 0x000) {
			inst_type = TraceDqrProfiler::INST_JALR;
			is_branch = true;

			t = instruction >> 20;

			if (t & (1 << 11)) { // sign extend offset
				t |= 0xfffff000;
			}

			immediate = t;
			rd = (TraceDqrProfiler::Reg)((instruction >> 7) & 0x1f);
			rs1 = (TraceDqrProfiler::Reg)((instruction >> 15) & 0x1f);
		}
		else {
			inst_type = TraceDqrProfiler::INST_UNKNOWN;
			immediate = 0;
			rd = TraceDqrProfiler::REG_unknown;
			rs1 = TraceDqrProfiler::REG_unknown;
			is_branch = false;
		}
		break;
	case 0x63:
		switch ((instruction >> 12) & 0x7) {
		case 0x0:
			inst_type = TraceDqrProfiler::INST_BEQ;
			break;
		case 0x1:
			inst_type = TraceDqrProfiler::INST_BNE;
			break;
		case 0x4:
			inst_type = TraceDqrProfiler::INST_BLT;
			break;
		case 0x5:
			inst_type = TraceDqrProfiler::INST_BGE;
			break;
		case 0x6:
			inst_type = TraceDqrProfiler::INST_BLTU;
			break;
		case 0x7:
			inst_type = TraceDqrProfiler::INST_BGEU;
			break;
		default:
			inst_type = TraceDqrProfiler::INST_UNKNOWN;
			immediate = 0;
			rd = TraceDqrProfiler::REG_unknown;
			rs1 = TraceDqrProfiler::REG_unknown;
			is_branch = false;
			return 0;
		}

		is_branch = true;

		t = MOVE_BIT(instruction, 8, 1);
		t |= MOVE_BIT(instruction, 9, 2);
		t |= MOVE_BIT(instruction, 10, 3);
		t |= MOVE_BIT(instruction, 11, 4);
		t |= MOVE_BIT(instruction, 25, 5);
		t |= MOVE_BIT(instruction, 26, 6);
		t |= MOVE_BIT(instruction, 27, 7);
		t |= MOVE_BIT(instruction, 28, 8);
		t |= MOVE_BIT(instruction, 29, 9);
		t |= MOVE_BIT(instruction, 30, 10);
		t |= MOVE_BIT(instruction, 7, 11);
		t |= MOVE_BIT(instruction, 31, 12);

		if (t & (1 << 12)) { // sign extend offset
			t |= 0xffffe000;
		}

		immediate = t;
		rd = TraceDqrProfiler::REG_unknown;
		rs1 = (TraceDqrProfiler::Reg)((instruction >> 15) & 0x1f);
		break;
	case 0x73:
		if (instruction == 0x00200073) {
			inst_type = TraceDqrProfiler::INST_URET;
			is_branch = true;
			immediate = 0;
		}
		else if (instruction == 0x10200073) {
			inst_type = TraceDqrProfiler::INST_SRET;
			is_branch = true;
			immediate = 0;
		}
		else if (instruction == 0x30200073) {
			inst_type = TraceDqrProfiler::INST_MRET;
			is_branch = true;
			immediate = 0;
		}
		else if (instruction == 0x00000073) {
			inst_type = TraceDqrProfiler::INST_ECALL;
			immediate = 0;
			is_branch = true;
		}
		else if (instruction == 0x00100073) {
			inst_type = TraceDqrProfiler::INST_EBREAK;
			immediate = 0;
			is_branch = true;
		}
		else {
			inst_type = TraceDqrProfiler::INST_UNKNOWN;
			immediate = 0;
			rd = TraceDqrProfiler::REG_unknown;
			rs1 = TraceDqrProfiler::REG_unknown;
			is_branch = false;
		}
		break;
	case 0x07: // vector load
		// Need to check width encoding field to distinguish between vector and normal FP loads (bits 12-14)
		switch ((instruction >> 12) & 0x07) {
		case 0x00:
		case 0x05:
		case 0x06:
		case 0x07:
			inst_type = TraceDqrProfiler::INST_VECT_LOAD;
			break;
		default:
			inst_type = TraceDqrProfiler::INST_UNKNOWN;
			break;
		}

		is_branch = false;
		immediate = 0;
		rd = TraceDqrProfiler::REG_unknown;
		rs1 = TraceDqrProfiler::REG_unknown;
		break;
	case 0x27: // vector store
		// Need to check width encoding field to distinguish between vector and normal FP stores (bits 12-14)
		switch ((instruction >> 12) & 0x07) {
		case 0x00:
		case 0x05:
		case 0x06:
		case 0x07:
			inst_type = TraceDqrProfiler::INST_VECT_STORE;
			break;
		default:
			inst_type = TraceDqrProfiler::INST_UNKNOWN;
			break;
		}

		is_branch = false;
		immediate = 0;
		rd = TraceDqrProfiler::REG_unknown;
		rs1 = TraceDqrProfiler::REG_unknown;
		break;
	case 0x2f: // vector AMO
		// Need to check width encoding field to distinguish between vector and normal AMO (bits 26-28)
		switch ((instruction >> 12) & 0x07) {
		case 0x00:
		case 0x05:
		case 0x06:
		case 0x07:
			if ((instruction >> 26) & 0x01) {
				inst_type = TraceDqrProfiler::INST_VECT_AMO_WW;
			}
			else {
				inst_type = TraceDqrProfiler::INST_VECT_AMO;
			}
			break;
		default:
			inst_type = TraceDqrProfiler::INST_UNKNOWN;
			break;
		}

		is_branch = false;
		immediate = 0;
		rd = TraceDqrProfiler::REG_unknown;
		rs1 = TraceDqrProfiler::REG_unknown;
		break;
	case 0x57: // vector arith or vector config
		if (((instruction >> 12) & 0x7) <= 6) {
			inst_type = TraceDqrProfiler::INST_VECT_ARITH;
		}
		else {
			inst_type = TraceDqrProfiler::INST_VECT_CONFIG;
		}

		immediate = 0;
		rd = TraceDqrProfiler::REG_unknown;
		rs1 = TraceDqrProfiler::REG_unknown;
		is_branch = false;
		break;
	default:
		inst_type = TraceDqrProfiler::INST_UNKNOWN;
		immediate = 0;
		rd = TraceDqrProfiler::REG_unknown;
		rs1 = TraceDqrProfiler::REG_unknown;
		is_branch = false;
		break;
	}

	return 0;
}

int Disassembler::decodeRV64Q0Instruction(uint32_t instruction, int& inst_size, TraceDqrProfiler::InstType& inst_type, TraceDqrProfiler::Reg& rs1, TraceDqrProfiler::Reg& rd, int32_t& immediate, bool& is_branch)
{
	// no branch or jump instruction in quadrant 0

	inst_size = 16;
	is_branch = false;
	immediate = 0;

	if ((instruction & 0x0003) != 0x0000) {
		return 1;
	}

	// we only crare about rs1 and rd for branch instructions, so just set them to unknown for now
	rs1 = TraceDqrProfiler::REG_unknown;
	rd = TraceDqrProfiler::REG_unknown;

	inst_type = TraceDqrProfiler::INST_UNKNOWN;

	return 0;
}

int Disassembler::decodeRV64Q1Instruction(uint32_t instruction, int& inst_size, TraceDqrProfiler::InstType& inst_type, TraceDqrProfiler::Reg& rs1, TraceDqrProfiler::Reg& rd, int32_t& immediate, bool& is_branch)
{
	// Q1 compressed instruction

	uint32_t t;

	inst_size = 16;

	switch (instruction >> 13) {
	case 0x5:
		inst_type = TraceDqrProfiler::INST_C_J;
		is_branch = true;

		t = MOVE_BIT(instruction, 3, 1);
		t |= MOVE_BIT(instruction, 4, 2);
		t |= MOVE_BIT(instruction, 5, 3);
		t |= MOVE_BIT(instruction, 11, 4);
		t |= MOVE_BIT(instruction, 2, 5);
		t |= MOVE_BIT(instruction, 7, 6);
		t |= MOVE_BIT(instruction, 6, 7);
		t |= MOVE_BIT(instruction, 9, 8);
		t |= MOVE_BIT(instruction, 10, 9);
		t |= MOVE_BIT(instruction, 8, 10);
		t |= MOVE_BIT(instruction, 12, 11);

		if (t & (1 << 11)) { // sign extend offset
			t |= 0xfffff000;
		}

		rs1 = TraceDqrProfiler::REG_unknown;
		rd = TraceDqrProfiler::REG_0;

		immediate = t;
		break;
	case 0x6:
		inst_type = TraceDqrProfiler::INST_C_BEQZ;
		is_branch = true;

		t = MOVE_BIT(instruction, 3, 1);
		t |= MOVE_BIT(instruction, 4, 2);
		t |= MOVE_BIT(instruction, 10, 3);
		t |= MOVE_BIT(instruction, 11, 4);
		t |= MOVE_BIT(instruction, 2, 5);
		t |= MOVE_BIT(instruction, 5, 6);
		t |= MOVE_BIT(instruction, 6, 7);
		t |= MOVE_BIT(instruction, 12, 8);

		if (t & (1 << 8)) { // sign extend offset
			t |= 0xfffffe00;
		}

		rs1 = (TraceDqrProfiler::Reg)((instruction >> 7) & 0x03);
		rd = TraceDqrProfiler::REG_unknown;

		immediate = t;
		break;
	case 0x7:
		inst_type = TraceDqrProfiler::INST_C_BNEZ;
		is_branch = true;

		t = MOVE_BIT(instruction, 3, 1);
		t |= MOVE_BIT(instruction, 4, 2);
		t |= MOVE_BIT(instruction, 10, 3);
		t |= MOVE_BIT(instruction, 11, 4);
		t |= MOVE_BIT(instruction, 2, 5);
		t |= MOVE_BIT(instruction, 5, 6);
		t |= MOVE_BIT(instruction, 6, 7);
		t |= MOVE_BIT(instruction, 12, 8);

		if (t & (1 << 8)) { // sign extend offset
			t |= 0xfffffe00;
		}

		rs1 = (TraceDqrProfiler::Reg)((instruction >> 7) & 0x03);
		rd = TraceDqrProfiler::REG_unknown;

		immediate = t;
		break;
	default:
		rs1 = TraceDqrProfiler::REG_unknown;
		rd = TraceDqrProfiler::REG_unknown;
		inst_type = TraceDqrProfiler::INST_UNKNOWN;
		immediate = 0;
		is_branch = 0;
		break;
	}

	return 0;
}

int Disassembler::decodeRV64Q2Instruction(uint32_t instruction, int& inst_size, TraceDqrProfiler::InstType& inst_type, TraceDqrProfiler::Reg& rs1, TraceDqrProfiler::Reg& rd, int32_t& immediate, bool& is_branch)
{
	// Q2 compressed instruction

	inst_size = 16;

	inst_type = TraceDqrProfiler::INST_UNKNOWN;
	is_branch = false;
	rs1 = TraceDqrProfiler::REG_unknown;
	rd = TraceDqrProfiler::REG_unknown;

	switch (instruction >> 13) {
	case 0x4:
		if (instruction & (1 << 12)) {
			if ((instruction & 0x007c) == 0x0000) {
				if ((instruction & 0x0f80) != 0x0000) {
					inst_type = TraceDqrProfiler::INST_C_JALR;
					is_branch = true;

					rs1 = (TraceDqrProfiler::Reg)((instruction >> 7) & 0x1f);
					rd = TraceDqrProfiler::REG_1;
					immediate = 0;
				}
				else {
					inst_type = TraceDqrProfiler::INST_EBREAK;
					immediate = 0;
					is_branch = true;
				}
			}
		}
		else {
			if ((instruction & 0x007c) == 0x0000) {
				if ((instruction & 0x0f80) != 0x0000) {
					inst_type = TraceDqrProfiler::INST_C_JR;
					is_branch = true;

					rs1 = (TraceDqrProfiler::Reg)((instruction >> 7) & 0x1f);
					rd = TraceDqrProfiler::REG_0;
					immediate = 0;
				}
			}
		}
		break;
	default:
		break;
	}

	return 0;
}

int Disassembler::decodeRV64Instruction(uint32_t instruction, int& inst_size, TraceDqrProfiler::InstType& inst_type, TraceDqrProfiler::Reg& rs1, TraceDqrProfiler::Reg& rd, int32_t& immediate, bool& is_branch)
{
	if ((instruction & 0x1f) == 0x1f) {
		fprintf(stderr, "Error: decodeRV64Instruction(): cann't decode instructions longer than 32 bits\n");
		return 1;
	}

	uint32_t t;

	inst_size = 32;

	switch (instruction & 0x7f) {
	case 0x6f:
		inst_type = TraceDqrProfiler::INST_JAL;
		is_branch = true;

		t = MOVE_BIT(instruction, 21, 1);
		t |= MOVE_BIT(instruction, 22, 2);
		t |= MOVE_BIT(instruction, 23, 3);
		t |= MOVE_BIT(instruction, 24, 4);
		t |= MOVE_BIT(instruction, 25, 5);
		t |= MOVE_BIT(instruction, 26, 6);
		t |= MOVE_BIT(instruction, 27, 7);
		t |= MOVE_BIT(instruction, 28, 8);
		t |= MOVE_BIT(instruction, 29, 9);
		t |= MOVE_BIT(instruction, 30, 10);
		t |= MOVE_BIT(instruction, 20, 11);
		t |= MOVE_BIT(instruction, 12, 12);
		t |= MOVE_BIT(instruction, 13, 13);
		t |= MOVE_BIT(instruction, 14, 14);
		t |= MOVE_BIT(instruction, 15, 15);
		t |= MOVE_BIT(instruction, 16, 16);
		t |= MOVE_BIT(instruction, 17, 17);
		t |= MOVE_BIT(instruction, 18, 18);
		t |= MOVE_BIT(instruction, 19, 19);
		t |= MOVE_BIT(instruction, 31, 20);

		if (t & (1 << 20)) { // sign extend offset
			t |= 0xffe00000;
		}

		immediate = t;
		rd = (TraceDqrProfiler::Reg)((instruction >> 7) & 0x1f);
		rs1 = TraceDqrProfiler::REG_unknown;
		break;
	case 0x67:
		if ((instruction & 0x7000) == 0x000) {
			inst_type = TraceDqrProfiler::INST_JALR;
			is_branch = true;

			t = instruction >> 20;

			if (t & (1 << 11)) { // sign extend offset
				t |= 0xfffff000;
			}

			immediate = t;
			rd = (TraceDqrProfiler::Reg)((instruction >> 7) & 0x1f);
			rs1 = (TraceDqrProfiler::Reg)((instruction >> 15) & 0x1f);
		}
		else {
			inst_type = TraceDqrProfiler::INST_UNKNOWN;
			immediate = 0;
			rd = TraceDqrProfiler::REG_unknown;
			rs1 = TraceDqrProfiler::REG_unknown;
			is_branch = false;
		}
		break;
	case 0x63:
		switch ((instruction >> 12) & 0x7) {
		case 0x0:
			inst_type = TraceDqrProfiler::INST_BEQ;
			break;
		case 0x1:
			inst_type = TraceDqrProfiler::INST_BNE;
			break;
		case 0x4:
			inst_type = TraceDqrProfiler::INST_BLT;
			break;
		case 0x5:
			inst_type = TraceDqrProfiler::INST_BGE;
			break;
		case 0x6:
			inst_type = TraceDqrProfiler::INST_BLTU;
			break;
		case 0x7:
			inst_type = TraceDqrProfiler::INST_BGEU;
			break;
		default:
			inst_type = TraceDqrProfiler::INST_UNKNOWN;
			immediate = 0;
			rd = TraceDqrProfiler::REG_unknown;
			rs1 = TraceDqrProfiler::REG_unknown;
			is_branch = false;
			return 0;
		}

		is_branch = true;

		t = MOVE_BIT(instruction, 8, 1);
		t |= MOVE_BIT(instruction, 9, 2);
		t |= MOVE_BIT(instruction, 10, 3);
		t |= MOVE_BIT(instruction, 11, 4);
		t |= MOVE_BIT(instruction, 25, 5);
		t |= MOVE_BIT(instruction, 26, 6);
		t |= MOVE_BIT(instruction, 27, 7);
		t |= MOVE_BIT(instruction, 28, 8);
		t |= MOVE_BIT(instruction, 29, 9);
		t |= MOVE_BIT(instruction, 30, 10);
		t |= MOVE_BIT(instruction, 7, 11);
		t |= MOVE_BIT(instruction, 31, 12);

		if (t & (1 << 12)) { // sign extend offset
			t |= 0xffffe000;
		}

		immediate = t;
		rd = TraceDqrProfiler::REG_unknown;
		rs1 = (TraceDqrProfiler::Reg)((instruction >> 15) & 0x1f);
		break;
	case 0x73:
		if (instruction == 0x00200073) {
			inst_type = TraceDqrProfiler::INST_URET;
			is_branch = true;
			immediate = 0;
		}
		else if (instruction == 0x10200073) {
			inst_type = TraceDqrProfiler::INST_SRET;
			is_branch = true;
			immediate = 0;
		}
		else if (instruction == 0x30200073) {
			inst_type = TraceDqrProfiler::INST_MRET;
			is_branch = true;
			immediate = 0;
		}
		else if (instruction == 0x00000073) {
			inst_type = TraceDqrProfiler::INST_ECALL;
			immediate = 0;
			is_branch = true;
		}
		else if (instruction == 0x00100073) {
			inst_type = TraceDqrProfiler::INST_EBREAK;
			immediate = 0;
			is_branch = true;
		}
		else {
			inst_type = TraceDqrProfiler::INST_UNKNOWN;
			immediate = 0;
			rd = TraceDqrProfiler::REG_unknown;
			rs1 = TraceDqrProfiler::REG_unknown;
			is_branch = false;
		}
		break;
	case 0x07: // vector load
		// Need to check width encoding field to distinguish between vector and normal FP loads (bits 12-14)
		switch ((instruction >> 12) & 0x07) {
		case 0x00:
		case 0x05:
		case 0x06:
		case 0x07:
			inst_type = TraceDqrProfiler::INST_VECT_LOAD;
			break;
		default:
			inst_type = TraceDqrProfiler::INST_UNKNOWN;
			break;
		}

		is_branch = false;
		immediate = 0;
		rd = TraceDqrProfiler::REG_unknown;
		rs1 = TraceDqrProfiler::REG_unknown;
		break;
	case 0x27: // vector store
		// Need to check width encoding field to distinguish between vector and normal FP stores (bits 12-14)
		switch ((instruction >> 12) & 0x07) {
		case 0x00:
		case 0x05:
		case 0x06:
		case 0x07:
			inst_type = TraceDqrProfiler::INST_VECT_STORE;
			break;
		default:
			inst_type = TraceDqrProfiler::INST_UNKNOWN;
			break;
		}

		is_branch = false;
		immediate = 0;
		rd = TraceDqrProfiler::REG_unknown;
		rs1 = TraceDqrProfiler::REG_unknown;
		break;
	case 0x2f: // vector AMO
		// Need to check width encoding field to distinguish between vector and normal AMO (bits 26-28)
		switch ((instruction >> 12) & 0x07) {
		case 0x00:
		case 0x05:
		case 0x06:
		case 0x07:
			if ((instruction >> 26) & 0x01) {
				inst_type = TraceDqrProfiler::INST_VECT_AMO_WW;
			}
			else {
				inst_type = TraceDqrProfiler::INST_VECT_AMO;
			}
			break;
		default:
			inst_type = TraceDqrProfiler::INST_UNKNOWN;
			break;
		}

		is_branch = false;
		immediate = 0;
		rd = TraceDqrProfiler::REG_unknown;
		rs1 = TraceDqrProfiler::REG_unknown;
		break;
	case 0x57: // vector arith or vector config
		if (((instruction >> 12) & 0x7) <= 6) {
			inst_type = TraceDqrProfiler::INST_VECT_ARITH;
		}
		else {
			inst_type = TraceDqrProfiler::INST_VECT_CONFIG;
		}
		immediate = 0;
		rd = TraceDqrProfiler::REG_unknown;
		rs1 = TraceDqrProfiler::REG_unknown;
		is_branch = false;
		break;
	default:
		inst_type = TraceDqrProfiler::INST_UNKNOWN;
		immediate = 0;
		rd = TraceDqrProfiler::REG_unknown;
		rs1 = TraceDqrProfiler::REG_unknown;
		is_branch = false;
		break;
	}

	return 0;
}

int Disassembler::decodeInstruction(uint32_t instruction, int archSize, int& inst_size, TraceDqrProfiler::InstType& inst_type, TraceDqrProfiler::Reg& rs1, TraceDqrProfiler::Reg& rd, int32_t& immediate, bool& is_branch)
{
	int rc;

	switch (archSize) {
	case 32:
		switch (instruction & 0x0003) {
		case 0x0000:	// quadrant 0, compressed
			rc = decodeRV32Q0Instruction(instruction, inst_size, inst_type, rs1, rd, immediate, is_branch);
			break;
		case 0x0001:	// quadrant 1, compressed
			rc = decodeRV32Q1Instruction(instruction, inst_size, inst_type, rs1, rd, immediate, is_branch);
			break;
		case 0x0002:	// quadrant 2, compressed
			rc = decodeRV32Q2Instruction(instruction, inst_size, inst_type, rs1, rd, immediate, is_branch);
			break;
		case 0x0003:	// not compressed. Assume RV32 for now
			rc = decodeRV32Instruction(instruction, inst_size, inst_type, rs1, rd, immediate, is_branch);
			break;
		}
		break;
	case 64:
		switch (instruction & 0x0003) {
		case 0x0000:	// quadrant 0, compressed
			rc = decodeRV64Q0Instruction(instruction, inst_size, inst_type, rs1, rd, immediate, is_branch);
			break;
		case 0x0001:	// quadrant 1, compressed
			rc = decodeRV64Q1Instruction(instruction, inst_size, inst_type, rs1, rd, immediate, is_branch);
			break;
		case 0x0002:	// quadrant 2, compressed
			rc = decodeRV64Q2Instruction(instruction, inst_size, inst_type, rs1, rd, immediate, is_branch);
			break;
		case 0x0003:	// not compressed. Assume RV32 for now
			rc = decodeRV64Instruction(instruction, inst_size, inst_type, rs1, rd, immediate, is_branch);
			break;
		}
		break;
	default:
		printf("Error: (): Unknown arch size %d\n", archSize);

		rc = 1;
	}

	return rc;
}

// make all path separators either '/' or '\'; also remove '/./' and /../. Remove weird double path
// showing up on linux

void sanePath(TraceDqrProfiler::pathType pt, const char* src, char* dst)
{
	char drive = 0;
	int r = 0;
	int w = 0;
	char sep;

	if (pt == TraceDqrProfiler::PATH_RAW) {
		strcpy(dst, src);

		return;
	}

	if (pt == TraceDqrProfiler::PATH_TO_WINDOWS) {
		sep = '\\';
	}
	else {
		sep = '/';
	}

	while (src[r] != 0) {
		switch (src[r]) {
		case ':':
			if (w > 0) {
				if (((dst[w - 1] >= 'a') && (dst[w - 1] <= 'z')) || ((dst[w - 1] >= 'A') && (dst[w - 1] <= 'Z'))) {
					drive = dst[w - 1];
					w = 0;
					dst[w] = drive;
					w += 1;
				}
			}

			dst[w] = src[r];
			w += 1;
			r += 1;
			break;
		case '/':
		case '\\':
			if ((w > 0) && (dst[w - 1] == sep)) {
				// skip; remove double /
				r += 1;
			}
			else {
				dst[w] = sep;
				w += 1;
				r += 1;
			}
			break;
		case '.':
			if ((w > 0) && (dst[w - 1] == sep)) {
				if ((src[r + 1] == '/') || (src[r + 1] == '\\')) { // have \.\ or /./
					r += 2;
				}
				else if ((src[r + 1] == '.') && ((src[r + 2] == '/') || (src[r + 2] == '\\'))) { // have \..\ or /../
					// scan back in w until either sep or beginning of line is found
					w -= 1;
					while ((w > 0) && (dst[w - 1] != sep)) {
						w -= 1;
					}
					r += 3;
				}
				else { // have a '.' in a name - just pass it on
					dst[w] = '.';
					w += 1;
					r += 1;
				}
			}
			else {	// might be at beginning of string. Could be a ./ or a ../; copy the . or .. if followed by a /
				if ((w == 0) && ((src[r + 1] == '/') || (src[r + 1] == '\\'))) {
					// have a ./ at the beginning - strip it off
					r += 2;
				}
				else {
					dst[w] = '.';
					w += 1;
					r += 1;
				}
			}
			break;
		default:
			dst[w] = src[r];
			w += 1;
			r += 1;
			break;
		}
	}

	dst[w] = 0;
}

TraceDqrProfiler::DQErr Disassembler::getFunctionName(TraceDqrProfiler::ADDRESS addr, const char*& function, int& offset)
{
	TraceDqrProfiler::DQErr rc;
	Sym* sym;

	function = nullptr;
	offset = 0;

	rc = symtab->lookupSymbolByAddress(addr, sym);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		return TraceDqrProfiler::DQERR_ERR;
	}

	if (sym != nullptr) {
		function = sym->name;
		offset = addr - sym->address;
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr Disassembler::findNearestLine(TraceDqrProfiler::ADDRESS addr, const char*& file, int& line)
{
	if (addr == 0) {
		file = nullptr;
		line = 0;

		return TraceDqrProfiler::DQERR_OK;
	}

	if (addr != cachedAddr) {
		TraceDqrProfiler::DQErr rc;

		rc = cacheSrcInfo(addr);
		if (rc != TraceDqrProfiler::DQERR_OK) {
			return TraceDqrProfiler::DQERR_ERR;
		}
	}

	file = cachedSecPtr->fName[cachedIndex];
	line = cachedSecPtr->line[cachedIndex];

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr Disassembler::getSrcLines(TraceDqrProfiler::ADDRESS addr, const char** filename, int* cutPathIndex, const char** functionname, unsigned int* linenumber, const char** lineptr)
{
	const char* file = nullptr;
	const char* function = nullptr;
	int line = 0;
	int offset;
	TraceDqrProfiler::DQErr rc;

	// need to loop through all sections with code below and try to find one that succeeds

	*filename = nullptr;
	*cutPathIndex = 0;
	*functionname = nullptr;
	*linenumber = 0;
	*lineptr = nullptr;

	rc = findNearestLine(addr, file, line);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		return TraceDqrProfiler::DQERR_ERR;
	}

	if (file == nullptr) {
		return TraceDqrProfiler::DQERR_OK;
	}

	*linenumber = line;

	rc = getFunctionName(addr, function, offset);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		return TraceDqrProfiler::DQERR_ERR;
	}

	if (file == nullptr) {
		return TraceDqrProfiler::DQERR_OK;
	}

	char fprime[2048];
	char* sane;

	if (strlen(file) > sizeof fprime) {
		sane = new char[strlen(file) + 1];
	}
	else {
		sane = fprime;
	}

	sanePath(pType, file, sane);

	// the fl/filelist stuff is to get the source line text

	struct fileReader::fileList* fl;

	fl = fileReader->findFile(sane);
	if (fl == nullptr) {
		printf("Error: Disassembler::getSrcLines(): fileReader failed\n");

		status = TraceDqrProfiler::DQERR_ERR;
		return TraceDqrProfiler::DQERR_ERR;
	}

	*filename = fl->name;
	*cutPathIndex = fl->cutPathIndex;

	// save function name and line src in function list struct so it will be saved for reuse, or later use throughout the
	// life of the object. Won't be overwritten. This is not caching.

	if (function != nullptr) {
		// find the function name in fncList

		struct fileReader::funcList* funcLst;

		for (funcLst = fl->funcs; (funcLst != nullptr) && (strcasecmp(funcLst->func, function) != 0); funcLst = funcLst->next) {
			// empty
		}

		if (funcLst == nullptr) {
			// add function to the list

			int len = strlen(function) + 1;
			char* fname = new char[len];
			strcpy(fname, function);

			funcLst = new fileReader::funcList;
			funcLst->func = fname;
			funcLst->next = fl->funcs;
			fl->funcs = funcLst;
		}

		// at this point funcLst should point to this function (if it was just added or not)

		*functionname = funcLst->func;
	}

	// line numbers start at 1

	if ((line >= 1) && (line <= (int)fl->lineCount)) {
		*lineptr = fl->lines[line - 1];
	}

	if (sane != fprime) {
		delete[] sane;
		sane = nullptr;
	}

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr Disassembler::getInstruction(TraceDqrProfiler::ADDRESS addr, ProfilerInstruction& instruction)
{
	if (sectionLst == nullptr) {
		return TraceDqrProfiler::DQERR_ERR;;
	}

	Section* sp = sectionLst->getSectionByAddress(addr);
	if (sp == nullptr || sp->code == nullptr) {
		return TraceDqrProfiler::DQERR_ERR;
	}

	TraceDqrProfiler::DQErr rc;
	int index;

	index = (addr - sp->startAddr) / 2;

	instruction.coreId = 0;
	instruction.CRFlag = 0;
	instruction.brFlags = 0;
	instruction.address = addr;

	int size;
	uint32_t inst = sp->code[index];
	rc = decodeInstructionSize(inst, size);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		status = TraceDqrProfiler::DQERR_ERR;

		return rc;
	}

	instruction.instSize = size;

	if (size > 16) {
		inst |= sp->code[index + 1] << 16;
	}

	instruction.instruction = inst;
	instruction.instructionText = sp->diss[index];

	Sym* sym;

	rc = symtab->lookupSymbolByAddress(addr, sym);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		return TraceDqrProfiler::DQERR_ERR;
	}

	if (sym != nullptr) {
		instruction.addressLabel = sym->name;
		instruction.addressLabelOffset = addr - sym->address;
	}
	else {
		instruction.addressLabel = nullptr;
		instruction.addressLabelOffset = 0;
	}

	instruction.timestamp = 0;

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr Disassembler::disassemble(TraceDqrProfiler::ADDRESS addr)
{
	if (sectionLst == nullptr) {
		return TraceDqrProfiler::DQERR_ERR;;
	}

	Section* sp = sectionLst->getSectionByAddress(addr);
	if (sp == nullptr) {
		return TraceDqrProfiler::DQERR_ERR;
	}

	TraceDqrProfiler::DQErr rc;
	cachedInstInfo* cii;

	cii = sp->getCachedInfo(addr);
	if (cii != nullptr) {
		printf("have cached info\n");

		source.sourceFile = cii->filename;
		source.cutPathIndex = cii->cutPathIndex;
		source.sourceFunction = cii->functionname;
		source.sourceLineNum = cii->linenumber;
		source.sourceLine = cii->lineptr;

		instruction.address = addr;
		instruction.instruction = cii->instruction;
		instruction.instSize = cii->instsize;
		instruction.instructionText = cii->instructionText;

		instruction.addressLabel = cii->addressLabel;
		instruction.addressLabelOffset = cii->addressLabelOffset;

		// instruction.timestamp = 0;
		// instruction.cycles = 0;

		return TraceDqrProfiler::DQERR_OK;
	}

	rc = getInstruction(addr, instruction);
	if (rc != TraceDqrProfiler::DQERR_OK) {
		return TraceDqrProfiler::DQERR_ERR;
	}

	//rc = getSrcLines(addr, &source.sourceFile, &source.cutPathIndex, &source.sourceFunction, &source.sourceLineNum, &source.sourceLine);
	//if (rc != TraceDqrProfiler::DQERR_OK) {
	//	return TraceDqrProfiler::DQERR_ERR;
	//}

	sp->setCachedInfo(addr, source.sourceFile, source.cutPathIndex, source.sourceFunction, source.sourceLineNum, source.sourceLine, instruction.instructionText, instruction.instruction, instruction.instSize, instruction.addressLabel, instruction.addressLabelOffset);

	return TraceDqrProfiler::DQERR_OK;
}

TraceDqrProfiler::DQErr Disassembler::cacheSrcInfo(TraceDqrProfiler::ADDRESS addr)
{
	if (sectionLst == nullptr) {
		return TraceDqrProfiler::DQERR_ERR;
	}

	Section* sp = sectionLst->getSectionByAddress(addr);
	if (sp == nullptr) {
		return TraceDqrProfiler::DQERR_ERR;
	}

	cachedAddr = addr;
	cachedSecPtr = sp;
	cachedIndex = (addr - sp->startAddr) / 2;

	return TraceDqrProfiler::DQERR_OK;
}

AddrStack::AddrStack(int size)
{
	stackSize = size;
	sp = size;

	if (size == 0) {
		stack = nullptr;
	}
	else {
		stack = new TraceDqrProfiler::ADDRESS[size];
	}
}

AddrStack::~AddrStack()
{
	if (stack != nullptr) {
		delete[] stack;
		stack = nullptr;
	}

	stackSize = 0;
	sp = 0;
}

void AddrStack::reset()
{
	sp = stackSize;
}

int AddrStack::push(TraceDqrProfiler::ADDRESS addr)
{
	if (sp <= 0) {
		return 1;
	}

	sp -= 1;
	stack[sp] = addr;

	return 0;
}

TraceDqrProfiler::ADDRESS AddrStack::pop()
{
	if (sp >= stackSize) {
		return -1;
	}

	TraceDqrProfiler::ADDRESS t = stack[sp];
	sp += 1;

	return t;
}
