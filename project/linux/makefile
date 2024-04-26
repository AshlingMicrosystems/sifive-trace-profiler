# Make command to use for dependencies
MAKE=make
CC=g++

# If no configuration is specified, "Release" will be used
ifndef "CFG"
CFG=Release
endif

COMPILE_INC=-I../../include
COMPILE_DEFS=-D__LINUX
COMPILE_FLAGS=-std=c++0x -Wall -fpermissive -Wno-unknown-pragmas -fstack-protector-strong -fPIC -MMD -shared -fvisibility=hidden -c -m64
JNI_INC=
JNI_INC_MD=
LINK_FLAGS=-std=c++0x -Wall -shared -fvisibility=hidden -z noexecstack -Wl,-z,relro,-z,now,-z,defs,-soname,"$(OUTFILE)" -o"$(OUTFILE)" -Xlinker -Bsymbolic
LINK_LIBS=-ldl -lpthread

ifeq "$(ARCH)" "64"
COMPILE_FLAGS+=-m64
LINK_FLAGS+=
else ifeq "$(ARCH)" "32"
COMPILE_FLAGS+=-m32
LINK_FLAGS+=
endif

ifeq "$(CFG)" "Release"
OUTDIR=Release
COMPILE_FLAGS+=-D_LOGGING_ENABLED -D_LOGGING_LEVEL=3
else ifeq "$(CFG)" "Debug"
OUTDIR=Debug
COMPILE_FLAGS+=-g -D_LOGGING_ENABLED -D_LOGGING_LEVEL=0
endif

COMPILE=$(CC) $(COMPILE_FLAGS) $(COMPILE_DEFS) $(COMPILE_INC)  $(JNI_INC) $(JNI_INC_MD) -o "$(OUTDIR)/$(*F).o" "$<"
LINK=$(CC) $(LINK_FLAGS) $(ALL_OBJS) $(LINK_LIBS)
OUTFILE=$(OUTDIR)/libdqr_profiler.so

ALL_OBJS=	$(OUTDIR)/dqr_profiler_interface.o \
            $(OUTDIR)/dqr_profiler.o \
			$(OUTDIR)/dqr_trace_profiler.o \
			$(OUTDIR)/SocketIntf.o \
			$(OUTDIR)/PacketFormat.o \
			$(OUTDIR)/linuxutils.o

# Pattern rules
$(OUTDIR)/%.o : ../../src/%.cpp
	@echo "Compiling $<"
	@$(COMPILE)

# Build rules
all: $(OUTFILE)

$(OUTFILE): $(OUTDIR) $(ALL_OBJS)
	@echo ""
	@echo "Linking $(OUTFILE)"
	@$(LINK)
	@echo ""

$(OUTDIR):
	@mkdir -p "$(OUTDIR)"

# Rebuild this project
rebuild: cleanall all

# Clean this project
clean:
	@rm -rf $(OUTDIR)
	@echo "Cleaned all"

# Clean this project and all dependencies
cleanall: clean

-include $(ALL_OBJS:.o=.d)