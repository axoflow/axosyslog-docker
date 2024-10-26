debuggerincludedir			= ${pkgincludedir}/debugger

EXTRA_DIST += lib/debugger/CMakeLists.txt \
	cmd-continue.c \
	cmd-display.c  \
	cmd-drop.c     \
	cmd-follow.c   \
	cmd-help.c     \
	cmd-info.c     \
	cmd-list.c     \
	cmd-print.c    \
	cmd-quit.c     \
	cmd-step.c     \
	cmd-trace.c

debuggerinclude_HEADERS = \
	lib/debugger/debugger.h		\
	lib/debugger/tracer.h		\
	lib/debugger/debugger-main.h

debugger_sources = \
	lib/debugger/debugger.c		\
	lib/debugger/tracer.c		\
	lib/debugger/debugger-main.c

include lib/debugger/tests/Makefile.am
