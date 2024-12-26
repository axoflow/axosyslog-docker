perfincludedir			= ${pkgincludedir}/perf

perfinclude_HEADERS = \
	lib/perf/perf.h

_perf_sources = \
	lib/perf/perf.c \
	lib/perf/trampoline.S

if ENABLE_PERF

perf_sources = $(_perf_sources)

else

EXTRA_DIST += $(_perf_sources)

endif
