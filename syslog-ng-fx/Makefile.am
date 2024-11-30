

bin_PROGRAMS			+= syslog-ng-fx/syslog-ng-fx

syslog_ng_fx_syslog_ng_fx_SOURCES		= 	\
	syslog-ng-fx/syslog-ng-fx.c

syslog_ng_fx_syslog_ng_fx_LDADD		= \
	$(MODULE_DEPS_LIBS) \
	$(TOOL_DEPS_LIBS) \
	$(top_builddir)/lib/secret-storage/libsecret-storage.la

syslog_ng_fx_syslog_ng_fx_CPPFLAGS  =     \
  $(AM_CPPFLAGS)            \
  -I$(top_srcdir)/syslog-ng-fx

EXTRA_syslog_ng_fx_syslog_ng_fx_DEPENDENCIES	= lib/libsyslog-ng.la lib/secret-storage/libsecret-storage.la
