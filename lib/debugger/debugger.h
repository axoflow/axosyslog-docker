/*
 * Copyright (c) 2015 Balabit
 * Copyright (c) 2015 Balázs Scheidler
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * As an additional exemption you are allowed to compile & link against the
 * OpenSSL libraries as published by the OpenSSL project. See the file
 * COPYING for details.
 *
 */
#ifndef DEBUGGER_DEBUGGER_H_INCLUDED
#define DEBUGGER_DEBUGGER_H_INCLUDED 1

#include "syslog-ng.h"
#include "cfg.h"
#include "mainloop.h"
#include "logpipe.h"

typedef enum
{
  DBG_WAITING_FOR_STEP,
  DBG_WAITING_FOR_BREAKPOINT,
  DBG_FOLLOW_AND_BREAK,
  DBG_FOLLOW_AND_TRACE,
  DBG_QUIT,
} DebuggerMode;

typedef struct _Debugger Debugger;


static inline DebuggerMode
debugger_get_mode(Debugger *self)
{
  return *(DebuggerMode *) self;
}

typedef gchar *(*FetchCommandFunc)(void);

gchar *debugger_builtin_fetch_command(void);
void debugger_register_command_fetcher(FetchCommandFunc fetcher);
void debugger_exit(Debugger *self);
void debugger_start_console(Debugger *self);
gboolean debugger_perform_tracing(Debugger *self, LogPipe *pipe, LogMessage *msg,
                                  const LogPathOptions *path_options);
gboolean debugger_stop_at_breakpoint(Debugger *self, LogPipe *pipe, LogMessage *msg,
                                     const LogPathOptions *path_options);

Debugger *debugger_new(MainLoop *main_loop, GlobalConfig *cfg);
void debugger_free(Debugger *self);

static inline gboolean
debugger_is_to_stop(Debugger *self, LogPipe *pipe, LogMessage *msg)
{
  DebuggerMode mode = debugger_get_mode(self);

  switch (mode)
    {
    case DBG_WAITING_FOR_BREAKPOINT:
      return (pipe->flags & PIF_BREAKPOINT);

    case DBG_WAITING_FOR_STEP:
      return TRUE;

    case DBG_FOLLOW_AND_BREAK:
      return (msg->flags & LF_STATE_TRACING);

    case DBG_FOLLOW_AND_TRACE:
      return FALSE;

    case DBG_QUIT:
      return FALSE;

    default:
      g_assert_not_reached();
    }
  return FALSE;
}

static inline gboolean
debugger_is_to_trace(Debugger *self, LogPipe *pipe, LogMessage *msg)
{
  DebuggerMode mode = debugger_get_mode(self);

  return (mode == DBG_FOLLOW_AND_TRACE) && (msg->flags & LF_STATE_TRACING);

}

#endif
