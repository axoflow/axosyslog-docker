/*
 * Copyright (c) 2015 Balabit
 * Copyright (c) 2015 Balázs Scheidler
 * Copyright (c) 2024 Balázs Scheidler <balazs.scheidler@axoflow.com>
 * Copyright (c) 2024 Axoflow
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

static gboolean
_cmd_help(Debugger *self, gint argc, gchar *argv[])
{
  if (self->breakpoint_site)
    {
      printf("syslog-ng interactive console\n"
             "Stopped on a breakpoint.\n"
             "The following commands are available:\n\n"
             "  help, h, ?               Display this help\n"
             "  info, i                  Display information about the current execution state\n"
             "  list, l                  Display source code at the current location\n"
             "  continue, c              Continue until the next breakpoint\n"
             "  step, s                  Single step\n"
             "  follow, f                Follow this message, ignoring any other breakpoints\n"
             "  display                  Set the displayed message template\n"
             "  trace, t                 Trace this message along the configuration\n"
             "  print, p                 Print the current log message\n"
             "  printx, px               Print the value of a filterx expression\n"
             "  drop, d                  Drop the current message\n"
             "  quit, q                  Tell syslog-ng to exit\n"
            );
    }
  else
    {
      printf("syslog-ng interactive console\n"
             "Stopped on an interrupt.\n"
             "The following commands are available:\n\n"
             "  help, h, ?               Display this help\n"
             "  list, l                  Display source code at the current location\n"
             "  continue, c              Continue until the next breakpoint\n"
             "  quit, q                  Tell syslog-ng to exit\n"
            );
    }
  return TRUE;
}
