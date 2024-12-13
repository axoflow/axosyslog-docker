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
_cmd_info_pipe(Debugger *self, LogPipe *pipe)
{
  gchar buf[1024];

  printf("LogPipe %p at %s\n", pipe, log_expr_node_format_location(pipe->expr_node, buf, sizeof(buf)));
  _display_source_line(self);

  return TRUE;
}

static gboolean
_cmd_info(Debugger *self, gint argc, gchar *argv[])
{
  if (argc >= 2)
    {
      if (strcmp(argv[1], "pipe") == 0)
        return _cmd_info_pipe(self, self->breakpoint_site->pipe);
    }

  printf("info: List of info subcommands\n"
         "info pipe -- display information about the current pipe\n");
  return TRUE;
}
