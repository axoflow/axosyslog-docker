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
_cmd_list(Debugger *self, gint argc, gchar *argv[])
{
  gint shift = 11;
  if (argc >= 2)
    {
      if (strcmp(argv[1], "+") == 0)
        shift = 11;
      else if (strcmp(argv[1], "-") == 0)
        shift = -11;
      else if (strcmp(argv[1], ".") == 0)
        {
          shift = 0;
          if (self->breakpoint_site)
            _set_current_location(self, self->breakpoint_site->pipe->expr_node);
        }
      else if (isdigit(argv[1][0]))
        {
          gint target_lineno = atoi(argv[1]);
          if (target_lineno <= 0)
            target_lineno = 1;
          self->current_location.list_start = target_lineno;
        }
      /* drop any arguments for repeated execution */
      _set_command(self, "l");
    }
  _display_source_line(self);
  if (shift)
    self->current_location.list_start += shift;
  return TRUE;
}
