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
_cmd_display(Debugger *self, gint argc, gchar *argv[])
{
  if (argc == 2)
    {
      GError *error = NULL;
      if (!log_template_compile(self->display_template, argv[1], &error))
        {
          printf("display: Error compiling template: %s\n", error->message);
          g_clear_error(&error);
          return TRUE;
        }
    }
  printf("display: The template is set to: \"%s\"\n", self->display_template->template_str);
  return TRUE;
}
