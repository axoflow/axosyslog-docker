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


static void
_display_msg_details(Debugger *self, LogMessage *msg)
{
  GString *output = g_string_sized_new(128);

  log_msg_values_foreach(msg, _format_nvpair, NULL);
  g_string_truncate(output, 0);
  log_msg_format_tags(msg, output, TRUE);
  printf("TAGS=%s\n", output->str);
  printf("\n");
  g_string_free(output, TRUE);
}

static gboolean
_display_msg_with_template_string(Debugger *self, LogMessage *msg, const gchar *template_string, GError **error)
{
  LogTemplate *template;

  template = log_template_new(self->cfg, NULL);
  if (!log_template_compile(template, template_string, error))
    {
      return FALSE;
    }
  _display_msg_with_template(self, msg, template);
  log_template_unref(template);
  return TRUE;
}

static gboolean
_cmd_print(Debugger *self, gint argc, gchar *argv[])
{
  if (argc == 1)
    _display_msg_details(self, self->breakpoint_site->msg);
  else if (argc == 2)
    {
      GError *error = NULL;
      if (!_display_msg_with_template_string(self, self->breakpoint_site->msg, argv[1], &error))
        {
          printf("print: %s\n", error->message);
          g_clear_error(&error);
        }
    }
  else
    printf("print: expected no arguments or exactly one\n");
  return TRUE;
}
