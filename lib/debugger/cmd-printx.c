/*
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

#include "filterx/filterx-parser.h"

static void
_eval_filterx_expr(Debugger *self, GList *list_of_exprs, LogMessage *msg)
{
  NVTable *payload = nv_table_ref(msg->payload);

  gint expr_index = 1;
  for (GList *l = list_of_exprs; l; l = l->next)
    {
      FilterXExpr *expr = (FilterXExpr *) l->data;
      FilterXObject *res = filterx_expr_eval(expr);

      if (!res)
        {
          printf("$%d = error(%s)\n", expr_index, filterx_eval_get_last_error());
          filterx_eval_clear_errors();
          goto fail;
        }

      GString *buf = scratch_buffers_alloc();
      if (!filterx_object_repr(res, buf))
        {
          LogMessageValueType t;
          if (!filterx_object_marshal(res, buf, &t))
            g_assert_not_reached();
        }
      printf("$%d = %s\n", expr_index, buf->str);

      filterx_object_unref(res);
      expr_index++;
    }

fail:
  nv_table_unref(payload);
}

static void
_display_filterx_expr(Debugger *self, gint argc, gchar *argv[])
{
  GList *list_of_exprs = NULL;
  for (gint i = 0; i < argc; i++)
    {
      gchar *expr_text = g_strdup_printf("%s;", argv[i]);
      CfgLexer *lexer = cfg_lexer_new_buffer(self->cfg, expr_text, strlen(expr_text));

      GList *partial = NULL;
      if (!cfg_run_parser(self->cfg, lexer, &filterx_parser, (gpointer *) &partial, NULL) ||
          !partial)
        {
          printf("Error parsing filterx expression: %s\n", expr_text);
          g_free(expr_text);
          goto exit;
        }
      g_free(expr_text);
      list_of_exprs = g_list_concat(list_of_exprs, partial);
    }
  _eval_filterx_expr(self,
                     list_of_exprs,
                     self->breakpoint_site->msg);

exit:
  g_list_free_full(list_of_exprs, (GDestroyNotify) filterx_expr_unref);
}

static gboolean
_cmd_printx(Debugger *self, gint argc, gchar *argv[])
{
  if (argc == 1)
    {
      gchar *vars[] = { "vars();", NULL };
      _display_filterx_expr(self, 1, vars);
    }
  else
    {
      _display_filterx_expr(self, argc - 1, &argv[1]);
    }
  return TRUE;
}
