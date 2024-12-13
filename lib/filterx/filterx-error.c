/*
 * Copyright (c) 2023 Balazs Scheidler <balazs.scheidler@axoflow.com>
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

#include "filterx/filterx-error.h"
#include "scratch-buffers.h"

void
filterx_error_clear(FilterXError *error)
{
  filterx_object_unref(error->object);
  if (error->free_info)
    g_free(error->info);
  memset(error, 0, sizeof(*error));
}

const gchar *
filterx_error_format(FilterXError *error)
{

  if (!error->message)
    {
      return "Error information unset";
    }

  GString *error_buffer = scratch_buffers_alloc();
  const gchar *extra_info = NULL;

  if (error->info)
    {
      extra_info = error->info;
    }
  else if (error->object)
    {
      GString *buf = scratch_buffers_alloc();

      if (!filterx_object_repr(error->object, buf))
        {
          LogMessageValueType t;
          if (!filterx_object_marshal(error->object, buf, &t))
            g_assert_not_reached();
        }
      extra_info = buf->str;
    }

  g_string_assign(error_buffer, error->message);
  if (extra_info)
    {
      g_string_append_len(error_buffer, ": ", 2);
      g_string_append(error_buffer, extra_info);
    }
  /* the caller does not need to free str, it is a scratch buffer */
  return error_buffer->str;
}

EVTTAG *
filterx_error_format_tag(FilterXError *error)
{
  const gchar *formatted_error = filterx_error_format(error);
  return evt_tag_str("error", formatted_error);
}

EVTTAG *
filterx_error_format_location_tag(FilterXError *error)
{
  return filterx_expr_format_location_tag(error->expr);
}

void
filterx_error_set_values(FilterXError *error, const gchar *message, FilterXExpr *expr, FilterXObject *object)
{
  error->message = message;
  error->expr = expr;
  error->object = filterx_object_ref(object);
}

void
filterx_error_set_info(FilterXError *error, gchar *info, gboolean free_info)
{
  error->info = info;
  error->free_info = free_info;
}
