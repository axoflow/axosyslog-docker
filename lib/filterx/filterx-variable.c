/*
 * Copyright (c) 2024 Axoflow
 * Copyright (c) 2024 László Várady
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

#include "filterx-variable.h"

FilterXVariableHandle
filterx_map_varname_to_handle(const gchar *name, FilterXVariableType type)
{
  if (type == FX_VAR_MESSAGE)
    name++;

  NVHandle nv_handle = log_msg_get_value_handle(name);

  if (type == FX_VAR_MESSAGE)
    return (FilterXVariableHandle) nv_handle;
  return (FilterXVariableHandle) nv_handle | FILTERX_HANDLE_FLOATING_BIT;
}

void
filterx_variable_clear(FilterXVariable *v)
{
  filterx_object_unref(v->value);
}

void
filterx_variable_init_instance(FilterXVariable *v, FilterXVariableHandle handle,
                               FilterXObject *initial_value, guint32 generation)
{
  v->handle = handle;
  v->assigned = FALSE;
  v->declared = FALSE;
  v->generation = generation;
  v->value = filterx_object_ref(initial_value);
}
