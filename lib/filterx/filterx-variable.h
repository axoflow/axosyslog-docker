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

#ifndef FILTERX_VARIABLE_H
#define FILTERX_VARIABLE_H

#include "syslog-ng.h"
#include "filterx-object.h"

#define FILTERX_SCOPE_MAX_GENERATION ((1UL << 20) - 1)

typedef guint32 FilterXVariableHandle;

typedef struct _FilterXVariable
{
  /* the MSB indicates that the variable is a floating one */
  FilterXVariableHandle handle;
  /*
   * assigned -- Indicates that the variable was assigned to a new value
   *
   * declared -- this variable is declared (e.g. retained for the entire input pipeline)
   */
  guint32 assigned:1,
          declared:1,
          generation:20;
  FilterXObject *value;
} FilterXVariable;

typedef enum
{
  FX_VAR_MESSAGE,
  FX_VAR_FLOATING,
  FX_VAR_DECLARED,
} FilterXVariableType;


void filterx_variable_init_instance(FilterXVariable *v, FilterXVariableHandle handle,
                                    FilterXObject *initial_value, guint32 generation);
void filterx_variable_free(FilterXVariable *v);

#define FILTERX_HANDLE_FLOATING_BIT (1UL << 31)

static inline gboolean
filterx_variable_handle_is_floating(FilterXVariableHandle handle)
{
  return !!(handle & FILTERX_HANDLE_FLOATING_BIT);
}

static inline gboolean
filterx_variable_handle_is_message_tied(FilterXVariableHandle handle)
{
  return !filterx_variable_handle_is_floating(handle);
}

static inline NVHandle
filterx_variable_handle_to_nv_handle(FilterXVariableHandle handle)
{
  return handle & ~FILTERX_HANDLE_FLOATING_BIT;
}

static inline gboolean
filterx_variable_is_floating(FilterXVariable *v)
{
  return filterx_variable_handle_is_floating(v->handle);
}

static inline gboolean
filterx_variable_is_message_tied(FilterXVariable *v)
{
  return filterx_variable_handle_is_message_tied(v->handle);
}

static inline NVHandle
filterx_variable_get_nv_handle(FilterXVariable *v)
{
  return filterx_variable_handle_to_nv_handle(v->handle);
}

static inline const gchar *
filterx_variable_get_name(FilterXVariable *v, gssize *len)
{
  return log_msg_get_handle_name(filterx_variable_get_nv_handle(v), len);
}

static inline FilterXObject *
filterx_variable_get_value(FilterXVariable *v)
{
  return filterx_object_ref(v->value);
}

static inline void
filterx_variable_set_value(FilterXVariable *v, FilterXObject *new_value)
{
  filterx_object_unref(v->value);
  v->value = filterx_object_ref(new_value);
  v->assigned = TRUE;
}

static inline void
filterx_variable_unset_value(FilterXVariable *v)
{
  filterx_variable_set_value(v, NULL);
}

static inline gboolean
filterx_variable_is_set(FilterXVariable *v)
{
  return v->value != NULL;
}

static inline gboolean
filterx_variable_is_declared(FilterXVariable *v)
{
  return v->declared;
}

static inline gboolean
filterx_variable_is_assigned(FilterXVariable *v)
{
  return v->assigned;
}

static inline gboolean
filterx_variable_is_same_generation(FilterXVariable *v, guint32 generation)
{
  return v->generation == generation;
}

static inline void
filterx_variable_set_generation(FilterXVariable *v, guint32 generation)
{
  v->generation = generation;
}

static inline void
filterx_variable_unassign(FilterXVariable *v)
{
  v->assigned = FALSE;
}

static inline void
filterx_variable_set_declared(FilterXVariable *v, gboolean declared)
{
  v->declared = declared;
}

FilterXVariableHandle filterx_map_varname_to_handle(const gchar *name, FilterXVariableType type);

#endif
