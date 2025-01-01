/*
 * Copyright (c) 2024 Attila Szakacs
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

#include "func-vars.h"
#include "filterx-eval.h"
#include "object-json.h"
#include "object-string.h"
#include "object-primitive.h"
#include "object-message-value.h"
#include "object-dict-interface.h"
#include "filterx-object-istype.h"

#include "scratch-buffers.h"
#include "str-utils.h"

static gboolean
_add_to_dict(FilterXVariable *variable, gpointer user_data)
{
  FilterXObject *vars = ((gpointer *)(user_data))[0];
  GString *name_buf = ((gpointer *)(user_data))[1];

  gssize name_len;
  const gchar *name_str = filterx_variable_get_name(variable, &name_len);

  if (filterx_variable_is_message_tied(variable))
    {
      g_string_assign(name_buf, "$");
      g_string_append_len(name_buf, name_str, name_len);
      name_str = name_buf->str;
      name_len = name_buf->len;
    }

  FilterXObject *name = filterx_string_new(name_str, name_len);

  FilterXObject *value = filterx_variable_get_value(variable);
  FilterXObject *cloned_value = filterx_object_clone(value);
  filterx_object_unref(value);

  gboolean success = filterx_object_set_subscript(vars, name, &cloned_value);

  filterx_object_unref(cloned_value);
  filterx_object_unref(name);
  return success;
}

FilterXObject *
filterx_simple_function_vars(FilterXExpr *s, FilterXObject *args[], gsize args_len)
{
  if (args && args_len != 0)
    {
      filterx_simple_function_argument_error(s, "Incorrect number of arguments", FALSE);
      return NULL;
    }

  FilterXEvalContext *context = filterx_eval_get_context();
  FilterXObject *vars = filterx_json_object_new_empty();

  ScratchBuffersMarker marker;
  GString *name_buf = scratch_buffers_alloc_and_mark(&marker);

  gpointer user_data[] = { vars, name_buf };
  if (!filterx_scope_foreach_variable(context->scope, _add_to_dict, user_data))
    {
      filterx_object_unref(vars);
      vars = NULL;
    }

  scratch_buffers_reclaim_marked(marker);
  return vars;
}

static gboolean
_load_from_dict(FilterXObject *key, FilterXObject *value, gpointer user_data)
{
  FilterXExpr *s = ((gpointer *)(user_data))[0];
  FilterXScope *scope = ((gpointer *)(user_data))[1];

  if (!filterx_object_is_type(key, &FILTERX_TYPE_NAME(string)))
    {
      filterx_eval_push_error("Variable name must be a string", s, key);
      return FALSE;
    }

  gsize key_len;
  const gchar *key_str = filterx_string_get_value_ref(key, &key_len);
  APPEND_ZERO(key_str, key_str, key_len);

  if (key_len == 0)
    {
      filterx_eval_push_error("Variable name must not be empty", s, key);
      return FALSE;
    }

  gboolean is_floating = key_str[0] != '$';
  FilterXVariableHandle handle = filterx_map_varname_to_handle(key_str, is_floating ? FX_VAR_FLOATING : FX_VAR_MESSAGE);

  FilterXVariable *variable = NULL;
  if (is_floating)
    variable = filterx_scope_register_declared_variable(scope, handle, NULL);
  else
    variable = filterx_scope_register_variable(scope, handle, NULL);

  FilterXObject *cloned_value = filterx_object_clone(value);
  filterx_variable_set_value(variable, cloned_value);
  filterx_object_unref(cloned_value);

  if (!variable)
    {
      filterx_eval_push_error("Failed to register variable", NULL, key);
      return FALSE;
    }

  if (debug_flag)
    {
      LogMessageValueType type;

      GString *repr = scratch_buffers_alloc();
      if (!filterx_object_repr(value, repr))
        filterx_object_marshal_append(value, repr, &type);

      msg_trace("FILTERX LOADV",
                filterx_expr_format_location_tag(s),
                evt_tag_str("key", key_str),
                evt_tag_str("value", repr->str),
                evt_tag_str("type", value->type->name),
                evt_tag_str("variable_type", is_floating ? "declared" : "message"));
    }

  return TRUE;
}

FilterXObject *
filterx_simple_function_load_vars(FilterXExpr *s, FilterXObject *args[], gsize args_len)
{
  if (!args || args_len != 1)
    {
      filterx_simple_function_argument_error(s, "Incorrect number of arguments", FALSE);
      return NULL;
    }

  FilterXObject *vars = args[0];
  FilterXObject *vars_unwrapped = filterx_ref_unwrap_ro(vars);
  FilterXObject *vars_unmarshalled = NULL;

  if (!filterx_object_is_type(vars_unwrapped, &FILTERX_TYPE_NAME(dict)))
    {
      if (!filterx_object_is_type(vars_unwrapped, &FILTERX_TYPE_NAME(message_value)))
        {
          filterx_simple_function_argument_error(s, g_strdup_printf("Argument must be dict typed, got %s instead",
                                                                    vars_unwrapped->type->name), TRUE);
          return NULL;
        }

      vars_unmarshalled = filterx_object_unmarshal(vars_unwrapped);
      vars_unwrapped = NULL;

      if (!filterx_object_is_type(vars_unmarshalled, &FILTERX_TYPE_NAME(dict)))
        {
          filterx_simple_function_argument_error(s, g_strdup_printf("Argument must be dict typed, got %s instead",
                                                                    vars_unmarshalled->type->name), TRUE);
          filterx_object_unref(vars_unmarshalled);
          return NULL;
        }
    }

  FilterXScope *scope = filterx_eval_get_scope();
  gpointer user_data[] = { s, scope };
  gboolean success = filterx_dict_iter(vars_unwrapped ? : vars_unmarshalled, _load_from_dict, user_data);

  filterx_object_unref(vars_unmarshalled);
  return success ? filterx_boolean_new(TRUE) : NULL;
}
