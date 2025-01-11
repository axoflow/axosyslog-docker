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
#include "filterx/expr-variable.h"
#include "filterx/object-message-value.h"
#include "filterx/object-string.h"
#include "filterx/filterx-scope.h"
#include "filterx/filterx-eval.h"
#include "filterx/filterx-variable.h"
#include "logmsg/logmsg.h"
#include "stats/stats-registry.h"
#include "stats/stats-cluster-single.h"


typedef struct _FilterXVariableExpr
{
  FilterXExpr super;
  FilterXVariableType variable_type;
  NVHandle handle;
  FilterXObject *variable_name;
  guint32 handle_is_macro:1;
} FilterXVariableExpr;

static FilterXObject *
_pull_variable_from_message(FilterXVariableExpr *self, FilterXEvalContext *context, LogMessage *msg)
{
  gssize value_len;
  LogMessageValueType t;
  const gchar *value = log_msg_get_value_if_set_with_type(msg, self->handle, &value_len, &t);
  if (!value)
    {
      filterx_eval_push_error("No such name-value pair in the log message", &self->super, self->variable_name);
      return NULL;
    }

  if (self->handle_is_macro)
    return filterx_message_value_new(value, value_len, t);
  else
    return filterx_message_value_new_borrowed(value, value_len, t);
}

/* NOTE: unset on a variable that only exists in the LogMessage, without making the message writable */
static void
_whiteout_variable(FilterXVariableExpr *self, FilterXEvalContext *context)
{
  filterx_scope_register_variable(context->scope, FX_VAR_MESSAGE_TIED, self->handle, NULL);
}

static FilterXObject *
_eval_variable(FilterXExpr *s)
{
  FilterXVariableExpr *self = (FilterXVariableExpr *) s;
  FilterXEvalContext *context = filterx_eval_get_context();
  FilterXVariable *variable;

  variable = filterx_scope_lookup_variable(context->scope, self->handle);
  if (variable)
    {
      FilterXObject *value = filterx_variable_get_value(variable);
      if (!value)
        {
          filterx_eval_push_error("Variable is unset", &self->super, self->variable_name);
        }
      return value;
    }

  if (filterx_variable_handle_is_message_tied(self->handle))
    {
      FilterXObject *msg_ref = _pull_variable_from_message(self, context, context->msg);
      if(!msg_ref)
        return NULL;
      filterx_scope_register_variable(context->scope, FX_VAR_MESSAGE_TIED, self->handle, msg_ref);
      return msg_ref;
    }

  filterx_eval_push_error("No such variable", s, self->variable_name);
  return NULL;
}

static void
_update_repr(FilterXExpr *s, FilterXObject *new_repr)
{
  FilterXVariableExpr *self = (FilterXVariableExpr *) s;
  FilterXScope *scope = filterx_eval_get_scope();
  FilterXVariable *variable = filterx_scope_lookup_variable(scope, self->handle);

  g_assert(variable != NULL);
  filterx_variable_set_value(variable, new_repr, FALSE);
}

static gboolean
_assign(FilterXExpr *s, FilterXObject *new_value)
{
  FilterXVariableExpr *self = (FilterXVariableExpr *) s;
  FilterXScope *scope = filterx_eval_get_scope();
  FilterXVariable *variable = filterx_scope_lookup_variable(scope, self->handle);

  if (self->handle_is_macro)
    {
      filterx_eval_push_error("Macro based variable cannot be changed", &self->super, self->variable_name);
      return FALSE;
    }

  if (!variable)
    {
      /* NOTE: we pass NULL as initial_value to make sure the new variable
       * is considered changed due to the assignment */

      variable = filterx_scope_register_variable(scope, self->variable_type, self->handle, NULL);
    }

  /* this only clones mutable objects */
  new_value = filterx_object_clone(new_value);
  filterx_variable_set_value(variable, new_value, TRUE);
  filterx_object_unref(new_value);
  return TRUE;
}

static gboolean
_isset(FilterXExpr *s)
{
  FilterXVariableExpr *self = (FilterXVariableExpr *) s;
  FilterXScope *scope = filterx_eval_get_scope();

  FilterXVariable *variable = filterx_scope_lookup_variable(scope, self->handle);
  if (variable)
    return filterx_variable_is_set(variable);

  FilterXEvalContext *context = filterx_eval_get_context();
  LogMessage *msg = context->msg;
  return log_msg_is_value_set(msg, self->handle);
}

static gboolean
_unset(FilterXExpr *s)
{
  FilterXVariableExpr *self = (FilterXVariableExpr *) s;

  if (self->handle_is_macro)
    {
      filterx_eval_push_error("Macro based variable cannot be changed", &self->super, self->variable_name);
      return FALSE;
    }

  FilterXEvalContext *context = filterx_eval_get_context();

  FilterXVariable *variable = filterx_scope_lookup_variable(context->scope, self->handle);
  if (variable)
    {
      filterx_variable_unset_value(variable);
      return TRUE;
    }

  LogMessage *msg = context->msg;
  if (log_msg_is_value_set(msg, self->handle))
    _whiteout_variable(self, context);

  return TRUE;
}

static void
_free(FilterXExpr *s)
{
  FilterXVariableExpr *self = (FilterXVariableExpr *) s;

  filterx_object_unref(self->variable_name);
  filterx_expr_free_method(s);
}

static FilterXExpr *
filterx_variable_expr_new(FilterXString *name, FilterXVariableType variable_type)
{
  FilterXVariableExpr *self = g_new0(FilterXVariableExpr, 1);

  filterx_expr_init_instance(&self->super, "variable");
  self->super.free_fn = _free;
  self->super.eval = _eval_variable;
  self->super._update_repr = _update_repr;
  self->super.assign = _assign;
  self->super.is_set = _isset;
  self->super.unset = _unset;

  self->variable_type = variable_type;
  self->variable_name = (FilterXObject *) name;
  self->handle = filterx_map_varname_to_handle(filterx_string_get_value_ref(self->variable_name, NULL), variable_type);
  if (variable_type == FX_VAR_MESSAGE_TIED)
    self->handle_is_macro = log_msg_is_handle_macro(filterx_variable_handle_to_nv_handle(self->handle));

  /* NOTE: name borrows the string value from the string object */
  self->super.name = filterx_string_get_value_ref(self->variable_name, NULL);

  return &self->super;
}

FilterXExpr *
filterx_msg_variable_expr_new(FilterXString *name)
{
  return filterx_variable_expr_new(name, FX_VAR_MESSAGE_TIED);
}

FilterXExpr *
filterx_floating_variable_expr_new(FilterXString *name)
{
  return filterx_variable_expr_new(name, FX_VAR_FLOATING);
}

void
filterx_variable_expr_declare(FilterXExpr *s)
{
  FilterXVariableExpr *self = (FilterXVariableExpr *) s;

  g_assert(s->eval == _eval_variable);
  /* we can only declare a floating variable */
  g_assert(self->variable_type == FX_VAR_FLOATING);
  self->variable_type = FX_VAR_DECLARED_FLOATING;
}
