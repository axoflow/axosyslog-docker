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
#include "filterx/filterx-scope.h"
#include "filterx/object-message-value.h"
#include "scratch-buffers.h"


volatile gint filterx_scope_variables_max = 16;

static inline FilterXVariable *
_get_variable_array(FilterXScope *self)
{
  if (self->coupled_variables)
    return self->variables.coupled;
  else
    return self->variables.separate;
}

static FilterXVariable *
_insert_into_large_enough_array(FilterXScope *self, FilterXVariable *elems, gint index)
{
  g_assert(self->variables.size >= self->variables.len + 1);

  gint n = self->variables.len - index;
  if (n)
    memmove(&elems[index + 1], &elems[index], n * sizeof(elems[0]));
  self->variables.len++;
  elems[index] = (FilterXVariable){0};
  return &elems[index];
}

static void
_separate_variables(FilterXScope *self)
{
  /* realloc */
  FilterXVariable *separate_array = g_new(FilterXVariable, self->variables.size * 2);

  memcpy(separate_array, self->variables.coupled, self->variables.len * sizeof(separate_array[0]));
  self->coupled_variables = FALSE;
  self->variables.size *= 2;
  self->variables.separate = separate_array;
}

static void
_grow_separate_array(FilterXScope *self)
{
  self->variables.size *= 2;
  self->variables.separate = g_realloc(self->variables.separate, self->variables.size * sizeof(self->variables.separate[0]));
}

static FilterXVariable *
_insert_variable(FilterXScope *self, gint index)
{
  if (self->coupled_variables)
    {
      if (self->variables.len + 1 < self->variables.size)
        return _insert_into_large_enough_array(self, self->variables.coupled, index);

      _separate_variables(self);
    }

  if (self->variables.len + 1 >= self->variables.size)
    _grow_separate_array(self);

  return _insert_into_large_enough_array(self, self->variables.separate, index);
}

static gboolean
_lookup_variable(FilterXScope *self, FilterXVariableHandle handle, FilterXVariable **v_slot, gint *v_index)
{
  gint l, h, m;
  FilterXVariable *variables = _get_variable_array(self);
  gint variables_len = self->variables.len;

  /* open-coded binary search */
  l = 0;
  h = variables_len - 1;
  while (l <= h)
    {
      m = (l + h) >> 1;

      FilterXVariable *m_elem = &variables[m];
      FilterXVariableHandle mv = m_elem->handle;

      if (mv == handle)
        {
          *v_slot = m_elem;
          *v_index = m;
          return TRUE;
        }
      else if (mv > handle)
        {
          h = m - 1;
        }
      else
        {
          l = m + 1;
        }
    }
  *v_slot = &variables[l];
  *v_index = l;
  return FALSE;
}

static gboolean
_validate_variable(FilterXScope *self, FilterXVariable *variable)
{
  if (filterx_variable_is_declared(variable))
    return TRUE;

  if (filterx_variable_is_floating(variable) &&
      !filterx_variable_is_same_generation(variable, self->generation))
    return FALSE;

  if (filterx_variable_is_message_tied(variable) &&
      !filterx_variable_is_same_generation(variable, self->msg->generation))
    return FALSE;
  return TRUE;
}


static FilterXVariable *
_register_variable(FilterXScope *self,
                   FilterXVariableType variable_type,
                   FilterXVariableHandle handle)
{
  FilterXVariable *v;
  gint v_index;

  if (_lookup_variable(self, handle, &v, &v_index))
    return v;

  v = _insert_variable(self, v_index);
  filterx_variable_init_instance(v, variable_type, handle);
  return v;
}

static FilterXVariable *
_pull_variable_from_parent_scope(FilterXScope *self, FilterXScope *scope, FilterXVariable *previous_v)
{
  FilterXVariable *v = _register_variable(self, previous_v->variable_type, previous_v->handle);

  *v = *previous_v;
  if (v->value)
    v->value = filterx_object_clone(v->value);

  msg_trace("Filterx scope, cloning scope variable",
            evt_tag_str("variable", log_msg_get_value_name((filterx_variable_get_nv_handle(v)), NULL)));
  return v;
}

FilterXVariable *
filterx_scope_lookup_variable(FilterXScope *self, FilterXVariableHandle handle)
{
  FilterXVariable *v;
  gint v_index;

  if (_lookup_variable(self, handle, &v, &v_index) &&
      _validate_variable(self, v))
    return v;

  for (FilterXScope *scope = self->parent_scope; scope; scope = scope->parent_scope)
    {
      if (_lookup_variable(scope, handle, &v, &v_index))
        {
          /* NOTE: we validate against @self */
          if (_validate_variable(self, v))
            return _pull_variable_from_parent_scope(self, scope, v);
          else
            msg_trace("Filterx scope, not cloning stale scope variable",
                      evt_tag_str("variable", log_msg_get_value_name((filterx_variable_get_nv_handle(v)), NULL)));

          return NULL;
        }
    }
  return NULL;
}

static FilterXObject *
_pull_variable_from_message(FilterXScope *self, NVHandle handle)
{
  gssize value_len;
  LogMessageValueType t;

  const gchar *value = log_msg_get_value_if_set_with_type(self->msg, handle, &value_len, &t);
  if (!value)
      return NULL;

  if (log_msg_is_handle_macro(handle))
    {
      FilterXObject *res = filterx_message_value_new(value, value_len, t);
      filterx_object_make_readonly(res);
      return res;
    }
  else
    return filterx_message_value_new_borrowed(value, value_len, t);
}


FilterXVariable *
filterx_scope_register_variable(FilterXScope *self,
                                FilterXVariableType variable_type,
                                FilterXVariableHandle handle)
{
  FilterXVariable *v = _register_variable(self, variable_type, handle);

  /* the scope needs to be synced with the message if it holds a
   * message-tied variable (e.g.  $MSG) */
  if (variable_type == FX_VAR_MESSAGE_TIED)
    {
      FilterXObject *value = _pull_variable_from_message(self, filterx_variable_handle_to_nv_handle(handle));
      self->syncable = TRUE;

      /* NOTE: value may be NULL on an error, in that case the variable becomes an unset one */
      filterx_variable_set_value(v, value, FALSE, self->msg->generation);
      filterx_object_unref(value);
    }
  else
    {
      filterx_variable_set_value(v, NULL, FALSE, self->generation);
    }
  return v;
}

gboolean
filterx_scope_foreach_variable(FilterXScope *self, FilterXScopeForeachFunc func, gpointer user_data)
{
  FilterXVariable *variables = _get_variable_array(self);

  for (gint i = 0; i < self->variables.len; i++)
    {
      FilterXVariable *variable = &variables[i];

      if (!variable->value)
        continue;

      if (!_validate_variable(self, variable))
        continue;

      if (!func(variable, user_data))
        return FALSE;
    }

  return TRUE;
}

/*
 * 1) sync objects to message
 * 2) drop undeclared objects
 */
void
filterx_scope_sync(FilterXScope *self, LogMessage *msg)
{
  filterx_scope_set_message(self, msg);
  if (!self->dirty)
    {
      msg_trace("Filterx sync: not syncing as scope is not dirty",
                evt_tag_printf("scope", "%p", self));
      return;
    }
  if (!self->syncable)
    {
      msg_trace("Filterx sync: not syncing as there are no variables to sync",
                evt_tag_printf("scope", "%p", self));
      self->dirty = FALSE;
      return;
    }

  GString *buffer = scratch_buffers_alloc();

  gint msg_generation = msg->generation;
  FilterXVariable *variables = _get_variable_array(self);

  for (gint i = 0; i < self->variables.len; i++)
    {
      FilterXVariable *v = &variables[i];

      /* we don't need to sync the value if:
       *
       *  1) this is a floating variable; OR
       *
       *  2) the value was extracted from the message but was not changed in
       *     place (for mutable objects), and was not assigned to.
       *
       */
      if (filterx_variable_is_floating(v))
        {
          /* we could unset undeclared, floating values here as we are
           * transitioning to the next filterx block.  But this is also
           * addressed by the variable generation counter mechanism.  This
           * means that we will unset those if some expr actually refers to
           * it.  Also, we skip the entire sync exercise, unless we have
           * message tied values, so we need to work even if floating
           * variables are not synced.
           *
           * With that said, let's not clear these.
           */
        }
      else if (v->value == NULL)
        {
          g_assert(v->generation == msg_generation);
          msg_trace("Filterx sync: whiteout variable, unsetting in message",
                    evt_tag_str("variable", log_msg_get_value_name(filterx_variable_get_nv_handle(v), NULL)));
          /* we need to unset */
          log_msg_unset_value(msg, filterx_variable_get_nv_handle(v));
          filterx_variable_unassign(v);
          v->generation++;
        }
      else if (filterx_variable_is_assigned(v) || filterx_object_is_modified_in_place(v->value))
        {
          LogMessageValueType t;

          g_assert(v->generation == msg_generation);
          msg_trace("Filterx sync: changed variable in scope, overwriting in message",
                    evt_tag_str("variable", log_msg_get_value_name(filterx_variable_get_nv_handle(v), NULL)));

          g_string_truncate(buffer, 0);
          if (!filterx_object_marshal(v->value, buffer, &t))
            g_assert_not_reached();
          log_msg_set_value_with_type(msg, filterx_variable_get_nv_handle(v), buffer->str, buffer->len, t);
          filterx_object_set_modified_in_place(v->value, FALSE);
          filterx_variable_unassign(v);
          v->generation++;
        }
      else
        {
          msg_trace("Filterx sync: variable in scope and message in sync, not doing anything",
                    evt_tag_str("variable", log_msg_get_value_name(filterx_variable_get_nv_handle(v), NULL)));
          v->generation++;
        }
    }
  /* FIXME: hack ! */
  msg->generation = msg_generation + 1;
  self->dirty = FALSE;
}

FilterXScope *
filterx_scope_new(FilterXScope *parent_scope)
{
  gsize alloc_size = sizeof(FilterXScope) + sizeof(FilterXVariable) * filterx_scope_variables_max;
  FilterXScope *self = g_malloc(alloc_size);

  memset(self, 0, sizeof(FilterXScope));
  g_atomic_counter_set(&self->ref_cnt, 1);
  self->parent_scope = filterx_scope_ref(parent_scope);
  self->variables.size = filterx_scope_variables_max;
  self->coupled_variables = TRUE;
  return self;
}

static FilterXScope *
filterx_scope_clone(FilterXScope *other)
{
  FilterXScope *self = filterx_scope_new(other);

  /* retain the generation counter */
  self->generation = other->generation;
  if (other->variables.len > 0)
    self->dirty = other->dirty;
  self->syncable = other->syncable;
  self->msg = log_msg_ref(other->msg);

  msg_trace("Filterx clone finished",
            evt_tag_printf("scope", "%p", self),
            evt_tag_printf("other", "%p", other),
            evt_tag_int("dirty", self->dirty),
            evt_tag_int("syncable", self->syncable),
            evt_tag_int("write_protected", self->write_protected));
  /* NOTE: we don't clone weak references, those only relate to mutable
   * objects, which we are cloning anyway */
  return self;
}

void
filterx_scope_write_protect(FilterXScope *self)
{
  self->write_protected = TRUE;
}

FilterXScope *
filterx_scope_make_writable(FilterXScope **pself)
{
  if ((*pself)->write_protected)
    {
      FilterXScope *new;

      new = filterx_scope_clone(*pself);
      filterx_scope_unref(*pself);
      *pself = new;
    }
  (*pself)->generation++;
  return *pself;
}

static void
_free(FilterXScope *self)
{
  /* NOTE: update the number of inlined variable allocations */
  gint variables_max = filterx_scope_variables_max;
  if (variables_max < self->variables.len)
    filterx_scope_variables_max = self->variables.len;

  if (self->msg)
    log_msg_unref(self->msg);

  FilterXVariable *variables = _get_variable_array(self);
  for (gint i = 0; i < self->variables.len; i++)
    {
      FilterXVariable *v = &variables[i];
      filterx_variable_clear(v);
    }
  if (!self->coupled_variables)
    g_free(self->variables.separate);
  filterx_scope_unref(self->parent_scope);
  g_free(self);
}

FilterXScope *
filterx_scope_ref(FilterXScope *self)
{
  if (self)
    g_atomic_counter_inc(&self->ref_cnt);
  return self;
}

void
filterx_scope_unref(FilterXScope *self)
{
  if (self && (g_atomic_counter_dec_and_test(&self->ref_cnt)))
    _free(self);
}
