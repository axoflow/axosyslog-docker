/*
 * Copyright (c) 2024 László Várady
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

#include "filterx-ref.h"
#include "filterx/filterx-object-istype.h"

static FilterXObject *
_filterx_ref_clone(FilterXObject *s)
{
  FilterXRef *self = (FilterXRef *) s;

  return filterx_ref_new(filterx_object_ref(self->value));
}

static void
_filterx_ref_cow(FilterXRef *self)
{
  if (g_atomic_counter_get(&self->value->fx_ref_cnt) <= 1)
    return;

  FilterXObject *cloned = filterx_object_clone(self->value);

  g_atomic_counter_dec_and_test(&self->value->fx_ref_cnt);
  filterx_object_unref(self->value);

  self->value = cloned;
  g_atomic_counter_inc(&self->value->fx_ref_cnt);
}

FilterXObject *
filterx_ref_unwrap_ro(FilterXObject *s)
{
  if (!s || !filterx_object_is_type(s, &FILTERX_TYPE_NAME(ref)))
    return s;

  FilterXRef *self = (FilterXRef *) s;
  return self->value;
}

FilterXObject *
filterx_ref_unwrap_rw(FilterXObject *s)
{
  if (!s || !filterx_object_is_type(s, &FILTERX_TYPE_NAME(ref)))
    return s;

  FilterXRef *self = (FilterXRef *) s;

  _filterx_ref_cow(self);

  return self->value;
}

/* mutator methods */

static gboolean
_filterx_ref_setattr(FilterXObject *s, FilterXObject *attr, FilterXObject **new_value)
{
  FilterXRef *self = (FilterXRef *) s;

  _filterx_ref_cow(self);

  return filterx_object_setattr(self->value, attr, new_value);
}

static gboolean
_filterx_ref_set_subscript(FilterXObject *s, FilterXObject *key, FilterXObject **new_value)
{
  FilterXRef *self = (FilterXRef *) s;

  _filterx_ref_cow(self);

  return filterx_object_set_subscript(self->value, key, new_value);
}

static gboolean
_filterx_ref_unset_key(FilterXObject *s, FilterXObject *key)
{
  FilterXRef *self = (FilterXRef *) s;

  _filterx_ref_cow(self);

  return filterx_object_unset_key(self->value, key);
}

static void
_filterx_ref_free(FilterXObject *s)
{
  FilterXRef *self = (FilterXRef *) s;

  g_atomic_counter_dec_and_test(&self->value->fx_ref_cnt);
  filterx_object_unref(self->value);

  filterx_object_free_method(s);
}

static void
_prohibit_readonly(FilterXObject *s)
{
  g_assert_not_reached();
}

static gboolean
_is_modified_in_place(FilterXObject *s)
{
  FilterXRef *self = (FilterXRef *) s;
  return filterx_object_is_modified_in_place(self->value);
}

static void
_set_modified_in_place(FilterXObject *s, gboolean modified)
{
  FilterXRef *self = (FilterXRef *) s;
  filterx_object_set_modified_in_place(self->value, modified);
}

/* readonly methods */

static FilterXObject *
_filterx_ref_unmarshal(FilterXObject *s)
{
  FilterXRef *self = (FilterXRef *) s;
  FilterXObject *unmarshalled = filterx_object_unmarshal(self->value);
  if (unmarshalled != self->value)
    return unmarshalled;

  filterx_object_unref(self->value);
  return filterx_object_ref(s);
}

static gboolean
_filterx_ref_marshal(FilterXObject *s, GString *repr, LogMessageValueType *t)
{
  FilterXRef *self = (FilterXRef *) s;

  if (self->value->type->marshal)
    return self->value->type->marshal(self->value, repr, t);

  return FALSE;
}

static gboolean
_filterx_ref_map_to_json(FilterXObject *s, struct json_object **object, FilterXObject **assoc_object)
{
  FilterXRef *self = (FilterXRef *) s;
  gboolean ok = filterx_object_map_to_json(self->value, object, assoc_object);
  if (*assoc_object != self->value)
    return ok;

  filterx_object_unref(self->value);
  *assoc_object = filterx_object_ref(s);
  return ok;
}

static gboolean
_filterx_ref_truthy(FilterXObject *s)
{
  FilterXRef *self = (FilterXRef *) s;
  return filterx_object_truthy(self->value);
}

static FilterXObject *
_filterx_ref_getattr(FilterXObject *s, FilterXObject *attr)
{
  FilterXRef *self = (FilterXRef *) s;
  return filterx_object_getattr(self->value, attr);
}

static FilterXObject *
_filterx_ref_get_subscript(FilterXObject *s, FilterXObject *key)
{
  FilterXRef *self = (FilterXRef *) s;
  return filterx_object_get_subscript(self->value, key);
}

static gboolean
_filterx_ref_is_key_set(FilterXObject *s, FilterXObject *key)
{
  FilterXRef *self = (FilterXRef *) s;
  return filterx_object_is_key_set(self->value, key);
}

static FilterXObject *
_filterx_ref_list_factory(FilterXObject *s)
{
  FilterXRef *self = (FilterXRef *) s;
  return filterx_object_create_list(self->value);
}

static FilterXObject *
_filterx_ref_dict_factory(FilterXObject *s)
{
  FilterXRef *self = (FilterXRef *) s;
  return filterx_object_create_dict(self->value);
}

static gboolean
_filterx_ref_repr(FilterXObject *s, GString *repr)
{
  FilterXRef *self = (FilterXRef *) s;

  if (self->value->type->repr)
    return self->value->type->repr(self->value, repr);

  return FALSE;
}

static gboolean
_filterx_ref_len(FilterXObject *s, guint64 *len)
{
  FilterXRef *self = (FilterXRef *) s;
  return filterx_object_len(self->value, len);
}

static FilterXObject *
_filterx_ref_add(FilterXObject *s, FilterXObject *object)
{
  FilterXRef *self = (FilterXRef *) s;
  return filterx_object_add_object(self->value, object);
}

/* NOTE: fastpath is in the header as an inline function */
FilterXObject *
_filterx_ref_new(FilterXObject *value)
{
  if (filterx_object_is_type(value, &FILTERX_TYPE_NAME(ref)))
    {
      FilterXRef *absorbed_ref = (FilterXRef *) value;
      value = filterx_object_ref(absorbed_ref->value);
      filterx_object_unref(&absorbed_ref->super);
    }

  FilterXRef *self = g_new0(FilterXRef, 1);

  filterx_object_init_instance(&self->super, &FILTERX_TYPE_NAME(ref));
  self->super.readonly = FALSE;

  self->value = value;
  g_atomic_counter_inc(&self->value->fx_ref_cnt);

  return &self->super;
}

FILTERX_DEFINE_TYPE(ref, FILTERX_TYPE_NAME(object),
                    .is_mutable = TRUE,
                    .unmarshal = _filterx_ref_unmarshal,
                    .marshal = _filterx_ref_marshal,
                    .clone = _filterx_ref_clone,
                    .map_to_json = _filterx_ref_map_to_json,
                    .truthy = _filterx_ref_truthy,
                    .getattr = _filterx_ref_getattr,
                    .setattr = _filterx_ref_setattr,
                    .get_subscript = _filterx_ref_get_subscript,
                    .set_subscript = _filterx_ref_set_subscript,
                    .is_key_set = _filterx_ref_is_key_set,
                    .unset_key = _filterx_ref_unset_key,
                    .list_factory = _filterx_ref_list_factory,
                    .dict_factory = _filterx_ref_dict_factory,
                    .repr = _filterx_ref_repr,
                    .len = _filterx_ref_len,
                    .add = _filterx_ref_add,
                    .make_readonly = _prohibit_readonly,
                    .is_modified_in_place = _is_modified_in_place,
                    .set_modified_in_place = _set_modified_in_place,
                    .free_fn = _filterx_ref_free,
                   );
