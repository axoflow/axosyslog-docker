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
#ifndef FILTERX_OBJECT_H_INCLUDED
#define FILTERX_OBJECT_H_INCLUDED

#include "logmsg/logmsg.h"
#include "compat/json.h"
#include "atomic.h"

typedef struct _FilterXType FilterXType;
typedef struct _FilterXObject FilterXObject;
typedef struct _FilterXExpr FilterXExpr;

struct _FilterXType
{
  FilterXType *super_type;
  const gchar *name;
  gboolean is_mutable;

  /* WARNING: adding a new method here requires an implementation in FilterXRef as well */
  FilterXObject *(*unmarshal)(FilterXObject *self);
  gboolean (*marshal)(FilterXObject *self, GString *repr, LogMessageValueType *t);
  FilterXObject *(*clone)(FilterXObject *self);
  gboolean (*map_to_json)(FilterXObject *self, struct json_object **object, FilterXObject **assoc_object);
  gboolean (*truthy)(FilterXObject *self);
  FilterXObject *(*getattr)(FilterXObject *self, FilterXObject *attr);
  gboolean (*setattr)(FilterXObject *self, FilterXObject *attr, FilterXObject **new_value);
  FilterXObject *(*get_subscript)(FilterXObject *self, FilterXObject *key);
  gboolean (*set_subscript)(FilterXObject *self, FilterXObject *key, FilterXObject **new_value);
  gboolean (*is_key_set)(FilterXObject *self, FilterXObject *key);
  gboolean (*unset_key)(FilterXObject *self, FilterXObject *key);
  FilterXObject *(*list_factory)(FilterXObject *self);
  FilterXObject *(*dict_factory)(FilterXObject *self);
  gboolean (*repr)(FilterXObject *self, GString *repr);
  gboolean (*len)(FilterXObject *self, guint64 *len);
  FilterXObject *(*add)(FilterXObject *self, FilterXObject *object);
  void (*make_readonly)(FilterXObject *self);
  gboolean (*is_modified_in_place)(FilterXObject *self);
  void (*set_modified_in_place)(FilterXObject *self, gboolean modified);
  void (*free_fn)(FilterXObject *self);
};

void filterx_type_init(FilterXType *type);
void _filterx_type_init_methods(FilterXType *type);

#define FILTERX_TYPE_NAME(_name) filterx_type_ ## _name
#define FILTERX_DECLARE_TYPE(_name) \
    extern FilterXType FILTERX_TYPE_NAME(_name)
#define FILTERX_DEFINE_TYPE(_name, _super_type, ...) \
    FilterXType FILTERX_TYPE_NAME(_name) =  \
    {           \
      .super_type = &_super_type,   \
      .name = # _name,        \
      __VA_ARGS__       \
    }

#define FILTERX_OBJECT_MAGIC_BIAS G_MAXINT32


FILTERX_DECLARE_TYPE(object);

struct _FilterXObject
{
  GAtomicCounter ref_cnt;
  GAtomicCounter fx_ref_cnt;

  /* NOTE:
   *
   *     modified_in_place -- set to TRUE in case the value in this
   *                          FilterXObject was changed.
   *                          don't use it directly, use
   *                          filterx_object_{is,set}_modified_in_place()
   *     readonly          -- marks the object as unmodifiable,
   *                          propagates to the inner elements lazily
   *
   */
  guint modified_in_place:1, readonly:1, weak_referenced:1;
  FilterXType *type;
};

FilterXObject *filterx_object_getattr_string(FilterXObject *self, const gchar *attr_name);
gboolean filterx_object_setattr_string(FilterXObject *self, const gchar *attr_name, FilterXObject **new_value);

FilterXObject *filterx_object_new(FilterXType *type);
gboolean filterx_object_freeze(FilterXObject *self);
void filterx_object_unfreeze_and_free(FilterXObject *self);
void filterx_object_init_instance(FilterXObject *self, FilterXType *type);
void filterx_object_free_method(FilterXObject *self);

static inline gboolean
filterx_object_is_frozen(FilterXObject *self)
{
  return g_atomic_counter_get(&self->ref_cnt) == FILTERX_OBJECT_MAGIC_BIAS;
}

static inline FilterXObject *
filterx_object_ref(FilterXObject *self)
{
  if (!self)
    return NULL;

  if (filterx_object_is_frozen(self))
    return self;

  g_atomic_counter_inc(&self->ref_cnt);

  return self;
}

static inline void
filterx_object_unref(FilterXObject *self)
{
  if (!self)
    return;

  if (filterx_object_is_frozen(self))
    return;

  g_assert(g_atomic_counter_get(&self->ref_cnt) > 0);
  if (g_atomic_counter_dec_and_test(&self->ref_cnt))
    {
      self->type->free_fn(self);
      g_free(self);
    }
}

static inline void
filterx_object_make_readonly(FilterXObject *self)
{
  if (self->type->make_readonly)
    self->type->make_readonly(self);

  self->readonly = TRUE;
}

static inline FilterXObject *
filterx_object_unmarshal(FilterXObject *self)
{
  if (self->type->unmarshal)
    return self->type->unmarshal(self);
  return filterx_object_ref(self);
}

static inline gboolean
filterx_object_repr(FilterXObject *self, GString *repr)
{
  if (self->type->repr)
    {
      g_string_truncate(repr, 0);
      return self->type->repr(self, repr);
    }
  return FALSE;
}

static inline gboolean
filterx_object_repr_append(FilterXObject *self, GString *repr)
{
  if (self->type->repr)
    {
      return self->type->repr(self, repr);
    }
  return FALSE;
}

static inline gboolean
filterx_object_len(FilterXObject *self, guint64 *len)
{
  if (!self->type->len)
    return FALSE;
  return self->type->len(self, len);
}

static inline gboolean
filterx_object_marshal(FilterXObject *self, GString *repr, LogMessageValueType *t)
{
  if (self->type->marshal)
    {
      g_string_truncate(repr, 0);
      return self->type->marshal(self, repr, t);
    }
  return FALSE;
}

static inline gboolean
filterx_object_marshal_append(FilterXObject *self, GString *repr, LogMessageValueType *t)
{
  if (self->type->marshal)
    return self->type->marshal(self, repr, t);
  return FALSE;
}

static inline FilterXObject *
filterx_object_clone(FilterXObject *self)
{
  if (self->readonly)
    return filterx_object_ref(self);
  return self->type->clone(self);
}

static inline gboolean
filterx_object_map_to_json(FilterXObject *self, struct json_object **object, FilterXObject **assoc_object)
{
  *assoc_object = NULL;
  if (self->type->map_to_json)
    {
      gboolean result = self->type->map_to_json(self, object, assoc_object);
      if (!(*assoc_object))
        *assoc_object = filterx_object_ref(self);
      return result;
    }
  return FALSE;
}

static inline gboolean
filterx_object_truthy(FilterXObject *self)
{
  return self->type->truthy(self);
}

static inline gboolean
filterx_object_falsy(FilterXObject *self)
{
  return !filterx_object_truthy(self);
}

static inline FilterXObject *
filterx_object_getattr(FilterXObject *self, FilterXObject *attr)
{
  if (!self->type->getattr)
    return NULL;

  FilterXObject *result = self->type->getattr(self, attr);
  if (result && self->readonly)
    filterx_object_make_readonly(result);
  return result;
}

static inline gboolean
filterx_object_setattr(FilterXObject *self, FilterXObject *attr, FilterXObject **new_value)
{
  g_assert(!self->readonly);

  if (self->type->setattr)
    return self->type->setattr(self, attr, new_value);
  return FALSE;
}

static inline FilterXObject *
filterx_object_get_subscript(FilterXObject *self, FilterXObject *key)
{
  if (!self->type->get_subscript)
    return NULL;

  FilterXObject *result = self->type->get_subscript(self, key);
  if (result && self->readonly)
    filterx_object_make_readonly(result);
  return result;
}

static inline gboolean
filterx_object_set_subscript(FilterXObject *self, FilterXObject *key, FilterXObject **new_value)
{
  g_assert(!self->readonly);

  if (self->type->set_subscript)
    return self->type->set_subscript(self, key, new_value);
  return FALSE;
}

static inline gboolean
filterx_object_is_key_set(FilterXObject *self, FilterXObject *key)
{
  if (self->type->is_key_set)
    return self->type->is_key_set(self, key);
  return FALSE;
}

static inline gboolean
filterx_object_unset_key(FilterXObject *self, FilterXObject *key)
{
  g_assert(!self->readonly);

  if (self->type->unset_key)
    return self->type->unset_key(self, key);
  return FALSE;
}

static inline FilterXObject *
filterx_object_create_list(FilterXObject *self)
{
  if (!self->type->list_factory)
    return NULL;

  return self->type->list_factory(self);
}

static inline FilterXObject *
filterx_object_create_dict(FilterXObject *self)
{
  if (!self->type->dict_factory)
    return NULL;

  return self->type->dict_factory(self);
}

static inline FilterXObject *
filterx_object_add_object(FilterXObject *self, FilterXObject *object)
{
  if (!self->type->add)
    {
      msg_error("The add method is not supported for the given type",
                evt_tag_str("type", self->type->name));
      return NULL;
    }

  return self->type->add(self, object);
}

static inline gboolean
filterx_object_is_modified_in_place(FilterXObject *self)
{
  if (G_UNLIKELY(self->type->is_modified_in_place))
    return self->type->is_modified_in_place(self);

  return self->modified_in_place;
}

static inline void
filterx_object_set_modified_in_place(FilterXObject *self, gboolean modified)
{
  if (G_UNLIKELY(self->type->set_modified_in_place))
    return self->type->set_modified_in_place(self, modified);

  self->modified_in_place = modified;
}

static inline FilterXObject *
filterx_object_path_lookup(FilterXObject *self, FilterXObject *keys[], size_t key_count)
{
  if (self == NULL)
    {
      return NULL;
    }

  if (!keys || key_count == 0)
    {
      return filterx_object_ref(self);
    }

  FilterXObject *next = filterx_object_get_subscript(self, keys[0]);
  if (next == NULL)
    {
      return NULL;
    }

  FilterXObject *res = filterx_object_path_lookup(next, keys + 1, key_count - 1);
  filterx_object_unref(next);
  return res;
}

static inline FilterXObject *
filterx_object_path_lookup_g(FilterXObject *self, GPtrArray *keys)
{
  return filterx_object_path_lookup(self, (FilterXObject **)keys->pdata, keys->len);
}

#endif
