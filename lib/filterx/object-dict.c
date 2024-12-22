/*
 * Copyright (c) 2024 Axoflow
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

#include "filterx/object-dict.h"
#include "filterx/object-dict-interface.h"
#include "filterx/object-extractor.h"
#include "filterx/object-json.h"
#include "filterx/object-string.h"
#include "filterx/object-message-value.h"
#include "filterx/filterx-object.h"
#include "filterx/filterx-object-istype.h"
#include "filterx/filterx-ref.h"
#include "filterx/filterx-eval.h"

#include "syslog-ng.h"
#include "str-utils.h"
#include "adt/iord_map.h"

typedef struct _FilterXDictKey
{
  FilterXObject *key_obj;
  IOrdMapNode n;
  guint8 in_cache:1;
} FilterXDictKey;

/*
 * FilterXDictValue is either a FilterXRef or an immutable FilterXObject.
 * The union and the cache are used to avoid unnecessary allocations.
 *
 * - FilterXDictValue can be casted to FilterXRef (check _filterx_dict_value_is_ref()) and vice versa.
 * - A FilterXRef is always owned and never cached.
 * - An immutable FilterXObject is never owned and may be cached.
 *
 * These are important because certain preconditions must be met due to the intrusive IOrdMapNode and the cache.
 */
typedef union _FilterXDictValue
{
  FilterXRef ref;
  struct
  {
    FilterXObject __null_pad;
    FilterXObject *val;
    IOrdMapNode n;
    guint8 in_cache:1;
  } immutable;
} FilterXDictValue;

G_STATIC_ASSERT(offsetof(FilterXRef, n) == offsetof(FilterXDictValue, immutable.n));
G_STATIC_ASSERT(offsetof(FilterXDictValue, ref) == offsetof(FilterXDictValue, immutable.__null_pad));
G_STATIC_ASSERT(offsetof(FilterXDictValue, ref) == 0);

#define CACHE_SIZE 32

struct _FilterXDictObj
{
  FilterXDict super;
  IOrdMap map;

  FilterXDictKey key_cache[CACHE_SIZE];
  FilterXDictValue value_cache[CACHE_SIZE];
  guint8 key_cache_len;
  guint8 value_cache_len;
};

static inline gboolean
_filterx_dict_value_is_ref(FilterXDictValue *value)
{
  /* safe because of __null_pad */
  return filterx_object_is_type((FilterXObject *) value, &FILTERX_TYPE_NAME(ref));
}

static gboolean
_filterx_dict_truthy(FilterXObject *s)
{
  return TRUE;
}

static inline gboolean
_filterx_dict_append_json_repr(FilterXDictObj *self, GString *repr)
{
  FilterXObject *json = filterx_json_object_new_empty();
  if (!filterx_dict_merge(json, &self->super.super))
    {
      filterx_object_unref(json);
      return FALSE;
    }

  g_string_append(repr, filterx_json_object_to_json_literal(json));
  filterx_object_unref(json);
  return TRUE;
}

static gboolean
_filterx_dict_marshal(FilterXObject *s, GString *repr, LogMessageValueType *t)
{
  FilterXDictObj *self = (FilterXDictObj *) s;

  *t = LM_VT_JSON;
  return _filterx_dict_append_json_repr(self, repr);
}

static gboolean
_filterx_dict_repr(FilterXObject *s, GString *repr)
{
  FilterXDictObj *self = (FilterXDictObj *) s;
  return _filterx_dict_append_json_repr(self, repr);
}

static gboolean
_deep_copy_item(FilterXObject *key, FilterXObject *value, gpointer user_data)
{
  FilterXObject *clone = (FilterXObject *) user_data;

  key = filterx_object_clone(key);
  FilterXObject *new_value = filterx_object_clone(value);

  gboolean ok = filterx_object_set_subscript(clone, key, &new_value);

  filterx_object_unref(new_value);
  filterx_object_unref(key);

  return ok;
}

static FilterXObject *
_filterx_dict_clone(FilterXObject *s)
{
  FilterXDictObj *self = (FilterXDictObj *) s;

  FilterXObject *clone = filterx_dict_new();
  filterx_dict_iter(&self->super.super, _deep_copy_item, clone);
  return clone;
}

static inline gboolean
_is_string(FilterXObject *o)
{
  return filterx_object_is_type(o, &FILTERX_TYPE_NAME(string))
         || (filterx_object_is_type(o, &FILTERX_TYPE_NAME(message_value))
             && filterx_message_value_get_type(o) == LM_VT_STRING);
}

static FilterXObject *
_filterx_dict_get_subscript(FilterXDict *s, FilterXObject *key)
{
  FilterXDictObj *self = (FilterXDictObj *) s;

  if (!_is_string(key))
    return NULL;

  FilterXDictKey k = { .key_obj = key };
  FilterXDictValue *value = iord_map_lookup(&self->map, &k);

  if (!value)
    return NULL;

  FilterXObject *v = _filterx_dict_value_is_ref(value) ? &value->ref.super : value->immutable.val;
  return filterx_object_ref(v);
}

static inline FilterXDictKey *
_key_cache_or_alloc(FilterXDictObj *self, FilterXObject *key)
{
  FilterXDictKey *k;
  if (self->key_cache_len < CACHE_SIZE)
    {
      k = &self->key_cache[self->key_cache_len++];
      k->in_cache = TRUE;
    }
  else
    k = g_new0(FilterXDictKey, 1);

  k->key_obj = filterx_object_ref(key);

  return k;
}

static inline FilterXDictValue *
_value_cache_or_alloc(FilterXDictObj *self, FilterXObject *value)
{
  if (filterx_object_is_type(value, &FILTERX_TYPE_NAME(ref)))
    return (FilterXDictValue *) filterx_object_ref(value);

  FilterXDictValue *v;
  if (self->value_cache_len < CACHE_SIZE)
    {
      v = &self->value_cache[self->value_cache_len++];
      v->immutable.in_cache = TRUE;
    }
  else
    v = g_new0(FilterXDictValue, 1);

  v->immutable.val = filterx_object_ref(value);

  return v;
}

static gboolean
_filterx_dict_set_subscript(FilterXDict *s, FilterXObject *key, FilterXObject **new_value)
{
  FilterXDictObj *self = (FilterXDictObj *) s;

  if (!_is_string(key))
    return FALSE;

  FilterXDictKey *k = _key_cache_or_alloc(self, key);
  FilterXDictValue *v = _value_cache_or_alloc(self, *new_value);

  // map other dicts/arrays to dictobj
  // filterx_object_set_modified_in_place(&self->super.super, TRUE);
  //     filterx_object_set_modified_in_place(root_container, TRUE);

  iord_map_insert(&self->map, k, v);
  return TRUE;
}

static gboolean
_filterx_dict_unset_key(FilterXDict *s, FilterXObject *key)
{
  FilterXDictObj *self = (FilterXDictObj *) s;

  if (!_is_string(key))
    return FALSE;

  FilterXDictKey k = { .key_obj = key };
  return iord_map_remove(&self->map, &k);

  // filterx_object_set_modified_in_place(&self->super.super, TRUE);
  //     filterx_object_set_modified_in_place(root_container, TRUE);
}

static guint64
_filterx_dict_size(FilterXDict *s)
{
  FilterXDictObj *self = (FilterXDictObj *) s;

  return iord_map_size(&self->map);
}

static gboolean
_filterx_dict_foreach_inner(gpointer key, gpointer value, gpointer c)
{
  gpointer *args = (gpointer *) c;
  FilterXDictIterFunc func = args[0];
  gpointer user_data = args[1];

  FilterXDictKey *k = key;
  FilterXDictValue *v = value;

  return func(k->key_obj, _filterx_dict_value_is_ref(v) ? &v->ref.super : v->immutable.val, user_data);
}

static gboolean
_filterx_dict_foreach(FilterXDict *s, FilterXDictIterFunc func, gpointer user_data)
{
  FilterXDictObj *self = (FilterXDictObj *) s;

  gpointer args[] = { func, user_data };
  return iord_map_foreach(&self->map, _filterx_dict_foreach_inner, args);
}
/*

static FilterXObject *
_list_factory(FilterXObject *self)
{
  return filterx_dict_array_new_empty();
}

*/

static FilterXObject *
_filterx_dict_factory(FilterXObject *self)
{
  return filterx_dict_new();
}


static void
_filterx_dict_free(FilterXObject *s)
{
  FilterXDictObj *self = (FilterXDictObj *) s;

  iord_map_destroy(&self->map);

  // filterx_weakref_clear(&self->root_container);

  filterx_object_free_method(s);
}

#define FILTERX_DICT_KEY_STR(key) \
  ({ \
    const gchar *__key_str; \
    gsize __key_str_len; \
    g_assert(filterx_object_extract_string_ref(key->key_obj, &__key_str, &__key_str_len)); \
    APPEND_ZERO(__key_str, __key_str, __key_str_len); \
    __key_str; \
  })

static guint
_key_hash(gconstpointer k)
{
  FilterXDictKey *key = (FilterXDictKey *) k;

  const gchar *key_str = FILTERX_DICT_KEY_STR(key);

  return g_str_hash(key_str);
}

static gboolean
_key_equal(gconstpointer a, gconstpointer b)
{
  FilterXDictKey *key_a = (FilterXDictKey *) a;
  FilterXDictKey *key_b = (FilterXDictKey *) b;

  const gchar *key_str_a = FILTERX_DICT_KEY_STR(key_a);
  const gchar *key_str_b = FILTERX_DICT_KEY_STR(key_b);

  return g_str_equal(key_str_a, key_str_b);
}

static void
_key_destroy(gpointer k)
{
  FilterXDictKey *key = (FilterXDictKey *) k;

  filterx_object_unref(key->key_obj);

  if (!key->in_cache)
    g_free(key);
}

static void
_value_destroy(gpointer v)
{
  FilterXDictValue *value = (FilterXDictValue *) v;

  if (_filterx_dict_value_is_ref(value))
    {
      filterx_object_unref(&value->ref.super);
      return;
    }

  filterx_object_unref(value->immutable.val);

  if (!value->immutable.in_cache)
    g_free(value);
}

FilterXObject *
filterx_dict_new(void)
{
  FilterXDictObj *self = g_new0(FilterXDictObj, 1);
  filterx_dict_init_instance(&self->super, &FILTERX_TYPE_NAME(dictobj));

  self->super.get_subscript = _filterx_dict_get_subscript;
  self->super.set_subscript = _filterx_dict_set_subscript;
  self->super.unset_key = _filterx_dict_unset_key;
  self->super.len = _filterx_dict_size;
  self->super.iter = _filterx_dict_foreach;

  //filterx_weakref_set(&self->root_container, root);
  //filterx_object_unref(root);
  iord_map_init_full(&self->map, _key_hash, _key_equal, _key_destroy, offsetof(FilterXDictKey, n),
                     _value_destroy, offsetof(FilterXDictValue, immutable.n));

  return &self->super.super;
}

FilterXObject *
filterx_dict_new_from_args(FilterXExpr *s, GPtrArray *args)
{
  if (!args || args->len == 0)
    return filterx_dict_new();

  if (args->len != 1)
    {
      filterx_eval_push_error("Too many arguments", s, NULL);
      return NULL;
    }

  FilterXObject *arg = (FilterXObject *) g_ptr_array_index(args, 0);

  FilterXObject *arg_unwrapped = filterx_ref_unwrap_ro(arg);
  if (filterx_object_is_type(arg_unwrapped, &FILTERX_TYPE_NAME(dictobj)))
    return filterx_object_ref(arg);

  if (filterx_object_is_type(arg_unwrapped, &FILTERX_TYPE_NAME(dict)))
    {
      FilterXObject *self = filterx_dict_new();
      if (!filterx_dict_merge(self, arg_unwrapped))
        {
          filterx_object_unref(self);
          return NULL;
        }
      return self;
    }

  const gchar *repr;
  gsize repr_len;
  if (filterx_object_extract_string_ref(arg, &repr, &repr_len))
    {
      FilterXObject *json = filterx_json_object_new_from_repr(repr, repr_len);

      FilterXObject *self = filterx_dict_new();
      if (!filterx_dict_merge(self, json))
        {
          filterx_object_unref(self);
          filterx_object_unref(json);
          return NULL;
        }
      filterx_object_unref(json);
      return self;
    }

  filterx_eval_push_error_info("Argument must be a dict or a string", s,
                               g_strdup_printf("got \"%s\" instead", arg_unwrapped->type->name), TRUE);
  return NULL;
}

FILTERX_DEFINE_TYPE(dictobj, FILTERX_TYPE_NAME(dict),
                    .is_mutable = TRUE,
                    .truthy = _filterx_dict_truthy,
                    .free_fn = _filterx_dict_free,
                    .marshal = _filterx_dict_marshal,
                    .repr = _filterx_dict_repr,
                    .clone = _filterx_dict_clone,
                    .dict_factory = _filterx_dict_factory,
                   );
