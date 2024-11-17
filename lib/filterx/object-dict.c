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

static gboolean
_filterx_dict_truthy(FilterXObject *s)
{
  return TRUE;
}

static gboolean
_filterx_dict_marshal(FilterXObject *s, GString *repr, LogMessageValueType *t)
{
  return TRUE;
}

static gboolean
_filterx_dict_repr(FilterXObject *s, GString *repr)
{
  return TRUE;
}

static FilterXObject *
_filterx_dict_clone(FilterXObject *s)
{
  return NULL;
}

static FilterXObject *
_filterx_dict_get_subscript(FilterXDict *s, FilterXObject *key)
{
  return NULL;
}

static gboolean
_filterx_dict_set_subscript(FilterXDict *s, FilterXObject *key, FilterXObject **new_value)
{
  return TRUE;
}

static gboolean
_filterx_dict_unset_key(FilterXDict *s, FilterXObject *key)
{
  return TRUE;
}

static guint64
_filterx_dict_size(FilterXDict *s)
{
  return 0;
}

static gboolean
_filterx_dict_foreach(FilterXDict *s, FilterXDictIterFunc func, gpointer user_data)
{
  return TRUE;
}

static FilterXObject *
_filterx_dict_factory(FilterXObject *self)
{
  return filterx_dict_new();
}

static void
_filterx_dict_free(FilterXObject *s)
{
  filterx_object_free_method(s);
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
