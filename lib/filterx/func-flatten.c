/*
 * Copyright (c) 2024 Axoflow
 * Copyright (c) 2024 Attila Szakacs <attila.szakacs@axoflow.com>
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

#include "filterx/func-flatten.h"
#include "filterx/object-dict-interface.h"
#include "filterx/object-primitive.h"
#include "filterx/object-string.h"
#include "filterx/filterx-eval.h"
#include "filterx/filterx-object-istype.h"
#include "filterx/filterx-ref.h"
#include "scratch-buffers.h"

#define FILTERX_FUNC_FLATTEN_USAGE "Usage: flatten(dict, separator=\".\")"

typedef struct FilterXFunctionFlatten_
{
  FilterXFunction super;
  FilterXExpr *dict_expr;
  gchar *separator;
} FilterXFunctionFlatten;

typedef struct FilterXFunctionFlattenKV_
{
  FilterXObject *key;
  FilterXObject *value;
} FilterXFunctionFlattenKV;

static void
_kv_init(FilterXFunctionFlattenKV *self, FilterXObject *key, FilterXObject *value)
{
  self->key = filterx_object_ref(key);
  self->value = filterx_object_ref(value);
}

static void
_kv_destroy(FilterXFunctionFlattenKV *self)
{
  filterx_object_unref(self->key);
  filterx_object_unref(self->value);
}

static gboolean
_collect_modifications_from_elem(FilterXObject *key, FilterXObject *value, gpointer user_data)
{
  FilterXFunctionFlatten *self = ((gpointer *) user_data)[0];
  GArray *flattened_kvs = ((gpointer *) user_data)[1];
  GPtrArray *top_level_dict_keys = ((gpointer *) user_data)[2];
  GString *key_buffer = ((gpointer *) user_data)[3];
  gboolean is_top_level = (gboolean) GPOINTER_TO_INT(((gpointer *) user_data)[4]);

  FilterXObject *dict = filterx_ref_unwrap_ro(value);
  if (filterx_object_is_type(dict, &FILTERX_TYPE_NAME(dict)))
    {
      if (is_top_level)
        g_ptr_array_add(top_level_dict_keys, filterx_object_ref(key));

      gssize orig_len = key_buffer->len;
      if (!filterx_object_repr_append(key, key_buffer))
        {
          filterx_eval_push_error("failed to call repr() on key", self->dict_expr, key);
          return FALSE;
        }
      g_string_append(key_buffer, self->separator);

      gpointer inner_user_data[] = { self, flattened_kvs, NULL, key_buffer, GINT_TO_POINTER(FALSE)};
      gboolean result = filterx_dict_iter(dict, _collect_modifications_from_elem, inner_user_data);

      g_string_truncate(key_buffer, orig_len);
      return result;
    }

  if (is_top_level)
    {
      /* Top level leaf. This KV does not need flattening, we can keep it. */
      return TRUE;
    }

  /* Not top level leaf. This KV needs flattening. */
  gssize orig_len = key_buffer->len;
  if (!filterx_object_repr_append(key, key_buffer))
    {
      filterx_eval_push_error("failed to call repr() on key", self->dict_expr, key);
      return FALSE;
    }

  FilterXObject *flat_key = filterx_string_new(key_buffer->str, (gssize) MIN(key_buffer->len, G_MAXSSIZE));
  FilterXFunctionFlattenKV kv;
  _kv_init(&kv, flat_key, value);
  g_array_append_val(flattened_kvs, kv);
  filterx_object_unref(flat_key);

  g_string_truncate(key_buffer, orig_len);
  return TRUE;
}

static gboolean
_collect_dict_modifications(FilterXFunctionFlatten *self, FilterXObject *dict,
                            GArray *flattened_kvs, GPtrArray *top_level_dict_keys)
{
  GString *key_buffer = scratch_buffers_alloc();
  gpointer user_data[] = { self, flattened_kvs, top_level_dict_keys, key_buffer, GINT_TO_POINTER(TRUE)};
  return filterx_dict_iter(dict, _collect_modifications_from_elem, user_data);
}

static gboolean
_remove_keys(FilterXFunctionFlatten *self, FilterXObject *dict, GPtrArray *keys)
{
  for (guint i = 0; i < keys->len; i++)
    {
      FilterXObject *key = (FilterXObject *) g_ptr_array_index(keys, i);
      if (!filterx_object_unset_key(dict, key))
        return FALSE;
    }

  return TRUE;
}

static gboolean
_add_kvs(FilterXFunctionFlatten *self, FilterXObject *dict, GArray *kvs)
{
  for (guint i = 0; i < kvs->len; i++)
    {
      FilterXFunctionFlattenKV *kv = &g_array_index(kvs, FilterXFunctionFlattenKV, i);

      FilterXObject *value = filterx_object_clone(kv->value);
      gboolean success = filterx_object_set_subscript(dict, kv->key, &value);
      filterx_object_unref(value);

      if (!success)
        {
          filterx_eval_push_error("failed to set dict value", self->dict_expr, kv->key);
          return FALSE;
        }
    }

  return TRUE;
}

static gboolean
_flatten(FilterXFunctionFlatten *self, FilterXObject *dict)
{
  GArray *flattened_kvs = g_array_new(FALSE, FALSE, sizeof(FilterXFunctionFlattenKV));
  GPtrArray *top_level_dict_keys = g_ptr_array_new_with_free_func((GDestroyNotify) filterx_object_unref);
  gboolean result = FALSE;

  if (!_collect_dict_modifications(self, dict, flattened_kvs, top_level_dict_keys))
    goto exit;

  if (!_remove_keys(self, dict, top_level_dict_keys))
    goto exit;

  if (!_add_kvs(self, dict, flattened_kvs))
    goto exit;

  result = TRUE;

exit:
  for (guint i = 0; i < flattened_kvs->len; i++)
    _kv_destroy(&g_array_index(flattened_kvs, FilterXFunctionFlattenKV, i));
  g_array_free(flattened_kvs, TRUE);
  g_ptr_array_free(top_level_dict_keys, TRUE);
  return result;
}

static FilterXObject *
_eval_fx_flatten(FilterXExpr *s)
{
  FilterXFunctionFlatten *self = (FilterXFunctionFlatten *) s;

  FilterXObject *obj = filterx_expr_eval_typed(self->dict_expr);
  if (!obj)
    return NULL;

  gboolean result = FALSE;

  FilterXObject *dict = filterx_ref_unwrap_rw(obj);
  if (!filterx_object_is_type(dict, &FILTERX_TYPE_NAME(dict)))
    {
      filterx_eval_push_error_info("object must be a dict", self->dict_expr,
                                   g_strdup_printf("got %s instead", dict->type->name), TRUE);
      goto exit;
    }

  result = _flatten(self, dict);

exit:
  filterx_object_unref(obj);
  return result ? filterx_boolean_new(TRUE) : NULL;
}

static FilterXExpr *
_optimize(FilterXExpr *s)
{
  FilterXFunctionFlatten *self = (FilterXFunctionFlatten *) s;

  self->dict_expr = filterx_expr_optimize(self->dict_expr);
  return filterx_function_optimize_method(&self->super);
}

static gboolean
_init(FilterXExpr *s, GlobalConfig *cfg)
{
  FilterXFunctionFlatten *self = (FilterXFunctionFlatten *) s;

  if (!filterx_expr_init(self->dict_expr, cfg))
    return FALSE;

  return filterx_function_init_method(&self->super, cfg);
}

static void
_deinit(FilterXExpr *s, GlobalConfig *cfg)
{
  FilterXFunctionFlatten *self = (FilterXFunctionFlatten *) s;

  filterx_expr_deinit(self->dict_expr, cfg);
  filterx_function_deinit_method(&self->super, cfg);
}

static void
_free(FilterXExpr *s)
{
  FilterXFunctionFlatten *self = (FilterXFunctionFlatten *) s;

  filterx_expr_unref(self->dict_expr);
  g_free(self->separator);
  filterx_function_free_method(&self->super);
}

static gchar *
_extract_separator_arg(FilterXFunctionArgs *args, GError **error)
{
  gboolean exists;
  const gchar *value = filterx_function_args_get_named_literal_string(args, "separator", NULL, &exists);
  if (!exists)
    return g_strdup(".");

  if (!value)
    {
      g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                  "separator argument must be string literal. " FILTERX_FUNC_FLATTEN_USAGE);
      return NULL;
    }

  return g_strdup(value);
}

static gboolean
_extract_args(FilterXFunctionFlatten *self, FilterXFunctionArgs *args, GError **error)
{
  if (filterx_function_args_len(args) != 1)
    {
      g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                  "invalid number of arguments. " FILTERX_FUNC_FLATTEN_USAGE);
      return FALSE;
    }

  self->dict_expr = filterx_function_args_get_expr(args, 0);
  g_assert(self->dict_expr);

  self->separator = _extract_separator_arg(args, error);
  if (!self->separator)
    return FALSE;

  return TRUE;
}

FilterXExpr *
filterx_function_flatten_new(FilterXFunctionArgs *args, GError **error)
{
  FilterXFunctionFlatten *self = g_new0(FilterXFunctionFlatten, 1);
  filterx_function_init_instance(&self->super, "flatten");
  self->super.super.eval = _eval_fx_flatten;
  self->super.super.optimize = _optimize;
  self->super.super.init = _init;
  self->super.super.deinit = _deinit;
  self->super.super.free_fn = _free;

  if (!_extract_args(self, args, error))
    goto error;

  filterx_function_args_free(args);
  return &self->super.super;

error:
  filterx_function_args_free(args);
  filterx_expr_unref(&self->super.super);
  return NULL;
}
