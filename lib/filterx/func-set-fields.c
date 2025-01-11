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

#include "filterx/func-set-fields.h"
#include "filterx/object-string.h"
#include "filterx/object-primitive.h"
#include "filterx/object-dict-interface.h"
#include "filterx/object-extractor.h"
#include "filterx/expr-literal.h"
#include "filterx/expr-literal-generator.h"
#include "filterx/filterx-object-istype.h"
#include "filterx/filterx-eval.h"

#include <string.h>

#define FILTERX_FUNC_SET_FIELDS_USAGE "set_fields(dict, overrides={\"field\":[...], ...}, defaults={\"field\":[...], ...})"

typedef struct Field_
{
  FilterXObject *key;
  GPtrArray *overrides;
  GPtrArray *defaults;
} Field;

static void
_field_optimize(Field *self)
{
  if (self->overrides)
    {
      for (guint i = 0; i < self->overrides->len; i++)
        {
          FilterXExpr *override = g_ptr_array_index(self->overrides, i);
          g_ptr_array_index(self->overrides, i) = filterx_expr_optimize(override);
        }
    }

  if (self->defaults)
    {
      for (guint i = 0; i < self->defaults->len; i++)
        {
          FilterXExpr *def = g_ptr_array_index(self->defaults, i);
          g_ptr_array_index(self->defaults, i) = filterx_expr_optimize(def);
        }
    }
}

static void
_field_deinit(Field *self, GlobalConfig *cfg)
{
  if (self->overrides)
    {
      for (guint i = 0; i < self->overrides->len; i++)
        {
          FilterXExpr *override = g_ptr_array_index(self->overrides, i);
          filterx_expr_deinit(override, cfg);
        }
    }

  if (self->defaults)
    {
      for (guint i = 0; i < self->defaults->len; i++)
        {
          FilterXExpr *def = g_ptr_array_index(self->defaults, i);
          filterx_expr_deinit(def, cfg);
        }
    }
}

static gboolean
_field_init(Field *self, GlobalConfig *cfg)
{
  if (self->overrides)
    {
      for (guint i = 0; i < self->overrides->len; i++)
        {
          FilterXExpr *override = g_ptr_array_index(self->overrides, i);
          if (!filterx_expr_init(override, cfg))
            goto error;
        }
    }

  if (self->defaults)
    {
      for (guint i = 0; i < self->defaults->len; i++)
        {
          FilterXExpr *def = g_ptr_array_index(self->defaults, i);
          if (!filterx_expr_init(def, cfg))
            goto error;
        }
    }

  return TRUE;

error:
  _field_deinit(self, cfg);
  return FALSE;
}

static void
_field_destroy(Field *self)
{
  filterx_object_unref(self->key);
  if (self->overrides)
    g_ptr_array_free(self->overrides, TRUE);
  if (self->defaults)
    g_ptr_array_free(self->defaults, TRUE);
}

static void
_field_add_override(Field *self, FilterXExpr *override)
{
  if (!self->overrides)
    self->overrides = g_ptr_array_new_with_free_func((GDestroyNotify) filterx_expr_unref);
  g_ptr_array_add(self->overrides, filterx_expr_ref(override));
}

static void
_field_add_default(Field *self, FilterXExpr *def)
{
  if (!self->defaults)
    self->defaults = g_ptr_array_new_with_free_func((GDestroyNotify) filterx_expr_unref);
  g_ptr_array_add(self->defaults, filterx_expr_ref(def));
}


typedef struct FilterXFunctionSetFields_
{
  FilterXFunction super;
  FilterXExpr *dict;
  GArray *fields;
} FilterXFunctionSetFields;

static gboolean
_set_with_fallbacks(FilterXObject *dict, FilterXObject *key, GPtrArray *values)
{
  gboolean changed = FALSE;

  if (!values || values->len == 0)
    return changed;

  for (guint i = 0; i < values->len; i++)
    {
      FilterXExpr *value = g_ptr_array_index(values, i);
      FilterXObject *value_obj = filterx_expr_eval(value);
      if (!value_obj)
        {
          filterx_eval_clear_errors();
          continue;
        }

      if (filterx_object_extract_null(value_obj))
        {
          filterx_object_unref(value_obj);
          continue;
        }

      FilterXObject *value_obj_cloned = filterx_object_clone(value_obj);
      filterx_object_unref(value_obj);

      if (!filterx_object_set_subscript(dict, key, &value_obj_cloned))
        {
          filterx_object_unref(value_obj_cloned);
          continue;
        }

      filterx_object_unref(value_obj_cloned);
      changed = TRUE;
      break;
    }

  return changed;
}

static void
_process_field(Field *field, FilterXObject *dict)
{
  gboolean changed = _set_with_fallbacks(dict, field->key, field->overrides);
  if (changed)
    return;

  if (filterx_object_is_key_set(dict, field->key))
    return;

  _set_with_fallbacks(dict, field->key, field->defaults);
}

static FilterXObject *
_eval_fx_set_fields(FilterXExpr *s)
{
  FilterXFunctionSetFields *self = (FilterXFunctionSetFields *) s;

  gboolean success = FALSE;

  FilterXObject *dict = filterx_expr_eval(self->dict);
  if (!dict)
    goto exit;

  FilterXObject *dict_unwrapped = filterx_ref_unwrap_ro(dict);
  if (!filterx_object_is_type(dict_unwrapped, &FILTERX_TYPE_NAME(dict)))
    {
      filterx_eval_push_error("First argument must be a dict. " FILTERX_FUNC_SET_FIELDS_USAGE, s, NULL);
      goto exit;
    }

  for (guint i = 0; i < self->fields->len; i++)
    {
      Field *field = &g_array_index(self->fields, Field, i);
      _process_field(field, dict);
    }

  success = TRUE;

exit:
  filterx_object_unref(dict);
  return success ? filterx_boolean_new(TRUE) : NULL;
}

static FilterXExpr *
_optimize(FilterXExpr *s)
{
  FilterXFunctionSetFields *self = (FilterXFunctionSetFields *) s;

  self->dict = filterx_expr_optimize(self->dict);

  for (guint i = 0; i < self->fields->len; i++)
    {
      Field *field = &g_array_index(self->fields, Field, i);
      _field_optimize(field);
    }

  return filterx_function_optimize_method(&self->super);
}

static gboolean
_init(FilterXExpr *s, GlobalConfig *cfg)
{
  FilterXFunctionSetFields *self = (FilterXFunctionSetFields *) s;

  if (!filterx_expr_init(self->dict, cfg))
    return FALSE;

  for (guint i = 0; i < self->fields->len; i++)
    {
      Field *field = &g_array_index(self->fields, Field, i);
      if (!_field_init(field, cfg))
        {
          for (guint j = 0; j < i; j++)
            {
              field = &g_array_index(self->fields, Field, j);
              _field_deinit(field, cfg);
            }
          filterx_expr_deinit(self->dict, cfg);
          return FALSE;
        }
    }

  return filterx_function_init_method(&self->super, cfg);
}

static void
_deinit(FilterXExpr *s, GlobalConfig *cfg)
{
  FilterXFunctionSetFields *self = (FilterXFunctionSetFields *) s;

  filterx_expr_deinit(self->dict, cfg);

  for (guint i = 0; i < self->fields->len; i++)
    {
      Field *field = &g_array_index(self->fields, Field, i);
      _field_deinit(field, cfg);
    }

  filterx_function_deinit_method(&self->super, cfg);
}

static void
_free(FilterXExpr *s)
{
  FilterXFunctionSetFields *self = (FilterXFunctionSetFields *) s;

  filterx_expr_unref(self->dict);

  for (guint i = 0; i < self->fields->len; i++)
    {
      Field *field = &g_array_index(self->fields, Field, i);
      _field_destroy(field);
    }
  g_array_free(self->fields, TRUE);

  filterx_function_free_method(&self->super);
}

static FilterXObject *
_extract_field_key_obj(FilterXExpr *key, GError **error)
{
  FilterXObject *key_obj = NULL;

  if (!filterx_expr_is_literal(key))
    goto exit;

  key_obj = filterx_expr_eval(key);
  if (!filterx_object_is_type(key_obj, &FILTERX_TYPE_NAME(string)))
    {
      filterx_object_unref(key_obj);
      key_obj = NULL;
      goto exit;
    }

exit:
  if (!key_obj)
    g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                "field name must be a string literal. " FILTERX_FUNC_SET_FIELDS_USAGE);
  return key_obj;
}

static gboolean
_are_field_keys_equal(FilterXObject *key_a, FilterXObject *key_b)
{
  gsize len_a, len_b;
  const gchar *key_a_str = filterx_string_get_value_ref(key_a, &len_a);
  const gchar *key_b_str = filterx_string_get_value_ref(key_b, &len_b);

  return len_a == len_b && strcmp(key_a_str, key_b_str) == 0;
}

static gboolean
_add_override(gsize index, FilterXExpr *value, gpointer user_data)
{
  Field *field = (Field *) user_data;
  _field_add_override(field, value);
  return TRUE;
}

static gboolean
_load_override(FilterXExpr *key, FilterXExpr *value, gpointer user_data)
{
  FilterXFunctionSetFields *self = ((gpointer *) user_data)[0];
  GError **error = ((gpointer *) user_data)[1];

  Field field = { 0 };

  field.key = _extract_field_key_obj(key, error);
  if (!field.key)
    return FALSE;

  if (filterx_expr_is_literal_list_generator(value))
    g_assert(filterx_literal_list_generator_foreach(value, _add_override, &field));
  else
    _field_add_override(&field, value);

  g_array_append_val(self->fields, field);
  return TRUE;
}

static gboolean
_extract_overrides_arg(FilterXFunctionSetFields *self, FilterXFunctionArgs *args, GError **error)
{
  FilterXExpr *overrides = filterx_function_args_get_named_expr(args, "overrides");
  if (!overrides)
    return TRUE;

  gboolean success = FALSE;

  if (!filterx_expr_is_literal_dict_generator(overrides))
    {
      g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                  "overrides argument must a literal dict. " FILTERX_FUNC_SET_FIELDS_USAGE);
      goto exit;
    }

  gpointer user_data[] = { self, error };
  success = filterx_literal_dict_generator_foreach(overrides, _load_override, user_data);

exit:
  filterx_expr_unref(overrides);
  return success;
}

static gboolean
_add_default(gsize index, FilterXExpr *value, gpointer user_data)
{
  Field *field = (Field *) user_data;
  _field_add_default(field, value);
  return TRUE;
}

static gboolean
_load_default(FilterXExpr *key, FilterXExpr *value, gpointer user_data)
{
  FilterXFunctionSetFields *self = ((gpointer *) user_data)[0];
  GError **error = ((gpointer *) user_data)[1];

  FilterXObject *key_obj = _extract_field_key_obj(key, error);
  if (!key_obj)
    return FALSE;

  Field *field = NULL;

  for (guint i = 0; i < self->fields->len; i++)
    {
      Field *possible_field = &g_array_index(self->fields, Field, i);
      if (_are_field_keys_equal(key_obj, possible_field->key))
        {
          field = possible_field;
          break;
        }
    }

  if (!field)
    {
      Field new_field = { 0 };
      g_array_append_val(self->fields, new_field);
      field = &g_array_index(self->fields, Field, self->fields->len - 1);
      field->key = filterx_object_ref(key_obj);
    }

  if (filterx_expr_is_literal_list_generator(value))
    g_assert(filterx_literal_list_generator_foreach(value, _add_default, field));
  else
    _field_add_default(field, value);

  filterx_object_unref(key_obj);
  return TRUE;
}

static gboolean
_extract_defaults_arg(FilterXFunctionSetFields *self, FilterXFunctionArgs *args, GError **error)
{
  FilterXExpr *defaults = filterx_function_args_get_named_expr(args, "defaults");
  if (!defaults)
    return TRUE;

  gboolean success = FALSE;

  if (!filterx_expr_is_literal_dict_generator(defaults))
    {
      g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                  "defaults argument must be a literal dict. " FILTERX_FUNC_SET_FIELDS_USAGE);
      goto exit;
    }

  gpointer user_data[] = { self, error };
  success = filterx_literal_dict_generator_foreach(defaults, _load_default, user_data);

exit:
  filterx_expr_unref(defaults);
  return success;
}

static gboolean
_extract_args(FilterXFunctionSetFields *self, FilterXFunctionArgs *args, GError **error)
{
  if (filterx_function_args_len(args) != 1)
    {
      g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                  "invalid number of arguments. " FILTERX_FUNC_SET_FIELDS_USAGE);
      return FALSE;
    }

  self->dict = filterx_function_args_get_expr(args, 0);

  if (!_extract_overrides_arg(self, args, error))
    return FALSE;

  if (!_extract_defaults_arg(self, args, error))
    return FALSE;

  return TRUE;
}

FilterXExpr *
filterx_function_set_fields_new(FilterXFunctionArgs *args, GError **error)
{
  FilterXFunctionSetFields *self = g_new0(FilterXFunctionSetFields, 1);
  filterx_function_init_instance(&self->super, "set_fields");

  self->super.super.eval = _eval_fx_set_fields;
  self->super.super.optimize = _optimize;
  self->super.super.init = _init;
  self->super.super.deinit = _deinit;
  self->super.super.free_fn = _free;

  self->fields = g_array_new(FALSE, FALSE, sizeof(Field));

  if (!_extract_args(self, args, error) ||
      !filterx_function_args_check(args, error))
    goto error;

  filterx_function_args_free(args);
  return &self->super.super;

error:
  filterx_function_args_free(args);
  filterx_expr_unref(&self->super.super);
  return NULL;
}
