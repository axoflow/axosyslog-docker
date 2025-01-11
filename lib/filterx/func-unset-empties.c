/*
 * Copyright (c) 2023 Axoflow
 * Copyright (c) 2024 Attila Szakacs
 * Copyright (c) 2024 shifter
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

#include "filterx/func-unset-empties.h"
#include "filterx/object-extractor.h"
#include "filterx/object-string.h"
#include "filterx/object-primitive.h"
#include "filterx/object-null.h"
#include "filterx/object-dict-interface.h"
#include "filterx/object-list-interface.h"
#include "filterx/filterx-eval.h"
#include "filterx/filterx-globals.h"
#include "filterx/func-flags.h"
#include "filterx/expr-literal-generator.h"
#include "filterx/expr-literal.h"
#include "filterx/filterx-object-istype.h"
#include "filterx/filterx-ref.h"

#define FILTERX_FUNC_UNSET_EMPTIES_USAGE "Usage: unset_empties(object, " \
FILTERX_FUNC_UNSET_EMPTIES_ARG_NAME_RECURSIVE"=bool, " \
FILTERX_FUNC_UNSET_EMPTIES_ARG_NAME_IGNORECASE"=bool, " \
FILTERX_FUNC_UNSET_EMPTIES_ARG_NAME_TARGETS"=[objects...], " \
FILTERX_FUNC_UNSET_EMPTIES_ARG_NAME_REPLACEMENT"=str);"

DEFINE_FUNC_FLAGS(FilterXFunctionUnsetEmptiesFlags,
                  FILTERX_FUNC_UNSET_EMPTIES_FLAG_RECURSIVE,
                  FILTERX_FUNC_UNSET_EMPTIES_FLAG_IGNORECASE,
                  FILTERX_FUNC_UNSET_EMPTIES_FLAG_REPLACE_NULL,
                  FILTERX_FUNC_UNSET_EMPTIES_FLAG_REPLACE_EMPTY_STRING,
                  FILTERX_FUNC_UNSET_EMPTIES_FLAG_REPLACE_EMPTY_LIST,
                  FILTERX_FUNC_UNSET_EMPTIES_FLAG_REPLACE_EMPTY_DICT
                 );

typedef struct FilterXFunctionUnsetEmpties_
{
  FilterXFunction super;
  FilterXExpr *object_expr;
  GPtrArray *targets;
  FilterXObject *replacement;
  guint64 flags;
} FilterXFunctionUnsetEmpties;

static gboolean _process_dict(FilterXFunctionUnsetEmpties *self, FilterXObject *obj);
static gboolean _process_list(FilterXFunctionUnsetEmpties *self, FilterXObject *obj);

typedef int (*str_cmp_fn)(const char *, const char *);

static inline gboolean
_string_compare(FilterXFunctionUnsetEmpties *self, const gchar *str, str_cmp_fn cmp_fn)
{
  guint num_targets = self->targets ? self->targets->len : 0;
  for (guint i = 0; i < num_targets; i++)
    {
      const gchar *target = g_ptr_array_index(self->targets, i);
      if (cmp_fn(str, target) == 0)
        return TRUE;
    }
  return FALSE;
}

static gboolean
_should_unset_string(FilterXFunctionUnsetEmpties *self, FilterXObject *obj)
{
  gsize str_len = 0;
  const gchar *str = NULL;
  if (!filterx_object_extract_string_ref(obj, &str, &str_len))
    return FALSE;
  g_assert(str);

  if (check_flag(self->flags, FILTERX_FUNC_UNSET_EMPTIES_FLAG_REPLACE_EMPTY_STRING) && (str_len == 0))
    return TRUE;

  if (check_flag(self->flags, FILTERX_FUNC_UNSET_EMPTIES_FLAG_IGNORECASE))
    {
      gboolean result = _string_compare(self, str, strcasecmp);
      return result;
    }
  return _string_compare(self, str, strcmp);
}

static gboolean
_should_unset(FilterXFunctionUnsetEmpties *self, FilterXObject *obj)
{
  filterx_assert_not_ref(obj);

  if (check_flag(self->flags, FILTERX_FUNC_UNSET_EMPTIES_FLAG_REPLACE_NULL) &&
      filterx_object_is_type(obj, &FILTERX_TYPE_NAME(null)))
    return TRUE;

  if ((check_flag(self->flags, FILTERX_FUNC_UNSET_EMPTIES_FLAG_REPLACE_EMPTY_LIST) &&
       filterx_object_is_type(obj, &FILTERX_TYPE_NAME(list))) ||
      (check_flag(self->flags, FILTERX_FUNC_UNSET_EMPTIES_FLAG_REPLACE_EMPTY_DICT) &&
       filterx_object_is_type(obj, &FILTERX_TYPE_NAME(dict))))
    {
      guint64 len;
      filterx_object_len(obj, &len);
      return len == 0;
    }
  return _should_unset_string(self, obj);
}

/* Also unsets inner dicts' and lists' values is recursive is set. */
static gboolean
_add_key_to_unset_list_if_needed(FilterXObject *key, FilterXObject *value, gpointer user_data)
{
  FilterXFunctionUnsetEmpties *self = ((gpointer *) user_data)[0];
  GList **keys_to_unset = ((gpointer *) user_data)[1];

  value = filterx_ref_unwrap_rw(value);
  if (check_flag(self->flags, FILTERX_FUNC_UNSET_EMPTIES_FLAG_RECURSIVE))
    {
      if (filterx_object_is_type(value, &FILTERX_TYPE_NAME(dict)) && !_process_dict(self, value))
        return FALSE;
      if (filterx_object_is_type(value, &FILTERX_TYPE_NAME(list)) && !_process_list(self, value))
        return FALSE;
    }

  if (!_should_unset(self, value))
    return TRUE;

  *keys_to_unset = g_list_append(*keys_to_unset, filterx_object_ref(key));
  return TRUE;
}

static gboolean
_process_dict(FilterXFunctionUnsetEmpties *self, FilterXObject *obj)
{
  GList *keys_to_unset = NULL;
  gpointer user_data[] = { self, &keys_to_unset };
  gboolean success = filterx_dict_iter(obj, _add_key_to_unset_list_if_needed, user_data);

  for (GList *elem = keys_to_unset; elem && success; elem = elem->next)
    {
      FilterXObject *key = (FilterXObject *) elem->data;
      if (self->replacement)
        {
          if (!filterx_object_set_subscript(obj, key, &self->replacement))
            success = FALSE;
        }
      else
        {
          if (!filterx_object_unset_key(obj, key))
            success = FALSE;
        }
    }

  g_list_free_full(keys_to_unset, (GDestroyNotify) filterx_object_unref);
  return success;
}

static gboolean
_process_list(FilterXFunctionUnsetEmpties *self, FilterXObject *obj)
{
  guint64 len;
  filterx_object_len(obj, &len);
  if (len == 0)
    return TRUE;

  for (gint64 i = ((gint64) len) - 1; i >= 0; i--)
    {
      FilterXObject *elem = filterx_list_get_subscript(obj, i);
      FilterXObject *elem_unwrapped = filterx_ref_unwrap_rw(elem);

      if (check_flag(self->flags, FILTERX_FUNC_UNSET_EMPTIES_FLAG_RECURSIVE))
        {
          if (filterx_object_is_type(elem_unwrapped, &FILTERX_TYPE_NAME(dict)) && !_process_dict(self, elem_unwrapped))
            {
              filterx_object_unref(elem);
              return FALSE;
            }
          if (filterx_object_is_type(elem_unwrapped, &FILTERX_TYPE_NAME(list)) && !_process_list(self, elem_unwrapped))
            {
              filterx_object_unref(elem);
              return FALSE;
            }
        }

      if (_should_unset(self, elem_unwrapped))
        {
          if (self->replacement)
            {
              if (!filterx_list_set_subscript(obj, i, &self->replacement))
                {
                  filterx_object_unref(elem);
                  return FALSE;
                }
            }
          else if (!filterx_list_unset_index(obj, i))
            {
              filterx_object_unref(elem);
              return FALSE;
            }
        }

      filterx_object_unref(elem);
    }

  return TRUE;
}

static FilterXObject *
_eval_fx_unset_empties(FilterXExpr *s)
{
  FilterXFunctionUnsetEmpties *self = (FilterXFunctionUnsetEmpties *) s;

  FilterXObject *obj = filterx_expr_eval(self->object_expr);
  if (!obj)
    {
      filterx_eval_push_error("Failed to evaluate first argument. " FILTERX_FUNC_UNSET_EMPTIES_USAGE, s, NULL);
      return NULL;
    }

  gboolean success = FALSE;
  FilterXObject *obj_unwrapped = filterx_ref_unwrap_rw(obj);
  if (filterx_object_is_type(obj_unwrapped, &FILTERX_TYPE_NAME(dict)))
    success = _process_dict(self, obj_unwrapped);
  else if (filterx_object_is_type(obj_unwrapped, &FILTERX_TYPE_NAME(list)))
    success = _process_list(self, obj_unwrapped);
  else
    filterx_eval_push_error("Object must be dict or list. " FILTERX_FUNC_UNSET_EMPTIES_USAGE, s, obj);

  filterx_object_unref(obj);
  return success ? filterx_boolean_new(TRUE) : NULL;
}

static FilterXExpr *
_optimize(FilterXExpr *s)
{
  FilterXFunctionUnsetEmpties *self = (FilterXFunctionUnsetEmpties *) s;

  self->object_expr = filterx_expr_optimize(self->object_expr);
  return filterx_function_optimize_method(&self->super);
}

static gboolean
_init(FilterXExpr *s, GlobalConfig *cfg)
{
  FilterXFunctionUnsetEmpties *self = (FilterXFunctionUnsetEmpties *) s;

  if (!filterx_expr_init(self->object_expr, cfg))
    return FALSE;

  return filterx_function_init_method(&self->super, cfg);
}

static void
_deinit(FilterXExpr *s, GlobalConfig *cfg)
{
  FilterXFunctionUnsetEmpties *self = (FilterXFunctionUnsetEmpties *) s;

  filterx_expr_deinit(self->object_expr, cfg);
  filterx_function_deinit_method(&self->super, cfg);
}

static void
_free(FilterXExpr *s)
{
  FilterXFunctionUnsetEmpties *self = (FilterXFunctionUnsetEmpties *) s;
  if (self->targets)
    g_ptr_array_free(self->targets, TRUE);
  filterx_expr_unref(self->object_expr);
  filterx_object_unref(self->replacement);
  filterx_function_free_method(&self->super);
}

static FilterXExpr *
_extract_object_expr(FilterXFunctionArgs *args, GError **error)
{
  FilterXExpr *object_expr = filterx_function_args_get_expr(args, 0);
  if (!object_expr)
    {
      g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                  "argument must be set: object. " FILTERX_FUNC_UNSET_EMPTIES_USAGE);
      return NULL;
    }

  return object_expr;
}

static gboolean
_extract_optional_arg_recursive(FilterXFunctionUnsetEmpties *self, FilterXFunctionArgs *args, GError **error)
{
  gboolean exists, eval_error;
  gboolean value = filterx_function_args_get_named_literal_boolean(args, FILTERX_FUNC_UNSET_EMPTIES_ARG_NAME_RECURSIVE,
                   &exists, &eval_error);
  if (!exists)
    return TRUE;

  if (eval_error)
    {
      g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                  FILTERX_FUNC_UNSET_EMPTIES_ARG_NAME_RECURSIVE" argument must be boolean literal. " FILTERX_FUNC_UNSET_EMPTIES_USAGE);
      return FALSE;
    }

  set_flag(&self->flags, FILTERX_FUNC_UNSET_EMPTIES_FLAG_RECURSIVE, value);

  return TRUE;
}

static gboolean
_extract_optional_arg_ignorecase(FilterXFunctionUnsetEmpties *self, FilterXFunctionArgs *args, GError **error)
{
  gboolean exists, eval_error;
  gboolean value = filterx_function_args_get_named_literal_boolean(args, FILTERX_FUNC_UNSET_EMPTIES_ARG_NAME_IGNORECASE,
                   &exists, &eval_error);
  if (!exists)
    return TRUE;

  if (eval_error)
    {
      g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                  FILTERX_FUNC_UNSET_EMPTIES_ARG_NAME_IGNORECASE" argument must be boolean literal. " FILTERX_FUNC_UNSET_EMPTIES_USAGE);
      return FALSE;
    }

  set_flag(&self->flags, FILTERX_FUNC_UNSET_EMPTIES_FLAG_IGNORECASE, value);

  return TRUE;
}


static gboolean
_extract_optional_arg_replacement(FilterXFunctionUnsetEmpties *self, FilterXFunctionArgs *args, GError **error)
{
  gboolean exists;
  FilterXObject *value = filterx_function_args_get_named_literal_object(args,
                         FILTERX_FUNC_UNSET_EMPTIES_ARG_NAME_REPLACEMENT, &exists);
  if (!exists)
    return TRUE;
  if (!value)
    {
      g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                  FILTERX_FUNC_UNSET_EMPTIES_ARG_NAME_REPLACEMENT" argument must be literal. " FILTERX_FUNC_UNSET_EMPTIES_USAGE);
      return FALSE;
    }

  self->replacement = value;
  return TRUE;
}

static gboolean
_handle_target_object(FilterXFunctionUnsetEmpties *self, FilterXObject *target, GError **error)
{
  g_assert(target);
  guint64 len;

  target = filterx_ref_unwrap_ro(target);

  if (filterx_object_is_type(target, &FILTERX_TYPE_NAME(null)))
    set_flag(&self->flags, FILTERX_FUNC_UNSET_EMPTIES_FLAG_REPLACE_NULL, TRUE);
  else if (filterx_object_is_type(target, &FILTERX_TYPE_NAME(list)))
    {
      g_assert(filterx_object_len(target, &len));
      if (len != 0)
        {
          g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                      FILTERX_FUNC_UNSET_EMPTIES_ARG_NAME_TARGETS" argument list must be empty! " FILTERX_FUNC_UNSET_EMPTIES_USAGE);
          return FALSE;
        }
      set_flag(&self->flags, FILTERX_FUNC_UNSET_EMPTIES_FLAG_REPLACE_EMPTY_LIST, TRUE);
    }
  else if (filterx_object_is_type(target, &FILTERX_TYPE_NAME(dict)))
    {
      g_assert(filterx_object_len(target, &len));
      if (len != 0)
        {
          g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                      FILTERX_FUNC_UNSET_EMPTIES_ARG_NAME_TARGETS" argument dict must be empty! " FILTERX_FUNC_UNSET_EMPTIES_USAGE);
          return FALSE;
        }
      set_flag(&self->flags, FILTERX_FUNC_UNSET_EMPTIES_FLAG_REPLACE_EMPTY_DICT, TRUE);
    }
  else if (filterx_object_is_type(target, &FILTERX_TYPE_NAME(string)))
    {
      const gchar *str = filterx_string_get_value_ref(target, &len);
      if (len == 0)
        {
          set_flag(&self->flags, FILTERX_FUNC_UNSET_EMPTIES_FLAG_REPLACE_EMPTY_STRING, TRUE);
          return TRUE;
        }
      if (check_flag(self->flags, FILTERX_FUNC_UNSET_EMPTIES_FLAG_IGNORECASE))
        {
          g_ptr_array_add(self->targets, g_strndup(str, len));
          return TRUE;
        }
      g_ptr_array_add(self->targets, g_strndup(str, len));
    }
  else
    {
      g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                  FILTERX_FUNC_UNSET_EMPTIES_ARG_NAME_TARGETS" has unknown target type: %s", target->type->name);
      return FALSE;
    }
  return TRUE;
}

static gboolean
_target_iterator(FilterXExpr *key, FilterXExpr *value, gpointer user_data)
{
  FilterXFunctionUnsetEmpties *self = ((gpointer *) user_data)[0];
  GError **error = ((gpointer *) user_data)[1];

  if (!filterx_expr_is_literal(value) && !filterx_expr_is_literal_generator(value))
    {
      g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                  FILTERX_FUNC_UNSET_EMPTIES_ARG_NAME_TARGETS" list members must be literals!" FILTERX_FUNC_UNSET_EMPTIES_USAGE);
      return FALSE;
    }

  FilterXObject *target = filterx_expr_eval(value);
  g_assert(target);

  gboolean res = _handle_target_object(self, target, error);
  filterx_object_unref(target);
  return res;
}

static gboolean
_extract_target_objects(FilterXFunctionUnsetEmpties *self, FilterXFunctionArgs *args, GError **error)
{
  gboolean exists;
  FilterXExpr *targets = filterx_function_args_get_named_expr(args,
                                                              FILTERX_FUNC_UNSET_EMPTIES_ARG_NAME_TARGETS);
  exists = !!targets;

  if (!exists)
    return TRUE;

  if (!filterx_expr_is_literal_list_generator(targets))
    {
      g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                  FILTERX_FUNC_UNSET_EMPTIES_ARG_NAME_TARGETS" argument must be literal list. " FILTERX_FUNC_UNSET_EMPTIES_USAGE);
      return FALSE;
    }

  guint64 num_targets = filterx_expr_literal_generator_len(targets);
  if (num_targets > 0)
    reset_flags(&self->flags, self->flags & (FLAG_VAL(FILTERX_FUNC_UNSET_EMPTIES_FLAG_IGNORECASE) |
                                             FLAG_VAL(FILTERX_FUNC_UNSET_EMPTIES_FLAG_RECURSIVE)));
  self->targets = g_ptr_array_new_full(num_targets, (GDestroyNotify)g_free);

  gpointer user_data[] = { self, error };
  gboolean result = TRUE;
  if (!filterx_literal_dict_generator_foreach(targets, _target_iterator, user_data))
    result = FALSE;
  filterx_expr_unref(targets);
  return result;
}

static gboolean
_extract_args(FilterXFunctionUnsetEmpties *self, FilterXFunctionArgs *args, GError **error)
{
  if (filterx_function_args_len(args) != 1)
    {
      g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                  "invalid number of arguments. " FILTERX_FUNC_UNSET_EMPTIES_USAGE);
      return FALSE;
    }

  self->object_expr = _extract_object_expr(args, error);
  if (!self->object_expr)
    return FALSE;

  if (!_extract_optional_arg_recursive(self, args, error))
    return FALSE;

  if (!_extract_optional_arg_ignorecase(self, args, error))
    return FALSE;

  if (!_extract_optional_arg_replacement(self, args, error))
    return FALSE;

  if (!_extract_target_objects(self, args, error))
    return FALSE;


  return TRUE;
}

FilterXExpr *
filterx_function_unset_empties_new(FilterXFunctionArgs *args, GError **error)
{
  FilterXFunctionUnsetEmpties *self = g_new0(FilterXFunctionUnsetEmpties, 1);
  filterx_function_init_instance(&self->super, "unset_empties");
  self->super.super.eval = _eval_fx_unset_empties;
  self->super.super.optimize = _optimize;
  self->super.super.init = _init;
  self->super.super.deinit = _deinit;
  self->super.super.free_fn = _free;

  /* everything is enabled except ignorecase */
  reset_flags(&self->flags,
              FLAG_VAL(FILTERX_FUNC_UNSET_EMPTIES_FLAG_RECURSIVE) |
              FLAG_VAL(FILTERX_FUNC_UNSET_EMPTIES_FLAG_REPLACE_NULL) |
              FLAG_VAL(FILTERX_FUNC_UNSET_EMPTIES_FLAG_REPLACE_EMPTY_STRING) |
              FLAG_VAL(FILTERX_FUNC_UNSET_EMPTIES_FLAG_REPLACE_EMPTY_LIST) |
              FLAG_VAL(FILTERX_FUNC_UNSET_EMPTIES_FLAG_REPLACE_EMPTY_DICT)
             );

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
