/*
 * Copyright (c) 2024 Axoflow
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

#include "filterx/func-path-lookup.h"
#include "filterx/object-dict-interface.h"
#include "filterx/object-list-interface.h"
#include "filterx/object-primitive.h"
#include "filterx/filterx-eval.h"
#include "filterx/object-json.h"
#include "filterx/expr-literal-generator.h"
#include "filterx/expr-literal.h"
#include "filterx/filterx-object.h"

typedef struct FilterXFunctionPathLookup_
{
  FilterXFunction super;
  FilterXExpr *object_expr;
  GPtrArray *keys;
} FilterXFunctionPathLookup;

static FilterXObject *
_eval(FilterXExpr *s)
{
  FilterXFunctionPathLookup *self = (FilterXFunctionPathLookup *) s;

  FilterXObject *object = filterx_expr_eval(self->object_expr);
  if (!object)
    {
      filterx_eval_push_error("Failed to evaluate first argument. " FILTERX_FUNC_PATH_LOOKUP_USAGE, s, NULL);
      return NULL;
    }

  FilterXObject *result = filterx_object_path_lookup_g(object, self->keys);
  filterx_object_unref(object);
  return result;
}

static gboolean
_init(FilterXExpr *s, GlobalConfig *cfg)
{
  FilterXFunctionPathLookup *self = (FilterXFunctionPathLookup *) s;

  if (!filterx_expr_init(self->object_expr, cfg))
    return FALSE;

  return filterx_function_init_method(&self->super, cfg);
}

static void
_deinit(FilterXExpr *s, GlobalConfig *cfg)
{
  FilterXFunctionPathLookup *self = (FilterXFunctionPathLookup *) s;
  filterx_expr_deinit(self->object_expr, cfg);
  filterx_function_deinit_method(&self->super, cfg);
}

static void
_free(FilterXExpr *s)
{
  FilterXFunctionPathLookup *self = (FilterXFunctionPathLookup *) s;
  if (self->keys)
    g_ptr_array_free(self->keys, TRUE);
  filterx_expr_unref(self->object_expr);
  filterx_function_free_method(&self->super);
}

static gboolean
_add_iterator(FilterXExpr *key, FilterXExpr *value, gpointer user_data)
{
  FilterXFunctionPathLookup *self = ((gpointer *) user_data)[0];
  GError **error = ((gpointer *) user_data)[1];

  if (!filterx_expr_is_literal(value) && !filterx_expr_is_literal_generator(value))
    {
      g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                  FILTERX_FUNC_PATH_LOOKUP_ERR_LITERAL_LIST_ELTS FILTERX_FUNC_PATH_LOOKUP_USAGE);
      return FALSE;
    }

  FilterXObject *target = filterx_expr_eval(value);
  g_assert(target);

  g_ptr_array_add(self->keys, target);

  return TRUE;
}

static gboolean
_extract_path(FilterXFunctionPathLookup *self, FilterXFunctionArgs *args, GError **error)
{
  gboolean exists;
  FilterXExpr *path = filterx_function_args_get_expr(args, 1);

  exists = !!path;

  if (!exists)
    return TRUE;

  if (!filterx_expr_is_literal_list_generator(path))
    {
      g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                  FILTERX_FUNC_PATH_LOOKUP_ERR_LITERAL_LIST FILTERX_FUNC_PATH_LOOKUP_USAGE);
      filterx_expr_unref(path);
      return FALSE;
    }

  guint64 len = filterx_expr_literal_generator_len(path);
  self->keys = g_ptr_array_new_full(len, (GDestroyNotify)filterx_object_unref);
  gpointer user_data[] = { self, error };

  gboolean result = TRUE;
  if (!filterx_literal_dict_generator_foreach(path, _add_iterator, user_data))
    result = FALSE;

  filterx_expr_unref(path);

  return result;
}

static FilterXExpr *
_extract_object_expr(FilterXFunctionArgs *args, GError **error)
{
  FilterXExpr *object_expr = filterx_function_args_get_expr(args, 0);
  if (!object_expr)
    {
      g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                  "argument must be set: object. " FILTERX_FUNC_PATH_LOOKUP_USAGE);
      return NULL;
    }

  return object_expr;
}

static gboolean
_extract_args(FilterXFunctionPathLookup *self, FilterXFunctionArgs *args, GError **error)
{
  if (filterx_function_args_len(args) != 2)
    {
      g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                  FILTERX_FUNC_PATH_LOOKUP_ERR_NUM_ARGS FILTERX_FUNC_PATH_LOOKUP_USAGE);
      return FALSE;
    }

  self->object_expr = _extract_object_expr(args, error);
  if (!self->object_expr)
    return FALSE;

  if (!_extract_path(self, args, error))
    return FALSE;

  return TRUE;
}

FilterXExpr *
filterx_function_path_lookup_new(FilterXFunctionArgs *args, GError **error)
{
  FilterXFunctionPathLookup *self = g_new0(FilterXFunctionPathLookup, 1);
  filterx_function_init_instance(&self->super, "path_lookup");
  self->super.super.eval = _eval;
  self->super.super.init = _init;
  self->super.super.deinit = _deinit;
  self->super.super.free_fn = _free;

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
