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

#include "filterx/expr-unset.h"
#include "filterx/object-primitive.h"

typedef struct FilterXExprUnset_
{
  FilterXFunction super;
  GPtrArray *exprs;
} FilterXExprUnset;

static FilterXObject *
_eval_unset(FilterXExpr *s)
{
  FilterXExprUnset *self = (FilterXExprUnset *) s;

  for (guint i = 0; i < self->exprs->len; i++)
    {
      FilterXExpr *expr = (FilterXExpr *) g_ptr_array_index(self->exprs, i);
      if (!filterx_expr_unset(expr))
        return NULL;
    }

  return filterx_boolean_new(TRUE);
}

static FilterXExpr *
_optimize(FilterXExpr *s)
{
  FilterXExprUnset *self = (FilterXExprUnset *) s;

  for (guint i = 0; i < self->exprs->len; i++)
    {
      FilterXExpr **expr = (FilterXExpr **) &g_ptr_array_index(self->exprs, i);
      *expr = filterx_expr_optimize(*expr);
    }
  return NULL;
}

static gboolean
_init(FilterXExpr *s, GlobalConfig *cfg)
{
  FilterXExprUnset *self = (FilterXExprUnset *) s;

  for (guint i = 0; i < self->exprs->len; i++)
    {
      FilterXExpr *expr = (FilterXExpr *) g_ptr_array_index(self->exprs, i);
      if (!filterx_expr_init(expr, cfg))
        {
          for (guint j = 0; j < i; j++)
            {
              expr = g_ptr_array_index(self->exprs, i);
              filterx_expr_deinit(expr, cfg);
            }
          return FALSE;
        }
    }

  return filterx_function_init_method(&self->super, cfg);
}

static void
_deinit(FilterXExpr *s, GlobalConfig *cfg)
{
  FilterXExprUnset *self = (FilterXExprUnset *) s;

  for (guint i = 0; i < self->exprs->len; i++)
    {
      FilterXExpr *expr = (FilterXExpr *) g_ptr_array_index(self->exprs, i);
      filterx_expr_deinit(expr, cfg);
    }

  filterx_function_deinit_method(&self->super, cfg);
}

static void
_free(FilterXExpr *s)
{
  FilterXExprUnset *self = (FilterXExprUnset *) s;

  g_ptr_array_unref(self->exprs);
  filterx_function_free_method(&self->super);
}

FilterXExpr *
filterx_function_unset_new(FilterXFunctionArgs *args, GError **error)
{
  FilterXExprUnset *self = g_new0(FilterXExprUnset, 1);
  filterx_function_init_instance(&self->super, "unset");

  self->super.super.eval = _eval_unset;
  self->super.super.optimize = _optimize;
  self->super.super.init = _init;
  self->super.super.deinit = _deinit;
  self->super.super.free_fn = _free;

  self->exprs = g_ptr_array_new_full(filterx_function_args_len(args), (GDestroyNotify) filterx_expr_unref);
  for (guint64 i = 0; i < filterx_function_args_len(args); i++)
    {
      FilterXExpr *expr = filterx_function_args_get_expr(args, i);
      if (!filterx_expr_unset_available(expr))
        {
          g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                      "expected argument %d to be unsettable", (gint) i);
          goto error;
        }
      g_ptr_array_add(self->exprs, expr);
    }

  if (!filterx_function_args_check(args, error))
    goto error;

  filterx_function_args_free(args);
  return &self->super.super;

error:
  filterx_function_args_free(args);
  filterx_expr_unref(&self->super.super);
  return NULL;
}
