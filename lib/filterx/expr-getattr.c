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
#include "filterx/expr-getattr.h"
#include "filterx/object-string.h"
#include "filterx/filterx-eval.h"
#include "stats/stats-registry.h"
#include "stats/stats-cluster-single.h"

typedef struct _FilterXGetAttr
{
  FilterXExpr super;
  FilterXExpr *operand;
  FilterXObject *attr;
  FilterXObject **path;
} FilterXGetAttr;

static FilterXObject *
_eval_operand(FilterXGetAttr *self, FilterXObject **attr)
{
  FilterXObject *o = filterx_expr_eval_typed(self->operand);

  if (!o)
    return NULL;

  *attr = self->attr;
  if (*attr)
    return o;

  FilterXObject *next_o;
  *attr = self->path[0];
  for (gint i = 0; self->path[i] && self->path[i+1]; i++)
    {
      next_o = filterx_object_getattr(o, *attr);
      if (!o)
        break;
      filterx_object_unref(o);
      o = next_o;
      *attr = self->path[i+1];
    }
  return o;
}

static FilterXObject *
_eval_getattr(FilterXExpr *s)
{
  FilterXGetAttr *self = (FilterXGetAttr *) s;
  FilterXObject *attr;

  FilterXObject *variable = _eval_operand(self, &attr);
  if (!variable)
    return NULL;

  FilterXObject *value = filterx_object_getattr(variable, attr);
  if (!value)
    {
      filterx_eval_push_error("Attribute lookup failed", s, attr);
      goto exit;
    }
exit:
  filterx_object_unref(variable);
  return value;
}

static gboolean
_unset(FilterXExpr *s)
{
  FilterXGetAttr *self = (FilterXGetAttr *) s;
  FilterXObject *attr;
  gboolean result = FALSE;

  FilterXObject *variable = _eval_operand(self, &attr);
  if (!variable)
    return FALSE;

  if (variable->readonly)
    {
      filterx_eval_push_error("Object unset-attr failed, object is readonly", s, attr);
      goto exit;
    }

  result = filterx_object_unset_key(variable, attr);

exit:
  filterx_object_unref(variable);
  return result;
}

static gboolean
_isset(FilterXExpr *s)
{
  FilterXGetAttr *self = (FilterXGetAttr *) s;
  FilterXObject *attr;
  FilterXObject *variable = _eval_operand(self, &attr);
  if (!variable)
    return FALSE;

  gboolean result = filterx_object_is_key_set(variable, attr);

  filterx_object_unref(variable);
  return result;
}

static void
_rollup_child_getattr(FilterXGetAttr *self, FilterXGetAttr *child)
{
  /* turn a list of getattrs into a single getattr with a path argument */
  GPtrArray *path = g_ptr_array_new();

  if (child->attr)
    {
      /* if this is an unoptimized FilterXGetAttr, let's use the "attr" member */
      g_ptr_array_add(path, filterx_object_ref(child->attr));
      g_assert(child->path == NULL);
    }
  else
    {
      /* optimized GetAttr, copy the entire path into ours */
      for (gint i = 0; child->path[i]; i++)
        {
          g_ptr_array_add(path, filterx_object_ref(child->path[i]));
        }
    }

  /* we are the last getattr so append it to the end */
  g_ptr_array_add(path, self->attr);
  /* null termination */
  g_ptr_array_add(path, NULL);

  /* replace self->attr with self->path */
  self->attr = NULL;
  self->path = (FilterXObject **) g_ptr_array_free(path, FALSE);
}

static FilterXExpr *
_optimize(FilterXExpr *s)
{
  FilterXGetAttr *self = (FilterXGetAttr *) s;

  self->operand = filterx_expr_optimize(self->operand);
  if (filterx_expr_is_getattr(self->operand))
    {
      FilterXGetAttr *child = (FilterXGetAttr *) self->operand;

      _rollup_child_getattr(self, child);
      self->operand = filterx_expr_ref(child->operand);

      filterx_expr_unref(&child->super);

      /* we need to return a ref */
      return filterx_expr_ref(s);
    }
  return NULL;
}

static gboolean
_init(FilterXExpr *s, GlobalConfig *cfg)
{
  FilterXGetAttr *self = (FilterXGetAttr *) s;

  if (!filterx_expr_init(self->operand, cfg))
    return FALSE;

  return filterx_expr_init_method(s, cfg);
}

static void
_deinit(FilterXExpr *s, GlobalConfig *cfg)
{
  FilterXGetAttr *self = (FilterXGetAttr *) s;

  filterx_expr_deinit(self->operand, cfg);
  filterx_expr_deinit_method(s, cfg);
}

static void
_free(FilterXExpr *s)
{
  FilterXGetAttr *self = (FilterXGetAttr *) s;

  if (self->attr)
    {
      filterx_object_unref(self->attr);
      g_assert(self->path == NULL);
    }
  else
    {
      for (gint i = 0; self->path[i]; i++)
        filterx_object_unref(self->path[i]);
      g_free(self->path);
      g_assert(self->attr == NULL);
    }

  filterx_expr_unref(self->operand);
  filterx_expr_free_method(s);
}

/* NOTE: takes the object reference */
FilterXExpr *
filterx_getattr_new(FilterXExpr *operand, FilterXString *attr_name)
{
  FilterXGetAttr *self = g_new0(FilterXGetAttr, 1);

  filterx_expr_init_instance(&self->super, FILTERX_EXPR_TYPE_NAME(getattr));
  self->super.eval = _eval_getattr;
  self->super.unset = _unset;
  self->super.is_set = _isset;
  self->super.optimize = _optimize;
  self->super.init = _init;
  self->super.deinit = _deinit;
  self->super.free_fn = _free;
  self->operand = operand;

  self->attr = (FilterXObject *) attr_name;
  /* NOTE: name borrows the string value from the string object */
  self->super.name = filterx_string_get_value_ref(self->attr, NULL);
  return &self->super;
}

FILTERX_EXPR_DEFINE_TYPE(getattr);