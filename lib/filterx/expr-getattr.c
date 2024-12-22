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
} FilterXGetAttr;

static FilterXObject *
_eval(FilterXExpr *s)
{
  FilterXGetAttr *self = (FilterXGetAttr *) s;

  FilterXObject *variable = filterx_expr_eval_typed(self->operand);

  if (!variable)
    return NULL;

  FilterXObject *attr = filterx_object_getattr(variable, self->attr);
  if (!attr)
    {
      filterx_eval_push_error("Attribute lookup failed", s, self->attr);
      goto exit;
    }
exit:
  filterx_object_unref(variable);
  return attr;
}

static gboolean
_unset(FilterXExpr *s)
{
  FilterXGetAttr *self = (FilterXGetAttr *) s;

  gboolean result = FALSE;

  FilterXObject *variable = filterx_expr_eval_typed(self->operand);
  if (!variable)
    return FALSE;

  if (variable->readonly)
    {
      filterx_eval_push_error("Object unset-attr failed, object is readonly", s, self->attr);
      goto exit;
    }

  result = filterx_object_unset_key(variable, self->attr);

exit:
  filterx_object_unref(variable);
  return result;
}

static gboolean
_isset(FilterXExpr *s)
{
  FilterXGetAttr *self = (FilterXGetAttr *) s;
  FilterXObject *variable = filterx_expr_eval_typed(self->operand);
  if (!variable)
    return FALSE;

  gboolean result = filterx_object_is_key_set(variable, self->attr);

  filterx_object_unref(variable);
  return result;
}

static FilterXExpr *
_optimize(FilterXExpr *s)
{
  FilterXGetAttr *self = (FilterXGetAttr *) s;

  self->operand = filterx_expr_optimize(self->operand);
  return NULL;
}

static gboolean
_init(FilterXExpr *s, GlobalConfig *cfg)
{
  FilterXGetAttr *self = (FilterXGetAttr *) s;

  if (!filterx_expr_init(self->operand, cfg))
    return FALSE;

  stats_lock();
  StatsClusterKey sc_key;
  stats_cluster_single_key_set(&sc_key, "fx_getattr_evals_total", NULL, 0);
  stats_register_counter(STATS_LEVEL3, &sc_key, SC_TYPE_SINGLE_VALUE, &self->super.eval_count);
  stats_unlock();

  return filterx_expr_init_method(s, cfg);
}

static void
_deinit(FilterXExpr *s, GlobalConfig *cfg)
{
  FilterXGetAttr *self = (FilterXGetAttr *) s;

  stats_lock();
  StatsClusterKey sc_key;
  stats_cluster_single_key_set(&sc_key, "fx_getattr_evals_total", NULL, 0);
  stats_unregister_counter(&sc_key, SC_TYPE_SINGLE_VALUE, &self->super.eval_count);
  stats_unlock();

  filterx_expr_deinit(self->operand, cfg);
  filterx_expr_deinit_method(s, cfg);
}

static void
_free(FilterXExpr *s)
{
  FilterXGetAttr *self = (FilterXGetAttr *) s;
  filterx_object_unref(self->attr);
  filterx_expr_unref(self->operand);
  filterx_expr_free_method(s);
}

/* NOTE: takes the object reference */
FilterXExpr *
filterx_getattr_new(FilterXExpr *operand, FilterXString *attr_name)
{
  FilterXGetAttr *self = g_new0(FilterXGetAttr, 1);

  filterx_expr_init_instance(&self->super, "getattr");
  self->super.eval = _eval;
  self->super.unset = _unset;
  self->super.is_set = _isset;
  self->super.optimize = _optimize;
  self->super.init = _init;
  self->super.deinit = _deinit;
  self->super.free_fn = _free;
  self->operand = operand;

  self->attr = (FilterXObject *) attr_name;

  return &self->super;
}
