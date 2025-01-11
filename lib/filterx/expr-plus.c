/*
 * Copyright (c) 2024 Balazs Scheidler <balazs.scheidler@axoflow.com>
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
#include "expr-plus.h"
#include "object-string.h"
#include "filterx-eval.h"
#include "filterx/expr-literal.h"
#include "scratch-buffers.h"

typedef struct FilterXOperatorPlus
{
  FilterXBinaryOp super;
  FilterXObject *literal_lhs;
  FilterXObject *literal_rhs;
} FilterXOperatorPlus;

static FilterXObject *
_eval_plus(FilterXExpr *s)
{
  FilterXOperatorPlus *self = (FilterXOperatorPlus *) s;

  FilterXObject *lhs_object = self->literal_lhs ? filterx_object_ref(self->literal_lhs)
                              : filterx_expr_eval_typed(self->super.lhs);
  if (!lhs_object)
    return NULL;

  FilterXObject *rhs_object = self->literal_rhs ? filterx_object_ref(self->literal_rhs)
                              : filterx_expr_eval(self->super.rhs);
  if (!rhs_object)
    {
      filterx_object_unref(lhs_object);
      return NULL;
    }

  FilterXObject *res = filterx_object_add_object(lhs_object, rhs_object);
  filterx_object_unref(lhs_object);
  filterx_object_unref(rhs_object);
  return res;
}

static FilterXExpr *
_optimize(FilterXExpr *s)
{
  FilterXOperatorPlus *self = (FilterXOperatorPlus *) s;

  if (filterx_binary_op_optimize_method(s))
    g_assert_not_reached();

  if (filterx_expr_is_literal(self->super.lhs))
    self->literal_lhs = filterx_expr_eval_typed(self->super.lhs);

  if (filterx_expr_is_literal(self->super.rhs))
    self->literal_rhs = filterx_expr_eval(self->super.rhs);

  if (self->literal_lhs && self->literal_rhs)
    return filterx_literal_new(_eval_plus(&self->super.super));
  return NULL;
}

static void
_filterx_operator_plus_free(FilterXExpr *s)
{
  FilterXOperatorPlus *self = (FilterXOperatorPlus *) s;
  filterx_object_unref(self->literal_lhs);
  filterx_object_unref(self->literal_rhs);

  filterx_binary_op_free_method(s);
}

FilterXExpr *
filterx_operator_plus_new(FilterXExpr *lhs, FilterXExpr *rhs)
{
  FilterXOperatorPlus *self = g_new0(FilterXOperatorPlus, 1);
  filterx_binary_op_init_instance(&self->super, "plus", lhs, rhs);
  self->super.super.optimize = _optimize;
  self->super.super.eval = _eval_plus;
  self->super.super.free_fn = _filterx_operator_plus_free;

  return &self->super.super;
}
