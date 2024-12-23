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
#include "filterx/expr-assign.h"
#include "filterx/object-primitive.h"
#include "filterx/filterx-ref.h"
#include "filterx/object-json.h"
#include "filterx/filterx-object-istype.h"
#include "filterx/filterx-eval.h"
#include "filterx/object-null.h"
#include "filterx/object-message-value.h"
#include "scratch-buffers.h"

static inline FilterXObject *
_assign(FilterXBinaryOp *self, FilterXObject *value)
{
  /* TODO: create ref unconditionally after implementing hierarchical CoW for JSON types
   * (or after creating our own dict/list repr) */
  if (!value->weak_referenced)
    {
      value = filterx_ref_new(value);
    }

  if (!filterx_expr_assign(self->lhs, value))
    {
      filterx_object_unref(value);
      return NULL;
    }

  return value;
}

static inline FilterXObject *
_suppress_error(void)
{
  msg_debug("FILTERX null coalesce assignment supressing error", filterx_format_last_error());
  filterx_eval_clear_errors();

  return filterx_null_new();
}

static FilterXObject *
_nullv_assign_eval(FilterXExpr *s)
{
  FilterXBinaryOp *self = (FilterXBinaryOp *) s;

  FilterXObject *value = filterx_expr_eval(self->rhs);

  if (!value || filterx_object_is_type(value, &FILTERX_TYPE_NAME(null))
      || (filterx_object_is_type(value, &FILTERX_TYPE_NAME(message_value))
          && filterx_message_value_get_type(value) == LM_VT_NULL))
    {
      if (!value)
        return _suppress_error();

      return value;
    }

  return _assign(self, value);
}

static FilterXObject *
_assign_eval(FilterXExpr *s)
{
  FilterXBinaryOp *self = (FilterXBinaryOp *) s;

  FilterXObject *value = filterx_expr_eval(self->rhs);

  if (!value)
    return NULL;

  return _assign(self, value);
}


/* NOTE: takes the object reference */
FilterXExpr *
filterx_assign_new(FilterXExpr *lhs, FilterXExpr *rhs)
{
  FilterXBinaryOp *self = g_new0(FilterXBinaryOp, 1);

  filterx_binary_op_init_instance(self, "assign", lhs, rhs);
  self->super.eval = _assign_eval;
  self->super.ignore_falsy_result = TRUE;
  return &self->super;
}

FilterXExpr *
filterx_nullv_assign_new(FilterXExpr *lhs, FilterXExpr *rhs)
{
  FilterXExpr *self = filterx_assign_new(lhs, rhs);
  self->type = "nullv_assign";
  self->eval = _nullv_assign_eval;
  return self;
}
