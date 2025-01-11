/*
 * Copyright (c) 2024 Axoflow
 * Copyright (c) 2024 shifter <shifter@axoflow.com>
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

#include "filterx/expr-null-coalesce.h"
#include "filterx/expr-literal.h"
#include "filterx/object-null.h"
#include "filterx/filterx-eval.h"
#include "filterx/object-message-value.h"
#include "filterx/filterx-object-istype.h"

typedef struct _FilterXNullCoalesce FilterXNullCoalesce;

struct _FilterXNullCoalesce
{
  FilterXBinaryOp super;
};

static FilterXObject *
_eval_null_coalesce(FilterXExpr *s)
{
  FilterXNullCoalesce *self = (FilterXNullCoalesce *) s;

  FilterXObject *lhs_object = filterx_expr_eval(self->super.lhs);
  if (!lhs_object || filterx_object_is_type(lhs_object, &FILTERX_TYPE_NAME(null))
      || (filterx_object_is_type(lhs_object, &FILTERX_TYPE_NAME(message_value))
          && filterx_message_value_get_type(lhs_object) == LM_VT_NULL))
    {
      if (!lhs_object)
        {
          msg_debug("FILTERX null coalesce supressing error:",
                    filterx_format_last_error());
          filterx_eval_clear_errors();
        }
      FilterXObject *rhs_object = filterx_expr_eval(self->super.rhs);
      filterx_object_unref(lhs_object);
      return rhs_object;
    }
  return lhs_object;
}

static FilterXExpr *
_optimize(FilterXExpr *s)
{
  FilterXNullCoalesce *self = (FilterXNullCoalesce *) s;

  if (filterx_binary_op_optimize_method(s))
    g_assert_not_reached();

  if (!filterx_expr_is_literal(self->super.lhs))
    return NULL;

  FilterXObject *lhs_object = filterx_expr_eval(self->super.lhs);
  if (!lhs_object || filterx_object_is_type(lhs_object, &FILTERX_TYPE_NAME(null)))
    {
      filterx_object_unref(lhs_object);
      return filterx_expr_ref(self->super.rhs);
    }

  filterx_object_unref(lhs_object);
  return filterx_expr_ref(self->super.lhs);
}

FilterXExpr *
filterx_null_coalesce_new(FilterXExpr *lhs, FilterXExpr *rhs)
{
  FilterXNullCoalesce *self = g_new0(FilterXNullCoalesce, 1);
  filterx_binary_op_init_instance(&self->super, "null_coalesce", lhs, rhs);
  self->super.super.eval = _eval_null_coalesce;
  self->super.super.optimize = _optimize;
  return &self->super.super;
}
