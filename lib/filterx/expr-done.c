/*
 * Copyright (c) 2024 Axoflow
 * Copyright (c) 2024 Szilard Parrag <szilard.parrag@axoflow.com>
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


#include "filterx/expr-done.h"
#include "filterx/filterx-eval.h"
#include "filterx/object-primitive.h"

static FilterXObject *
_eval_done(FilterXExpr *s)
{
  FilterXEvalContext *context = filterx_eval_get_context();
  context->eval_control_modifier = FXC_DONE;

  return filterx_boolean_new(TRUE);
}

FilterXExpr *
filterx_expr_done(void)
{
  FilterXExpr *self = g_new0(FilterXExpr, 1);
  filterx_expr_init_instance(self, "done");
  self->eval = _eval_done;

  return self;
}
