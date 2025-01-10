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
#ifndef FILTERX_EXPR_VARIABLE_H_INCLUDED
#define FILTERX_EXPR_VARIABLE_H_INCLUDED

#include "filterx/filterx-expr.h"
#include "filterx/filterx-config.h"
#include "filterx/object-string.h"
#include "cfg.h"

FilterXExpr *filterx_msg_variable_expr_new(FilterXString *name);
FilterXExpr *filterx_floating_variable_expr_new(FilterXString *name);
void filterx_variable_expr_declare(FilterXExpr *s);

static inline FilterXString *
filterx_frozen_dollar_msg_varname(GlobalConfig *cfg, const gchar *name)
{
  gchar *dollar_name = g_strdup_printf("$%s", name);
  FilterXString *dollar_name_obj = filterx_config_frozen_string(cfg, dollar_name);
  g_free(dollar_name);

  return dollar_name_obj;
}

FILTERX_EXPR_DECLARE_TYPE(variable);

#endif
