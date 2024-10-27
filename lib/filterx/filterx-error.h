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


#ifndef FILTERX_ERROR_H_INCLUDED
#define FILTERX_ERROR_H_INCLUDED

#include "filterx/filterx-scope.h"
#include "filterx/filterx-expr.h"
#include "template/eval.h"

typedef struct _FilterXError
{
  const gchar *message;
  FilterXExpr *expr;
  FilterXObject *object;
  gchar *info;
  gboolean free_info;
} FilterXError;

void filterx_error_clear(FilterXError *error);
const gchar *filterx_error_format(FilterXError *error);
EVTTAG *filterx_error_format_tag(FilterXError *error);
EVTTAG *filterx_error_format_location_tag(FilterXError *error);
void filterx_error_set_info(FilterXError *error, gchar *info, gboolean free_info);
void filterx_error_set_values(FilterXError *error, const gchar *message, FilterXExpr *expr, FilterXObject *object);


#endif
