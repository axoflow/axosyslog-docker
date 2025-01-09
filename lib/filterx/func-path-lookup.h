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

#ifndef FILTERX_FUNC_PATH_LOOKUP_H_INCLUDED
#define FILTERX_FUNC_PATH_LOOKUP_H_INCLUDED

#include "filterx/expr-function.h"

#define FILTERX_FUNC_PATH_LOOKUP_USAGE "Usage: path_lookup(dict_or_list, list)"
#define FILTERX_FUNC_PATH_LOOKUP_ERR_NONDICT "Argument must be a dict."
#define FILTERX_FUNC_PATH_LOOKUP_ERR_NUM_ARGS "Invalid number of arguments."
#define FILTERX_FUNC_PATH_LOOKUP_ERR_LITERAL_LIST "List argument must be literal list."
#define FILTERX_FUNC_PATH_LOOKUP_ERR_LITERAL_LIST_ELTS "List members must be literals."

FilterXExpr *filterx_function_path_lookup_new(FilterXFunctionArgs *args, GError **error);

#endif
