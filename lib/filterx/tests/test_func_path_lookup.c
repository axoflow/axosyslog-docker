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

#include <criterion/criterion.h>
#include "libtest/filterx-lib.h"

#include "filterx/func-flatten.h"
#include "filterx/object-string.h"
#include "filterx/object-primitive.h"
#include "filterx/object-json.h"
#include "filterx/expr-literal.h"
#include "filterx/func-path-lookup.h"
#include "filterx/filterx-eval.h"
#include "filterx/object-dict-interface.h"
#include "filterx/object-list-interface.h"
#include "filterx/expr-literal-generator.h"

#include "apphook.h"
#include "scratch-buffers.h"

FilterXExpr *
_list_generator_helper(FilterXExpr *first, ...)
{
  FilterXExpr *result = filterx_literal_list_generator_new();
  GList *target_vals = NULL;
  va_list va;

  va_start(va, first);
  FilterXExpr *arg = first;
  while (arg)
    {
      target_vals = g_list_append(target_vals, filterx_literal_generator_elem_new(NULL, arg, FALSE));
      arg = va_arg(va, FilterXExpr *);
    }
  va_end(va);


  filterx_literal_generator_set_elements(result, target_vals);
  return result;
}

Test(filterx_func_path_lookup, empty_args)
{
  GList *args = NULL;

  GError *error = NULL;
  FilterXExpr *fn = filterx_function_path_lookup_new(filterx_function_args_new(args, NULL), &error);
  cr_assert_null(fn);
  cr_assert_not_null(error);

  cr_assert_str_eq(error->message, FILTERX_FUNC_PATH_LOOKUP_ERR_NUM_ARGS FILTERX_FUNC_PATH_LOOKUP_USAGE);
  g_clear_error(&error);
}

Test(filterx_func_path_lookup, invalid_args_number)
{
  GList *args = NULL;
  args = g_list_append(args, filterx_function_arg_new(NULL, filterx_non_literal_new(filterx_string_new("not a dict",
                                                      -1))));

  GError *error = NULL;
  FilterXExpr *fn = filterx_function_path_lookup_new(filterx_function_args_new(args, NULL), &error);
  cr_assert_null(fn);
  cr_assert_not_null(error);

  cr_assert_str_eq(error->message, FILTERX_FUNC_PATH_LOOKUP_ERR_NUM_ARGS FILTERX_FUNC_PATH_LOOKUP_USAGE);
  g_clear_error(&error);
}

Test(filterx_func_path_lookup, invalid_arg_type_first_arg)
{
  GList *args = NULL;
  args = g_list_append(args, filterx_function_arg_new(NULL,
                                                      filterx_non_literal_new(filterx_string_new("not a dict or list",
                                                          -1))));

  FilterXExpr *keys = _list_generator_helper(filterx_literal_new(filterx_string_new("anything", -1)), NULL);
  args = g_list_append(args, filterx_function_arg_new(NULL, keys));


  GError *error = NULL;
  FilterXExpr *fn = filterx_function_path_lookup_new(filterx_function_args_new(args, NULL), &error);
  cr_assert_not_null(fn);
  cr_assert_null(error);

  FilterXObject *obj = filterx_expr_eval(fn);
  cr_assert_null(obj);

  filterx_expr_unref(fn);
  g_clear_error(&error);
}

Test(filterx_func_path_lookup, empty_keys)
{
  GList *args = NULL;

  FilterXObject *first = filterx_string_new("not a dict or list", -1);
  args = g_list_append(args, filterx_function_arg_new(NULL, filterx_non_literal_new(first)));

  FilterXExpr *keys = _list_generator_helper(NULL, NULL);
  args = g_list_append(args, filterx_function_arg_new(NULL, keys));


  GError *error = NULL;
  FilterXExpr *fn = filterx_function_path_lookup_new(filterx_function_args_new(args, NULL), &error);
  cr_assert_not_null(fn);
  cr_assert_null(error);

  FilterXObject *obj = filterx_expr_eval(fn);
  cr_assert_not_null(obj);

  cr_assert_eq(obj, first);

  filterx_object_unref(first);
  filterx_expr_unref(fn);
  g_clear_error(&error);
}

Test(filterx_func_path_lookup, keys_not_literal_generator)
{
  FilterXObject *first = filterx_json_new_from_repr("{\"foo\":{\"bar\":{\"baz\":\"foo\"}}, \"bar\":{\"baz\": null}}", -1);
  GList *args = NULL;
  args = g_list_append(args, filterx_function_arg_new(NULL, filterx_non_literal_new(first)));
  args = g_list_append(args, filterx_function_arg_new(NULL,
                                                      filterx_literal_new(filterx_json_array_new_from_repr("[\"foo\"]", -1))));

  GError *error = NULL;
  FilterXExpr *fn = filterx_function_path_lookup_new(filterx_function_args_new(args, NULL), &error);
  cr_assert_null(fn);
  cr_assert_not_null(error);

  cr_assert_str_eq(error->message, FILTERX_FUNC_PATH_LOOKUP_ERR_LITERAL_LIST FILTERX_FUNC_PATH_LOOKUP_USAGE);
  g_clear_error(&error);
}

Test(filterx_func_path_lookup, some_of_keys_elts_are_not_literal_generator)
{
  FilterXObject *first = filterx_json_new_from_repr("{\"foo\":{\"bar\":{\"baz\":\"foo\"}}, \"bar\":{\"baz\": null}}", -1);
  GList *args = NULL;
  args = g_list_append(args, filterx_function_arg_new(NULL, filterx_non_literal_new(first)));

  FilterXExpr *keys = _list_generator_helper(filterx_literal_new(filterx_string_new("foo", -1)),
                                             filterx_non_literal_new(filterx_string_new("bar", -1)), NULL);
  args = g_list_append(args, filterx_function_arg_new(NULL, keys));

  GError *error = NULL;
  FilterXExpr *fn = filterx_function_path_lookup_new(filterx_function_args_new(args, NULL), &error);
  cr_assert_null(fn);
  cr_assert_not_null(error);

  cr_assert_str_eq(error->message, FILTERX_FUNC_PATH_LOOKUP_ERR_LITERAL_LIST_ELTS FILTERX_FUNC_PATH_LOOKUP_USAGE);
  g_clear_error(&error);
}

Test(filterx_func_path_lookup, nested_dict_lookup)
{
  FilterXObject *first = filterx_json_new_from_repr("{\"foo\":{\"bar\":{\"baz\":\"foo\"}}, \"bar\":{\"baz\": null}}", -1);
  GList *args = NULL;
  args = g_list_append(args, filterx_function_arg_new(NULL, filterx_non_literal_new(first)));

  FilterXExpr *keys = _list_generator_helper(filterx_literal_new(filterx_string_new("foo", -1)),
                                             filterx_literal_new(filterx_string_new("bar", -1)), NULL);
  args = g_list_append(args, filterx_function_arg_new(NULL, keys));

  GError *error = NULL;
  FilterXExpr *fn = filterx_function_path_lookup_new(filterx_function_args_new(args, NULL), &error);
  cr_assert_not_null(fn);
  cr_assert_null(error);

  FilterXObject *obj = filterx_expr_eval(fn);
  cr_assert_not_null(obj);

  GString *repr = scratch_buffers_alloc();
  cr_assert(filterx_object_repr(obj, repr));

  cr_assert_str_eq(repr->str, "{\"baz\":\"foo\"}");

  filterx_object_unref(obj);
  filterx_expr_unref(fn);
  g_clear_error(&error);
}

Test(filterx_func_path_lookup, nested_list_lookup)
{
  FilterXObject *first = filterx_json_new_from_repr("[[3,2,1],[4,5,6],[7,8,9]]", -1);
  GList *args = NULL;
  args = g_list_append(args, filterx_function_arg_new(NULL, filterx_non_literal_new(first)));

  FilterXExpr *keys = _list_generator_helper(filterx_literal_new(filterx_integer_new(1)),
                                             filterx_literal_new(filterx_integer_new(-1)), NULL);
  args = g_list_append(args, filterx_function_arg_new(NULL, keys));

  GError *error = NULL;
  FilterXExpr *fn = filterx_function_path_lookup_new(filterx_function_args_new(args, NULL), &error);
  cr_assert_not_null(fn);
  cr_assert_null(error);

  FilterXObject *obj = filterx_expr_eval(fn);
  cr_assert_not_null(obj);

  GString *repr = scratch_buffers_alloc();
  cr_assert(filterx_object_repr(obj, repr));

  cr_assert_str_eq(repr->str, "6");

  filterx_object_unref(obj);
  filterx_expr_unref(fn);
  g_clear_error(&error);
}

static void
setup(void)
{
  app_startup();
  init_libtest_filterx();
}

static void
teardown(void)
{
  scratch_buffers_explicit_gc();
  deinit_libtest_filterx();
  app_shutdown();
}

TestSuite(filterx_func_path_lookup, .init = setup, .fini = teardown);
