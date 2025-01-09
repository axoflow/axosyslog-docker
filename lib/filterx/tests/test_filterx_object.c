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
#include <criterion/criterion.h>
#include "libtest/filterx-lib.h"

#include "filterx/object-dict-interface.h"
#include "filterx/object-list-interface.h"
#include "filterx/object-string.h"
#include "filterx/object-json.h"
#include "apphook.h"
#include "scratch-buffers.h"

GPtrArray *
_assert_filterx_list_to_ptrarray(FilterXObject *keys)
{
  guint64 len;
  cr_assert(filterx_object_len(keys, &len));

  GPtrArray *result = g_ptr_array_new_full(len, (GDestroyNotify)filterx_object_unref);

  for (int i = 0; i < len; i++)
    {
      g_ptr_array_add(result, filterx_list_get_subscript(keys, i));
    }

  filterx_object_unref(keys);
  return result;
}

Test(filterx_object, test_path_lookup_empty)
{
  const gchar *input = "{\"foo\":{\"bar\":\"baz\"},\"bar\":{\"baz\":null}}";
  FilterXObject *json = filterx_json_new_from_repr(input, -1);
  cr_assert_not_null(json);

  GPtrArray *keys = _assert_filterx_list_to_ptrarray(filterx_json_array_new_from_repr("[]", -1));

  FilterXObject *res = filterx_object_path_lookup_g(json, keys);
  cr_assert(res);

  GString *repr = scratch_buffers_alloc();
  cr_assert(filterx_object_repr(res, repr));
  cr_assert_str_eq(input, repr->str);

  g_ptr_array_free(keys, TRUE);
  filterx_object_unref(json);
  filterx_object_unref(res);
}

Test(filterx_object, test_path_lookup)
{
  FilterXObject *json = filterx_json_new_from_repr("{\"foo\":{\"bar\":\"baz\"}, \"bar\":{\"baz\": null}}", -1);
  cr_assert_not_null(json);

  GPtrArray *keys = _assert_filterx_list_to_ptrarray(filterx_json_array_new_from_repr("[\"foo\"]", -1));
  cr_assert_not_null(keys);

  FilterXObject *res = filterx_object_path_lookup_g(json, keys);
  cr_assert(res);

  GString *repr = scratch_buffers_alloc();
  cr_assert(filterx_object_repr(res, repr));
  cr_assert_str_eq("{\"bar\":\"baz\"}", repr->str);

  g_ptr_array_free(keys, TRUE);
  filterx_object_unref(json);
  filterx_object_unref(res);
}

Test(filterx_object, test_path_lookup_nested)
{
  FilterXObject *json = filterx_json_new_from_repr("{\"foo\":{\"bar\":{\"baz\":\"foo\"}}, \"bar\":{\"baz\": null}}", -1);
  cr_assert_not_null(json);

  GPtrArray *keys = _assert_filterx_list_to_ptrarray(filterx_json_array_new_from_repr("[\"foo\",\"bar\"]", -1));
  cr_assert_not_null(keys);

  FilterXObject *res = filterx_object_path_lookup_g(json, keys);
  cr_assert(res);

  GString *repr = scratch_buffers_alloc();
  cr_assert(filterx_object_repr(res, repr));
  cr_assert_str_eq("{\"baz\":\"foo\"}", repr->str);

  g_ptr_array_free(keys, TRUE);
  filterx_object_unref(json);
  filterx_object_unref(res);
}

Test(filterx_object, test_path_lookup_list)
{
  FilterXObject *json = filterx_json_new_from_repr("[\"foo\", \"bar\", \"baz\"]", -1);
  cr_assert_not_null(json);

  GPtrArray *keys = _assert_filterx_list_to_ptrarray(filterx_json_array_new_from_repr("[1]", -1));
  cr_assert_not_null(keys);

  FilterXObject *res = filterx_object_path_lookup_g(json, keys);
  cr_assert(res);

  GString *repr = scratch_buffers_alloc();
  cr_assert(filterx_object_repr(res, repr));
  cr_assert_str_eq("bar", repr->str);

  g_ptr_array_free(keys, TRUE);
  filterx_object_unref(json);
  filterx_object_unref(res);
}

Test(filterx_object, test_path_lookup_return_list)
{
  FilterXObject *json = filterx_json_new_from_repr("[\"foo\", [\"tik\", \"tak\", \"toe\"], \"baz\"]", -1);
  cr_assert_not_null(json);

  GPtrArray *keys = _assert_filterx_list_to_ptrarray(filterx_json_array_new_from_repr("[1]", -1));
  cr_assert_not_null(keys);

  FilterXObject *res = filterx_object_path_lookup_g(json, keys);
  cr_assert(res);

  GString *repr = scratch_buffers_alloc();
  cr_assert(filterx_object_repr(res, repr));
  cr_assert_str_eq("[\"tik\",\"tak\",\"toe\"]", repr->str);

  g_ptr_array_free(keys, TRUE);
  filterx_object_unref(json);
  filterx_object_unref(res);
}

Test(filterx_object, test_path_lookup_nested_list)
{
  FilterXObject *json = filterx_json_new_from_repr("[\"foo\", [\"tik\", \"tak\", \"toe\"], \"baz\"]", -1);
  cr_assert_not_null(json);

  GPtrArray *keys = _assert_filterx_list_to_ptrarray(filterx_json_array_new_from_repr("[1,2]", -1));
  cr_assert_not_null(keys);

  FilterXObject *res = filterx_object_path_lookup_g(json, keys);
  cr_assert(res);

  GString *repr = scratch_buffers_alloc();
  cr_assert(filterx_object_repr(res, repr));
  cr_assert_str_eq("toe", repr->str);

  g_ptr_array_free(keys, TRUE);
  filterx_object_unref(json);
  filterx_object_unref(res);
}

Test(filterx_object, test_path_lookup_mixed)
{
  FilterXObject *json = filterx_json_new_from_repr("[\"foo\", {\"tik\":33, \"tak\":44, \"toe\":55}, \"baz\"]", -1);
  cr_assert_not_null(json);

  GPtrArray *keys = _assert_filterx_list_to_ptrarray(filterx_json_array_new_from_repr("[1,\"tak\"]", -1));
  cr_assert_not_null(keys);

  FilterXObject *res = filterx_object_path_lookup_g(json, keys);
  cr_assert(res);

  GString *repr = scratch_buffers_alloc();
  cr_assert(filterx_object_repr(res, repr));
  cr_assert_str_eq("44", repr->str);

  g_ptr_array_free(keys, TRUE);
  filterx_object_unref(json);
  filterx_object_unref(res);
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

TestSuite(filterx_object, .init = setup, .fini = teardown);
