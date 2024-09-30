/*
 * Copyright (c) 2024 Axoflow
 * Copyright (c) 2024 Szilard Parrag
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

#include "filterx/func-str.h"
#include "filterx/object-primitive.h"
#include "filterx/expr-literal.h"
#include "filterx/expr-literal-generator.h"
#include "filterx/filterx-eval.h"
#include "filterx/object-extractor.h"
#include "filterx/object-string.h"
#include "filterx/object-list-interface.h"
#include "scratch-buffers.h"

#define FILTERX_FUNC_STARTSWITH_USAGE "Usage: startswith(string, prefix, ignorecase=true)" \
"or startswith(string, [prefix_1, prefix_2, ..], ignorecase=true)"

#define FILTERX_FUNC_ENDSWITH_USAGE "Usage: endswith(string, suffix, ignorecase=true)" \
"or endswith(string, [suffix_1, suffix_2, ..], ignorecase=true)"

#define FILTERX_FUNC_INCLUDES_USAGE "Usage: includes(string, substring, ignorecase=true)" \
"or includes(string, [substring_1, substring_2, ..], ignorecase=true)"

typedef struct _FilterXStringWithCache
{
  FilterXExpr *expr;
  const gchar *str_value;
  gsize str_len;
} FilterXStringWithCache;

typedef gboolean (*FilterXExprAffixProcessFunc)(const gchar *haystack, gsize haystack_len, const gchar *needle,
                                                gsize needle_len);
typedef struct _FilterXExprAffix
{
  FilterXFunction super;
  gboolean ignore_case;
  FilterXExpr *haystack;
  struct
  {
    FilterXExpr *expr;
    GPtrArray *cached_strings;
  } needle;
  FilterXExprAffixProcessFunc process;
} FilterXExprAffix;

static GString *
_format_str_obj(FilterXObject *obj)
{
  GString *str = scratch_buffers_alloc();

  if(!filterx_object_repr(obj, str))
    return NULL;

  return str;
}

static gboolean
_do_casefold(GString *str)
{
  if(str->len > G_MAXSSIZE)
    return FALSE;

  gchar *casefolded_str = g_utf8_casefold(str->str, (gssize) str->len);
  g_string_assign(str, casefolded_str);

  g_free(casefolded_str);
  return TRUE;
}

static GString *
_expr_format(FilterXExpr *expr, gboolean ignore_case)
{
  FilterXObject *obj = filterx_expr_eval_typed(expr);
  if (!obj)
    return NULL;

  GString *result = _format_str_obj(obj);
  if (!result)
    filterx_eval_push_error("failed to extract string value, repr() failed", expr, obj);
  filterx_object_unref(obj);

  if (ignore_case && !_do_casefold(result))
    return NULL;

  return result;
}

static GString *
_obj_format(FilterXObject *obj, gboolean ignore_case)
{
  GString *result = _format_str_obj(obj);
  if (!result)
    filterx_eval_push_error("failed to extract string value, repr() failed", NULL, obj);
  filterx_object_unref(obj);

  if (ignore_case && !_do_casefold(result))
    return NULL;

  return result;
}

static gboolean
_string_with_cache_fill_cache(FilterXStringWithCache *self, gboolean ignore_case)
{
  if(!filterx_expr_is_literal(self->expr))
    return TRUE;

  return !!_expr_format(self->expr, ignore_case);
}

static FilterXStringWithCache *
_string_with_cache_new(FilterXExpr *expr, gboolean ignore_case)
{
  FilterXStringWithCache *self = g_new0(FilterXStringWithCache, 1);
  self->expr = expr;

  if (!_string_with_cache_fill_cache(self, ignore_case))
    return NULL;

  return self;
}

static gboolean
_string_with_cache_get_string_value(FilterXStringWithCache *self, gboolean ignore_case, const gchar **dst,
                                    gsize *len)
{
  if(self->str_value)
    {
      *dst = self->str_value;
      *len = self->str_len;
      return TRUE;
    }

  GString *res = _expr_format(self->expr, ignore_case);
  if (!res)
    return FALSE;

  *dst = res->str;
  *len = res->len;
  return TRUE;
}

static gboolean
_cache_needle(guint64 index, FilterXExpr *value, gpointer user_data)
{
  gboolean *ignore_case = ((gpointer *)user_data)[0];
  GPtrArray *cached_strings = ((gpointer *) user_data)[1];

  FilterXStringWithCache *obj_with_cache =  _string_with_cache_new(value, *ignore_case);
  if(!obj_with_cache)
    return FALSE;

  g_ptr_array_add(cached_strings, obj_with_cache);
  return TRUE;
}


static gboolean
_expr_affix_init_needle(FilterXExprAffix *self, FilterXExpr *needle)
{
  self->needle.expr = filterx_expr_ref(needle);
  if (filterx_expr_is_literal(self->needle.expr))
    {
      FilterXStringWithCache *obj_with_cache =  _string_with_cache_new(self->needle.expr, self->ignore_case);
      if (!obj_with_cache)
        return FALSE;
      g_ptr_array_add(self->needle.cached_strings, obj_with_cache);
    }
  if (filterx_expr_is_literal_list_generator(self->needle.expr))
    {
      gpointer user_data[] = {&self->ignore_case, self->needle.cached_strings};
      if(!filterx_literal_list_generator_foreach(self->needle.expr, _cache_needle, user_data))
        return FALSE;
    }
  return TRUE;
}

static void
_expr_affix_free(FilterXExpr *s)
{
  FilterXExprAffix *self = (FilterXExprAffix *) s;
  g_ptr_array_free(self->needle.cached_strings, TRUE);

  filterx_function_free_method(&self->super);
}

static GPtrArray *
_expr_affix_eval_needle(FilterXExprAffix *self)
{
  FilterXObject *needle_obj = filterx_expr_eval(self->needle.expr);
  if (!needle_obj)
    return NULL;
  GPtrArray *needles = NULL;

  if (filterx_object_is_type(needle_obj, &FILTERX_TYPE_NAME(string)))
    {
      GString *str_value = _obj_format(needle_obj, self->ignore_case);
      filterx_object_unref(needle_obj);
      if (!str_value)
        return NULL;
      needles = g_ptr_array_sized_new(1);
      g_ptr_array_add(needles, str_value);
      return needles;
    }
  else if (filterx_object_is_type(needle_obj, &FILTERX_TYPE_NAME(list)))
    {
      guint64 len;
      filterx_object_len(needle_obj, &len);

      if (len == 0)
        {
          filterx_object_unref(needle_obj);
          return NULL;
        }
      needles = g_ptr_array_sized_new(len);

      for (guint64 i = 0; i < len; i++)
        {
          FilterXObject *elem = filterx_list_get_subscript(needle_obj, i);

          GString *str_value = _obj_format(elem, self->ignore_case);
          filterx_object_unref(elem);
          if (!str_value)
            goto error;
          g_ptr_array_add(needles, str_value);
        }
      filterx_object_unref(needle_obj);
      return needles;
    }

error:
  g_ptr_array_free(needles, TRUE);
  return NULL;
}

static FilterXObject *
_expr_affix_eval(FilterXExpr *s)
{
  FilterXExprAffix *self = (FilterXExprAffix *)s;
  FilterXObject *result = NULL;

  ScratchBuffersMarker marker;
  scratch_buffers_mark(&marker);
  GString *haystack_str = _expr_format(self->haystack, self->ignore_case);
  if (!haystack_str)
    goto exit;

  gboolean matches = FALSE;
  const gchar *needle_str;
  gsize needle_len;

  if(self->needle.cached_strings->len != 0)
    {
      for(guint64 i = 0; i < self->needle.cached_strings->len && !matches; i++)
        {
          FilterXStringWithCache *current_needle = g_ptr_array_index(self->needle.cached_strings, i);
          if (!_string_with_cache_get_string_value(current_needle, self->ignore_case, &needle_str, &needle_len))
            goto exit;
          matches = self->process(haystack_str->str, haystack_str->len, needle_str, needle_len);
        }
      result = filterx_boolean_new(matches);
      goto exit;
    }

  GPtrArray *needle_list = _expr_affix_eval_needle(self);
  if (!needle_list)
    goto exit;

  if(needle_list->len != 0)
    {
      for(guint64 i = 0; i < needle_list->len && !matches; i++)
        {
          GString *current_needle = g_ptr_array_index(needle_list, i);
          matches = self->process(haystack_str->str, haystack_str->len, current_needle->str, current_needle->len);
        }
    }
  g_ptr_array_free(needle_list, TRUE);
  result = filterx_boolean_new(matches);

exit:
  scratch_buffers_reclaim_marked(marker);
  return result;

}

static FilterXExpr *
_extract_haystack_arg(FilterXFunctionArgs *args, GError **error, const gchar *function_usage)
{
  gsize len = filterx_function_args_len(args);
  if (len < 1)
    {
      g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                  "invalid number of arguments. %s", function_usage);
      return NULL;
    }
  FilterXExpr *haystack = filterx_function_args_get_expr(args, 0);
  if (!haystack)
    {
      g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                  "haystack must be set. %s", function_usage);
      return NULL;
    }
  return haystack;
}

static FilterXExpr *
_extract_needle_arg(FilterXFunctionArgs *args, GError **error, const gchar *function_usage)
{
  gsize len = filterx_function_args_len(args);

  if(len < 2)
    {
      g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                  "invalid number of arguments. %s", function_usage);
      return NULL;
    }
  FilterXExpr *needle = filterx_function_args_get_expr(args, 1);
  if (!needle)
    {
      g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                  "needle must be set. %s", function_usage);
      return NULL;
    }
  return needle;
}

static gboolean
_extract_optional_args(gboolean *ignore_case, FilterXFunctionArgs *args, GError **error, const gchar *function_usage)
{
  gboolean exists, eval_error;
  gboolean value = filterx_function_args_get_named_literal_boolean(args, "ignorecase", &exists, &eval_error);
  if (!exists)
    return TRUE;

  if (eval_error)
    {
      g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                  "ignorecase argument must be boolean literal. %s", function_usage);
      return FALSE;
    }

  *ignore_case = value;
  return TRUE;
}

static FilterXExpr *
_function_affix_new(FilterXFunctionArgs *args,
                    const gchar *affix_name,
                    FilterXExprAffixProcessFunc process_func,
                    const gchar *usage,
                    GError **error)
{
  FilterXExprAffix *self = g_new0(FilterXExprAffix, 1);

  gboolean ignore_case = FALSE;
  if (!_extract_optional_args(&ignore_case, args, error, usage))
    goto error;

  FilterXExpr *haystack_expr = _extract_haystack_arg(args, error, usage);
  if (!haystack_expr)
    goto error;

  FilterXExpr *needle_expr = _extract_needle_arg(args, error, usage);
  if (!needle_expr)
    {
      g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                  "needle must be set. %s", usage);
      goto error;
    }

  filterx_function_init_instance(&self->super, affix_name);
  self->ignore_case = ignore_case;
  self->super.super.eval = _expr_affix_eval;
  self->super.super.free_fn = _expr_affix_free;

  self->needle.cached_strings = g_ptr_array_new();
  self->process = process_func;
  self->haystack = haystack_expr;

  if(!_expr_affix_init_needle(self, needle_expr))
    {
      g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                  "needle caching failed.");
      goto error;
    }

  filterx_function_args_free(args);
  return &self->super.super;

error:
  filterx_function_args_free(args);
  filterx_expr_unref(&self->super.super);
  return NULL;
}

static gboolean
_function_startswith_process(const gchar *haystack, gsize haystack_len, const gchar *needle, gsize needle_len)
{
  if (needle_len > haystack_len)
    return FALSE;
  return memcmp(haystack, needle, needle_len) == 0;
}

FilterXExpr *
filterx_function_startswith_new(FilterXFunctionArgs *args, GError **error)
{
  return _function_affix_new(args, "startswith", _function_startswith_process,
                             FILTERX_FUNC_STARTSWITH_USAGE, error);
}

static gboolean
_function_endswith_process(const gchar *haystack, gsize haystack_len, const gchar *needle, gsize needle_len)
{
  if (needle_len > haystack_len)
    return FALSE;
  return memcmp(haystack + haystack_len - needle_len, needle, needle_len) == 0;
}

FilterXExpr *
filterx_function_endswith_new(FilterXFunctionArgs *args, GError **error)
{
  return _function_affix_new(args, "endswith", _function_endswith_process, FILTERX_FUNC_ENDSWITH_USAGE,
                             error);
}

static gboolean
_function_includes_process(const gchar *haystack, gsize haystack_len, const gchar *needle, gsize needle_len)
{
  if (needle_len > haystack_len)
    return FALSE;
  return g_strstr_len(haystack, haystack_len, needle) != NULL;
}

FilterXExpr *
filterx_function_includes_new(FilterXFunctionArgs *args, GError **error)
{
  return _function_affix_new(args, "includes", _function_includes_process, FILTERX_FUNC_INCLUDES_USAGE,
                             error);
}
