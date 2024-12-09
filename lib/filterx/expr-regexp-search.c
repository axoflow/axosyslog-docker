/*
 * Copyright (c) 2023 Axoflow
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

#include "expr-regexp-search.h"
#include "filterx/expr-regexp.h"
#include "filterx/object-primitive.h"
#include "filterx/object-extractor.h"
#include "filterx/object-string.h"
#include "filterx/object-list-interface.h"
#include "filterx/object-dict-interface.h"
#include "filterx/expr-function.h"
#include "filterx/filterx-object-istype.h"
#include "filterx/filterx-ref.h"
#include "filterx/expr-regexp-common.h"
#include "compat/pcre.h"
#include "scratch-buffers.h"

DEFINE_FUNC_FLAG_NAMES(FilterXRegexpSearchFlags,
                       FILTERX_REGEXP_SEARCH_KEEP_GRP_ZERO_NAME,
                       FILTERX_REGEXP_SEARCH_LIST_MODE_NAME
                      );

#define FILTERX_FUNC_REGEXP_SEARCH_USAGE "Usage: regexp_search(string, pattern, " \
FILTERX_REGEXP_SEARCH_KEEP_GRP_ZERO_NAME"=(boolean), "\
FILTERX_REGEXP_SEARCH_LIST_MODE_NAME"=(boolean))"

typedef struct FilterXExprRegexpSearchGenerator_
{
  FilterXGeneratorFunction super;
  FilterXExpr *lhs;
  pcre2_code_8 *pattern;
  FLAGSET flags;
} FilterXExprRegexpSearchGenerator;

static gboolean
_store_matches_to_list(pcre2_code_8 *pattern, const FilterXReMatchState *state, FilterXObject *fillable)
{
  guint32 num_matches = pcre2_get_ovector_count(state->match_data);
  PCRE2_SIZE *matches = pcre2_get_ovector_pointer(state->match_data);

  for (gint i = 0; i < num_matches; i++)
    {
      if (num_matches > 1 && i==0 && !check_flag(state->flags, FILTERX_REGEXP_SEARCH_KEEP_GRP_ZERO))
        continue;
      gint begin_index = matches[2 * i];
      gint end_index = matches[2 * i + 1];
      if (begin_index < 0 || end_index < 0)
        continue;

      FilterXObject *value = filterx_string_new(state->lhs_str + begin_index, end_index - begin_index);
      gboolean success = filterx_list_append(fillable, &value);
      filterx_object_unref(value);

      if (!success)
        {
          msg_error("FilterX: Failed to append regexp match to list", evt_tag_int("index", i));
          return FALSE;
        }
    }

  return TRUE;
}

static gboolean
_store_matches_to_dict(pcre2_code_8 *pattern, const FilterXReMatchState *state, FilterXObject *fillable)
{
  PCRE2_SIZE *matches = pcre2_get_ovector_pointer(state->match_data);
  guint32 num_matches = pcre2_get_ovector_count(state->match_data);
  gchar num_str_buf[G_ASCII_DTOSTR_BUF_SIZE];

  /* First store all matches with string formatted indexes as keys. */
  for (guint32 i = 0; i < num_matches; i++)
    {
      if (num_matches > 1 && i==0 && !check_flag(state->flags, FILTERX_REGEXP_SEARCH_KEEP_GRP_ZERO))
        continue;

      PCRE2_SIZE begin_index = matches[2 * i];
      PCRE2_SIZE end_index = matches[2 * i + 1];
      if (begin_index < 0 || end_index < 0)
        continue;

      g_snprintf(num_str_buf, sizeof(num_str_buf), "%" G_GUINT32_FORMAT, i);
      FilterXObject *key = filterx_string_new(num_str_buf, -1);
      FilterXObject *value = filterx_string_new(state->lhs_str + begin_index, end_index - begin_index);

      gboolean success = filterx_object_set_subscript(fillable, key, &value);

      filterx_object_unref(key);
      filterx_object_unref(value);

      if (!success)
        {
          msg_error("FilterX: Failed to add regexp match to dict", evt_tag_str("key", num_str_buf));
          return FALSE;
        }
    }

  gchar *name_table = NULL;
  guint32 name_entry_size = 0;
  guint32 namecount = 0;
  pcre2_pattern_info(pattern, PCRE2_INFO_NAMETABLE, &name_table);
  pcre2_pattern_info(pattern, PCRE2_INFO_NAMEENTRYSIZE, &name_entry_size);
  pcre2_pattern_info(pattern, PCRE2_INFO_NAMECOUNT, &namecount);

  /* Rename named matches. */
  for (guint32 i = 0; i < namecount; i++, name_table += name_entry_size)
    {
      int n = (name_table[0] << 8) | name_table[1];
      PCRE2_SIZE begin_index = matches[2 * n];
      PCRE2_SIZE end_index = matches[2 * n + 1];
      const gchar *namedgroup_name = name_table + 2;

      if (begin_index < 0 || end_index < 0)
        continue;

      g_snprintf(num_str_buf, sizeof(num_str_buf), "%" G_GUINT32_FORMAT, n);
      FilterXObject *num_key = filterx_string_new(num_str_buf, -1);
      FilterXObject *key = filterx_string_new(namedgroup_name, -1);
      FilterXObject *value = filterx_object_get_subscript(fillable, num_key);

      gboolean success = filterx_object_set_subscript(fillable, key, &value);
      g_assert(filterx_object_unset_key(fillable, num_key));

      filterx_object_unref(key);
      filterx_object_unref(num_key);
      filterx_object_unref(value);

      if (!success)
        {
          msg_error("FilterX: Failed to add regexp match to dict", evt_tag_str("key", namedgroup_name));
          return FALSE;
        }
    }

  return TRUE;
}

static gboolean
_store_matches(pcre2_code_8 *pattern, const FilterXReMatchState *state, FilterXObject *fillable)
{
  fillable = filterx_ref_unwrap_rw(fillable);

  if (filterx_object_is_type(fillable, &FILTERX_TYPE_NAME(list)))
    return _store_matches_to_list(pattern, state, fillable);

  if (filterx_object_is_type(fillable, &FILTERX_TYPE_NAME(dict)))
    return _store_matches_to_dict(pattern, state, fillable);

  msg_error("FilterX: Failed to store regexp match data, invalid fillable type",
            evt_tag_str("type", fillable->type->name));
  return FALSE;
}

static gboolean
_regexp_search_generator_generate(FilterXExprGenerator *s, FilterXObject *fillable)
{
  FilterXExprRegexpSearchGenerator *self = (FilterXExprRegexpSearchGenerator *) s;

  gboolean result;
  FilterXReMatchState state;
  filterx_expr_rematch_state_init(&state);
  state.flags = self->flags;

  gboolean matched = filterx_regexp_match_eval(self->lhs, self->pattern, &state);
  if (!matched)
    {
      result = TRUE;
      goto exit;
    }

  if (!state.match_data)
    {
      /* Error happened during matching. */
      result = FALSE;
      goto exit;
    }

  result = _store_matches(self->pattern, &state, fillable);

exit:
  filterx_expr_rematch_state_cleanup(&state);
  return result;
}

static FilterXObject *
_regexp_search_generator_create_container(FilterXExprGenerator *s, FilterXExpr *fillable_parent)
{
  FilterXExprRegexpSearchGenerator *self = (FilterXExprRegexpSearchGenerator *) s;

  if (check_flag(self->flags, FILTERX_REGEXP_SEARCH_LIST_MODE))
    return filterx_generator_create_list_container(s, fillable_parent);

  return filterx_generator_create_dict_container(s, fillable_parent);
}

static gboolean
_regexp_search_generator_init(FilterXExpr *s, GlobalConfig *cfg)
{
  FilterXExprRegexpSearchGenerator *self = (FilterXExprRegexpSearchGenerator *) s;

  if (!filterx_expr_init(self->lhs, cfg))
    return FALSE;

  return filterx_generator_init_method(s, cfg);
}

static void
_regexp_search_generator_deinit(FilterXExpr *s, GlobalConfig *cfg)
{
  FilterXExprRegexpSearchGenerator *self = (FilterXExprRegexpSearchGenerator *) s;

  filterx_expr_deinit(self->lhs, cfg);
  filterx_generator_deinit_method(s, cfg);
}

static void
_regexp_search_generator_free(FilterXExpr *s)
{
  FilterXExprRegexpSearchGenerator *self = (FilterXExprRegexpSearchGenerator *) s;

  filterx_expr_unref(self->lhs);
  if (self->pattern)
    pcre2_code_free(self->pattern);
  filterx_generator_function_free_method(&self->super);
}

static gboolean
_extract_optional_arg_flag(FilterXExprRegexpSearchGenerator *self, FilterXRegexpSearchFlags flag,
                           FilterXFunctionArgs *args, GError **error)
{
  return filterx_regexp_extract_optional_arg_flag(&self->flags, FilterXRegexpSearchFlags_NAMES,
                                                  FilterXRegexpSearchFlags_MAX, flag, FILTERX_FUNC_REGEXP_SEARCH_USAGE, args, error);
}

static gboolean
_extract_search_args(FilterXExprRegexpSearchGenerator *self, FilterXFunctionArgs *args, GError **error)
{
  if (filterx_function_args_len(args) != 2)
    {
      g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                  "invalid number of arguments. " FILTERX_FUNC_REGEXP_SEARCH_USAGE);
      return FALSE;
    }

  self->lhs = filterx_function_args_get_expr(args, 0);

  const gchar *pattern = filterx_function_args_get_literal_string(args, 1, NULL);
  if (!pattern)
    {
      g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                  "pattern must be string literal. " FILTERX_FUNC_REGEXP_SEARCH_USAGE);
      return FALSE;
    }

  self->pattern = filterx_regexp_compile_pattern_defaults(pattern);
  if (!self->pattern)
    {
      g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                  "failed to compile pattern. " FILTERX_FUNC_REGEXP_SEARCH_USAGE);
      return FALSE;
    }

  return TRUE;

}

/* Takes reference of lhs */
FilterXExpr *
filterx_generator_function_regexp_search_new(FilterXFunctionArgs *args, GError **error)
{
  FilterXExprRegexpSearchGenerator *self = g_new0(FilterXExprRegexpSearchGenerator, 1);

  filterx_generator_function_init_instance(&self->super, "regexp_search");
  self->super.super.generate = _regexp_search_generator_generate;
  self->super.super.super.init = _regexp_search_generator_init;
  self->super.super.super.deinit = _regexp_search_generator_deinit;
  self->super.super.super.free_fn = _regexp_search_generator_free;
  self->super.super.create_container = _regexp_search_generator_create_container;

  if (!_extract_optional_arg_flag(self, FILTERX_REGEXP_SEARCH_KEEP_GRP_ZERO, args, error))
    goto error;

  if (!_extract_optional_arg_flag(self, FILTERX_REGEXP_SEARCH_LIST_MODE, args, error))
    goto error;

  if (!_extract_search_args(self, args, error) ||
      !filterx_function_args_check(args, error))
    goto error;

  filterx_function_args_free(args);
  return &self->super.super.super;

error:
  filterx_function_args_free(args);
  filterx_expr_unref(&self->super.super.super);
  return NULL;
}