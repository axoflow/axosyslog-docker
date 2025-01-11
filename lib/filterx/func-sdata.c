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

#include "func-sdata.h"
#include "filterx/object-primitive.h"
#include "filterx/filterx-eval.h"
#include "filterx/object-string.h"
#include "filterx/object-extractor.h"
#include "filterx/object-json.h"

#include <string.h>

#define SDATA_PREFIX_LEN (7)

#define FILTERX_FUNC_IS_SDATA_FROM_ENTERPRISE_USAGE "Usage: is_sdata_from_enteprise(\"32473\")"

typedef struct FilterXFunctionIsSdataFromEnteprise_
{
  FilterXFunction super;
  gchar *str_literal;
  gsize str_literal_len;
} FilterXFunctionIsSdataFromEnteprise;

static gboolean
_extract_args(FilterXFunctionIsSdataFromEnteprise *self, FilterXFunctionArgs *args, GError **error)
{
  gsize len = filterx_function_args_len(args);
  if (len != 1)
    {
      g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                  "invalid number of arguments. " FILTERX_FUNC_IS_SDATA_FROM_ENTERPRISE_USAGE);
      return FALSE;
    }

  gsize str_literal_len;
  const gchar *str_literal = filterx_function_args_get_literal_string(args, 0, &str_literal_len);
  if (!str_literal)
    {
      g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                  "argument must be a string literal. " FILTERX_FUNC_IS_SDATA_FROM_ENTERPRISE_USAGE);
      return FALSE;
    }
  self->str_literal = g_strdup(str_literal);
  self->str_literal_len = str_literal_len;
  return TRUE;
}

static FilterXObject *
_eval_fx_is_sdata_from(FilterXExpr *s)
{
  FilterXFunctionIsSdataFromEnteprise *self = (FilterXFunctionIsSdataFromEnteprise *) s;

  gboolean contains = FALSE;
  FilterXEvalContext *context = filterx_eval_get_context();
  LogMessage *msg = context->msg;

  for (guint8 i = 0; i < msg->num_sdata && !contains; i++)
    {
      const gchar *value = log_msg_get_value_name(msg->sdata[i], NULL);
      gchar *at_sign = strchr(value, '@');
      if (!at_sign)
        continue;
      contains = strncmp(at_sign+1, self->str_literal, self->str_literal_len) == 0;
    }

  return filterx_boolean_new(contains);
}

static void
_free(FilterXExpr *s)
{
  FilterXFunctionIsSdataFromEnteprise *self = (FilterXFunctionIsSdataFromEnteprise *) s;

  g_free(self->str_literal);
  filterx_function_free_method(&self->super);
}


FilterXExpr *
filterx_function_is_sdata_from_enterprise_new(FilterXFunctionArgs *args, GError **error)
{
  FilterXFunctionIsSdataFromEnteprise *self = g_new0(FilterXFunctionIsSdataFromEnteprise, 1);
  filterx_function_init_instance(&self->super, "is_sdata_from_enterprise");

  if (!_extract_args(self, args, error) || !filterx_function_args_check(args, error))
    goto error;
  self->super.super.eval = _eval_fx_is_sdata_from;
  self->super.super.free_fn = _free;
  filterx_function_args_free(args);
  return &self->super.super;

error:
  filterx_function_args_free(args);
  filterx_expr_unref(&self->super.super);
  return NULL;
}


FilterXObject *
filterx_simple_function_has_sdata(FilterXExpr *s, FilterXObject *args[], gsize args_len)
{
  if (args && args_len != 0)
    {
      filterx_simple_function_argument_error(s, "Incorrect number of arguments", FALSE);
      return NULL;
    }

  FilterXEvalContext *context = filterx_eval_get_context();
  LogMessage *msg = context->msg;
  return filterx_boolean_new(msg->num_sdata != 0);
}

static gboolean
_should_create_new_dict(const gchar *previous_sd_id, gsize previous_sd_id_len, const gchar *current_sd_id,
                        gsize current_sd_id_len)
{
  if (previous_sd_id_len != current_sd_id_len)
    return TRUE;

  return strncmp(previous_sd_id, current_sd_id, previous_sd_id_len) != 0;
}


static gboolean
_extract_sd_components(const gchar *key, gssize key_len, const gchar **sd_id_start, gsize *sd_id_len,
                       const gchar **sd_param_name_start, gsize *sd_param_name_len)
{
  /* skip '.SDATA.' */
  if (key_len < SDATA_PREFIX_LEN)
    return FALSE;

  const gchar *last_dot = NULL;
  for(gsize i = key_len; i > 0 && !last_dot; i--)
    {
      if (key[i-1] == '.')
        last_dot = key + i - 1;
    }
  if (!last_dot)
    return FALSE;

  *sd_id_start = key + SDATA_PREFIX_LEN;
  *sd_id_len = last_dot - *sd_id_start;

  *sd_param_name_start = last_dot + 1;
  *sd_param_name_len = key + key_len - *sd_param_name_start;

  return TRUE;
}


static gboolean
_insert_into_dict(FilterXObject *dict, const gchar *key, gssize key_len, const gchar *value, gssize value_len)
{
  FilterXObject *fob_key = filterx_string_new(key, key_len);
  FilterXObject *fob_value = filterx_string_new(value, value_len);
  gboolean res = filterx_object_set_subscript(dict, fob_key, &fob_value);

  filterx_object_unref(fob_key);
  filterx_object_unref(fob_value);

  return res;
}

static gboolean
_insert_while_same_sd_id(LogMessage *msg, guint8 index, guint8 num_sdata, guint8 *num_insertions,
                         FilterXObject *inner_dict,
                         const gchar *current_sd_id_start, gsize current_sd_id_len)
{
  const gchar *next_sd_id_start;
  gsize next_sd_id_len;
  const gchar *param_name_start;
  gsize param_name_len;

  *num_insertions = 0;

  for (guint8 j = index + 1; j < num_sdata; j++)
    {
      gssize next_name_len;
      const gchar *next_name = log_msg_get_value_name(msg->sdata[j], &next_name_len);
      gssize next_value_len;
      const gchar *next_value = log_msg_get_value(msg, msg->sdata[j], &next_value_len);

      if (!_extract_sd_components(next_name, next_name_len, &next_sd_id_start, &next_sd_id_len, &param_name_start,
                                  &param_name_len))
        {
          filterx_object_unref(inner_dict);
          return FALSE;
        }

      if (_should_create_new_dict(current_sd_id_start, current_sd_id_len, next_sd_id_start, next_sd_id_len))
        break;

      if (!_insert_into_dict(inner_dict, param_name_start, param_name_len, next_value, next_value_len))
        return FALSE;

      (*num_insertions)++;
    }

  return TRUE;
}

static gboolean
_generate(FilterXExprGenerator *s, FilterXObject *fillable)
{
  FilterXEvalContext *context = filterx_eval_get_context();
  LogMessage *msg = context->msg;

  const gchar *current_sd_id_start;
  gsize current_sd_id_len;
  const gchar *param_name_start;
  gsize param_name_len;

  for (guint8 i = 0; i < msg->num_sdata;)
    {
      gssize name_len;
      const gchar *name = log_msg_get_value_name(msg->sdata[i], &name_len);
      gssize value_len;
      const gchar *value = log_msg_get_value(msg, msg->sdata[i], &value_len);

      if (!_extract_sd_components(name, name_len, &current_sd_id_start, &current_sd_id_len, &param_name_start,
                                  &param_name_len))
        {
          return FALSE;
        }

      FilterXObject *inner_dict = filterx_object_create_dict(fillable);
      if (!_insert_into_dict(inner_dict, param_name_start, param_name_len, value, value_len))
        return FALSE;

      guint8 num_insertions;
      if(!_insert_while_same_sd_id(msg, i, msg->num_sdata, &num_insertions, inner_dict, current_sd_id_start,
                                   current_sd_id_len))
        return FALSE;
      i += num_insertions + 1;

      FilterXObject *sd_id_key = filterx_string_new(current_sd_id_start, current_sd_id_len);
      filterx_object_set_subscript(fillable, sd_id_key, &inner_dict);
      filterx_object_unref(inner_dict);
      filterx_object_unref(sd_id_key);
    }

  return TRUE;
}

static void
_get_sdata_free(FilterXExpr *s)
{
  FilterXGenFuncGetSdata *self = (FilterXGenFuncGetSdata *) s;
  filterx_generator_function_free_method(&self->super);
}

FilterXExpr *
filterx_generator_function_get_sdata_new(FilterXFunctionArgs *args, GError **error)
{
  FilterXGenFuncGetSdata *self = g_new0(FilterXGenFuncGetSdata, 1);

  filterx_generator_function_init_instance(&self->super, "get_sdata");
  self->super.super.generate = _generate;
  self->super.super.super.free_fn = _get_sdata_free;
  self->super.super.create_container = filterx_generator_create_dict_container;

  if (filterx_function_args_len(args) != 0)
    {
      g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL, "invalid number of arguments.");
      goto error;
    }

  filterx_function_args_free(args);
  return &self->super.super.super;

error:
  filterx_function_args_free(args);
  filterx_expr_unref(&self->super.super.super);
  return NULL;
}
