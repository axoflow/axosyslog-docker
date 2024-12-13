/*
 * Copyright (c) 2024 Axoflow
 * Copyright (c) 2024 Attila Szakacs <attila.szakacs@axoflow.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * As an additional exemption you are allowed to compile & link against the
 * OpenSSL libraries as published by the OpenSSL project. See the file
 * COPYING for details.
 *
 */

#include "func-update-metric.h"
#include "filterx/filterx-metrics.h"
#include "filterx/expr-literal.h"
#include "filterx/filterx-eval.h"
#include "filterx/object-extractor.h"
#include "filterx/object-primitive.h"
#include "stats/stats.h"

#define FILTERX_FUNC_UPDATE_METRIC_USAGE "update_metric(\"key\", labels={\"key\": \"value\"}, increment=1, level=0)"

typedef struct FilterXFunctionUpdateMetric_
{
  FilterXFunction super;
  FilterXMetrics *metrics;
  gint level;

  struct
  {
    FilterXExpr *expr;
    gint64 value;
  } increment;
} FilterXFunctionUpdateMetric;

static gboolean
_get_increment(FilterXFunctionUpdateMetric *self, gint64 *increment)
{
  if (!self->increment.expr)
    {
      *increment = self->increment.value;
      return TRUE;
    }

  FilterXObject *increment_obj = filterx_expr_eval_typed(self->increment.expr);
  if (!increment_obj)
    return FALSE;

  gboolean success = filterx_integer_unwrap(increment_obj, increment);
  if (!success)
    filterx_eval_push_error("metric increment must be an integer", self->increment.expr, increment_obj);

  filterx_object_unref(increment_obj);
  return success;
}

static FilterXObject *
_eval(FilterXExpr *s)
{
  FilterXFunctionUpdateMetric *self = (FilterXFunctionUpdateMetric *) s;

  gboolean success = FALSE;

  gint64 increment;
  if (!_get_increment(self, &increment))
    goto exit;

  StatsCounterItem *counter;
  if (!filterx_metrics_get_stats_counter(self->metrics, &counter))
    goto exit;

  stats_counter_add(counter, increment);
  success = TRUE;

exit:
  if (!success)
    {
      /* It would be nice to introduce a counter for this. */
      msg_debug("FilterX: Failed to process update_metric()", filterx_eval_format_last_error_tag());
      filterx_eval_clear_errors();
    }

  return filterx_boolean_new(TRUE);
}

static gboolean
_init(FilterXExpr *s, GlobalConfig *cfg)
{
  FilterXFunctionUpdateMetric *self = (FilterXFunctionUpdateMetric *) s;

  if (!filterx_expr_init(self->increment.expr, cfg))
    return FALSE;

  if (!filterx_metrics_init(self->metrics, cfg))
    {
      filterx_expr_deinit(self->increment.expr, cfg);
      return FALSE;
    }

  return filterx_function_init_method(&self->super, cfg);
}

static void
_deinit(FilterXExpr *s, GlobalConfig *cfg)
{
  FilterXFunctionUpdateMetric *self = (FilterXFunctionUpdateMetric *) s;
  filterx_expr_deinit(self->increment.expr, cfg);
  filterx_metrics_deinit(self->metrics, cfg);
  filterx_function_deinit_method(&self->super, cfg);
}

static void
_free(FilterXExpr *s)
{
  FilterXFunctionUpdateMetric *self = (FilterXFunctionUpdateMetric *) s;

  if (self->metrics)
    filterx_metrics_free(self->metrics);
  filterx_expr_unref(self->increment.expr);

  filterx_function_free_method(&self->super);
}

static gboolean
_extract_increment_arg(FilterXFunctionUpdateMetric *self, FilterXFunctionArgs *args, GError **error)
{
  self->increment.value = 1;
  self->increment.expr = filterx_function_args_get_named_expr(args, "increment");

  if (self->increment.expr && filterx_expr_is_literal(self->increment.expr))
    {
      FilterXObject *increment_obj = filterx_expr_eval(self->increment.expr);
      if (!increment_obj)
        {
          g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                      "failed to evaluate increment. " FILTERX_FUNC_UPDATE_METRIC_USAGE);
          return FALSE;
        }

      gboolean success = filterx_object_extract_integer(increment_obj, &self->increment.value);
      filterx_object_unref(increment_obj);
      if (!success)
        {
          g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                      "failed to set increment, increment must be integer. " FILTERX_FUNC_UPDATE_METRIC_USAGE);
          return FALSE;
        }

      filterx_expr_unref(self->increment.expr);
      self->increment.expr = NULL;
    }

  return TRUE;
}

static gboolean
_extract_level_arg(FilterXFunctionUpdateMetric *self, FilterXFunctionArgs *args, GError **error)
{
  gboolean exists;
  gboolean arg_error;
  self->level = filterx_function_args_get_named_literal_integer(args, "level", &exists, &arg_error);

  if (arg_error)
    {
      g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                  "failed to set level, level must be a literal integer. " FILTERX_FUNC_UPDATE_METRIC_USAGE);
      return FALSE;
    }

  if (!exists)
    self->level = STATS_LEVEL0;

  return TRUE;
}

static gboolean
_init_metrics(FilterXFunctionUpdateMetric *self, FilterXFunctionArgs *args, GError **error)
{
  FilterXExpr *key = filterx_function_args_get_expr(args, 0);
  FilterXExpr *labels = filterx_function_args_get_named_expr(args, "labels");

  self->metrics = filterx_metrics_new(self->level, key, labels);

  filterx_expr_unref(key);
  filterx_expr_unref(labels);

  return !!self->metrics;
}

static gboolean
_extract_args(FilterXFunctionUpdateMetric *self, FilterXFunctionArgs *args, GError **error)
{
  if (filterx_function_args_len(args) != 1)
    {
      g_set_error(error, FILTERX_FUNCTION_ERROR, FILTERX_FUNCTION_ERROR_CTOR_FAIL,
                  "invalid number of arguments. " FILTERX_FUNC_UPDATE_METRIC_USAGE);
      return FALSE;
    }

  if (!_extract_increment_arg(self, args, error))
    return FALSE;

  if (!_extract_level_arg(self, args, error))
    return FALSE;

  if (!_init_metrics(self, args, error))
    return FALSE;

  return TRUE;
}

FilterXExpr *
filterx_function_update_metric_new(FilterXFunctionArgs *args, GError **error)
{
  FilterXFunctionUpdateMetric *self = g_new0(FilterXFunctionUpdateMetric, 1);
  filterx_function_init_instance(&self->super, "update_metric");

  self->super.super.eval = _eval;
  self->super.super.init = _init;
  self->super.super.deinit = _deinit;
  self->super.super.free_fn = _free;

  if (!_extract_args(self, args, error) ||
      !filterx_function_args_check(args, error))
    goto error;

  filterx_function_args_free(args);
  return &self->super.super;

error:
  filterx_function_args_free(args);
  filterx_expr_unref(&self->super.super);
  return NULL;
}

FILTERX_FUNCTION(update_metric, filterx_function_update_metric_new);
