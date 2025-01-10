/*
 * Copyright (c) 2024 Axoflow
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

#ifndef FILTERX_EXPR_H_INCLUDED
#define FILTERX_EXPR_H_INCLUDED

#include "filterx-object.h"
#include "cfg-lexer.h"
#include "stats/stats-counter.h"

struct _FilterXExpr
{
  StatsCounterItem *eval_count;
  /* evaluate expression */
  FilterXObject *(*eval)(FilterXExpr *self);

  /* not thread-safe */
  guint32 ref_cnt;
  guint32 ignore_falsy_result:1, suppress_from_trace:1, inited:1, optimized:1;

  /* not to be used except for FilterXMessageRef, replace any cached values
   * with the unmarshaled version */
  void (*_update_repr)(FilterXExpr *self, FilterXObject *new_repr);

  /* assign a new value to this expr */
  gboolean (*assign)(FilterXExpr *self, FilterXObject *new_value);

  /* is the expression set? */
  gboolean (*is_set)(FilterXExpr *self);
  /* unset the expression */
  gboolean (*unset)(FilterXExpr *self);

  gboolean (*init)(FilterXExpr *self, GlobalConfig *cfg);
  void (*deinit)(FilterXExpr *self, GlobalConfig *cfg);
  FilterXExpr *(*optimize)(FilterXExpr *self);
  void (*free_fn)(FilterXExpr *self);

  /* type of the expr, is not freed, assumed to be managed by something else
   * */

  const gchar *type;

  /* name associated with the expr (e.g.  function name), is not freed by
   * FilterXExpr, assumed to be managed by something else */
  const gchar *name;
  CFG_LTYPE *lloc;
  gchar *expr_text;
};

#define FILTERX_EXPR_TYPE_NAME(_type) filterx_expr_type_ ## _type

#define FILTERX_EXPR_DECLARE_TYPE(_type) \
  extern const gchar *FILTERX_EXPR_TYPE_NAME(_type); \
  \
  static inline gboolean \
  filterx_expr_is_ ## _type(FilterXExpr *expr) \
  { \
    return expr && expr->type == FILTERX_EXPR_TYPE_NAME(_type); \
  }

#define FILTERX_EXPR_DEFINE_TYPE(_type) \
  const gchar *FILTERX_EXPR_TYPE_NAME(_type) = # _type

/*
 * Evaluate the expression and return the result as a FilterXObject.  The
 * result can either be a
 *
 *   1) raw representation (e.g.  a marshalled series of bytes + syslog-ng
 *      type hint encapsulated into a FilterXMessageValue)
 *
 *   2) typed representation (e.g.  a demarshalled object, something other
 *      than FilterXMessageValue, like FilterXJSON)
 *
 * If the caller is not ok with handling the raw representation, just use
 * filterx_expr_eval_typed() which will unmarshall any values before
 * returning them.
 */
static inline FilterXObject *
filterx_expr_eval(FilterXExpr *self)
{
  stats_counter_inc(self->eval_count);

  return self->eval(self);
}

/*
 * Evaluate the expression and return the result as a typed FilterXObject.
 * This function will call filterx_expr_eval() and then unmarshal the result
 * so the result is always a typed object.
 */
static inline FilterXObject *
filterx_expr_eval_typed(FilterXExpr *self)
{
  FilterXObject *result = filterx_expr_eval(self);

  if (!result)
    return NULL;

  FilterXObject *unmarshalled = filterx_object_unmarshal(result);

  if (!unmarshalled)
    {
      filterx_object_unref(result);
      return NULL;
    }

  if (result == unmarshalled)
    {
      filterx_object_unref(unmarshalled);
      return result;
    }

  filterx_object_unref(result);
  if (self->_update_repr)
    self->_update_repr(self, unmarshalled);

  return unmarshalled;
}

static inline gboolean
filterx_expr_assign(FilterXExpr *self, FilterXObject *new_value)
{
  if (self->assign)
    return self->assign(self, new_value);
  return FALSE;
}

static inline gboolean
filterx_expr_is_set(FilterXExpr *self)
{
  if (self->is_set)
    return self->is_set(self);
  return FALSE;
}

static inline gboolean
filterx_expr_unset(FilterXExpr *self)
{
  if (self->unset)
    return self->unset(self);
  return FALSE;
}

static inline gboolean
filterx_expr_unset_available(FilterXExpr *self)
{
  return self->unset != NULL;
}

void filterx_expr_set_location(FilterXExpr *self, CfgLexer *lexer, CFG_LTYPE *lloc);
void filterx_expr_set_location_with_text(FilterXExpr *self, CFG_LTYPE *lloc, const gchar *text);
EVTTAG *filterx_expr_format_location_tag(FilterXExpr *self);
FilterXExpr *filterx_expr_optimize(FilterXExpr *self);
void filterx_expr_init_instance(FilterXExpr *self, const gchar *type);
FilterXExpr *filterx_expr_new(void);
FilterXExpr *filterx_expr_ref(FilterXExpr *self);
void filterx_expr_unref(FilterXExpr *self);
gboolean filterx_expr_init_method(FilterXExpr *self, GlobalConfig *cfg);
void filterx_expr_deinit_method(FilterXExpr *self, GlobalConfig *cfg);
void filterx_expr_free_method(FilterXExpr *self);

static inline gboolean
filterx_expr_init(FilterXExpr *self, GlobalConfig *cfg)
{
  if (!self || self->inited)
    return TRUE;

  if (!self->init || self->init(self, cfg))
    {
      self->inited = TRUE;
      return TRUE;
    }

  return FALSE;
}

static inline void
filterx_expr_deinit(FilterXExpr *self, GlobalConfig *cfg)
{
  if (!self || !self->inited)
    return;

  if (self->deinit)
    self->deinit(self, cfg);

  self->inited = FALSE;
}

typedef struct _FilterXUnaryOp
{
  FilterXExpr super;
  FilterXExpr *operand;
} FilterXUnaryOp;

FilterXExpr *filterx_unary_op_optimize_method(FilterXExpr *s);
gboolean filterx_unary_op_init_method(FilterXExpr *s, GlobalConfig *cfg);
void filterx_unary_op_deinit_method(FilterXExpr *s, GlobalConfig *cfg);
void filterx_unary_op_free_method(FilterXExpr *s);
void filterx_unary_op_init_instance(FilterXUnaryOp *self, const gchar *name, FilterXExpr *operand);

typedef struct _FilterXBinaryOp
{
  FilterXExpr super;
  FilterXExpr *lhs, *rhs;
} FilterXBinaryOp;

FilterXExpr *filterx_binary_op_optimize_method(FilterXExpr *s);
gboolean filterx_binary_op_init_method(FilterXExpr *s, GlobalConfig *cfg);
void filterx_binary_op_deinit_method(FilterXExpr *s, GlobalConfig *cfg);
void filterx_binary_op_free_method(FilterXExpr *s);
void filterx_binary_op_init_instance(FilterXBinaryOp *self, const gchar *name, FilterXExpr *lhs, FilterXExpr *rhs);

#endif
