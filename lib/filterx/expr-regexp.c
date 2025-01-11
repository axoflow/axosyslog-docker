/*
 * Copyright (c) 2024 Attila Szakacs
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

#include "filterx/expr-regexp.h"
#include "filterx/object-primitive.h"
#include "filterx/object-extractor.h"
#include "filterx/object-string.h"
#include "filterx/object-list-interface.h"
#include "filterx/object-dict-interface.h"
#include "filterx/expr-function.h"
#include "filterx/filterx-object-istype.h"
#include "filterx/filterx-ref.h"
#include "compat/pcre.h"
#include "scratch-buffers.h"
#include "filterx/expr-regexp-common.h"

typedef struct FilterXExprRegexpMatch_
{
  FilterXExpr super;
  FilterXExpr *lhs;
  pcre2_code_8 *pattern;
  gboolean invert;
} FilterXExprRegexpMatch;

static FilterXObject *
_regexp_match_eval(FilterXExpr *s)
{
  FilterXExprRegexpMatch *self = (FilterXExprRegexpMatch *) s;

  FilterXObject *result = NULL;
  FilterXReMatchState state;
  filterx_expr_rematch_state_init(&state);

  gboolean matched = filterx_regexp_match_eval(self->lhs, self->pattern, &state);
  if (!state.match_data)
    {
      /* Error happened during matching. */
      goto exit;
    }

  result = filterx_boolean_new(matched != self->invert);

exit:
  filterx_expr_rematch_state_cleanup(&state);
  return result;
}

static FilterXExpr *
_regexp_match_optimize(FilterXExpr *s)
{
  FilterXExprRegexpMatch *self = (FilterXExprRegexpMatch *) s;

  self->lhs = filterx_expr_optimize(self->lhs);
  return NULL;
}

static gboolean
_regexp_match_init(FilterXExpr *s, GlobalConfig *cfg)
{
  FilterXExprRegexpMatch *self = (FilterXExprRegexpMatch *) s;

  if (!filterx_expr_init(self->lhs, cfg))
    return FALSE;

  return filterx_expr_init_method(s, cfg);
}

static void
_regexp_match_deinit(FilterXExpr *s, GlobalConfig *cfg)
{
  FilterXExprRegexpMatch *self = (FilterXExprRegexpMatch *) s;

  filterx_expr_deinit(self->lhs, cfg);
  filterx_expr_deinit_method(s, cfg);
}

static void
_regexp_match_free(FilterXExpr *s)
{
  FilterXExprRegexpMatch *self = (FilterXExprRegexpMatch *) s;

  filterx_expr_unref(self->lhs);
  if (self->pattern)
    pcre2_code_free(self->pattern);
  filterx_expr_free_method(s);
}

/* Takes reference of lhs */
FilterXExpr *
filterx_expr_regexp_match_new(FilterXExpr *lhs, const gchar *pattern)
{
  FilterXExprRegexpMatch *self = g_new0(FilterXExprRegexpMatch, 1);

  filterx_expr_init_instance(&self->super, "regexp_match");
  self->super.eval = _regexp_match_eval;
  self->super.optimize = _regexp_match_optimize;
  self->super.init = _regexp_match_init;
  self->super.deinit = _regexp_match_deinit;
  self->super.free_fn = _regexp_match_free;

  self->lhs = lhs;
  self->pattern = filterx_regexp_compile_pattern_defaults(pattern);
  if (!self->pattern)
    {
      filterx_expr_unref(&self->super);
      return NULL;
    }

  return &self->super;
}

FilterXExpr *
filterx_expr_regexp_nomatch_new(FilterXExpr *lhs, const gchar *pattern)
{
  FilterXExprRegexpMatch *self = (FilterXExprRegexpMatch *)filterx_expr_regexp_match_new(lhs, pattern);
  self->invert = TRUE;
  return &self->super;
}
