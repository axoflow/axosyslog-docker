/*
 * Copyright (c) 2024 Axoflow
 * Copyright (c) 2024 Attila Szakacs <attila.szakacs@axoflow.com>
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

#include "filterx/expr-generator.h"

/* Takes reference of fillable */
void
filterx_generator_set_fillable(FilterXExpr *s, FilterXExpr *fillable)
{
  FilterXExprGenerator *self = (FilterXExprGenerator *) s;

  self->fillable = fillable;
}

static FilterXObject *
_eval_generator(FilterXExpr *s)
{
  FilterXExprGenerator *self = (FilterXExprGenerator *) s;

  FilterXObject *fillable = filterx_expr_eval_typed(self->fillable);
  if (!fillable)
    return NULL;

  if (self->generate(self, fillable))
    return fillable;

  filterx_object_unref(fillable);
  return NULL;
}

FilterXExpr *
filterx_generator_optimize_method(FilterXExpr *s)
{
  FilterXExprGenerator *self = (FilterXExprGenerator *) s;

  self->fillable = filterx_expr_optimize(self->fillable);
  return NULL;
}

void
filterx_generator_init_instance(FilterXExpr *s)
{
  filterx_expr_init_instance(s, FILTERX_EXPR_TYPE_NAME(generator));
  s->optimize = filterx_generator_optimize_method;
  s->init = filterx_generator_init_method;
  s->deinit = filterx_generator_deinit_method;
  s->eval = _eval_generator;
  s->ignore_falsy_result = TRUE;
}

gboolean
filterx_generator_init_method(FilterXExpr *s, GlobalConfig *cfg)
{
  FilterXExprGenerator *self = (FilterXExprGenerator *) s;

  if (!filterx_expr_init(self->fillable, cfg))
    return FALSE;

  return filterx_expr_init_method(s, cfg);
}

void
filterx_generator_deinit_method(FilterXExpr *s, GlobalConfig *cfg)
{
  FilterXExprGenerator *self = (FilterXExprGenerator *) s;

  filterx_expr_deinit(self->fillable, cfg);
  filterx_expr_deinit_method(s, cfg);
}

void
filterx_generator_free_method(FilterXExpr *s)
{
  FilterXExprGenerator *self = (FilterXExprGenerator *) s;

  filterx_expr_unref(self->fillable);
  filterx_expr_free_method(s);
}

FILTERX_EXPR_DEFINE_TYPE(generator);

typedef struct FilterXExprGeneratorCreateContainer_
{
  FilterXExpr super;
  FilterXExprGenerator *generator;
  FilterXExpr *fillable_parent;
} FilterXExprGeneratorCreateContainer;

static FilterXObject *
_create_container_eval(FilterXExpr *s)
{
  FilterXExprGeneratorCreateContainer *self = (FilterXExprGeneratorCreateContainer *) s;

  return self->generator->create_container(self->generator, self->fillable_parent);
}

static FilterXExpr *
_create_container_optimize(FilterXExpr *s)
{
  FilterXExprGeneratorCreateContainer *self = (FilterXExprGeneratorCreateContainer *) s;

  self->fillable_parent = filterx_expr_optimize(self->fillable_parent);
  return NULL;
}

static gboolean
_create_container_init(FilterXExpr *s, GlobalConfig *cfg)
{
  FilterXExprGeneratorCreateContainer *self = (FilterXExprGeneratorCreateContainer *) s;

  if (!filterx_expr_init(self->fillable_parent, cfg))
    return FALSE;

  return filterx_expr_init_method(s, cfg);
}

static void
_create_container_deinit(FilterXExpr *s, GlobalConfig *cfg)
{
  FilterXExprGeneratorCreateContainer *self = (FilterXExprGeneratorCreateContainer *) s;

  filterx_expr_deinit(self->fillable_parent, cfg);
  filterx_expr_deinit_method(s, cfg);
}

static void
_create_container_free(FilterXExpr *s)
{
  FilterXExprGeneratorCreateContainer *self = (FilterXExprGeneratorCreateContainer *) s;

  filterx_expr_unref(&self->generator->super);
  filterx_expr_unref(self->fillable_parent);
  filterx_expr_free_method(s);
}

FilterXObject *
filterx_generator_create_dict_container(FilterXExprGenerator *s, FilterXExpr *fillable_parent)
{
  FilterXObject *fillable_parent_obj = filterx_expr_eval_typed(fillable_parent);
  if (!fillable_parent_obj)
    return NULL;

  FilterXObject *result = filterx_object_create_dict(fillable_parent_obj);
  filterx_object_unref(fillable_parent_obj);
  return result;
}

FilterXObject *
filterx_generator_create_list_container(FilterXExprGenerator *s, FilterXExpr *fillable_parent)
{
  FilterXObject *fillable_parent_obj = filterx_expr_eval_typed(fillable_parent);
  if (!fillable_parent_obj)
    return NULL;

  FilterXObject *result = filterx_object_create_list(fillable_parent_obj);
  filterx_object_unref(fillable_parent_obj);
  return result;
}

/* Takes reference of g and fillable_parent */
FilterXExpr *
filterx_generator_create_container_new(FilterXExpr *g, FilterXExpr *fillable_parent)
{
  FilterXExprGeneratorCreateContainer *self = g_new0(FilterXExprGeneratorCreateContainer, 1);

  filterx_expr_init_instance(&self->super, "create_container");
  self->generator = (FilterXExprGenerator *) g;
  self->fillable_parent = fillable_parent;
  self->super.optimize = _create_container_optimize;
  self->super.init = _create_container_init;
  self->super.deinit = _create_container_deinit;
  self->super.eval = _create_container_eval;
  self->super.free_fn = _create_container_free;

  return &self->super;
}
