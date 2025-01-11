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

#ifndef FILTERX_EXPR_LITERAL_GENERATOR_H_INCLUDED
#define FILTERX_EXPR_LITERAL_GENERATOR_H_INCLUDED

#include "filterx/expr-generator.h"

typedef gboolean (*FilterXLiteralDictGeneratorForeachFunc)(FilterXExpr *, FilterXExpr *, gpointer);
typedef gboolean (*FilterXLiteralListGeneratorForeachFunc)(gsize, FilterXExpr *, gpointer);

typedef struct FilterXLiteralGeneratorElem_ FilterXLiteralGeneratorElem;
typedef struct FilterXExprLiteralGenerator_ FilterXExprLiteralGenerator;

FilterXLiteralGeneratorElem *filterx_literal_generator_elem_new(FilterXExpr *key, FilterXExpr *value,
    gboolean cloneable);

FilterXExpr *filterx_literal_dict_generator_new(void);
FilterXExpr *filterx_literal_list_generator_new(void);
void filterx_literal_generator_set_elements(FilterXExpr *s, GList *elements);
gboolean filterx_literal_dict_generator_foreach(FilterXExpr *s, FilterXLiteralDictGeneratorForeachFunc func,
                                                gpointer user_data);
gboolean filterx_literal_list_generator_foreach(FilterXExpr *s, FilterXLiteralListGeneratorForeachFunc func,
                                                gpointer user_data);

FilterXExpr *filterx_literal_inner_dict_generator_new(FilterXExpr *root_literal_generator, GList *elements);
FilterXExpr *filterx_literal_inner_list_generator_new(FilterXExpr *root_literal_generator, GList *elements);

guint filterx_expr_literal_generator_len(FilterXExpr *s);

FILTERX_EXPR_DECLARE_TYPE(literal_inner_dict_generator);
FILTERX_EXPR_DECLARE_TYPE(literal_inner_list_generator);

static inline gboolean
filterx_expr_is_literal_dict_generator(FilterXExpr *s)
{
  FilterXExprGenerator *generator = (FilterXExprGenerator *) s;
  return (filterx_expr_is_generator(s) && generator->create_container == filterx_generator_create_dict_container)
         || filterx_expr_is_literal_inner_dict_generator(s);
}

static inline gboolean
filterx_expr_is_literal_list_generator(FilterXExpr *s)
{
  FilterXExprGenerator *generator = (FilterXExprGenerator *) s;
  return (filterx_expr_is_generator(s) && generator->create_container == filterx_generator_create_list_container)
         || filterx_expr_is_literal_inner_list_generator(s);
}

static inline gboolean
filterx_expr_is_literal_generator(FilterXExpr *s)
{
  return filterx_expr_is_literal_list_generator(s) || filterx_expr_is_literal_dict_generator(s);
}

#endif
