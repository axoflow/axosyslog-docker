/*
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
#include "filterx/expr-setattr.h"
#include "filterx/object-primitive.h"
#include "filterx/object-string.h"
#include "filterx/filterx-eval.h"
#include "filterx/filterx-ref.h"
#include "filterx/filterx-object-istype.h"
#include "filterx/filterx-eval.h"
#include "filterx/object-null.h"
#include "filterx/object-message-value.h"
#include "scratch-buffers.h"
#include "stats/stats-registry.h"
#include "stats/stats-cluster-single.h"

typedef struct _FilterXSetAttr
{
  FilterXExpr super;
  FilterXExpr *object;
  FilterXObject *attr;
  FilterXExpr *new_value;
} FilterXSetAttr;

static inline FilterXObject *
_setattr(FilterXSetAttr *self, FilterXObject *object, FilterXObject **new_value)
{
  if (object->readonly)
    {
      filterx_eval_push_error("Attribute set failed, object is readonly", &self->super, self->attr);
      return NULL;
    }

  /* TODO: create ref unconditionally after implementing hierarchical CoW for JSON types
   * (or after creating our own dict/list repr) */
  if (!(*new_value)->weak_referenced)
    {
      *new_value = filterx_ref_new(*new_value);
    }

  FilterXObject *cloned = filterx_object_clone(*new_value);
  filterx_object_unref(*new_value);
  *new_value = NULL;

  if (!filterx_object_setattr(object, self->attr, &cloned))
    {
      filterx_eval_push_error("Attribute set failed", &self->super, self->attr);
      filterx_object_unref(cloned);
      return NULL;
    }

  return cloned;
}

static inline FilterXObject *
_suppress_error(void)
{
  msg_debug("FILTERX null coalesce assignment supressing error", filterx_format_last_error());
  filterx_eval_clear_errors();

  return filterx_null_new();
}

static FilterXObject *
_nullv_setattr_eval(FilterXExpr *s)
{
  FilterXSetAttr *self = (FilterXSetAttr *) s;
  FilterXObject *result = NULL;

  FilterXObject *new_value = filterx_expr_eval(self->new_value);
  if (!new_value || filterx_object_is_type(new_value, &FILTERX_TYPE_NAME(null))
      || (filterx_object_is_type(new_value, &FILTERX_TYPE_NAME(message_value))
          && filterx_message_value_get_type(new_value) == LM_VT_NULL))
    {
      if (!new_value)
        return _suppress_error();

      return new_value;
    }

  FilterXObject *object = filterx_expr_eval_typed(self->object);
  if (!object)
    goto exit;

  result = _setattr(self, object, &new_value);

exit:
  filterx_object_unref(new_value);
  filterx_object_unref(object);
  return result;
}

static FilterXObject *
_setattr_eval(FilterXExpr *s)
{
  FilterXSetAttr *self = (FilterXSetAttr *) s;
  FilterXObject *result = NULL;

  FilterXObject *new_value = filterx_expr_eval(self->new_value);
  if (!new_value)
    return NULL;

  FilterXObject *object = filterx_expr_eval_typed(self->object);
  if (!object)
    goto exit;

  result = _setattr(self, object, &new_value);

exit:
  filterx_object_unref(new_value);
  filterx_object_unref(object);
  return result;
}

static FilterXExpr *
_optimize(FilterXExpr *s)
{
  FilterXSetAttr *self = (FilterXSetAttr *) s;

  self->object = filterx_expr_optimize(self->object);
  self->new_value = filterx_expr_optimize(self->new_value);
  return NULL;
}

static gboolean
_init(FilterXExpr *s, GlobalConfig *cfg)
{
  FilterXSetAttr *self = (FilterXSetAttr *) s;

  if (!filterx_expr_init(self->object, cfg))
    return FALSE;

  if (!filterx_expr_init(self->new_value, cfg))
    {
      filterx_expr_deinit(self->object, cfg);
      return FALSE;
    }

  return filterx_expr_init_method(s, cfg);
}

static void
_deinit(FilterXExpr *s, GlobalConfig *cfg)
{
  FilterXSetAttr *self = (FilterXSetAttr *) s;

  filterx_expr_deinit(self->object, cfg);
  filterx_expr_deinit(self->new_value, cfg);
  filterx_expr_deinit_method(s, cfg);
}

static void
_free(FilterXExpr *s)
{
  FilterXSetAttr *self = (FilterXSetAttr *) s;

  filterx_object_unref(self->attr);
  filterx_expr_unref(self->object);
  filterx_expr_unref(self->new_value);
  filterx_expr_free_method(s);
}

FilterXExpr *
filterx_nullv_setattr_new(FilterXExpr *object, FilterXString *attr_name, FilterXExpr *new_value)
{
  FilterXSetAttr *self = g_new0(FilterXSetAttr, 1);

  filterx_expr_init_instance(&self->super, "nullv_setattr");
  self->super.eval = _nullv_setattr_eval;
  self->super.optimize = _optimize;
  self->super.init = _init;
  self->super.deinit = _deinit;
  self->super.free_fn = _free;
  self->object = object;

  self->attr = (FilterXObject *) attr_name;

  self->new_value = new_value;
  self->super.ignore_falsy_result = TRUE;
  /* NOTE: name borrows the string value from the string object */
  self->super.name = filterx_string_get_value_ref(self->attr, NULL);
  return &self->super;
}

/* Takes reference of object and new_value */
FilterXExpr *
filterx_setattr_new(FilterXExpr *object, FilterXString *attr_name, FilterXExpr *new_value)
{
  FilterXSetAttr *self = g_new0(FilterXSetAttr, 1);

  filterx_expr_init_instance(&self->super, "setattr");
  self->super.eval = _setattr_eval;
  self->super.optimize = _optimize;
  self->super.init = _init;
  self->super.deinit = _deinit;
  self->super.free_fn = _free;
  self->object = object;

  self->attr = (FilterXObject *) attr_name;

  self->new_value = new_value;
  self->super.ignore_falsy_result = TRUE;
  return &self->super;
}
