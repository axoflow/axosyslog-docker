/*
 * Copyright (c) 2024 László Várady
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

#ifndef FILTERX_REF_H
#define FILTERX_REF_H

#include "filterx/filterx-object.h"

/*
 * References are currently not part of the FilterX language (hopefully, they
 * never will be). FilterXRef is used to reference the same FilterXObject from
 * multiple locations (variables, other types of assignments) in order to
 * implement copy-on-write. For this reason, FilterXRef pretends to be a
 * FilterXObject, but it's not a real FilterX type.
 *
 * FilterXRef is a final class, do not inherit from it.
 *
 * The functionality behind FilterXRef and the locations where they are used are
 * open for extension.
 */

FILTERX_DECLARE_TYPE(ref);

typedef struct _FilterXRef
{
  FilterXObject super;
  FilterXObject *value;
} FilterXRef;


/* Call them only where downcasting to a specific type is needed, the returned object should only be used locally. */
FilterXObject *filterx_ref_unwrap_ro(FilterXObject *s);
FilterXObject *filterx_ref_unwrap_rw(FilterXObject *s);

static inline gboolean
_filterx_type_is_referenceable(FilterXType *t)
{
  return t->is_mutable && t != &FILTERX_TYPE_NAME(ref);
}

FilterXObject *_filterx_ref_new(FilterXObject *value);

static inline FilterXObject *
filterx_ref_new(FilterXObject *value)
{
  if (!value || value->readonly || !_filterx_type_is_referenceable(value->type))
    return value;
  return _filterx_ref_new(value);
}

#endif
