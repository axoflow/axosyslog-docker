/*
 * Copyright (c) 2024 Axoflow
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

#ifndef ADT_IORD_MAP_H
#define ADT_IORD_MAP_H

#include <stddef.h>
#include <iv_list.h>

#include "syslog-ng.h"

/*
 * Intrusive insertion-ordered map
 *
 * This implementation offers average O(1) complexity for insertion, deletion,
 * and lookup operations, while providing O(N) iteration with the preservation
 * of insertion order. However, this efficiency comes at the cost of increased
 * memory usage.
 */

typedef struct _IOrdMap IOrdMap;
typedef struct iv_list_head IOrdMapNode;

typedef gboolean (*IOrdMapForeachFunc)(gpointer key, gpointer value, gpointer user_data);


IOrdMap *iord_map_new(GHashFunc hash_func, GEqualFunc key_equal_func,
                      guint16 key_container_offset, guint16 value_container_offset);
IOrdMap *iord_map_new_full(GHashFunc hash_func, GEqualFunc key_equal_func,
                           GDestroyNotify key_destroy_func, guint16 key_container_offset,
                           GDestroyNotify value_destroy_func, guint16 value_container_offset);
void iord_map_free(IOrdMap *self);

gboolean iord_map_contains(IOrdMap *self, gconstpointer key);

/* insertion/deletion is not allowed */
gboolean iord_map_foreach(IOrdMap *self, IOrdMapForeachFunc func, gpointer user_data);

gboolean iord_map_insert(IOrdMap *self, gpointer key, gpointer value);
gboolean iord_map_prepend(IOrdMap *self, gpointer key, gpointer value);
gpointer iord_map_lookup(IOrdMap *self, gconstpointer key);
gboolean iord_map_remove(IOrdMap *self, gconstpointer key);
void iord_map_clear(IOrdMap *self);
gsize iord_map_size(IOrdMap *self);

IOrdMapNode *iord_map_get_keys(IOrdMap *self);
IOrdMapNode *iord_map_get_values(IOrdMap *self);

#define iord_map_node_init(node) INIT_IV_LIST_HEAD(node)
#define iord_map_node_foreach(head, current, next) iv_list_for_each_safe(current, next, head)
#define iord_map_node_entry(node, type, member) iv_list_entry(node, type, member)

#endif
