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

#include "iord_map.h"

#define iord_map_node_container_of(node, offset) ((guint8 *) (node) - (intptr_t) (offset))
#define iord_map_node_from_container(container, offset) ((IOrdMapNode *) ((guint8 *) (container) + (intptr_t) (offset)))


void
iord_map_init(IOrdMap *self, GHashFunc hash_func, GEqualFunc key_equal_func,
              guint16 key_container_offset, guint16 value_container_offset)
{
  iord_map_init_full(self, hash_func, key_equal_func, NULL, key_container_offset, NULL, value_container_offset);
}

void
iord_map_init_full(IOrdMap *self, GHashFunc hash_func, GEqualFunc key_equal_func,
                   GDestroyNotify key_destroy_func, guint16 key_container_offset,
                   GDestroyNotify value_destroy_func, guint16 value_container_offset)
{
  self->ht = g_hash_table_new_full(hash_func, key_equal_func, key_destroy_func, value_destroy_func);
  iord_map_node_init(&self->keys);
  iord_map_node_init(&self->values);
  self->key_destroy_func = key_destroy_func;
  self->key_container_offset = key_container_offset;
  self->value_destroy_func = value_destroy_func;
  self->value_container_offset = value_container_offset;
}

void
iord_map_destroy(IOrdMap *self)
{
  g_hash_table_destroy(self->ht);
}

IOrdMap *
iord_map_new(GHashFunc hash_func, GEqualFunc key_equal_func,
             guint16 key_container_offset, guint16 value_container_offset)
{
  return iord_map_new_full(hash_func, key_equal_func, NULL, key_container_offset, NULL, value_container_offset);
}

IOrdMap *
iord_map_new_full(GHashFunc hash_func, GEqualFunc key_equal_func,
                  GDestroyNotify key_destroy_func, guint16 key_container_offset,
                  GDestroyNotify value_destroy_func, guint16 value_container_offset)
{
  IOrdMap *self = g_new0(IOrdMap, 1);

  iord_map_init_full(self, hash_func, key_equal_func, key_destroy_func, key_container_offset,
                     value_destroy_func, value_container_offset);

  return self;
}

void
iord_map_free(IOrdMap *self)
{
  iord_map_destroy(self);
  g_free(self);
}

gboolean
iord_map_contains(IOrdMap *self, gconstpointer key)
{
  return g_hash_table_contains(self->ht, key);
}

gboolean
iord_map_foreach(IOrdMap *self, IOrdMapForeachFunc func, gpointer user_data)
{
  for (struct iv_list_head *key = self->keys.next, *value = self->values.next;
       key != &self->keys;
       key = key->next, value = value->next)
    {
      gpointer key_container = iord_map_node_container_of(key, self->key_container_offset);
      gpointer value_container = iord_map_node_container_of(value, self->value_container_offset);
      if (!func(key_container, value_container, user_data))
        return FALSE;
    }

  return TRUE;
}

gboolean
iord_map_insert(IOrdMap *self, gpointer key, gpointer value)
{
  IOrdMapNode *key_node = iord_map_node_from_container(key, self->key_container_offset);
  g_assert(!key_node->next || iv_list_empty(key_node));

  gpointer orig_key, old_value;
  if (!g_hash_table_lookup_extended(self->ht, key, &orig_key, &old_value))
    {
      iv_list_add_tail(key_node, &self->keys);
      goto finish;
    }

  iv_list_del(iord_map_node_from_container(orig_key, self->key_container_offset));
  iv_list_del(iord_map_node_from_container(old_value, self->value_container_offset));

  /* keeps the original key */
  iv_list_add_tail(iord_map_node_from_container(orig_key, self->key_container_offset), &self->keys);

finish:
  iv_list_add_tail(iord_map_node_from_container(value, self->value_container_offset), &self->values);
  return g_hash_table_insert(self->ht, key, value);
}

gboolean
iord_map_prepend(IOrdMap *self, gpointer key, gpointer value)
{
  IOrdMapNode *key_node = iord_map_node_from_container(key, self->key_container_offset);
  g_assert(!key_node->next || iv_list_empty(key_node));

  gpointer orig_key, old_value;
  if (!g_hash_table_lookup_extended(self->ht, key, &orig_key, &old_value))
    {
      iv_list_add(key_node, &self->keys);
      goto finish;
    }

  iv_list_del(iord_map_node_from_container(orig_key, self->key_container_offset));
  iv_list_del(iord_map_node_from_container(old_value, self->value_container_offset));

  /* keeps the original key */
  iv_list_add(iord_map_node_from_container(orig_key, self->key_container_offset), &self->keys);

finish:
  iv_list_add(iord_map_node_from_container(value, self->value_container_offset), &self->values);
  return g_hash_table_insert(self->ht, key, value);
}

gpointer
iord_map_lookup(IOrdMap *self, gconstpointer key)
{
  return g_hash_table_lookup(self->ht, key);
}

gboolean
iord_map_remove(IOrdMap *self, gconstpointer key)
{
  gpointer key_to_delete, value_to_delete;
  if (!g_hash_table_steal_extended(self->ht, key, &key_to_delete, &value_to_delete))
    return FALSE;

  iv_list_del(iord_map_node_from_container(key_to_delete, self->key_container_offset));
  iv_list_del(iord_map_node_from_container(value_to_delete, self->value_container_offset));

  if (self->key_destroy_func)
    self->key_destroy_func(key_to_delete);

  if (self->value_destroy_func)
    self->value_destroy_func(value_to_delete);

  return TRUE;
}

void
iord_map_clear(IOrdMap *self)
{
  g_hash_table_remove_all(self->ht);
  iord_map_node_init(&self->keys);
  iord_map_node_init(&self->values);
}

gsize
iord_map_size(IOrdMap *self)
{
  return g_hash_table_size(self->ht);
}

IOrdMapNode *
iord_map_get_keys(IOrdMap *self)
{
  return &self->keys;
}

IOrdMapNode *
iord_map_get_values(IOrdMap *self)
{
  return &self->values;
}
