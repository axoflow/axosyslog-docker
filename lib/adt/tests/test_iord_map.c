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

#include "adt/iord_map.h"

#include <criterion/criterion.h>

typedef struct _TestKey
{
  const gchar *key;
  IOrdMapNode n;
} TestKey;

typedef struct _TestData
{
  gint a;
  gint b;
  IOrdMapNode n;
  IOrdMapNode n2;
  gint c;
} TestData;

#define assert_value_equals(actual, expected) \
  ({ \
    cr_assert_eq((actual)->a, (expected)->a); \
    cr_assert_eq((actual)->b, (expected)->b); \
    cr_assert_eq((actual)->c, (expected)->c); \
  })

static inline gboolean
assert_foreach_func(gpointer k, gpointer v, gpointer user_data)
{
  TestKey *key = k;
  TestData *value = v;

  gint *expected = user_data;

  gchar expected_key[32];
  g_snprintf(expected_key, sizeof(expected_key), "key%d", *expected);
  cr_assert_str_eq(key->key, expected_key);
  cr_assert_eq(value->a, *expected);

  (*expected)++;

  return TRUE;
}

Test(iord_map, new_map_is_empty)
{
  IOrdMap *map = iord_map_new(g_str_hash, g_str_equal, offsetof(TestKey, n), offsetof(TestData, n));

  cr_assert_not_null(map);
  cr_assert_eq(iord_map_size(map), 0);

  IOrdMapNode *keys = iord_map_get_keys(map);

  IOrdMapNode *current, *next;
  iord_map_node_foreach(keys, current, next)
  {
    cr_assert_fail("empty map should have no keys");
  }

  iord_map_free(map);
}

Test(iord_map, insert_lookup_and_contains)
{
  IOrdMap *map = iord_map_new(g_str_hash, g_str_equal, offsetof(TestKey, n), offsetof(TestData, n));

  TestKey key = { "key" };
  TestData value = { .a = 1, .b = 2, .c = 3 };
  TestData value2 = { .a = 4, .b = 5, .c = 6 };

  cr_assert(iord_map_insert(map, &key, &value));
  g_assert(iord_map_contains(map, &key));
  TestData *actual = iord_map_lookup(map, &key);
  assert_value_equals(actual, &value);

  cr_assert_not(iord_map_insert(map, &key, &value2));
  actual = iord_map_lookup(map, &key);
  assert_value_equals(actual, &value2);

  cr_assert_eq(iord_map_size(map), 1);

  iord_map_free(map);
}

Test(iord_map, remove)
{
  IOrdMap *map = iord_map_new(g_str_hash, g_str_equal, offsetof(TestKey, n), offsetof(TestData, n));

  TestKey key = { "key" };
  TestData value = { .a = 1, .b = 2, .c = 3 };

  cr_assert_not(iord_map_remove(map, &key));

  iord_map_insert(map, &key, &value);
  cr_assert(iord_map_remove(map, &key));

  iord_map_free(map);
}

Test(iord_map, clear)
{
  IOrdMap *map = iord_map_new(g_str_hash, g_str_equal, offsetof(TestKey, n), offsetof(TestData, n));

  TestKey key = { "key" };
  TestKey key2 = { "key2" };
  TestData value = { .a = 1, .b = 2, .c = 3 };
  TestData value2 = { .a = 4, .b = 5, .c = 6 };

  iord_map_insert(map, &key, &value);
  iord_map_insert(map, &key2, &value2);

  iord_map_clear(map);

  cr_assert_eq(iord_map_size(map), 0);
  cr_assert_not(iord_map_contains(map, &key));
  cr_assert_not(iord_map_contains(map, &key2));

  IOrdMapNode *keys = iord_map_get_keys(map);
  IOrdMapNode *current, *next;
  iord_map_node_foreach(keys, current, next)
  {
    cr_assert_fail("map should be empty");
  }

  iord_map_free(map);
}

Test(iord_map, insertion_order_is_preserved)
{
  IOrdMap *map = iord_map_new(g_str_hash, g_str_equal, offsetof(TestKey, n), offsetof(TestData, n));

  TestKey expected_keys[] = {{"key1"}, {"key2"}, {"key3"}, {"key4"}, {"key5"}};
  TestData expected_values[] = {{1}, {2}, {3}, {4}, {5}};

  for (gint i = 0; i < G_N_ELEMENTS(expected_keys); i++)
    {
      iord_map_insert(map, &expected_keys[i], &expected_values[i]);
    }

  IOrdMapNode *current, *next;
  IOrdMapNode *keys = iord_map_get_keys(map);
  gint i = 0;
  iord_map_node_foreach(keys, current, next)
  {
    TestKey *current_key = iord_map_node_entry(current, TestKey, n);
    cr_assert_str_eq(current_key->key, expected_keys[i].key);
    i++;
  }
  cr_assert_eq(i, G_N_ELEMENTS(expected_keys));

  IOrdMapNode *values = iord_map_get_values(map);
  i = 0;
  iord_map_node_foreach(values, current, next)
  {
    TestData *current_value = iord_map_node_entry(current, TestData, n);
    cr_assert_eq(current_value->a, expected_values[i].a);
    i++;
  }
  cr_assert_eq(i, G_N_ELEMENTS(expected_values));

  gint idx = 1;
  iord_map_foreach(map, assert_foreach_func, &idx);
  cr_assert_eq(idx, 6);

  iord_map_free(map);
}

Test(iord_map, reinsert_moves_key_to_end)
{
  IOrdMap *map = iord_map_new(g_str_hash, g_str_equal, offsetof(TestKey, n), offsetof(TestData, n));

  TestKey keys[] = {{"key1"}, {"key2"}, {"key3"}, {"key4"}, {"key5"}};
  TestData values[] = {{1}, {2}, {3}, {4}, {5}};
  TestData new_value = {9};

  for (gint i = 0; i < G_N_ELEMENTS(keys); i++)
    {
      iord_map_insert(map, &keys[i], &values[i]);
    }

  iord_map_insert(map, &keys[0], &new_value);

  IOrdMapNode *actual_keys = iord_map_get_keys(map);

  /* first element*/
  cr_assert_str_eq(iord_map_node_entry(actual_keys->next, TestKey, n)->key, "key2");

  /* last element */
  cr_assert_str_eq(iord_map_node_entry(actual_keys->prev, TestKey, n)->key, "key1");

  iord_map_free(map);
}

Test(iord_map, prepend)
{
  IOrdMap *map = iord_map_new(g_str_hash, g_str_equal, offsetof(TestKey, n), offsetof(TestData, n));

  TestKey keys[] = {{"key1"}, {"key2"}, {"key3"}, {"key4"}, {"key5"}};
  TestData expected_values[] = {{1}, {2}, {3}, {4}, {5}};

  for (gint i = 0; i < G_N_ELEMENTS(keys); i++)
    {
      iord_map_prepend(map, &keys[i], &expected_values[i]);
    }

  IOrdMapNode *values = iord_map_get_values(map);
  gint i = G_N_ELEMENTS(keys);
  IOrdMapNode *current, *next;
  iord_map_node_foreach(values, current, next)
  {
    TestData *current_value = iord_map_node_entry(current, TestData, n);
    cr_assert_eq(current_value->a, expected_values[i-1].a);
    i--;
  }

  cr_assert_eq(i, 0);

  iord_map_free(map);
}

gint destruct_key_called = 0;
static inline void
destruct_key(gpointer data)
{
  destruct_key_called++;
}

gint destruct_value_called = 0;
static inline void
destruct_value(gpointer data)
{
  destruct_value_called++;
}

Test(iord_map, destructors_are_called)
{
  IOrdMap *map = iord_map_new_full(g_str_hash, g_str_equal, destruct_key, offsetof(TestKey, n),
                                   destruct_value, offsetof(TestData, n));

  TestKey key = { "key" };
  TestKey key2 = { "key2" };
  TestData value = { .a = 1, .b = 2, .c = 3 };
  TestData value2 = { .a = 4, .b = 5, .c = 6 };

  TestKey same_key = { "key" };
  TestData new_value = { .a = 4, .b = 5, .c = 6 };

  iord_map_insert(map, &key, &value);
  iord_map_insert(map, &key2, &value2);

  iord_map_insert(map, &same_key, &new_value);

  cr_assert_eq(destruct_key_called, 1);
  cr_assert_eq(destruct_value_called, 1);

  iord_map_clear(map);

  cr_assert_eq(destruct_key_called, 3);
  cr_assert_eq(destruct_value_called, 3);

  iord_map_free(map);
}

Test(iord_map, multi_map_node)
{
  IOrdMap *map = iord_map_new(g_str_hash, g_str_equal, offsetof(TestKey, n), offsetof(TestData, n));
  IOrdMap *map2 = iord_map_new(g_str_hash, g_str_equal, offsetof(TestKey, n), offsetof(TestData, n2));

  TestKey key = {"key1"};
  TestKey key2 = {"key2"};
  TestKey key3 = {"key3"};
  TestData value = {0};
  TestData multi_node_data = { .a = 1, .b = 2, .c = 3 };

  iord_map_insert(map, &key, &multi_node_data);
  iord_map_insert(map, &key2, &value);
  iord_map_insert(map2, &key3, &multi_node_data);

  TestData expected_values[] = {multi_node_data, value};

  IOrdMapNode *values = iord_map_get_values(map);
  IOrdMapNode *current, *next;
  gint i = 0;
  iord_map_node_foreach(values, current, next)
  {
    TestData *current_value = iord_map_node_entry(current, TestData, n);
    cr_assert_eq(current_value->a, expected_values[i].a);
    i++;
  }
  cr_assert_eq(i, G_N_ELEMENTS(expected_values));


  values = iord_map_get_values(map2);
  i = 0;
  iord_map_node_foreach(values, current, next)
  {
    cr_assert_eq(i, 0);

    TestData *current_value = iord_map_node_entry(current, TestData, n2);
    cr_assert_eq(current_value->a, 1);
    cr_assert_eq(current_value->b, 2);
    cr_assert_eq(current_value->c, 3);
    i++;
  }

  iord_map_free(map2);
  iord_map_free(map);
}
