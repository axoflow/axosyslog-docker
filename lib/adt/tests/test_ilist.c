/*
 * Copyright (c) 2024 Axoflow
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

#include "adt/ilist.h"
#include <criterion/criterion.h>

typedef struct _TestNode
{
  int value;
  IListNode node;
} TestData;

Test(ilist, init)
{
  IList list;
  ilist_init(&list);
  cr_assert(ilist_is_empty(&list));
}

Test(ilist, pop_back)
{
  IList list;
  ilist_init(&list);

  TestData e1 = { .value = 1 };
  TestData e2 = { .value = 2 };

  ilist_push_back(&list, &e1.node);
  ilist_push_back(&list, &e2.node);

  IList *popped = ilist_pop_back(&list);
  cr_assert_eq(ilist_entry(popped, TestData, node)->value, 2);
  cr_assert_eq(ilist_entry(list.prev, TestData, node)->value, 1);
}

Test(ilist, pop_front)
{
  IList list;
  ilist_init(&list);

  TestData e1 = { .value = 1 };
  TestData e2 = { .value = 2 };

  ilist_push_back(&list, &e1.node);
  ilist_push_back(&list, &e2.node);

  IList *popped = ilist_pop_front(&list);
  cr_assert_eq(ilist_entry(popped, TestData, node)->value, 1);
  cr_assert_eq(ilist_entry(list.next, TestData, node)->value, 2);
}

Test(ilist, reverse)
{
  IList list;
  ilist_init(&list);

  TestData e1 = { .value = 1 };
  TestData e2 = { .value = 2 };
  TestData e3 = { .value = 3 };

  ilist_push_back(&list, &e1.node);
  ilist_push_back(&list, &e2.node);
  ilist_push_back(&list, &e3.node);

  ilist_reverse(&list);

  cr_assert_eq(ilist_entry(list.next, TestData, node)->value, 3);
  cr_assert_eq(ilist_entry(list.next->next, TestData, node)->value, 2);
  cr_assert_eq(ilist_entry(list.prev, TestData, node)->value, 1);
}

Test(ilist, splice_back)
{
  IList list1, list2;
  ilist_init(&list1);
  ilist_init(&list2);

  TestData e1 = { .value = 1 };
  TestData e2 = { .value = 2 };
  TestData e3 = { .value = 3 };

  ilist_push_back(&list1, &e1.node);
  ilist_push_back(&list2, &e2.node);
  ilist_push_back(&list2, &e3.node);

  ilist_splice_back(&list1, &list2);

  cr_assert_eq(ilist_entry(list1.next, TestData, node)->value, 1);
  cr_assert_eq(ilist_entry(list1.next->next, TestData, node)->value, 2);
  cr_assert_eq(ilist_entry(list1.prev, TestData, node)->value, 3);
}
