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

#ifndef ADT_ILIST
#define ADT_ILIST

#include <stddef.h>
#include <iv_list.h>

/*
 * Intrusive list (just a wrapper around iv_list for easier use)
 */

typedef struct iv_list_head IList;
typedef struct iv_list_head IListNode;

#define ilist_init(self) INIT_IV_LIST_HEAD(self)
#define ilist_push_back(self, node) iv_list_add_tail(node, self)
#define ilist_push_front(self, node) iv_list_add(node, self)
#define ilist_splice_back(self, list) iv_list_splice_tail(list, self)
#define ilist_splice_front(self, list) iv_list_splice(list, self)
#define ilist_remove(node) iv_list_del(node)
#define ilist_is_empty(self) iv_list_empty(self)
#define ilist_foreach(self, current, next) iv_list_for_each_safe(current, next, self)
#define ilist_entry(self, type, member) iv_list_entry(self, type, member)

static inline IList *
ilist_pop_back(IList *self)
{
  IList *e = self->prev;
  iv_list_del(e);
  return e;
}

static inline IList *
ilist_pop_front(IList *self)
{
  IList *e = self->next;
  iv_list_del(e);
  return e;
}

static inline void
_ilist_reverse_node_links(IList *node)
{
  IList *orig_next = node->next;
  node->next = node->prev;
  node->prev = orig_next;
}

static inline void
ilist_reverse(IList *self)
{
  IList *current = self->next;

  while (current != self)
    {
      _ilist_reverse_node_links(current);
      current = current->prev;
    }

  _ilist_reverse_node_links(self);
}

#endif
