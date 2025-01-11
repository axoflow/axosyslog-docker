/*
 * Copyright (c) 2024 Axoflow
 * Copyright (c) 2024 Balázs Scheidler <balazs.scheidler@axoflow.com>
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

#include "perf.h"
#include "console.h"
#include <sys/mman.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

static gboolean perf_enabled;

typedef struct _PerfTrampolineArea
{
  guint8 *area;
  gsize size;
  gsize code_size;
  struct
  {
    gint num;
    gint alloc;
  } trampolines;
} PerfTrampolineArea;

extern void _perf_trampoline_func_start(void);
extern void _perf_trampoline_func_end(void);

#define PAGE_SIZE 4096
#define PAGE_MAX_INDEX ((PAGE_SIZE-1))

#define SIZE_TO_PAGES(s) (((s + PAGE_MAX_INDEX) & ~PAGE_MAX_INDEX) / PAGE_SIZE)
#define PAGE_TO_SIZE(p)  (p * PAGE_SIZE)

#define ROUND_TO_PAGE_BOUNDARY(p) ((gpointer) ((((uintptr_t) (p)) / PAGE_SIZE) * PAGE_SIZE))

#define MAX_TRAMPOLINES 16384

static gboolean
_allocate_trampoline_area(PerfTrampolineArea *self)
{
  guint8 *start = (guint8 *) &_perf_trampoline_func_start;
  guint8 *end = (guint8 *) &_perf_trampoline_func_end;

  self->code_size = end - start;
  gsize code_pages = SIZE_TO_PAGES(self->code_size * MAX_TRAMPOLINES);

  self->size = PAGE_TO_SIZE(code_pages);
  self->area = mmap(NULL,
                    self->size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                    -1, 0);
  if (self->area == MAP_FAILED)
    return FALSE;

  self->trampolines.num = self->size / self->code_size;
  self->trampolines.alloc = 0;

  for (gint i = 0; i < self->trampolines.num; i++)
    {
      memcpy(self->area + i * self->code_size, start, self->code_size * sizeof(gchar));
    }
  return TRUE;
}

static gpointer
_generate_trampoline(PerfTrampolineArea *self, gpointer target_address)
{
  if (self->trampolines.alloc >= self->trampolines.num)
    return NULL;


  guint8 *trampoline_start = self->area + (self->trampolines.alloc++) * self->code_size;
  guint8 *trampoline_end = trampoline_start + self->code_size;

  guint8 *trampoline_page_start = ROUND_TO_PAGE_BOUNDARY(trampoline_start);
  guint8 *trampoline_page_end = ROUND_TO_PAGE_BOUNDARY(trampoline_end);
  gsize trampoline_page_len = (trampoline_page_end - trampoline_page_start) + PAGE_SIZE;

  gint res = mprotect(trampoline_page_start, trampoline_page_len, PROT_READ | PROT_WRITE);
  if (res < 0)
    return NULL;


  uintptr_t *value_p = (uintptr_t *) (trampoline_end - sizeof(target_address));
  *value_p = (uintptr_t) target_address;

  __builtin___clear_cache((gpointer) trampoline_start, (gpointer) trampoline_end);

  res = mprotect(trampoline_page_start, trampoline_page_len, PROT_READ | PROT_EXEC);
  if (res < 0)
    return NULL;
  return (gpointer) trampoline_start;
}

static gboolean
_is_trampoline_address(PerfTrampolineArea *self, guint8 *address)
{
  return self->area <= address && self->area + self->size > address;
}

static gboolean
_save_symbol(gpointer address, gsize size, const gchar *symbol_name)
{
  gchar filename[64];
  static FILE *mapfile = NULL;

  if (!mapfile)
    {
      g_snprintf(filename, sizeof(filename), "/tmp/perf-%d.map", (int) getpid());
      mapfile = fopen(filename, "a");
      if (!mapfile)
        return FALSE;
    }
  fprintf(mapfile, "%0lx %ld %p:%s\n", (uintptr_t) address, size, address, symbol_name);
  fflush(mapfile);
  return TRUE;
}

static PerfTrampolineArea trampolines;

static gchar *
_sanitize_symbol(const gchar *symbol_name)
{
  GString *translated_text = g_string_sized_new(256);

  for (gsize i = 0; i < symbol_name[i]; i++)
    {
      gchar ch = symbol_name[i];
      switch (ch)
        {
        case ' ':
        case '\t':
          g_string_append_unichar(translated_text, 0xa0);
          break;
        case '(':
          g_string_append_unichar(translated_text, 0x27EE);
          break;
        case ')':
          g_string_append_unichar(translated_text, 0x27EF);
          break;
        case '"':
          g_string_append_unichar(translated_text, 0x201D);
          break;
        default:
          g_string_append_c(translated_text, ch);
          break;
        }
    }
  return g_string_free(translated_text, FALSE);
}

gpointer
perf_generate_trampoline(gpointer target_address, const gchar *symbol_name)
{
  if (_is_trampoline_address(&trampolines, target_address))
    return target_address;

  gpointer t = _generate_trampoline(&trampolines, target_address);

  if (!t)
    {
      console_printf("WARNING: out of free trampoline slots, unable to instrument symbol '%s', "
                     "increase MAX_TRAMPOLINES", symbol_name);
      return target_address;
    }

  gchar *sanitized_symbol = _sanitize_symbol(symbol_name);
  _save_symbol(t, trampolines.code_size, sanitized_symbol);
  g_free(sanitized_symbol);
  return t;
}

gboolean
perf_is_enabled(void)
{
  return perf_enabled;
}

gboolean
perf_autodetect(void)
{
  /* perf sets this environment variable, so with that set, we can assume we
   * are running under perf record */

  if (getenv("PERF_BUILDID_DIR") != NULL)
    return TRUE;
  return FALSE;
}

gboolean
perf_enable(void)
{
  if (!_allocate_trampoline_area(&trampolines))
    return FALSE;

  console_printf("perf support enabled");
  perf_enabled = TRUE;
  return TRUE;
}
