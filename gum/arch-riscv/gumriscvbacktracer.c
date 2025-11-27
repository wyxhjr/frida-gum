/*
 * Copyright (C) 2013-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2021 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

 #include "gumarmbacktracer.h"

 #include "guminterceptor.h"
 #include "gummemorymap.h"
 
 struct _GumRiscvBacktracer
 {
   GObject parent;
 
   GumMemoryMap * code;
   GumMemoryMap * writable;
 };
 
 static void gum_riscv_backtracer_iface_init (gpointer g_iface,
     gpointer iface_data);
 static void gum_riscv_backtracer_dispose (GObject * object);
 static void gum_arm_backtracer_generate (GumBacktracer * backtracer,
     const GumCpuContext * cpu_context, GumReturnAddressArray * return_addresses,
     guint limit);
 
 G_DEFINE_TYPE_EXTENDED (GumRiscvBacktracer,
                         gum_riscv_backtracer,
                         G_TYPE_OBJECT,
                         0,
                         G_IMPLEMENT_INTERFACE (GUM_TYPE_BACKTRACER,
                                                gum_riscv_backtracer_iface_init))

static void
gum_riscv_backtracer_class_init (GumRiscvBacktracerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_riscv_backtracer_dispose;
}

static void
gum_riscv_backtracer_iface_init (gpointer g_iface,
                               gpointer iface_data)
{
  GumBacktracerInterface * iface = g_iface;

  iface->generate = gum_riscv_backtracer_generate;
}

static void
gum_riscv_backtracer_init (GumRiscvBacktracer * self)
{
  self->code = gum_memory_map_new (GUM_PAGE_EXECUTE);
  self->writable = gum_memory_map_new (GUM_PAGE_WRITE);
}

static void
gum_riscv_backtracer_dispose (GObject * object)
{
  GumRiscvBacktracer * self = GUM_RISCV_BACKTRACER (object);

  g_clear_object (&self->code);
  g_clear_object (&self->writable);

  G_OBJECT_CLASS (gum_riscv_backtracer_parent_class)->dispose (object);
}