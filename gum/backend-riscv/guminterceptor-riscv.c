/*
 * Copyright (C) 2010-2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2025 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminterceptor-priv.h"

#include "gumriscvreader.h"
#include "gumriscvrelocator.h"
#include "gumriscvwriter.h"
#include "gumlibc.h"
#include "gummemory.h"

#include <string.h>
#include <unistd.h>

#define GUM_FRAME_OFFSET_CPU_CONTEXT 0
#define GUM_FRAME_OFFSET_NEXT_HOP \
    (GUM_FRAME_OFFSET_CPU_CONTEXT + sizeof (GumCpuContext))

#define GUM_FCDATA(context) \
    ((GumRiscvFunctionContextData *) (context)->backend_data.storage)

/* RISC-V instructions are 32-bit (4 bytes) */
#define GUM_HOOK_SIZE 8

/* RISC-V JAL instruction can jump ±1MB (21-bit signed offset) */
#define GUM_RISCV_JAL_MAX_DISTANCE (1 << 20)

typedef struct _GumRiscvFunctionContextData GumRiscvFunctionContextData;

struct _GumInterceptorBackend
{
  GumCodeAllocator * allocator;

  GumRiscvWriter writer;
  GumRiscvRelocator relocator;

  GumCodeSlice * enter_thunk;
  GumCodeSlice * leave_thunk;
};

struct _GumRiscvFunctionContextData
{
  guint redirect_code_size;
  riscv_reg scratch_reg;
};

static void gum_interceptor_backend_create_thunks (
    GumInterceptorBackend * self);
static void gum_interceptor_backend_destroy_thunks (
    GumInterceptorBackend * self);

static void gum_emit_enter_thunk (GumRiscvWriter * cw);
static void gum_emit_leave_thunk (GumRiscvWriter * cw);

static void gum_emit_prolog (GumRiscvWriter * cw);
static void gum_emit_epilog (GumRiscvWriter * cw);

static gboolean gum_interceptor_backend_prepare_trampoline (
    GumInterceptorBackend * self,
    GumFunctionContext * ctx,
    gboolean * need_deflector);

 GumInterceptorBackend *
 _gum_interceptor_backend_create (GRecMutex * mutex,
                                  GumCodeAllocator * allocator)
 {
   GumInterceptorBackend * backend;
 
   backend = g_slice_new (GumInterceptorBackend);
   backend->allocator = allocator;
 
   gum_riscv_writer_init (&backend->writer, NULL);
   gum_riscv_relocator_init (&backend->relocator, NULL, &backend->writer);
 
   gum_interceptor_backend_create_thunks (backend);
 
  return backend;
}

gboolean
_gum_interceptor_backend_claim_grafted_trampoline (GumInterceptorBackend * self,
                                                   GumFunctionContext * ctx)
{
  return FALSE;
}

static gboolean
gum_interceptor_backend_prepare_trampoline (GumInterceptorBackend * self,
                                            GumFunctionContext * ctx,
                                            gboolean * need_deflector)
{
  GumRiscvFunctionContextData * data = GUM_FCDATA (ctx);
  gpointer function_address = ctx->function_address;
  guint redirect_limit;

  *need_deflector = FALSE;

  if (gum_riscv_relocator_can_relocate (function_address, GUM_HOOK_SIZE,
      GUM_SCENARIO_ONLINE, &redirect_limit, &data->scratch_reg))
  {
    data->redirect_code_size = GUM_HOOK_SIZE;

    ctx->trampoline_slice = gum_code_allocator_alloc_slice (self->allocator);
  }
  else
  {
    GumAddressSpec spec;
    gsize alignment;

    if (redirect_limit >= 4)
    {
      data->redirect_code_size = 4;

      spec.near_address = function_address;
      spec.max_distance = GUM_RISCV_JAL_MAX_DISTANCE;
      alignment = 0;
    }
    else
    {
      return FALSE;
    }

    ctx->trampoline_slice = gum_code_allocator_try_alloc_slice_near (
        self->allocator, &spec, alignment);
    if (ctx->trampoline_slice == NULL)
    {
      ctx->trampoline_slice = gum_code_allocator_alloc_slice (self->allocator);
      *need_deflector = TRUE;
    }
  }

  if (data->scratch_reg == RISCV_REG_INVALID)
    return FALSE;

  return TRUE;
}

gboolean
_gum_interceptor_backend_create_trampoline (GumInterceptorBackend * self,
                                            GumFunctionContext * ctx)
{
  GumRiscvWriter * cw = &self->writer;
  GumRiscvRelocator * rl = &self->relocator;
  gpointer function_address = ctx->function_address;
  GumRiscvFunctionContextData * data = GUM_FCDATA (ctx);
  gboolean need_deflector;
  guint reloc_bytes;

  if (!gum_interceptor_backend_prepare_trampoline (self, ctx, &need_deflector))
    return FALSE;

  gum_riscv_writer_reset (cw, ctx->trampoline_slice->data);
  cw->pc = GUM_ADDRESS (ctx->trampoline_slice->pc);

  ctx->on_enter_trampoline =
      ctx->trampoline_slice->pc + gum_riscv_writer_offset (cw);

  if (need_deflector)
  {
    /* TODO: implement deflector behavior */
    g_assert_not_reached ();
  }

  /* Load function context into t0 (x5) */
  gum_riscv_writer_put_la_reg_address (cw, RISCV_REG_T0, GUM_ADDRESS (ctx));
  /* Load enter_thunk address into t1 */
  gum_riscv_writer_put_la_reg_address (cw, RISCV_REG_T1,
      GUM_ADDRESS (self->enter_thunk->pc));
  /* Jump to enter_thunk */
  gum_riscv_writer_put_jalr_reg (cw, RISCV_REG_ZERO, RISCV_REG_T1, 0);

  ctx->on_leave_trampoline =
      ctx->trampoline_slice->pc + gum_riscv_writer_offset (cw);

  /* Load function context into t0 (x5) */
  gum_riscv_writer_put_la_reg_address (cw, RISCV_REG_T0, GUM_ADDRESS (ctx));
  /* Load leave_thunk address into t1 */
  gum_riscv_writer_put_la_reg_address (cw, RISCV_REG_T1,
      GUM_ADDRESS (self->leave_thunk->pc));
  /* Jump to leave_thunk */
  gum_riscv_writer_put_jalr_reg (cw, RISCV_REG_ZERO, RISCV_REG_T1, 0);

  gum_riscv_writer_flush (cw);
  g_assert (gum_riscv_writer_offset (cw) <= ctx->trampoline_slice->size);

  ctx->on_invoke_trampoline =
      ctx->trampoline_slice->pc + gum_riscv_writer_offset (cw);

  /* Set up function address for the relocated code */
  /* Note: RISC-V doesn't have T9 like MIPS, use T2 as scratch register */
  gum_riscv_writer_put_la_reg_address (cw, RISCV_REG_T2,
      GUM_ADDRESS (function_address));

  gum_riscv_relocator_reset (rl, function_address, cw);

  do
  {
    reloc_bytes = gum_riscv_relocator_read_one (rl, NULL);
    g_assert (reloc_bytes != 0);
  }
  while (reloc_bytes < data->redirect_code_size);

  gum_riscv_relocator_write_all (rl);

  if (!gum_riscv_relocator_eoi (rl))
  {
    GumAddress resume_at;

    resume_at = GUM_ADDRESS (function_address) + reloc_bytes;
    gum_riscv_writer_put_la_reg_address (cw, data->scratch_reg, resume_at);
    gum_riscv_writer_put_jalr_reg (cw, RISCV_REG_ZERO, data->scratch_reg, 0);
  }

  gum_riscv_writer_flush (cw);
  g_assert (gum_riscv_writer_offset (cw) <= ctx->trampoline_slice->size);

  ctx->overwritten_prologue_len = reloc_bytes;
  gum_memcpy (ctx->overwritten_prologue, function_address, reloc_bytes);

  return TRUE;
}

void
_gum_interceptor_backend_destroy_trampoline (GumInterceptorBackend * self,
                                             GumFunctionContext * ctx)
{
  gum_code_slice_unref (ctx->trampoline_slice);
  gum_code_deflector_unref (ctx->trampoline_deflector);
  ctx->trampoline_slice = NULL;
  ctx->trampoline_deflector = NULL;
}

void
_gum_interceptor_backend_activate_trampoline (GumInterceptorBackend * self,
                                              GumFunctionContext * ctx,
                                              gpointer prologue)
{
  GumRiscvWriter * cw = &self->writer;
  GumRiscvFunctionContextData * data = GUM_FCDATA (ctx);
  GumAddress on_enter = GUM_ADDRESS (ctx->on_enter_trampoline);

  gum_riscv_writer_reset (cw, prologue);
  cw->pc = GUM_ADDRESS (ctx->function_address);

  if (ctx->trampoline_deflector != NULL)
  {
    /* TODO: implement branch to deflector */
    g_assert_not_reached ();
  }
  else
  {
    switch (data->redirect_code_size)
    {
      case 4:
        /* Use JAL instruction for 4-byte redirect */
        /* TODO: implement gum_riscv_writer_put_jal_imm if needed */
        /* For now, use load + jalr for all cases */
        gum_riscv_writer_put_la_reg_address (cw, RISCV_REG_T1, on_enter);
        gum_riscv_writer_put_jalr_reg (cw, RISCV_REG_ZERO, RISCV_REG_T1, 0);
        break;
      case GUM_HOOK_SIZE:
        /* Load address and jump for 8-byte redirect */
        gum_riscv_writer_put_la_reg_address (cw, RISCV_REG_T1, on_enter);
        gum_riscv_writer_put_jalr_reg (cw, RISCV_REG_ZERO, RISCV_REG_T1, 0);
        break;
      default:
        g_assert_not_reached ();
    }
  }

  gum_riscv_writer_flush (cw);
  g_assert (gum_riscv_writer_offset (cw) <= data->redirect_code_size);
}

void
_gum_interceptor_backend_deactivate_trampoline (GumInterceptorBackend * self,
                                                GumFunctionContext * ctx,
                                                gpointer prologue)
{
  gum_memcpy (prologue, ctx->overwritten_prologue,
      ctx->overwritten_prologue_len);
}

 gpointer
 _gum_interceptor_backend_get_function_address (GumFunctionContext * ctx)
 {
   return ctx->function_address;
 }
 
 gpointer
 _gum_interceptor_backend_resolve_redirect (GumInterceptorBackend * self,
                                            gpointer address)
 {
   /* TODO: implement resolve redirect */
   return NULL;
 }
 
 gsize
 _gum_interceptor_backend_detect_hook_size (gconstpointer code,
                                            csh capstone,
                                            cs_insn * insn)
 {
   /* TODO: implement hook size detection */
   return 0;
 }

 void
_gum_interceptor_backend_destroy (GumInterceptorBackend * backend)
{
  gum_interceptor_backend_destroy_thunks (backend);

  gum_riscv_relocator_clear (&backend->relocator);
  gum_riscv_writer_clear (&backend->writer);

  g_slice_free (GumInterceptorBackend, backend);
}

static void
gum_interceptor_backend_create_thunks (GumInterceptorBackend * self)
{
  GumRiscvWriter * cw = &self->writer;

  self->enter_thunk = gum_code_allocator_alloc_slice (self->allocator);
  gum_riscv_writer_reset (cw, self->enter_thunk->data);
  cw->pc = GUM_ADDRESS (self->enter_thunk->pc);
  gum_emit_enter_thunk (cw);
  gum_riscv_writer_flush (cw);
  g_assert (gum_riscv_writer_offset (cw) <= self->enter_thunk->size);

  self->leave_thunk = gum_code_allocator_alloc_slice (self->allocator);
  gum_riscv_writer_reset (cw, self->leave_thunk->data);
  cw->pc = GUM_ADDRESS (self->leave_thunk->pc);
  gum_emit_leave_thunk (cw);
  gum_riscv_writer_flush (cw);
  g_assert (gum_riscv_writer_offset (cw) <= self->leave_thunk->size);
}

static void
gum_interceptor_backend_destroy_thunks (GumInterceptorBackend * self)
{
  gum_code_slice_unref (self->leave_thunk);
  gum_code_slice_unref (self->enter_thunk);
}

static void
gum_emit_enter_thunk (GumRiscvWriter * cw)
{
  gum_emit_prolog (cw);

  /* Prepare arguments for _gum_function_context_begin_invocation:
   * a0 = function_ctx (passed from trampoline)
   * a1 = cpu_context pointer
   * a2 = return_address pointer
   * a3 = next_hop pointer
   */
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_A1, RISCV_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_A2, RISCV_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT + G_STRUCT_OFFSET (GumCpuContext, ra));
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_A3, RISCV_REG_SP,
      GUM_FRAME_OFFSET_NEXT_HOP);

  /* Use t0 (x5) as scratch register for function_ctx */
  gum_riscv_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (_gum_function_context_begin_invocation), 4,
      GUM_ARG_REGISTER, RISCV_REG_T0,
      GUM_ARG_REGISTER, RISCV_REG_A1,  /* cpu_context */
      GUM_ARG_REGISTER, RISCV_REG_A2,  /* return_address */
      GUM_ARG_REGISTER, RISCV_REG_A3); /* next_hop */

  gum_emit_epilog (cw);
}

static void
gum_emit_leave_thunk (GumRiscvWriter * cw)
{
  gum_emit_prolog (cw);

  /* Prepare arguments for _gum_function_context_end_invocation:
   * a0 = function_ctx (passed from trampoline)
   * a1 = cpu_context pointer
   * a2 = next_hop pointer
   */
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_A1, RISCV_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_A2, RISCV_REG_SP,
      GUM_FRAME_OFFSET_NEXT_HOP);

  /* Use t0 (x5) as scratch register for function_ctx */
  gum_riscv_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (_gum_function_context_end_invocation), 3,
      GUM_ARG_REGISTER, RISCV_REG_T0,
      GUM_ARG_REGISTER, RISCV_REG_A1,  /* cpu_context */
      GUM_ARG_REGISTER, RISCV_REG_A2); /* next_hop */

  gum_emit_epilog (cw);
}

static void
gum_emit_prolog (GumRiscvWriter * cw)
{
  /*
   * Set up our stack frame:
   *
   * [next_hop]
   * [cpu_context]
   *
   * RISC-V calling convention:
   * - Save all callee-saved registers: s0-s11 (x8-x9, x18-x27)
   * - Save all argument registers: a0-a7 (x10-x17)
   * - Save temporary registers: t0-t6 (x5-x7, x28-x31)
   * - Save ra (x1), sp (x2), gp (x3), tp (x4)
   */

  /* Reserve space for next_hop */
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gpointer)));

  /* Save callee-saved registers (s0-s11) */
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_riscv_writer_put_sw_reg_reg_offset (cw, RISCV_REG_S11, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_riscv_writer_put_sw_reg_reg_offset (cw, RISCV_REG_S10, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_riscv_writer_put_sw_reg_reg_offset (cw, RISCV_REG_S9, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_riscv_writer_put_sw_reg_reg_offset (cw, RISCV_REG_S8, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_riscv_writer_put_sw_reg_reg_offset (cw, RISCV_REG_S7, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_riscv_writer_put_sw_reg_reg_offset (cw, RISCV_REG_S6, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_riscv_writer_put_sw_reg_reg_offset (cw, RISCV_REG_S5, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_riscv_writer_put_sw_reg_reg_offset (cw, RISCV_REG_S4, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_riscv_writer_put_sw_reg_reg_offset (cw, RISCV_REG_S3, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_riscv_writer_put_sw_reg_reg_offset (cw, RISCV_REG_S2, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_riscv_writer_put_sw_reg_reg_offset (cw, RISCV_REG_S1, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_riscv_writer_put_sw_reg_reg_offset (cw, RISCV_REG_S0, RISCV_REG_SP, 0);

  /* Save temporary registers (t0-t6) */
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_riscv_writer_put_sw_reg_reg_offset (cw, RISCV_REG_T6, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_riscv_writer_put_sw_reg_reg_offset (cw, RISCV_REG_T5, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_riscv_writer_put_sw_reg_reg_offset (cw, RISCV_REG_T4, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_riscv_writer_put_sw_reg_reg_offset (cw, RISCV_REG_T3, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_riscv_writer_put_sw_reg_reg_offset (cw, RISCV_REG_T2, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_riscv_writer_put_sw_reg_reg_offset (cw, RISCV_REG_T1, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_riscv_writer_put_sw_reg_reg_offset (cw, RISCV_REG_T0, RISCV_REG_SP, 0);

  /* Save argument registers (a0-a7) */
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_riscv_writer_put_sw_reg_reg_offset (cw, RISCV_REG_A7, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_riscv_writer_put_sw_reg_reg_offset (cw, RISCV_REG_A6, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_riscv_writer_put_sw_reg_reg_offset (cw, RISCV_REG_A5, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_riscv_writer_put_sw_reg_reg_offset (cw, RISCV_REG_A4, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_riscv_writer_put_sw_reg_reg_offset (cw, RISCV_REG_A3, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_riscv_writer_put_sw_reg_reg_offset (cw, RISCV_REG_A2, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_riscv_writer_put_sw_reg_reg_offset (cw, RISCV_REG_A1, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_riscv_writer_put_sw_reg_reg_offset (cw, RISCV_REG_A0, RISCV_REG_SP, 0);

  /* Save special registers: ra, sp, gp, tp */
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_riscv_writer_put_sw_reg_reg_offset (cw, RISCV_REG_RA, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_riscv_writer_put_sw_reg_reg_offset (cw, RISCV_REG_GP, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_riscv_writer_put_sw_reg_reg_offset (cw, RISCV_REG_TP, RISCV_REG_SP, 0);

  /*
   * Calculate and save original SP (before we stored all the context above)
   * This is needed for the GumCpuContext structure
   */
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_T0, RISCV_REG_SP,
      sizeof (GumCpuContext) + sizeof (gpointer));
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_riscv_writer_put_sw_reg_reg_offset (cw, RISCV_REG_T0, RISCV_REG_SP, 0);

  /* Dummy PC placeholder */
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) sizeof (gsize)));
  gum_riscv_writer_put_sw_reg_reg_offset (cw, RISCV_REG_ZERO, RISCV_REG_SP, 0);
}

static void
gum_emit_epilog (GumRiscvWriter * cw)
{
  /* Restore PC placeholder */
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_T0, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));

  /* Restore SP */
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_T0, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));

  /* Restore special registers: tp, gp, ra */
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_TP, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_GP, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_RA, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));

  /* Restore argument registers (a0-a7) */
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_A0, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_A1, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_A2, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_A3, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_A4, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_A5, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_A6, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_A7, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));

  /* Restore temporary registers (t0-t6) */
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_T0, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_T1, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_T2, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_T3, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_T4, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_T5, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_T6, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));

  /* Restore callee-saved registers (s0-s11) */
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_S0, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_S1, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_S2, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_S3, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_S4, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_S5, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_S6, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_S7, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_S8, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_S9, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_S10, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_S11, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gsize));

  /*
   * Pop and jump to the next_hop.
   * Load next_hop into t0 and jump to it
   */
  gum_riscv_writer_put_lw_reg_reg_offset (cw, RISCV_REG_T0, RISCV_REG_SP, 0);
  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      sizeof (gpointer));
  gum_riscv_writer_put_jalr_reg (cw, RISCV_REG_ZERO, RISCV_REG_T0, 0);
}
