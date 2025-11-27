/*
 * Copyright (C) 2014-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2025 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumriscvrelocator.h"

#include "gummemory.h"

#if GLIB_SIZEOF_VOID_P == 4
# define GUM_DEFAULT_RISCV_MODE CS_MODE_RISCV32
#else
# define GUM_DEFAULT_RISCV_MODE CS_MODE_RISCV64
#endif
#define GUM_MAX_INPUT_INSN_COUNT (100)

typedef struct _GumCodeGenCtx GumCodeGenCtx;

struct _GumCodeGenCtx
{
  const cs_insn * insn;
  cs_riscv * detail;

  GumRiscvWriter * output;
};

GumRiscvRelocator *
gum_riscv_relocator_new (gconstpointer input_code,
                        GumRiscvWriter * output)
{
  GumRiscvRelocator * relocator;

  relocator = g_slice_new (GumRiscvRelocator);

  gum_riscv_relocator_init (relocator, input_code, output);

  return relocator;
}

GumRiscvRelocator *
gum_riscv_relocator_ref (GumRiscvRelocator * relocator)
{
  g_atomic_int_inc (&relocator->ref_count);

  return relocator;
}

void
gum_riscv_relocator_unref (GumRiscvRelocator * relocator)
{
  if (g_atomic_int_dec_and_test (&relocator->ref_count))
  {
    gum_riscv_relocator_clear (relocator);

    g_slice_free (GumRiscvRelocator, relocator);
  }
}

void
gum_riscv_relocator_init (GumRiscvRelocator * relocator,
                         gconstpointer input_code,
                         GumRiscvWriter * output)
{
  relocator->ref_count = 1;

  cs_arch_register_riscv ();
  cs_open (CS_ARCH_RISCV, GUM_DEFAULT_RISCV_MODE | GUM_DEFAULT_CS_ENDIAN,
      &relocator->capstone);
  cs_option (relocator->capstone, CS_OPT_DETAIL, CS_OPT_ON);
  relocator->input_insns = g_new0 (cs_insn *, GUM_MAX_INPUT_INSN_COUNT);

  relocator->output = NULL;

  gum_riscv_relocator_reset (relocator, input_code, output);
}

void
gum_riscv_relocator_clear (GumRiscvRelocator * relocator)
{
  guint i;

  gum_riscv_relocator_reset (relocator, NULL, NULL);

  for (i = 0; i != GUM_MAX_INPUT_INSN_COUNT; i++)
  {
    cs_insn * insn = relocator->input_insns[i];
    if (insn != NULL)
    {
      cs_free (insn, 1);
      relocator->input_insns[i] = NULL;
    }
  }
  g_free (relocator->input_insns);

  cs_close (&relocator->capstone);
}

void
gum_riscv_relocator_reset (GumRiscvRelocator * relocator,
                          gconstpointer input_code,
                          GumRiscvWriter * output)
{
  relocator->input_start = input_code;
  relocator->input_cur = input_code;
  relocator->input_pc = GUM_ADDRESS (input_code);

  if (output != NULL)
    gum_riscv_writer_ref (output);
  if (relocator->output != NULL)
    gum_riscv_writer_unref (relocator->output);
  relocator->output = output;

  relocator->inpos = 0;
  relocator->outpos = 0;

  relocator->eob = FALSE;
  relocator->eoi = FALSE;
}

static guint
gum_riscv_relocator_inpos (GumRiscvRelocator * self)
{
  return self->inpos % GUM_MAX_INPUT_INSN_COUNT;
}

static guint
gum_riscv_relocator_outpos (GumRiscvRelocator * self)
{
  return self->outpos % GUM_MAX_INPUT_INSN_COUNT;
}

static void
gum_riscv_relocator_increment_inpos (GumRiscvRelocator * self)
{
  self->inpos++;
  g_assert (self->inpos > self->outpos);
}

static void
gum_riscv_relocator_increment_outpos (GumRiscvRelocator * self)
{
  self->outpos++;
  g_assert (self->outpos <= self->inpos);
}

guint
gum_riscv_relocator_read_one (GumRiscvRelocator * self,
                             const cs_insn ** instruction)
{
  cs_insn ** insn_ptr, * insn;
  const uint8_t * code;
  size_t size;
  uint64_t address;

  if (self->eoi)
    return 0;

  insn_ptr = &self->input_insns[gum_riscv_relocator_inpos (self)];

  if (*insn_ptr == NULL)
    *insn_ptr = cs_malloc (self->capstone);

  code = self->input_cur;
  size = 4;
  address = self->input_pc;
  insn = *insn_ptr;

  if (!cs_disasm_iter (self->capstone, &code, &size, &address, insn))
    return 0;

  switch (insn->id)
  {
    case RISCV_INS_JAL:
    case RISCV_INS_JALR:
      self->eob = TRUE;
      self->eoi = TRUE;
      break;
    case RISCV_INS_BEQ:
    case RISCV_INS_BNE:
    case RISCV_INS_BLT:
    case RISCV_INS_BGE:
    case RISCV_INS_BLTU:
    case RISCV_INS_BGEU:
      self->eob = TRUE;
      self->eoi = FALSE;
      break;
    case RISCV_INS_ECALL:
    case RISCV_INS_EBREAK:
      self->eob = TRUE;
      self->eoi = TRUE;
      break;
    default:
      self->eob = FALSE;
      break;
  }

  gum_riscv_relocator_increment_inpos (self);

  if (instruction != NULL)
    *instruction = insn;

  self->input_cur = code;
  self->input_pc = address;

  return self->input_cur - self->input_start;
}

cs_insn *
gum_riscv_relocator_peek_next_write_insn (GumRiscvRelocator * self)
{
  if (self->outpos == self->inpos)
    return NULL;

  return self->input_insns[gum_riscv_relocator_outpos (self)];
}

gpointer
gum_riscv_relocator_peek_next_write_source (GumRiscvRelocator * self)
{
  cs_insn * next;

  next = gum_riscv_relocator_peek_next_write_insn (self);
  if (next == NULL)
    return NULL;

  return GSIZE_TO_POINTER (next->address);
}

void
gum_riscv_relocator_skip_one (GumRiscvRelocator * self)
{
  gum_riscv_relocator_increment_outpos (self);
}

gboolean
gum_riscv_relocator_write_one (GumRiscvRelocator * self)
{
  const cs_insn * insn;
  GumCodeGenCtx ctx;
  gboolean rewritten;

  if ((insn = gum_riscv_relocator_peek_next_write_insn (self)) == NULL)
    return FALSE;
  gum_riscv_relocator_increment_outpos (self);
  ctx.insn = insn;
  ctx.detail = &ctx.insn->detail->riscv;
  ctx.output = self->output;

  rewritten = FALSE;

  switch (insn->id)
  {
    /*
     * RISC-V branch and jump instructions need relocation:
     * - JAL: absolute address -> relative offset
     * - JALR: usually doesn't need relocation (uses register)
     * - Branches: relative offset may need adjustment
     */
    case RISCV_INS_JAL:
    {
      cs_riscv_op * op;
      gint64 target, offset;

      if (ctx.detail->op_count >= 1)
      {
        op = &ctx.detail->operands[ctx.detail->op_count - 1];
        if (op->type == RISCV_OP_IMM)
        {
          target = (gint64) op->imm;
          offset = target - (gint64) self->output->pc;

          if (gum_riscv_writer_can_branch_directly_between (
              self->output->pc, target))
          {
            gum_riscv_writer_put_jal_imm (ctx.output, target);
            rewritten = TRUE;
          }
        }
      }
      break;
    }
    default:
      rewritten = FALSE;
      break;
  }

  if (!rewritten)
  {
    gum_riscv_writer_put_bytes (ctx.output, insn->bytes, insn->size);
  }

  return TRUE;
}

void
gum_riscv_relocator_write_all (GumRiscvRelocator * self)
{
  G_GNUC_UNUSED guint count = 0;

  while (gum_riscv_relocator_write_one (self))
    count++;

  g_assert (count > 0);
}

gboolean
gum_riscv_relocator_eob (GumRiscvRelocator * self)
{
  return self->eob;
}

gboolean
gum_riscv_relocator_eoi (GumRiscvRelocator * self)
{
  return self->eoi;
}

gboolean
gum_riscv_relocator_can_relocate (gpointer address,
                                 guint min_bytes,
                                 GumRelocationScenario scenario,
                                 guint * maximum,
                                 riscv_reg * available_scratch_reg)
{
  guint n = 0;
  guint8 * buf;
  GumRiscvWriter cw;
  GumRiscvRelocator rl;
  guint reloc_bytes;

  buf = g_alloca (3 * min_bytes);
  gum_riscv_writer_init (&cw, buf);

  gum_riscv_relocator_init (&rl, address, &cw);

  do
  {
    const cs_insn * insn;
    gboolean safe_to_relocate_further;

    reloc_bytes = gum_riscv_relocator_read_one (&rl, &insn);
    if (reloc_bytes == 0)
      break;

    n = reloc_bytes;

    if (scenario == GUM_SCENARIO_ONLINE)
    {
      switch (insn->id)
      {
        case RISCV_INS_JAL:
        case RISCV_INS_JALR:
        case RISCV_INS_ECALL:
        case RISCV_INS_EBREAK:
          safe_to_relocate_further = FALSE;
          break;
        default:
          safe_to_relocate_further = TRUE;
          break;
      }
    }
    else
    {
      safe_to_relocate_further = TRUE;
    }

    if (!safe_to_relocate_further)
      break;
  }
  while (reloc_bytes < min_bytes);

  if (!rl.eoi)
  {
    csh capstone;
    cs_insn * insn;
    size_t count, i;

    cs_open (CS_ARCH_RISCV, GUM_DEFAULT_RISCV_MODE | GUM_DEFAULT_CS_ENDIAN,
        &capstone);
    cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);

    count = cs_disasm (capstone, rl.input_cur, 1024, rl.input_pc, 0, &insn);
    g_assert (insn != NULL);

    for (i = 0; i != count; i++)
    {
      cs_riscv * d = &insn[i].detail->riscv;

      switch (insn[i].id)
      {
        case RISCV_INS_JAL:
        {
          cs_riscv_op * op;
          gint64 target, offset;

          if (d->op_count >= 1)
          {
            op = &d->operands[d->op_count - 1];
            if (op->type == RISCV_OP_IMM)
            {
              target = (gint64) op->imm;
              offset = target - (gint64) GPOINTER_TO_SIZE (address);
              if (offset > 0 && offset < (gint64) n)
                n = offset;
            }
          }
          break;
        }
        case RISCV_INS_JALR:
          break;
        default:
          break;
      }
    }

    cs_free (insn, count);
    cs_close (&capstone);
  }

  if (available_scratch_reg != NULL)
  {
    gboolean t0_used, t1_used, t2_used;
    guint insn_index;

    t0_used = FALSE;
    t1_used = FALSE;
    t2_used = FALSE;

    for (insn_index = 0; insn_index != n / 4; insn_index++)
    {
      const cs_insn * insn = rl.input_insns[insn_index];
      const cs_riscv * info = &insn->detail->riscv;
      uint8_t op_index;

      for (op_index = 0; op_index != info->op_count; op_index++)
      {
        const cs_riscv_op * op = &info->operands[op_index];

        if (op->type == RISCV_OP_REG)
        {
          t0_used |= op->reg == RISCV_REG_T0;
          t1_used |= op->reg == RISCV_REG_T1;
          t2_used |= op->reg == RISCV_REG_T2;
        }
      }
    }

    if (!t0_used)
      *available_scratch_reg = RISCV_REG_T0;
    else if (!t1_used)
      *available_scratch_reg = RISCV_REG_T1;
    else if (!t2_used)
      *available_scratch_reg = RISCV_REG_T2;
    else
      *available_scratch_reg = RISCV_REG_INVALID;
  }

  gum_riscv_relocator_clear (&rl);
  gum_riscv_writer_clear (&cw);

  if (maximum != NULL)
    *maximum = n;

  return n >= min_bytes;
}

guint
gum_riscv_relocator_relocate (gpointer from,
                             guint min_bytes,
                             gpointer to)
{
  GumRiscvWriter cw;
  GumRiscvRelocator rl;
  guint reloc_bytes;

  gum_riscv_writer_init (&cw, to);

  gum_riscv_relocator_init (&rl, from, &cw);

  do
  {
    reloc_bytes = gum_riscv_relocator_read_one (&rl, NULL);
    g_assert (reloc_bytes != 0);
  }
  while (reloc_bytes < min_bytes);

  gum_riscv_relocator_write_all (&rl);

  gum_riscv_relocator_clear (&rl);
  gum_riscv_writer_clear (&cw);

  return reloc_bytes;
}
