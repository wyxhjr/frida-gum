# Gum 架构特定测试详解

## 概述

Gum 测试框架针对不同的 CPU 架构提供了专门的测试套件，确保代码生成器、重定位器、拦截器和代码跟踪器在不同架构上都能正确工作。

## 支持的架构

- **x86/x86_64** (`arch-x86/`)
- **ARM** (`arch-arm/`)
- **ARM64** (`arch-arm64/`)
- **MIPS** (`arch-mips/`)
- **RISC-V** (`arch-riscv/`)

## 测试类型

### 1. 代码生成器测试 (Writer Tests)

测试各架构的代码生成器能否正确生成机器码。

#### x86 Writer (`arch-x86/x86writer.c`)

**测试内容**:
- 跳转和调用指令（`jump_label`, `call_label`, `call_indirect`）
- 算术运算（`add`, `inc`, `dec`）
- 逻辑运算（`and`, `shl`）
- 内存操作（`mov`, `push`, `pop`）
- 比较和测试（`test`, `cmp`）
- 浮点操作（`fxsave`, `fxrstor`）
- 原子操作（`lock_xadd`）

**示例测试**:
```c
TESTCASE (add_eax_ecx)
{
  // 测试生成 add eax, ecx 指令
  gum_x86_writer_put_add_reg_reg (&fixture->cw, X86_REG_EAX, X86_REG_ECX);
  gum_x86_writer_flush (&fixture->cw);
  
  // 验证生成的机器码
  assert_output_equals (0x01, 0xc8);  // add eax, ecx
}
```

**特点**:
- 支持 32 位和 64 位模式
- 测试不同的调用约定（C API、系统调用 API）
- 验证扩展寄存器（R8-R15）的使用

#### ARM Writer (`arch-arm/armwriter.c`)

**测试内容**:
- 加载指令（`ldr_u32`, `ldr_pc_u32`）
- 批量加载（`ldmia`）
- 向量寄存器操作（`vpush`, `vpop`）
- 大块代码生成（`ldr_in_large_block`）

**示例测试**:
```c
TESTCASE (ldr_u32)
{
  // 测试生成 ldr r0, #0x1337 指令
  gum_arm_writer_put_ldr_reg_u32 (&fixture->aw, ARM_REG_R0, 0x1337);
  gum_arm_writer_flush (&fixture->aw);
  
  // 验证生成的机器码
  assert_output_n_equals (0, 0xe59f0004);  // ldr r0, [pc, #4]
  g_assert_cmphex (fixture->output[3 + 0], ==, 0x1337);
}
```

**特点**:
- ARM 模式（32 位指令）
- 处理 PC 相对寻址
- 支持大块代码生成（跨页边界）

#### ARM64 Writer (`arch-arm64/arm64writer.c`)

**测试内容**:
- 条件分支（`cbz`, `tbnz`）
- 跳转和调用（`b`, `bl`, `br`, `blr`, `ret`）
- 寄存器操作（`push`, `pop`, `mov`, `uxtw`）
- 算术运算（`add`, `sub`, `and`, `eor`）
- 内存操作（`ldr`, `str`）
- 函数调用（`call_reg`）

**示例测试**:
```c
TESTCASE (call_reg)
{
  // 测试通过寄存器调用函数，传递参数
  gum_arm64_writer_put_call_reg_with_arguments (&fixture->aw, ARM64_REG_X3,
      2,
      GUM_ARG_REGISTER, ARM64_REG_X5,
      GUM_ARG_REGISTER, ARM64_REG_W7);
  
  // 验证生成的指令序列
  assert_output_n_equals (0, 0xd3407ce1);  // uxtw x1, w7
  assert_output_n_equals (1, 0xaa0503e0);  // mov x0, x5
  assert_output_n_equals (2, 0xd63f0060);  // blr x3
}
```

**特点**:
- 64 位架构
- 支持指针认证（ptrauth）
- 测试扩展寄存器（X0-X30）

### 2. 代码重定位器测试 (Relocator Tests)

测试将现有代码重定位到新位置时，相对地址和跳转目标是否正确更新。

#### x86 Relocator (`arch-x86/x86relocator.c`)

**测试内容**:
- 一对一重定位（`one_to_one`）
- 相对调用重定位（`call_near_relative`）
- 跳转重定位（`jmp_short`, `jmp_near`）
- 条件跳转重定位（`jcc_short`, `jcc_near`）
- RIP 相对寻址（64 位模式）
- 指令跳过和窥视（`skip_instruction`, `peek_next_write`）

**示例测试**:
```c
TESTCASE (call_near_relative)
{
  guint8 input[] = {
    0xe8, 0x04, 0x00, 0x00, 0x00,  // call dummy (相对偏移 +4)
    // ... dummy 函数
  };
  
  SETUP_RELOCATOR_WITH (input);
  
  // 读取并重定位指令
  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_write_all (&fixture->rl);
  
  // 验证相对偏移已更新
  gint32 reloc_distance = *((gint32 *) (fixture->output + 1));
  gint32 expected_distance = /* 计算新偏移 */;
  g_assert_cmpint (reloc_distance, ==, expected_distance);
}
```

**特点**:
- 处理短跳转（1 字节偏移）和近跳转（4 字节偏移）
- 64 位模式下的 RIP 相对寻址
- 处理红色区域（Red Zone）

#### ARM Relocator (`arch-arm/armrelocator.c`)

**测试内容**:
- ARM 模式指令重定位
- Thumb 模式指令重定位
- PC 相对寻址更新
- 条件分支重定位

#### ARM64 Relocator (`arch-arm64/arm64relocator.c`)

**测试内容**:
- 64 位指令重定位
- PC 相对寻址（ADR, ADRP）
- 条件分支重定位
- 函数调用重定位

### 3. 拦截器测试 (Interceptor Tests)

测试函数拦截在不同架构上的实现。

#### ARM Interceptor (`arch-arm/interceptor-arm.c`)

**测试内容**:
- 非对齐函数拦截（`attach_to_unaligned_function`）
- Thumb 模式 thunk 拦截（`attach_to_thumb_thunk_reading_lr`）
- Thumb 函数拦截（`attach_to_thumb_function_reading_lr`）

**特点**:
- ARM 架构支持 ARM 和 Thumb 两种指令集
- Thumb 模式使用 16 位指令，地址需要对齐到 2 字节边界
- 测试处理链接寄存器（LR）的特殊情况

**示例测试**:
```c
TESTCASE (attach_to_unaligned_function)
{
  // 创建一个非对齐的 Thumb 函数（地址 +1）
  gpointer page = gum_alloc_n_pages (1, GUM_PAGE_RWX);
  gpointer code = page + 2;  // 2 字节对齐
  gint (* f) (void) = code + 1;  // 非对齐地址
  
  // 生成 Thumb 代码
  GumThumbWriter tw;
  gum_thumb_writer_init (&tw, code);
  gum_thumb_writer_put_ldr_reg_u32 (&tw, ARM_REG_R0, 1337);
  // ...
  
  // 拦截非对齐函数
  interceptor_fixture_attach (fixture, 0, f, '>', '<');
  g_assert_cmpint (f (), ==, 1337);
  g_assert_cmpstr (fixture->result->str, ==, "><");
}
```

#### ARM64 Interceptor (`arch-arm64/interceptor-arm64.c`)

**测试内容**:
- ARM64 特定拦截场景
- 指针认证处理（如果支持）

### 4. 代码跟踪测试 (Stalker Tests)

测试代码执行跟踪功能，这是 Gum 最复杂的功能之一。

#### x86 Stalker (`arch-x86/stalker-x86.c`)

**测试内容**:
- 基本事件（`call`, `ret`, `exec`）
- 调用深度跟踪（`call_depth`）
- 调用探针（`call_probe`）
- 自定义转换器（`custom_transformer`）
- 跳转跟踪（条件跳转、无条件跳转）
- 间接调用跟踪
- 系统调用跟踪（`follow_syscall`）
- 线程跟踪（`follow_thread`, `create_thread`）
- 自修改代码检测
- 异常处理（Linux 上的 C++ 异常）

**示例测试**:
```c
TESTCASE (call)
{
  // 跟踪函数调用事件
  gum_stalker_follow_me (fixture->stalker, fixture->transformer, NULL);
  
  // 调用被跟踪的函数
  target_function (fixture->result);
  
  // 验证事件被正确记录
  g_assert_cmpstr (fixture->result->str, ==, ">target_function<");
  
  gum_stalker_unfollow_me (fixture->stalker);
}
```

**特点**:
- 支持 32 位和 64 位模式
- 处理各种 x86 指令变体
- Linux 上支持 C++ 异常处理测试
- Windows 特定测试（消息循环、回调等）

#### ARM Stalker (`arch-arm/stalker-arm.c`)

**测试内容**:
- ARM/Thumb 模式切换跟踪
- 条件执行指令跟踪
- PC 相对寻址处理

#### ARM64 Stalker (`arch-arm64/stalker-arm64.c`)

**测试内容**:
- ARM64 指令跟踪
- Darwin/macOS 特定测试（`stalker-arm64-darwin.m`, `stalker-arm64-macos.m`）
- 指针认证支持

## 测试组织结构

### 目录结构

```
tests/core/
├── arch-x86/
│   ├── x86writer.c              # x86 代码生成器测试
│   ├── x86writer-fixture.c      # x86 writer fixture
│   ├── x86relocator.c           # x86 重定位器测试
│   ├── x86relocator-fixture.c   # x86 relocator fixture
│   ├── stalker-x86.c            # x86 代码跟踪测试
│   ├── stalker-x86-fixture.c    # x86 stalker fixture
│   ├── stalker-x86-exceptions.cpp  # C++ 异常处理测试
│   └── stalker-x86-macos.m      # macOS 特定测试
├── arch-arm/
│   ├── armwriter.c               # ARM 代码生成器测试
│   ├── armrelocator.c            # ARM 重定位器测试
│   ├── thumbwriter.c             # Thumb 代码生成器测试
│   ├── thumbrelocator.c          # Thumb 重定位器测试
│   ├── interceptor-arm.c         # ARM 拦截器测试
│   └── stalker-arm.c             # ARM 代码跟踪测试
└── arch-arm64/
    ├── arm64writer.c             # ARM64 代码生成器测试
    ├── arm64relocator.c          # ARM64 重定位器测试
    ├── interceptor-arm64.c       # ARM64 拦截器测试
    ├── stalker-arm64.c           # ARM64 代码跟踪测试
    ├── stalker-arm64-darwin.m    # Darwin 特定测试
    └── stalker-arm64-macos.m     # macOS 特定测试
```

### Fixture 模式

每个架构的测试都使用 Fixture 模式来设置和清理测试环境：

```c
// x86writer-fixture.c
typedef struct _TestCodeWriterFixture
{
  guint8 output[32];           // 输出缓冲区
  GumX86Writer cw;              // x86 writer 实例
} TestCodeWriterFixture;

static void
test_code_writer_fixture_setup (TestCodeWriterFixture * fixture,
                                gconstpointer data)
{
  gum_x86_writer_init (&fixture->cw, fixture->output);
  gum_x86_writer_set_target_cpu (&fixture->cw, GUM_CPU_AMD64);
  gum_x86_writer_set_target_abi (&fixture->cw, GUM_ABI_WINDOWS);
}

static void
test_code_writer_fixture_teardown (TestCodeWriterFixture * fixture,
                                   gconstpointer data)
{
  gum_x86_writer_clear (&fixture->cw);
}
```

## 条件编译和注册

### 构建系统条件编译

在 `meson.build` 中，根据目标架构条件性地包含测试文件：

```meson
# 所有架构都包含的测试
core_sources = [
  'arch-x86' / 'x86writer.c',
  'arch-x86' / 'x86relocator.c',
  'arch-arm' / 'armwriter.c',
  'arch-arm' / 'armrelocator.c',
  # ...
]

# x86/x86_64 特定测试
if host_arch in ['x86', 'x86_64']
  core_sources += [
    'arch-x86' / 'stalker-x86.c',
  ]
  if host_os == 'macos'
    core_sources += [
      'arch-x86' / 'stalker-x86-macos.m',
    ]
  endif
endif

# ARM 特定测试
if host_arch == 'arm'
  core_sources += [
    'arch-arm' / 'interceptor-arm.c',
    'arch-arm' / 'stalker-arm.c',
  ]
endif

# ARM64 特定测试
if host_arch == 'arm64'
  core_sources += [
    'arch-arm64' / 'interceptor-arm64.c',
    'arch-arm64' / 'stalker-arm64.c',
  ]
  if host_os_family == 'darwin'
    core_sources += [
      'arch-arm64' / 'stalker-arm64-darwin.m',
    ]
  endif
endif
```

### 运行时条件注册

在 `gumtest.c` 中，根据架构和功能可用性条件性地注册测试：

```c
// 代码生成器测试（所有架构）
TESTLIST_REGISTER (x86writer);
TESTLIST_REGISTER (armwriter);
TESTLIST_REGISTER (thumbwriter);
TESTLIST_REGISTER (arm64writer);

// 重定位器测试（需要 Capstone 支持）
if (cs_support (CS_ARCH_X86))
  TESTLIST_REGISTER (x86relocator);
if (cs_support (CS_ARCH_ARM))
  TESTLIST_REGISTER (armrelocator);
if (cs_support (CS_ARCH_ARM))
  TESTLIST_REGISTER (thumbrelocator);
if (cs_support (CS_ARCH_ARM64))
  TESTLIST_REGISTER (arm64relocator);

// 架构特定拦截器测试
#ifdef HAVE_ARM
  TESTLIST_REGISTER (interceptor_arm);
#endif
#ifdef HAVE_ARM64
  TESTLIST_REGISTER (interceptor_arm64);
#endif

// Stalker 测试（需要 Stalker 支持）
if (gum_stalker_is_supported ())
{
#if defined (HAVE_I386) || defined (HAVE_ARM) || defined (HAVE_ARM64)
    TESTLIST_REGISTER (stalker);
#endif
#if defined (HAVE_ARM64) && defined (HAVE_DARWIN)
    TESTLIST_REGISTER (stalker_darwin);
#endif
}
```

### 测试内条件编译

在测试代码内部，也使用条件编译来处理架构差异：

```c
// x86relocator.c
TESTLIST_BEGIN (x86relocator)
  TESTENTRY (one_to_one)
  TESTENTRY (call_near_relative)
  
#if GLIB_SIZEOF_VOID_P == 4
  // 32 位特定测试
  TESTENTRY (call_near_gnu_get_pc_thunk)
  TESTENTRY (call_near_android_get_pc_thunk)
#endif

#if GLIB_SIZEOF_VOID_P == 8
  // 64 位特定测试
  TESTENTRY (rip_relative_move_different_target)
  TESTENTRY (rip_relative_call)
#endif
TESTLIST_END ()
```

## 测试验证方法

### 1. 机器码验证

直接验证生成的机器码字节：

```c
TESTCASE (add_eax_ecx)
{
  gum_x86_writer_put_add_reg_reg (&fixture->cw, X86_REG_EAX, X86_REG_ECX);
  gum_x86_writer_flush (&fixture->cw);
  
  // 验证生成的机器码: 01 c8 = add eax, ecx
  assert_output_equals (0x01, 0xc8);
}
```

### 2. 执行验证

生成代码并实际执行，验证功能正确性：

```c
TESTCASE (ldr_in_large_block)
{
  gpointer code = gum_alloc_n_pages (2, GUM_PAGE_RWX);
  
  // 生成代码
  gum_memory_patch_code (code, code_size, gum_emit_ldr_in_large_block, code);
  
  // 执行并验证结果
  gint (* impl) (void) = code;
  g_assert_cmpint (impl (), ==, 0x1337);
  
  gum_free_pages (code);
}
```

### 3. 差异比较

使用 `test_util_diff_binary()` 比较生成的代码和期望的代码：

```c
static void
test_code_writer_fixture_assert_output_equals (TestCodeWriterFixture * fixture,
                                               const guint8 * expected_code,
                                               guint expected_length)
{
  guint actual_length = gum_x86_writer_offset (&fixture->cw);
  
  if (actual_length != expected_length ||
      memcmp (fixture->output, expected_code, expected_length) != 0)
  {
    gchar * diff = test_util_diff_binary (expected_code, expected_length,
        fixture->output, actual_length);
    g_print ("\n\nGenerated code is not equal to expected code:\n\n%s\n", diff);
    g_free (diff);
    g_assert_not_reached ();
  }
}
```

## 特殊测试场景

### 1. 大块代码生成

测试跨页边界的代码生成：

```c
TESTCASE (ldr_in_large_block)
{
  const gsize code_size_in_pages = 2;
  gpointer code = gum_alloc_n_pages (code_size_in_pages, GUM_PAGE_RW);
  
  // 生成大量代码，测试 PC 相对寻址在跨页时的处理
  gum_arm_writer_put_ldr_reg_u32 (&aw, ARM_REG_R0, 0x1337);
  for (i = 0; i != 1024; i++)
    gum_arm_writer_put_nop (&aw);
  
  // 验证代码正确执行
  gint (* impl) (void) = code;
  g_assert_cmpint (impl (), ==, 0x1337);
}
```

### 2. 非对齐地址

测试非对齐地址的处理（特别是 Thumb 模式）：

```c
TESTCASE (attach_to_unaligned_function)
{
  gpointer code = page + 2;  // 2 字节对齐
  gint (* f) (void) = code + 1;  // 非对齐地址（+1）
  
  // 测试拦截非对齐函数
  interceptor_fixture_attach (fixture, 0, f, '>', '<');
  g_assert_cmpint (f (), ==, 1337);
}
```

### 3. 异常处理

测试 C++ 异常在代码跟踪中的处理（x86 Linux）：

```c
#if defined (HAVE_LINUX) && !defined (HAVE_ANDROID)
TESTGROUP_BEGIN ("ExceptionHandling")
  TESTENTRY (no_exceptions)
  TESTENTRY (try_and_catch)
  TESTENTRY (try_and_catch_excluded)
  TESTENTRY (try_and_dont_catch)
TESTGROUP_END ()
#endif
```

## 平台特定测试

### macOS/Darwin 特定测试

使用 Objective-C/Objective-C++ 编写：

- `stalker-x86-macos.m` - x86 macOS 特定测试
- `stalker-arm64-macos.m` - ARM64 macOS 特定测试
- `stalker-arm64-darwin.m` - ARM64 Darwin 特定测试

这些测试通常涉及：
- Objective-C 方法调用跟踪
- Swift 函数调用跟踪
- macOS 特定的系统调用

## 测试覆盖的架构特性

### x86/x86_64
- ✅ 32 位和 64 位模式
- ✅ 各种寻址模式（寄存器、立即数、内存）
- ✅ 扩展寄存器（R8-R15）
- ✅ RIP 相对寻址（64 位）
- ✅ 红色区域（Red Zone）
- ✅ 各种调用约定
- ✅ 浮点和 SIMD 指令

### ARM
- ✅ ARM 模式（32 位指令）
- ✅ Thumb 模式（16/32 位指令）
- ✅ ARM/Thumb 模式切换
- ✅ 条件执行
- ✅ PC 相对寻址
- ✅ 批量加载/存储（LDM/STM）
- ✅ 向量寄存器（NEON）

### ARM64
- ✅ 64 位指令集
- ✅ 扩展寄存器（X0-X30, W0-W30）
- ✅ PC 相对寻址（ADR/ADRP）
- ✅ 指针认证（ptrauth）
- ✅ 条件分支（CBZ/CBNZ, TBZ/TBNZ）
- ✅ 向量寄存器（SIMD）

## 最佳实践

1. **使用 Fixture**: 所有架构测试都使用 Fixture 模式，确保测试隔离
2. **验证机器码**: 直接验证生成的机器码，确保指令正确
3. **执行验证**: 对于复杂场景，实际执行生成的代码验证功能
4. **条件编译**: 使用条件编译处理架构差异
5. **平台特定测试**: 为平台特定功能编写专门的测试
6. **大块代码测试**: 测试跨页边界的代码生成
7. **边界情况**: 测试非对齐地址、特殊指令等边界情况

## 总结

架构特定测试确保了 Gum 库在不同 CPU 架构上的正确性：

- ✅ **代码生成器**: 验证生成的机器码正确
- ✅ **重定位器**: 验证代码重定位时地址更新正确
- ✅ **拦截器**: 验证函数拦截在不同架构上的实现
- ✅ **代码跟踪**: 验证代码执行跟踪的复杂功能

这些测试通过条件编译和运行时注册，确保只在支持的架构上运行相应的测试，同时保持代码的可维护性和可移植性。
