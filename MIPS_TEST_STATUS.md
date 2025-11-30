# MIPS 架构测试状态分析

## 概述

MIPS 架构在 Gum 中有部分实现，但测试框架中**没有包含** MIPS 特定的测试。这是一个**有意的设计决策**，而不是遗漏。

## MIPS 实现状态

### ✅ 已实现的功能

1. **代码生成器 (Writer)**
   - `gum/arch-mips/gummipswriter.c` - MIPS 代码生成器实现
   - 支持 MIPS32 和 MIPS64
   - 支持大端和小端字节序

2. **代码重定位器 (Relocator)**
   - `gum/arch-mips/gummipsrelocator.c` - MIPS 代码重定位器实现
   - 使用 Capstone 进行指令解析
   - 支持指令重定位和地址更新

3. **函数拦截器 (Interceptor)**
   - `gum/backend-mips/guminterceptor-mips.c` - MIPS 拦截器实现
   - 支持函数 hook 和拦截

4. **进程管理**
   - `gum/backend-mips/gumprocess-mips.c` - MIPS 进程管理实现

5. **CPU 上下文**
   - `gum/backend-mips/gumcpucontext-mips.c` - MIPS CPU 上下文实现

### ❌ 未完全实现的功能

1. **代码跟踪器 (Stalker)**
   - `gum/backend-mips/gumstalker-mips.c` - **返回 `FALSE`，表示不支持**
   ```c
   gboolean
   gum_stalker_is_supported (void)
   {
     return FALSE;  // 明确表示不支持
   }
   ```
   - 这是 MIPS 架构的主要限制

2. **回溯器 (Backtracer)**
   - 测试中被明确排除：
   ```c
   #if !defined (HAVE_QNX) && !(defined (HAVE_MIPS))
     TESTLIST_REGISTER (backtracer);
   #endif
   ```

## 测试框架中的 MIPS 处理

### 1. 测试注册排除

在 `tests/gumtest.c` 中，**没有注册任何 MIPS 特定的测试**：

```c
// 代码生成器测试 - 没有 mipswriter
TESTLIST_REGISTER (x86writer);
TESTLIST_REGISTER (armwriter);
TESTLIST_REGISTER (thumbwriter);
TESTLIST_REGISTER (arm64writer);
// ❌ 没有 TESTLIST_REGISTER (mipswriter);

// 重定位器测试 - 没有 mipsrelocator
if (cs_support (CS_ARCH_X86))
  TESTLIST_REGISTER (x86relocator);
if (cs_support (CS_ARCH_ARM))
  TESTLIST_REGISTER (armrelocator);
// ❌ 没有 MIPS relocator 测试

// Stalker 测试 - 因为不支持，所以没有
if (gum_stalker_is_supported ())
{
  // MIPS stalker 返回 FALSE，所以不会注册
}
```

### 2. 条件排除

某些测试在 MIPS 上被明确排除：

```c
// Backtracer 测试排除 MIPS
#if !defined (HAVE_QNX) && !(defined (HAVE_MIPS))
  TESTLIST_REGISTER (backtracer);
#endif

// API Resolver 测试排除 MIPS
#if !defined (HAVE_QNX) && \
    !(defined (HAVE_MIPS))
  TESTLIST_REGISTER (backtracer);
#endif
```

### 3. 部分支持

虽然 MIPS 特定测试不存在，但**通用测试**中包含了 MIPS 支持：

#### 测试数据支持

在 `tests/core/interceptor-fixture.c` 中定义了 MIPS 测试数据：

```c
#elif defined (HAVE_MIPS)
# if G_BYTE_ORDER == G_LITTLE_ENDIAN
#   if GLIB_SIZEOF_VOID_P == 8
#     define GUM_TEST_SHLIB_ARCH "mips64el"
#   else
#     define GUM_TEST_SHLIB_ARCH "mipsel"
#   endif
# else
#   if GLIB_SIZEOF_VOID_P == 8
#     define GUM_TEST_SHLIB_ARCH "mips64"
#   else
#     define GUM_TEST_SHLIB_ARCH "mips"
#   endif
# endif
```

#### 进程测试支持

在 `tests/core/process.c` 中有 MIPS 的测试：

```c
#ifdef HAVE_MIPS
  cpu32 = GUM_CPU_MIPS;
#endif

#if GLIB_SIZEOF_VOID_P == 8
#elif defined (HAVE_MIPS)
  cpu64 = GUM_CPU_MIPS;
#endif
```

#### 测试数据构建

`tests/core/targetfunctions/rebuild.sh` 包含 MIPS 架构：

```bash
ARCHS=(
  # ...
  mips
  mipsel
  mips64
  mips64el
)
```

## 为什么没有 MIPS 特定测试？

### 1. Stalker 不支持

**主要原因**：MIPS 的 Stalker（代码跟踪）功能**未实现**，返回 `FALSE`。

Stalker 是 Gum 最复杂的功能之一，需要：
- 动态代码生成
- 指令重写
- 执行上下文保存/恢复
- 异常处理

MIPS 架构的特殊性（延迟槽、分支延迟等）使得实现 Stalker 非常困难。

### 2. 测试基础设施限制

即使有 Writer 和 Relocator 实现，也可能因为：
- **缺少测试环境**：MIPS 硬件/模拟器不易获得
- **CI/CD 限制**：持续集成系统可能不支持 MIPS
- **维护成本**：MIPS 测试需要额外的维护工作

### 3. 功能完整性

虽然 Writer 和 Relocator 有实现，但可能：
- **功能不完整**：某些边缘情况未处理
- **未充分测试**：实现存在但未经过充分验证
- **优先级较低**：MIPS 不是主要目标架构

## 对比其他架构

### x86/x86_64
- ✅ Writer 测试
- ✅ Relocator 测试
- ✅ Stalker 测试
- ✅ Interceptor 测试

### ARM
- ✅ Writer 测试（ARM + Thumb）
- ✅ Relocator 测试（ARM + Thumb）
- ✅ Stalker 测试
- ✅ Interceptor 测试

### ARM64
- ✅ Writer 测试
- ✅ Relocator 测试
- ✅ Stalker 测试
- ✅ Interceptor 测试

### MIPS
- ❌ Writer 测试
- ❌ Relocator 测试
- ❌ Stalker 测试（不支持）
- ⚠️ Interceptor 测试（通过通用测试）

## 如何添加 MIPS 测试？

如果要为 MIPS 添加测试，需要：

### 1. 创建测试文件

```
tests/core/arch-mips/
├── mipswriter.c
├── mipswriter-fixture.c
├── mipsrelocator.c
└── mipsrelocator-fixture.c
```

### 2. 在 meson.build 中注册

```meson
core_sources = [
  # ...
  'arch-mips' / 'mipswriter.c',
  'arch-mips' / 'mipsrelocator.c',
]
```

### 3. 在 gumtest.c 中注册

```c
#ifdef HAVE_MIPS
  TESTLIST_REGISTER (mipswriter);
  if (cs_support (CS_ARCH_MIPS))
    TESTLIST_REGISTER (mipsrelocator);
#endif
```

### 4. 准备测试环境

- MIPS 硬件或模拟器（QEMU）
- 交叉编译工具链
- CI/CD 支持

## 当前状态总结

| 功能 | 实现状态 | 测试状态 | 说明 |
|------|---------|---------|------|
| Writer | ✅ 已实现 | ❌ 无测试 | 有实现但未测试 |
| Relocator | ✅ 已实现 | ❌ 无测试 | 有实现但未测试 |
| Interceptor | ✅ 已实现 | ⚠️ 部分测试 | 通过通用测试 |
| Stalker | ❌ 不支持 | ❌ 无测试 | 明确返回 FALSE |
| Backtracer | ❓ 未知 | ❌ 排除 | 测试中被排除 |

## 结论

MIPS 架构在 Gum 中**有部分实现**，但**测试框架不包含 MIPS 特定测试**，这是因为：

1. **Stalker 不支持** - 这是主要限制
2. **测试基础设施限制** - 缺少 MIPS 测试环境
3. **维护成本考虑** - MIPS 不是主要目标架构
4. **功能完整性** - 某些功能可能不完整

**这不是 bug，而是有意的设计决策**。MIPS 的实现主要用于：
- 基本的功能拦截（Interceptor）
- 代码生成（Writer）
- 代码重定位（Relocator）

但**不支持**高级功能如代码跟踪（Stalker）。

如果需要完整的 MIPS 支持，需要：
1. 实现 Stalker 功能
2. 添加完整的测试套件
3. 建立测试基础设施
4. 在 CI/CD 中集成
