# Gum 测试框架解析

## 概述

Gum 测试框架基于 GLib 的 GTest 框架构建，提供了一个结构化的测试系统来验证 Gum 库的各个功能模块。

## 架构组成

### 1. 测试运行器 (`gumtest.c`)

**位置**: `/workspace/tests/gumtest.c`

**主要功能**:
- 初始化 Gum 库和测试环境
- 注册所有测试套件
- 运行测试并统计结果
- 处理平台特定的初始化（Windows、Darwin、Android等）

**关键特性**:
- 使用 GLib 的内存管理（`g_mem_set_vtable`）
- 支持 Valgrind 检测
- 支持 AddressSanitizer (ASAN)
- 平台特定的初始化（如 iOS 的 jailbreak 检测、QNX 的系统模块加载）

**测试注册流程**:
```c
// 核心测试
TESTLIST_REGISTER (testutil);
TESTLIST_REGISTER (tls);
TESTLIST_REGISTER (cloak);
TESTLIST_REGISTER (memory);
// ... 更多测试

// 条件性测试注册
if (gum_stalker_is_supported ()) {
    TESTLIST_REGISTER (stalker);
}
```

### 2. 测试工具库 (`testutil.c` / `testutil.h`)

**位置**: `/workspace/tests/testutil.c`, `/workspace/tests/testutil.h`

**提供的功能**:

#### 测试宏定义

1. **TESTLIST_BEGIN(NAME) / TESTLIST_END()**
   - 定义测试套件的注册函数
   - 格式: `void test_<NAME>_add_tests(gpointer fixture_data)`

2. **TESTENTRY_SIMPLE(NAME, PREFIX, FUNC)**
   - 注册简单的测试用例（无 fixture）
   - 使用 `g_test_add_func()` 注册

3. **TESTENTRY_WITH_FIXTURE(NAME, PREFIX, FUNC, STRUCT)**
   - 注册带 fixture 的测试用例
   - 需要提供 setup/teardown 函数
   - 使用 `g_test_add()` 注册

4. **TESTGROUP_BEGIN(NAME) / TESTGROUP_END()**
   - 定义测试组，用于组织相关测试

5. **TESTLIST_REGISTER(NAME) / TESTLIST_REGISTER_WITH_DATA(NAME, DATA)**
   - 注册测试套件到主测试运行器

#### 工具函数

- **差异比较工具**:
  - `test_util_diff_binary()` - 二进制数据差异比较
  - `test_util_diff_text()` - 文本差异比较
  - `test_util_diff_xml()` - XML 差异比较

- **系统信息获取**:
  - `test_util_get_data_dir()` - 获取测试数据目录
  - `test_util_get_system_module_name()` - 获取系统模块名称
  - `test_util_heap_apis()` - 获取堆 API 列表

- **异常处理工具**:
  - `gum_try_read_and_write_at()` - 安全的内存读写测试

### 3. Python 测试运行脚本 (`run.py`)

**位置**: `/workspace/tests/run.py`

**功能**:
- 简单的包装脚本，用于运行编译后的测试可执行文件
- 处理 Windows 平台的特殊路径设置
- 传递环境变量

**使用方式**:
```python
# Meson 测试配置中调用
test('gum', python,
  args: [files('run.py'), runner.full_path()],
  timeout: 120,
)
```

### 4. 构建系统集成 (`meson.build`)

**位置**: `/workspace/tests/meson.build`

**构建流程**:

1. **收集测试源文件**:
   - `runner_sources`: 测试运行器核心文件
   - 各子目录的测试库（`gum_tests_core`, `gum_tests_heap` 等）

2. **链接测试库**:
   - 将所有测试模块链接到单个可执行文件
   - 平台特定的链接选项（符号导出、框架链接等）

3. **平台特定处理**:
   - **Darwin**: 代码签名（`sign.sh`）
   - **Windows**: DLL 复制
   - **其他平台**: 版本脚本

## 测试组织结构

### 目录结构

```
tests/
├── core/              # 核心功能测试
│   ├── memory.c       # 内存操作测试
│   ├── interceptor.c  # 函数拦截测试
│   ├── stalker-*.c    # 代码跟踪测试
│   └── arch-*/        # 架构特定测试
├── heap/              # 堆管理测试
├── prof/              # 性能分析测试
├── gumjs/             # JavaScript 绑定测试
├── gumpp/             # C++ 绑定测试
├── data/              # 测试数据文件
└── stubs/             # 测试桩代码
```

### 测试文件命名约定

- **简单测试**: `<module>.c` (如 `memory.c`)
- **带 Fixture 的测试**: `<module>-fixture.c` (如 `interceptor-fixture.c`)
- **架构特定测试**: `arch-<arch>/<module>.c`

## 测试编写模式

### 1. 简单测试示例

```c
#define TESTCASE(NAME) \
    void test_memory_ ## NAME (void)
#define TESTENTRY(NAME) \
    TESTENTRY_SIMPLE ("Core/Memory", test_memory, NAME)

TESTLIST_BEGIN (memory)
  TESTENTRY (read_from_valid_address_should_succeed)
  TESTENTRY (read_from_invalid_address_should_fail)
TESTLIST_END ()

TESTCASE (read_from_valid_address_should_succeed)
{
  guint8 magic[2] = { 0x13, 0x37 };
  gsize n_bytes_read;
  guint8 * result;

  result = gum_memory_read (magic, sizeof (magic), &n_bytes_read);
  g_assert_nonnull (result);
  g_assert_cmpuint (n_bytes_read, ==, sizeof (magic));
  
  g_free (result);
}
```

### 2. 带 Fixture 的测试示例

```c
typedef struct _TestInterceptorFixture TestInterceptorFixture;

struct _TestInterceptorFixture
{
  GumInterceptor * interceptor;
  GString * result;
  // ... 其他字段
};

#define TESTCASE(NAME) \
    void test_interceptor_ ## NAME ( \
        TestInterceptorFixture * fixture, gconstpointer data)
#define TESTENTRY(NAME) \
    TESTENTRY_WITH_FIXTURE ("Core/Interceptor", \
        test_interceptor, NAME, TestInterceptorFixture)

static void
test_interceptor_fixture_setup (TestInterceptorFixture * fixture,
                                gconstpointer data)
{
  fixture->interceptor = gum_interceptor_obtain ();
  fixture->result = g_string_sized_new (4096);
}

static void
test_interceptor_fixture_teardown (TestInterceptorFixture * fixture,
                                   gconstpointer data)
{
  g_object_unref (fixture->interceptor);
  g_string_free (fixture->result, TRUE);
}

TESTLIST_BEGIN (interceptor)
  TESTENTRY (can_attach_detach_listener)
TESTLIST_END ()

TESTCASE (can_attach_detach_listener)
{
  // 使用 fixture->interceptor 进行测试
  g_assert_nonnull (fixture->interceptor);
}
```

## 测试断言

使用 GLib 的断言宏:
- `g_assert_nonnull()` / `g_assert_null()`
- `g_assert_cmpint()` / `g_assert_cmpuint()` / `g_assert_cmpstr()`
- `g_assert_true()` / `g_assert_false()`
- `GUM_ASSERT_CMPADDR()` - 地址比较（自定义宏）

## 平台特定测试

### 条件编译

测试框架使用条件编译来支持不同平台:

```c
#ifdef HAVE_WINDOWS
  TESTLIST_REGISTER (boundschecker);
#endif

#ifdef HAVE_DARWIN
  TESTLIST_REGISTER (interceptor_darwin);
#endif

#ifdef HAVE_ANDROID
  TESTLIST_REGISTER (interceptor_android);
#endif
```

### 架构特定测试

- **x86/x86_64**: `arch-x86/`
- **ARM**: `arch-arm/`
- **ARM64**: `arch-arm64/`
- **MIPS**: `arch-mips/`
- **RISC-V**: `arch-riscv/`

## 测试数据管理

### 数据目录

- **位置**: `/workspace/tests/data/`
- **内容**: 预编译的共享库（用于测试函数拦截、模块加载等）
- **平台特定**: 包含多个平台的 `.so` / `.dylib` / `.dll` 文件

### 数据访问

```c
gchar * data_dir = test_util_get_data_dir ();
gchar * lib_path = g_build_filename (data_dir, "targetfunctions.so", NULL);
```

## 特殊测试工具

### 1. Low-level Helpers (`lowlevelhelpers.c`)

提供底层测试辅助函数，用于测试代码生成、内存操作等。

### 2. Stubs (`stubs/`)

测试桩代码，模拟系统行为:
- `fakebacktracer.c` - 模拟回溯器
- `fakeeventsink.c` - 模拟事件接收器
- `dummyclasses.c` - 模拟类（用于 Objective-C 测试）

### 3. Valgrind 支持

```c
#include "valgrind.h"

if (RUNNING_ON_VALGRIND) {
    // Valgrind 特定处理
}
```

## 测试执行流程

1. **初始化阶段**:
   - 初始化 Gum 库 (`gum_init()`)
   - 初始化测试工具 (`_test_util_init()`)
   - 设置内存管理

2. **注册阶段**:
   - 调用各测试套件的 `test_<name>_add_tests()` 函数
   - 构建测试树结构

3. **执行阶段**:
   - `g_test_run()` 执行所有注册的测试
   - 统计测试结果

4. **清理阶段**:
   - 清理资源
   - 关闭 Gum 库 (`gum_shutdown()`)

## 运行测试

### 使用 Meson

```bash
meson test
# 或运行特定测试
meson test --gtest_filter="Core/Memory/*"
```

### 直接运行

```bash
./build/tests/gum-tests
# 或使用 Python 包装器
python tests/run.py ./build/tests/gum-tests
```

## 测试覆盖范围

### 核心功能
- 内存操作 (`memory.c`)
- 进程管理 (`process.c`)
- 模块注册表 (`moduleregistry.c`)
- 线程注册表 (`threadregistry.c`)
- TLS (`tls.c`)
- 代码生成器 (`*writer.c`)
- 代码重定位器 (`*relocator.c`)
- 函数拦截 (`interceptor.c`)
- 代码跟踪 (`stalker-*.c`)
- API 解析器 (`apiresolver.c`)
- 回溯器 (`backtracer.c`)

### 堆管理
- 分配跟踪 (`allocationtracker`)
- 边界检查 (`boundschecker`)
- 页面池 (`pagepool`)
- 对象跟踪 (`instancetracker`, `cobjecttracker`)

### 性能分析
- 采样器 (`sampler`)
- 分析器 (`profiler`)

## 最佳实践

1. **测试命名**: 使用描述性名称，如 `read_from_valid_address_should_succeed`
2. **测试隔离**: 每个测试应该是独立的，不依赖其他测试的执行顺序
3. **资源清理**: 确保在测试中分配的资源被正确释放
4. **平台兼容**: 使用条件编译处理平台差异
5. **Fixture 使用**: 对于需要复杂设置的测试，使用 fixture 模式

## 总结

Gum 测试框架提供了一个完整的测试基础设施，支持:
- ✅ 多平台测试（Windows、Linux、macOS、iOS、Android等）
- ✅ 多架构支持（x86、ARM、ARM64、MIPS、RISC-V）
- ✅ 灵活的测试组织（简单测试、Fixture 测试、测试组）
- ✅ 丰富的测试工具（差异比较、系统信息获取等）
- ✅ 与构建系统集成（Meson）
- ✅ 条件性测试注册（根据平台/架构/功能可用性）

该框架使得 Gum 库能够在各种环境中进行全面的功能验证，确保代码质量和跨平台兼容性。
