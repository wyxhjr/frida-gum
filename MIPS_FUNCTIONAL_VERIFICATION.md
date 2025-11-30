# MIPS 功能验证指南

## 概述

虽然 MIPS 没有架构特定的单元测试，但可以通过以下方式验证功能可用性：

## 1. 自动化验证（CI/CD）

### 1.1 编译验证

**每次 PR 自动运行**：

```yaml
# .github/workflows/ci.yml
cross:
  - { id: linux-mips, opts: '--host=mips-linux-gnu' }
  - { id: linux-mipsel, opts: '--host=mipsel-linux-gnu' }
  - { id: linux-mips64, opts: '--host=mips64-linux-gnuabi64' }
  - { id: linux-mips64el, opts: '--host=mips64el-linux-gnuabi64' }
```

**验证内容**：
- ✅ 代码能够成功编译
- ✅ 没有编译错误
- ✅ 链接成功
- ✅ 生成正确的二进制文件

### 1.2 测试数据验证（最关键）

**`check-targetfunctions` 任务**：

```yaml
check-targetfunctions:
  arch: [mips, mipsel, mips64, mips64el]
```

**验证流程**：

1. **重新构建测试库**：
   ```bash
   ./tests/core/targetfunctions/rebuild.sh mips
   ```

2. **检查二进制文件是否变化**：
   ```bash
   git status tests/data/targetfunctions-linux-mips.so
   git status tests/data/specialfunctions-linux-mips.so
   ```

3. **如果文件变化，CI 失败**：
   - 说明 MIPS Writer/Relocator 生成的代码与预期不一致
   - 需要检查实现或更新测试数据

**为什么这很重要**：
- `targetfunctions` 和 `specialfunctions` 使用 MIPS Writer 和 Relocator 生成代码
- 如果 MIPS 实现有问题，重新构建会产生不同的二进制文件
- 这是**间接但有效**的功能验证

## 2. 手动功能验证

### 2.1 使用 QEMU 模拟器运行测试

#### 方法一：使用 `run-linux-vm.sh` 脚本

项目提供了脚本用于在 MIPS 模拟器中运行测试：

```bash
# 运行 MIPS32 大端测试
./tests/run-linux-vm.sh mips

# 运行 MIPS32 小端测试
./tests/run-linux-vm.sh mipsel
```

**脚本功能**：
- 使用 `arm_now` 工具设置 MIPS 模拟器
- 在 QEMU 中运行测试
- 自动处理测试环境设置

**前置要求**：
- 安装 `arm_now` 工具
- 安装 QEMU
- 构建 MIPS 版本的测试程序

#### 方法二：手动设置 QEMU 环境

```bash
# 1. 构建 MIPS 版本的测试
./configure --host=mips-linux-gnu --enable-tests
make

# 2. 准备测试文件
cd build/tests
tar -czf gum-tests-mips.tar.gz gum-tests data/

# 3. 在 QEMU 中运行
qemu-system-mips \
  -M malta \
  -m 512M \
  -kernel vmlinux \
  -initrd initrd.img \
  -append "root=/dev/ram" \
  -nographic

# 4. 在模拟器中解压并运行
tar -xzf gum-tests-mips.tar.gz
./gum-tests
```

### 2.2 在实际 MIPS 设备上测试

如果有实际的 MIPS 硬件：

```bash
# 1. 交叉编译
./configure --host=mips-linux-gnu --enable-tests
make

# 2. 传输到设备
scp build/tests/gum-tests user@mips-device:/tmp/
scp -r build/tests/data user@mips-device:/tmp/

# 3. 在设备上运行
ssh user@mips-device
cd /tmp
./gum-tests
```

## 3. 功能验证清单

### 3.1 Writer 功能验证

**验证 MIPS Writer 生成的代码**：

```c
// 手动测试代码示例
#include <gum/gum.h>
#include <gum/gummipswriter.h>

void test_mips_writer() {
    guint32 code[16];
    GumMipsWriter writer;
    
    gum_mips_writer_init(&writer, code);
    
    // 生成一些指令
    gum_mips_writer_put_add_reg_reg_reg(&writer, 
        GUM_MIPS_REG_V0, GUM_MIPS_REG_A0, GUM_MIPS_REG_A1);
    
    gum_mips_writer_flush(&writer);
    
    // 验证生成的机器码
    // 0x00851020 = add $v0, $a0, $a1
    g_assert_cmphex(code[0], ==, 0x00851020);
}
```

**验证方法**：
1. 使用 `check-targetfunctions` 任务（自动化）
2. 手动检查生成的机器码
3. 执行生成的代码验证功能

### 3.2 Relocator 功能验证

**验证 MIPS Relocator 重定位**：

```c
// 手动测试代码示例
#include <gum/gummipsrelocator.h>

void test_mips_relocator() {
    guint8 input[] = {
        0x0c, 0x00, 0x00, 0x01,  // jal 0x4 (相对调用)
        // ...
    };
    guint8 output[256];
    GumMipsRelocator relocator;
    
    gum_mips_relocator_init(&relocator, input, output);
    
    // 读取并重定位
    const cs_insn *insn;
    gum_mips_relocator_read_one(&relocator, &insn);
    gum_mips_relocator_write_all(&relocator);
    
    // 验证相对地址已更新
    // ...
}
```

**验证方法**：
1. 使用 `check-targetfunctions` 任务（自动化）
2. 手动验证重定位后的地址
3. 执行重定位后的代码

### 3.3 Interceptor 功能验证

**验证函数拦截**：

```c
// 手动测试代码示例
#include <gum/guminterceptor.h>

static void on_enter(GumInvocationContext *context) {
    g_print("Function called!\n");
}

void test_mips_interceptor() {
    GumInterceptor *interceptor = gum_interceptor_obtain();
    TestCallbackListener *listener = test_callback_listener_new();
    
    listener->on_enter = on_enter;
    
    // 拦截函数
    gum_interceptor_attach(interceptor, target_function, 
        GUM_INVOCATION_LISTENER(listener), NULL);
    
    // 调用被拦截的函数
    target_function();
    
    // 验证拦截成功
    // ...
    
    gum_interceptor_detach(interceptor, GUM_INVOCATION_LISTENER(listener));
}
```

**验证方法**：
1. 运行通用 interceptor 测试（如果有 MIPS 环境）
2. 手动测试函数拦截
3. 在实际应用中使用

## 4. 验证流程

### 4.1 开发时的验证

1. **修改 MIPS 代码后**：
   ```bash
   # 重新构建测试数据
   ./tests/core/targetfunctions/rebuild.sh mips
   
   # 检查是否有变化
   git diff tests/data/targetfunctions-linux-mips.so
   ```

2. **如果有变化**：
   - 检查变化是否合理
   - 如果合理，提交更新的测试数据
   - 如果不合理，修复代码

### 4.2 CI 中的验证

CI 会自动：
1. ✅ 编译 MIPS 版本
2. ✅ 验证测试数据
3. ✅ 检查二进制文件一致性

### 4.3 发布前的验证

在发布前应该：
1. ✅ 运行 `check-targetfunctions` 验证所有 MIPS 变体
2. ✅ 在 QEMU 中运行测试（如果可能）
3. ✅ 在实际设备上测试（如果有）

## 5. 验证工具和脚本

### 5.1 测试数据构建脚本

```bash
# 构建单个架构的测试数据
./tests/core/targetfunctions/rebuild.sh mips

# 构建所有架构的测试数据
./tests/core/targetfunctions/rebuild.sh
```

### 5.2 VM 测试脚本

```bash
# 在 MIPS 模拟器中运行测试
./tests/run-linux-vm.sh mips
```

### 5.3 验证脚本示例

```bash
#!/bin/bash
# verify-mips.sh

set -e

ARCH=$1
if [ -z "$ARCH" ]; then
    echo "Usage: $0 <mips|mipsel|mips64|mips64el>"
    exit 1
fi

echo "Building test data for $ARCH..."
./tests/core/targetfunctions/rebuild.sh "$ARCH"

echo "Checking for changes..."
if git diff --quiet tests/data/targetfunctions-linux-$ARCH.so \
                   tests/data/specialfunctions-linux-$ARCH.so; then
    echo "✅ No changes detected - implementation is correct"
    exit 0
else
    echo "❌ Changes detected - review the diff:"
    git diff tests/data/targetfunctions-linux-$ARCH.so \
             tests/data/specialfunctions-linux-$ARCH.so
    exit 1
fi
```

## 6. 验证覆盖范围

### 当前验证覆盖

| 功能 | 编译验证 | 测试数据验证 | 运行时验证 | 实际使用 |
|------|---------|-------------|-----------|---------|
| **Writer** | ✅ | ✅ | ❌ | ⚠️ |
| **Relocator** | ✅ | ✅ | ❌ | ⚠️ |
| **Interceptor** | ✅ | ✅ | ⚠️ | ✅ |
| **Stalker** | ✅ | ❌ | ❌ | ❌ (不支持) |

### 验证强度

1. **编译验证** - 基础验证，确保代码能编译
2. **测试数据验证** - **关键验证**，确保生成的代码正确
3. **运行时验证** - 完整验证，需要测试环境
4. **实际使用** - 最终验证，在真实场景中使用

## 7. 常见问题和解决方案

### 问题 1：测试数据验证失败

**症状**：`check-targetfunctions` 任务失败

**原因**：
- MIPS Writer/Relocator 实现有变化
- 编译器版本或选项变化
- 代码逻辑错误

**解决**：
1. 检查代码变化是否合理
2. 如果合理，更新测试数据：`git add tests/data/*.so`
3. 如果不合理，修复代码

### 问题 2：无法运行测试

**症状**：没有 MIPS 测试环境

**解决**：
1. 使用 QEMU 设置模拟器
2. 使用 `run-linux-vm.sh` 脚本
3. 在实际设备上测试

### 问题 3：功能不工作

**症状**：在实际使用中发现问题

**解决**：
1. 检查是否是最新版本
2. 查看是否有已知问题
3. 提交 bug 报告

## 8. 最佳实践

1. **每次修改 MIPS 代码后**：
   - 运行 `check-targetfunctions` 验证
   - 检查测试数据是否有变化

2. **发布前**：
   - 验证所有 MIPS 变体（mips, mipsel, mips64, mips64el）
   - 在模拟器或实际设备上测试

3. **持续改进**：
   - 添加架构特定测试（如果可能）
   - 改进验证流程
   - 文档化验证方法

## 9. 总结

MIPS 功能验证主要通过：

1. ✅ **自动化验证**（CI/CD）：
   - 编译验证
   - 测试数据验证（最关键）

2. ⚠️ **手动验证**（可选）：
   - QEMU 模拟器测试
   - 实际设备测试

3. ✅ **实际使用验证**：
   - 在 Frida 项目中使用
   - 用户反馈

**虽然没有架构特定的单元测试，但 `check-targetfunctions` 任务提供了关键的功能验证**，确保 MIPS Writer 和 Relocator 的实现是正确的。
