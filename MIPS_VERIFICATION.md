# MIPS 架构验证方式

## 概述

虽然 MIPS 没有架构特定的单元测试，但通过以下方式进行验证：

## 1. 编译验证（Compilation Verification）

### CI/CD 中的构建测试

在 `.github/workflows/ci.yml` 中，MIPS 架构会进行**交叉编译验证**：

```yaml
cross:
  strategy:
    matrix:
      include:
        - { id: linux-mips,           opts: '--host=mips-linux-gnu',                                  pkg: g++-mips-linux-gnu          }
        - { id: linux-mipsel,         opts: '--host=mipsel-linux-gnu',                                pkg: g++-mipsel-linux-gnu        }
        - { id: linux-mips64,         opts: '--host=mips64-linux-gnuabi64',                           pkg: g++-mips64-linux-gnuabi64   }
        - { id: linux-mips64el,       opts: '--host=mips64el-linux-gnuabi64',                         pkg: g++-mips64el-linux-gnuabi64 }
```

**验证内容**：
- ✅ 代码能够成功编译
- ✅ 没有编译错误
- ✅ 链接成功
- ✅ 生成正确的二进制文件

**支持的 MIPS 变体**：
- `mips` - MIPS32 大端
- `mipsel` - MIPS32 小端
- `mips64` - MIPS64 大端
- `mips64el` - MIPS64 小端

### ManyLinux 构建

```yaml
manylinux:
  strategy:
    matrix:
      arch: [x86, x86_64, x86_64-musl, armhf, arm64, arm64-musl, mips, mipsel, mips64, mips64el]
```

在 Docker 容器中构建 MIPS 版本，确保：
- ✅ 在隔离环境中编译
- ✅ 使用正确的工具链
- ✅ 生成可用的 devkit

## 2. 测试数据验证（Test Data Verification）

### check-targetfunctions 任务

这是**最重要的验证方式**：

```yaml
check-targetfunctions:
  strategy:
    matrix:
      arch: [x86, x86_64, armhf, armbe8, arm64, arm64be, arm64beilp32, mips, mipsel, mips64, mips64el]
```

**验证流程**：

1. **重新构建测试数据**：
   ```bash
   ./tests/core/targetfunctions/rebuild.sh mips
   ```

2. **检查是否有变化**：
   ```bash
   git status --porcelain tests/data/targetfunctions-linux-mips.so
   git status --porcelain tests/data/specialfunctions-linux-mips.so
   ```

3. **如果有变化，CI 失败**：
   - 这意味着源代码和预构建的二进制文件不一致
   - 需要更新测试数据

**验证内容**：
- ✅ MIPS Writer 生成的代码正确
- ✅ MIPS Relocator 重定位正确
- ✅ 测试库能够正确编译和链接
- ✅ 生成的二进制文件与预期一致

**为什么这很重要**：
- `targetfunctions` 和 `specialfunctions` 是用于 interceptor 测试的库
- 这些库使用 MIPS Writer 和 Relocator 生成代码
- 如果 MIPS 实现有问题，重新构建会产生不同的二进制文件
- CI 会检测到这种差异并失败

## 3. 通用测试（Generic Tests）

### Interceptor 测试

虽然 MIPS 没有架构特定的 interceptor 测试，但**通用 interceptor 测试会在 MIPS 上运行**（如果有 MIPS 测试环境）：

**测试数据支持**：
```c
// tests/core/interceptor-fixture.c
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

**测试内容**：
- 函数拦截基本功能
- 参数传递
- 返回值处理
- CPU 上下文保存/恢复

**限制**：
- ❌ 没有 MIPS 特定的测试环境（CI 中不运行）
- ⚠️ 只能在手动设置的 MIPS 环境中运行

## 4. 实际使用验证（Real-world Usage）

### Frida 项目中的使用

MIPS 实现主要在 **Frida 项目**中使用：

1. **Frida Core** - 使用 Gum 的 MIPS 实现
2. **Frida Server** - 在 MIPS 设备上运行
3. **实际设备测试** - 在真实的 MIPS 设备或模拟器上测试

**验证方式**：
- ✅ 实际设备上的功能测试
- ✅ 用户反馈和 bug 报告
- ✅ 集成测试

## 5. 代码审查（Code Review）

### 实现质量保证

虽然没有单元测试，但通过以下方式保证质量：

1. **代码审查** - PR 审查确保实现正确
2. **架构一致性** - 参考其他架构的实现
3. **代码风格** - 遵循项目规范

## 验证方式总结

| 验证方式 | 自动化 | 覆盖范围 | 频率 |
|---------|--------|---------|------|
| **编译验证** | ✅ | 所有 MIPS 变体 | 每次 PR |
| **测试数据验证** | ✅ | Writer/Relocator | 每次 PR |
| **通用测试** | ❌ | Interceptor | 手动/实际设备 |
| **实际使用** | ⚠️ | 完整功能 | 持续 |

## 为什么没有运行测试？

### CI 限制

在 `manylinux` 任务中：

```yaml
- name: Test
  if: matrix.arch == 'x86' || matrix.arch == 'x86_64'
  run: make test
```

**只有 x86/x86_64 运行测试**，因为：
1. **测试环境限制** - MIPS 模拟器/硬件不易获得
2. **性能考虑** - 模拟器运行慢
3. **维护成本** - 需要额外的 CI 资源

### 测试数据验证的重要性

虽然不运行完整测试，但 **`check-targetfunctions` 任务提供了关键的验证**：

- ✅ 确保 MIPS Writer 生成的代码正确
- ✅ 确保 MIPS Relocator 重定位正确
- ✅ 确保测试库能够正确编译

这是**间接但有效**的验证方式。

## 如何改进 MIPS 验证？

如果要添加完整的 MIPS 测试，需要：

1. **添加架构特定测试**：
   - `tests/core/arch-mips/mipswriter.c`
   - `tests/core/arch-mips/mipsrelocator.c`

2. **设置测试环境**：
   - QEMU MIPS 模拟器
   - 或实际的 MIPS 硬件

3. **在 CI 中运行**：
   ```yaml
   - name: Test
     if: matrix.arch == 'mips' || matrix.arch == 'mipsel'
     run: make test
   ```

4. **添加 Stalker 支持**（如果可能）

## 结论

MIPS 的验证主要通过以下方式进行：

1. ✅ **编译验证** - 确保代码能够编译
2. ✅ **测试数据验证** - 确保 Writer/Relocator 正确（最重要的验证）
3. ⚠️ **通用测试** - 理论上支持，但需要手动环境
4. ⚠️ **实际使用** - 在 Frida 项目中使用和验证

**虽然没有架构特定的单元测试，但 `check-targetfunctions` 任务提供了关键的验证**，确保 MIPS Writer 和 Relocator 的实现是正确的。
