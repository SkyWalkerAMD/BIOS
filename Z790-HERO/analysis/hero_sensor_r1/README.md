# HERO 3001 IPMI 传感器初始化实验版 R1

**2026-09-28 更正：发现 R1 对 PCI 通知 GUID 的解释及硬性启动依赖存在问题；用户新日志的实际 BIOS 已为 3107。请先阅读 [更正记录](CORRECTION-20260928.md)。下文是原 R1 的历史设计与检查记录，不表示该依赖已验证。**

日期：2026-09-20。**已生成修改后的 CAP；未验证实机启动、刷写接受性或传感器读数。它不是已完成验证的 IPMI BIOS。**

用户已说明没有可用的 HERO 专用 IPMI BIOS，本方案不再依赖 ASUS 提供该文件。目标环境按用户提供的信息：HERO BIOS 3001、ASUS IPMI EXPANSION CARD、BMC 1.3.13、BMC_HEADER 已连接，目前看不到主板传感器。

## 文件

- `HERO-3001-IPMI-SENSOR-R1-EXPERIMENTAL.CAP`：离线构建的实验镜像，33,558,528 字节。
- `manifest.json`：输入/输出 SHA-256、每个二进制补丁的地址、原始字节、替换字节及原因。
- `verification.json`：独立重新解析和局部 x64 仿真结果。
- `modules/`：三个适配后的 FFS、内部 PE 映像和变更反汇编。这里的 `.efi` 是组件，不是可独立运行的诊断程序。

CAP SHA-256：

```text
36a5b7058b2522e1366ff51fe7d4ab6e86de9748d4cb24edfb5f203b8d53a282
```

## 实际修改

只在 HERO 原镜像现有固件卷的空闲尾部加入三个 DXE 文件。插入范围为 CAP 文件偏移 `[0x1A47F58, 0x1A5070A)`；实际有 34,154 个字节发生变化，这些位置在原镜像中全部是 `FF`。

原有 717 个 FFS 文件节点全部与源文件逐字节相同，新增后为 720 个。没有移动原有文件、修改原有固件卷边界、重压缩主 DXE 卷，或替换 HERO 的 Setup、PEI、ME、板型标识和传感器硬件表。两个用户原始 CAP 也保持不变。

| 组件 | GUID | R1 处理 |
|---|---|---|
| BMC 检测和传感器参数发布 | `68A0D4CA-9022-474C-BA22-483480DC9A0A` | 等待 PCI 枚举和变量服务后检查扩展卡；清零共享参数缓冲区；改用 ReadyToBoot 触发参数发布；缺少参数时退出 |
| DXE IPMI transport | `6372357A-06D7-43EF-B55C-1964F3DD6916` | 等待扩展卡就绪通知；跳过供体的本地 PCD 令牌 `0x0B` 写入及远程 CMOS 清除处理 |
| BMC 板级参数 | `05602C82-5F85-4735-AF53-053502178D02` | 直接初始化参数；去除 `Setup[0xD0F]` 访问；取消供体风扇策略/S3 回调；替换已核对的五个 HERO HWM 标识 |

供体的 `AmiTseAfterTimeOutGuid` 在 HERO 文件中未找到；R1 使用 UEFI 的 `ReadyToBoot` 事件组 `7CE88FB3-4BD7-4679-87A8-A8D8DEE50D2B`。没有把不存在的通知接口当成已经满足的依赖。

五个 HWM 标识是通过两份固件内的完整 40 字节硬件描述记录匹配的：除标识字段本身外，其余 38 字节相同。对应关系如下。它们不是 IPMI SDR 的传感器编号，也不代表所有传感器已适配。

| ProArt 标识 | HERO 标识 |
|---|---|
| `0x238E` | `0x25CA` |
| `0x239A` | `0x25D6` |
| `0x2394` | `0x25D0` |
| `0x23C0` | `0x2600` |
| `0x23D4` | `0x2614` |

R1 将风扇来源参数固定为 BIOS，并关闭供体的 BMC 风扇配置与 EC 风扇掩码写入路径。这里的“关闭”是没有启用这些供体操作，并不表示已经验证风扇实时遥测可用。

## 已做的验证

UEFIExtract A75 独立重新解析了最终 CAP，确认三个新文件的 GUID、FFS/PE 校验和、依赖表达式及文件结构。对比确认原有全部 FFS 节点保持一致，修改仅落在上述原空闲区。原固件已有的微码校验提示和 `0x1CC1090` 处 Unknown 00h section 没有被这次修改改变。

Unicorn 2.1.4 中的六个局部 x64 仿真场景通过：缺少 ServerSetup、存在 ServerSetup、没有扩展卡、参数分配失败、参数尚未初始化、事件创建失败。仿真还检查了栈对齐、被调用者应保留的寄存器及分配缓冲区边界。

正常模拟路径只读取 `ServerSetup`，没有访问 HERO 的 `Setup`；记录到的变量写入仅为临时 `BmcPresentVar`。在模拟成功响应下，发布路径发送的 OEM 命令是 NetFn `0x30` 的 `0x90`、`0x94`、`0x92`、`0x02`，没有进入供体风扇控制路径。

**这些 EFI/BMC 响应全部是测试桩生成的。仿真没有验证完整 DXE 启动、真实 KCS/SMBus 通信、BMC 对命令的接受程度或实际传感器精度。** transport 的物理通信实现沿用供体，本次没有对它做完整硬件仿真。

## 尚未解决的实机问题

1. 外层固件卷中新驱动在 HERO 实机上的发现和调度，需要通过驱动加载/协议记录验证。当前镜像可以被解析，不等于已经证明三个驱动会运行。
2. BMC 的传感器激活列表仍沿用供体，尚未用目标卡的 SDR 输出确认编号、名称、通道和换算。新镜像可能只有部分传感器可用，也可能仍然没有读数。
3. 供体风扇/EC 配置被排除，其是否为特定传感器实时读取的必要条件尚未确认。需要区分“出现 SDR 记录”“开机快照”“持续变化的实时读数”。
4. 没有加入 PEI/SMM IPMI、S3 恢复、完整 Server Management 菜单、远程刷写、配置导入或 watchdog/FRB 组件。本版本不能代表这些功能已移植。
5. 本机分析环境不是目标 HERO，没有在目标上执行任何操作。

## 刷写状态

这是对原厂签名 CAP 内容的修改，保留原 4 KiB 头不等于获得 ASUS 重新签名。没有确认 EZ Flash/FlashBack 是否接受它，也没有确定目标机 Boot Guard 状态。**目前不应将此文件当作可直接刷入的成品。**

进入实机写入验证之前，需要针对目标 HERO 核实可恢复的完整 SPI 备份和恢复方法。官网下载 CAP 不等于包含该板个体数据的实机备份。本次未提供强制刷写、绕过认证或替换板型识别的步骤。

现阶段最有用的只读记录仍是目标 BMC 的 SDR 和传感器列表。密码用 `-a` 交互输入：

```text
ipmitool -I lanplus -H <BMC_IP> -U <用户名> -a mc info
ipmitool -I lanplus -H <BMC_IP> -U <用户名> -a sdr elist all
ipmitool -I lanplus -H <BMC_IP> -U <用户名> -a sensor list
```

## 复核

构建脚本位于上一级 `build_sensor_r1.py`，验证脚本为 `verify_sensor_r1.py`。它们依赖本项目已有的两份原始 CAP、UEFIExtract 完整拆解目录、`inventory.json` 和 `tools/pydeps` 中的 pefile、capstone、unicorn。构建脚本不会写入硬件。

标准调度机制的参考是 [TianoCore DXE Dispatcher 源码](https://github.com/tianocore/edk2/blob/master/MdeModulePkg/Core/Dxe/Dispatcher/Dispatcher.c)，它说明了固件卷文件发现及 DEPEX 调度方式；这不是 HERO 实机派发成功的证据。板级判断与补丁来自用户提供固件的静态分析。
