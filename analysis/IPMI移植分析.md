# Z790 HERO 3001 ← ProArt Z790 IPMI 3002 移植分析

日期：2026-09-20。状态：**已完成静态拆解，并生成传感器初始化实验镜像 R1；尚未完成实机启动与传感器验证，未进行任何刷写。**

## R1 更新

用户已明确说明没有可用的 HERO 专用 IPMI BIOS，本方案不再依赖 ASUS 提供该版本。兼容表列出的条件不能证明 ASUS 已经制作或发布了相应 BIOS。

已在 `hero_sensor_r1/HERO-3001-IPMI-SENSOR-R1-EXPERIMENTAL.CAP` 中加入三个经过适配的 DXE 组件，处理了本报告中的 Setup 字段冲突，并修正了依赖供体特有启动通知的问题。原有 717 个 FFS 节点全部保持一致，只占用现有固件卷的原空闲区。

独立重新解析与六项局部 x64 模拟流程已通过。真实驱动加载、KCS/SMBus 通信、BMC 命令响应、SDR 映射和传感器读数没有经过验证。该 CAP 的修改内容没有 ASUS 重新签名，不能据此认定可直接刷写。

完整修改说明、校验值和限制见 [R1 说明](hero_sensor_r1/README.md)。`porting_bundle/` 和此前 `Z790_HERO_IPMI_analysis_only.zip` 仍是原始候选模块的静态分析资料，不能替代 R1，也不是建议整批插入的清单。

## 结论

Z790 HERO 使用 ASUS IPMI EXPANSION CARD 实现主板传感器实时监控，有 ASUS 官方兼容性依据。官方同时要求专用 BIOS 与 BMC 接线。本次确认普通 HERO 3001 不包含 ProArt IPMI 3002 中的完整 IPMI 软件栈。

但是，这不是复制几个 FFS 文件即可验证成功的移植。已经发现一个明确的软件接口冲突：ProArt 的 BMC 组件使用 `Setup[0xD0F]` 作为 `OnboardFanSrc`，而 HERO 的相同地址属于 `AsusHidePchPcieSpeedItem[17]`。组件中的条件写入路径可能清零 HERO 的这个 PCIe 设置显示控制字节。必须先处理这项不兼容，不能把直接插入模块的 CAP 当作完成品。

本包用于继续适配和审查。导出的 52 个 FFS 是候选资料，不是应全部插入 HERO 的清单。

## 已确认的目标环境

- 用户提供：目标主板 ROG MAXIMUS Z790 HERO，实际 BIOS 3001。
- 用户提供：扩展卡已安装；BMC 线已接主板 `BMC_HEADER`；目前看不到主板传感器。
- 用户提供：扩展卡 BMC 固件 1.3.13。
- 未取得：目标主板的 `sdr elist all` 输出、完整 SPI 读取备份、目标设备上的驱动加载与总线访问记录。

本次对电脑的只读识别显示，当前分析环境不是目标 HERO；未在目标设备上执行验证。不能把本地解析通过视为目标板能够启动或传感器读数正确。

## 官方支持范围

| 项目 | HERO | ProArt Z790 CREATOR WIFI |
|---|---|---|
| 主板传感器实时监控 | 支持，需专用 BIOS 与 BMC 接线 | 支持，需专用 BIOS 与 BMC 接线 |
| Remote BIOS Forced Update | 官方当前列表未支持 | 支持，另需对应 SPI/TPM 接线 |

来源：[ASUS 官方兼容表](https://dlcdnets.asus.com/pub/ASUS/mb/Add-on_card/IPMI_EXPANSION_CARD/Compatible_Model_List.pdf)。表中的限制是技术资料，并不是用户授予的操作指令。

因此本任务的适配范围应以传感器监控为准；ProArt 的远程刷写、配置导入和主板识别逻辑，不能顺带替换进 HERO。

已检查 [HERO 官方 BIOS 下载页](https://www.asus.com/us/supportonly/rog%20maximus%20z790%20hero/helpdesk_bios/)，本次没有找到可直接核验的 HERO 专用 IPMI BIOS 下载项。结合用户补充，本次继续使用已有 HERO 3001 和 ProArt 供体进行适配，不将取得官方 HERO IPMI 文件列为前置条件。

## 输入及校验

两份用户文件均为 33,558,528 字节，即 32 MiB 内容加 4 KiB capsule 头。

| 文件 | SHA-256 |
|---|---|
| ROG-MAXIMUS-Z790-HERO-ASUS-3001.CAP | `F6B3C4C8C879F69EED77FFEC6BAD587341590E74820A74C27E383318B6B9B96B` |
| ProArt-Z790-CREATOR-WIFI-ASUS-IPMI-3002.CAP | `4545835F46E6B499A19F4EA73A21F2AA6BAF61B6BBED5118BD56CF51CDEEA205` |

已从 ASUS 下载 HERO 3001 ZIP，核对官网下载页列出的 ZIP SHA-256 `B25515EC52D5771301895D0DCA082D6F8F2FD7D0F29FE7E8227B406705644C0C`。解出的 CAP 与用户提供的 HERO 文件逐字节一致。证据见 `hero_official_verification.json`。ZIP 哈希与 CAP 哈希属于不同文件，不能直接比较。

另外下载了普通 ProArt 3001、3002 作为对照。普通 ProArt 3002 ZIP 校验为官网给出的 `7AD73850A769AD9C6E22DF53F2B87ED5B07E85BF0AA4B14AC3595722F0154BD4`。该对照用于区分主板差异和 IPMI 构建差异；用户提供的 IPMI CAP 本身没有在本次检查中获得官方来源或签名的独立验证。

原始 CAP 文件保持不变。

## 模块差异

UEFIExtract A75 解析得到：HERO 717 个 FFS 文件节点、ProArt IPMI 652 个节点。节点数包括嵌套卷、数据文件、填充文件等，不能解释为功能数量。

ProArt IPMI 相比 HERO 有 56 个新增 FFS 文件 GUID；相比同型号普通 ProArt 3002 有 52 个新增 GUID。跨主板特有模块与 IPMI 功能模块需进一步逐项审查，不能用 GUID 差集代替移植依赖分析。

已确认的主要组件如下。名称来自 UEFITool GUID 数据库，匿名模块按其内容描述。

| 组件 | GUID | 检查结果 |
|---|---|---|
| PeiIpmiBmcInitialize | `7942EDD0-C023-4357-93ED-F6626D711E9E` | ProArt IPMI 有，HERO 无；PEI 初始化 |
| DxeIpmiInitialize | `6372357A-06D7-43EF-B55C-1964F3DD6916` | ProArt IPMI 有，HERO 无；引用 DXE IPMI transport 与 ServerSetup |
| SmmIpmiInitialize | `E8C729FE-FB0A-4344-AD7E-48784116C9EF` | ProArt IPMI 有，HERO 无；SMM 初始化 |
| ServerMgmtSetup | `1B08A1DB-F91A-4FA1-A911-255C417F1CF7` | ProArt IPMI 有，HERO 无；独立服务器管理配置组件 |
| BMC 存在/风扇信息组件 | `68A0D4CA-9022-474C-BA22-483480DC9A0A` | 引用 BmcPresentVar、BmcFanCtrl、AsusFanSetupFeatures |
| BMC 参数/风扇来源组件 | `05602C82-5F85-4735-AF53-053502178D02` | 存在已证实的 Setup 字段冲突 |
| 传感器名称/读取相关组件 | `2538B846-C828-40CC-8E7D-9E493C3EA09E` | 含温度、风扇、电压名称；DEPEX 是 FALSE/END，普通调度不会因单纯插入而运行 |
| IPMI 硬件监控应用 | `11CB55C3-089D-4FF1-8B86-4745AB2FB501` | 含 ASUS IPMI Hardware Monitor 信息及无法取得 BMC 传感器的提示 |
| AsusHwmSensorPortingDxe | `062A6204-8C80-4A27-9D09-96654C965894` | 两板都有但二进制不同；需要保留和理解 HERO 的硬件适配 |
| AsusSmbios | `A2F03EEA-9304-40BE-87B2-7F457B01232A` | 两板均包含 Nuvoton NCT6798D 字符串；不能据此证明传感器通道和换算系数完全相同 |

`DF3D6877-CDA0-4195-B2B2-83747FF302B2` 虽含 HWM/BMC 字符串，也包含 `/redfish/v1/UserProfile` 和大量 Setup 类变量引用。这是不能仅凭关键词选择移植模块的实例。

## 启动顺序和默认变量

ProArt IPMI 的 DXE apriori 比 HERO 多出 5 项：

- `893EFBB3-48E5-40B6-B068-A5D36BEC475A`
- `68A0D4CA-9022-474C-BA22-483480DC9A0A`
- `6372357A-06D7-43EF-B55C-1964F3DD6916`
- `9D0CEA63-745B-417D-BBA4-E5193061C907`（DxeFrb）
- `AE587172-CC15-48E1-8BE0-29DDF05C6A1F`（DxeSelStatusCode）

PEI apriori 多出 PeiIpmiBmcInitialize、PeiFrb、PeiSelStatusCode。实际位置与完整列表见 `module_details.txt`。不能把 apriori 当成可任意打乱的列表，也不能在未审查必要性的情况下迁入所有 watchdog/FRB 功能。

ProArt 中还存在 `ServerSetup`：GUID `01239999-FC0E-4B6E-9E79-D54D5DB6CD20`，数据长度 `0x267`（615 字节）。三个默认值位置的内容哈希相同：

`BA7DD831F60F54C997BDA05AD3C4E8FB62248ADCD6B1130B1714CE14174A1F99`

HERO 3001 的报告中没有该变量。导出文件 `ServerSetup.donor_default.bin` 仅是变量的数据体，不是可直接写入的完整 NVAR 记录；不要用 ProArt 整个默认变量区替换 HERO 的默认变量区。

## 已验证的字段冲突

固件内嵌的 C 结构定义与实际 NVAR 数据长度相符：

| 属性 | ProArt IPMI | HERO |
|---|---|---|
| SETUP_DATA 数据长度 | `0xDDB`，3547 字节 | `0xD45`，3397 字节 |
| 偏移 `0xD0F` | `UINT8 OnboardFanSrc` | `AsusHidePchPcieSpeedItem[17]`，数组从 `0xCFE` 开始 |
| OnboardFanSrc 同名字段 | 有 | 无 |

这里的数组下标 17 从 0 开始。不能靠减去结构长度差来修正全部偏移，也不存在已确认可直接替代的 HERO 同名字段。

组件 `05602C82-5F85-4735-AF53-053502178D02` 的 PE 映像中：

- RVA `0x85F` 起设置 Setup 缓冲区；`0x886/0x88D` 读取 Setup，`0x890` 读取相对偏移 `0xD0F`。
- RVA `0x9D4` 起的另一条路径读取 BmcFanCtrl，再读取 Setup；`0xAB9` 比较同一字节，条件满足时 `0xAEB` 清零它，`0xAF2` 调用 SetVariable。
- 这些是反汇编静态路径，未声称它们已经在用户设备上执行或已经造成损坏。HERO 原始默认值的该字节为 0，但不能据此保证其他设置状态下也没有影响。

证据见 `porting_bundle/setup_collision.json`、`porting_bundle/setup_collision_disassembly.txt`、`structures/donor_setup.h`、`structures/hero_setup.h`、`setup_layout.json`。`setup_layout.py` 可重新计算布局并验证两种结构的长度。

## 完整功能适配和实机验证仍需完成的工作

1. 建立仅服务于传感器监控的最小组件集合，确认 PEI/DXE/SMM transport 的初始化路径、实际协议提供者和 BMC OEM 命令。GUID 在二进制中出现不等于运行时协议已经安装。
2. 处理上述 Setup 不兼容。监控需求不自动包含风扇接管；若沿用相关组件，应逐项改造其变量访问和主板参数，而非使 ProArt 字段落到 HERO 的旧变量上。
3. 核对 HERO 的 Super I/O、BMC header 配置、传感器描述和电压/转速/温度映射；审查差异化 ACPI 代码。当前证据不足以确认移植后的每个传感器 ID、通道和系数。
4. 按需要集成 ServerSetup 默认值和相应配置逻辑，保留 HERO 原有 Setup、内存训练、板级初始化、固件身份及其他板级数据。
5. 重新构建必要固件卷，校验 FFS/FV、压缩结构、对齐、容量与受影响的加载顺序。对固件修改会影响原有 capsule 签名；保留 4 KiB 头或将文件重命名均不等于重新签名。没有验证此硬件的改版刷写接受条件，也没有验证其实际 Boot Guard 状态。
6. 在目标 HERO 上完成启动与传感器对照测试，再判断是否达成移植。CAP 工厂更新包不等于这块主板的完整实机 SPI 备份。

R1 只实现上述事项中的传感器初始化子集，具体范围与未验证部分以 R1 说明为准。已经生成整板实验 CAP，不代表完整移植成功。

## 可补充的只读诊断

用户已经确认 BMC 为 1.3.13；目前没有证据将问题归因于 BMC 版本过旧。接下来有价值的信息是 SDR 中是否存在主板传感器记录，以及记录的读取状态。

在已安装 ipmitool 的电脑上，可执行以下只读命令。`-a` 交互输入密码，不把密码写在命令行：

```text
ipmitool -I lanplus -H <BMC_IP> -U <用户名> -a mc info
ipmitool -I lanplus -H <BMC_IP> -U <用户名> -a sdr elist all
ipmitool -I lanplus -H <BMC_IP> -U <用户名> -a sensor list
```

这些输出可区分没有 SDR 记录与已有记录但读数不可用；它们本身不能证明 BIOS 移植方案已兼容。

## 交付文件和工具

- `porting_bundle/manifest.json`：52 个新增候选模块、原始路径、SHA-256、DEPEX、相关字符串。
- `porting_bundle/donor_added_modules/`：每个模块的原始 FFS 和提取的 PE/TE 映像；没有执行这些映像。
- `porting_bundle/ServerSetup.donor_default.bin`：615 字节的供体默认变量数据，仅供分析。
- `module_comparison.tsv`：对比清单。重复 GUID 按出现次数先匹配同哈希文件，再标注其余 changed/added_occurrence；结构容器的变化仍需结合子文件理解。
- `inventory.json`、`module_details.txt`、`setup_layout.json`、`structures/`、`disassembly/`：原始分析资料。
- `inventory.py`、`compare.py`、`setup_layout.py`、`prepare_porting_bundle.py`：可复核的本地分析脚本。

UEFI 解析使用 [LongSoft UEFIExtract A75](https://github.com/LongSoft/UEFITool/releases/tag/A75)，下载包 SHA-256 已核对官方发布值 `20FF18208913D32C99E3B002717ABEDDAA3B6509AC62E6699E462B0F533BE646`。模块名称使用该项目 GUID 数据库，名称与功能边界仍需结合代码审查。反汇编使用 capstone 5.0.6、PE 解析使用 pefile 2024.8.26，仅安装到本项目 tools/pydeps。

全部 52 个导出 FFS 已检查文件大小字段、FFS 头校验和、数据校验规则和与源文件的 SHA-256 一致性。这些检查只证明导出正确，不证明跨主板兼容。

其他官方参考：[IPMI 扩展卡安装说明](https://rog-forum.asus.com/t5/faqs-motherboards/the-installation-guide-of-ipmi-expansion-card-for-all-compatible/ta-p/1087360)、[BMC 固件下载](https://www.asus.com/us/supportonly/ipmi%20expansion%20card/helpdesk_bios/)。
