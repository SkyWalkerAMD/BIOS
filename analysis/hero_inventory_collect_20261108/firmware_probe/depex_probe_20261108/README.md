# .71 I2B 身份复核与启动依赖探针

本目录只做离线分析，并提供可由 I3a 调用的只读采集模块。没有修改 CAP、FFS、已发布 ISO 或实机固件。

## I2B 实机证据

输入是 `analysis/hero_ipmi_continued_live_20261108/hero71-fw-i2b.TXT`。按原始 CRLF 字节复核：6495 字节，CRC32 `A58AC3DF`，SHA256 `4f12cee70e9f0a0339b0d114927f7a46bcdf45322bc66ab7e3119d223d41e3b6`。

两个文件都存在于第 6 个可见固件卷，预分配缓冲的 ReadFile 成功。本次没有使用 NULL 缓冲回退。相应 API 未发现，330 个 LoadedImage 中也没有匹配的 FV 文件路径；其中 328 个映像有 FV 文件路径，没有记录到不可读或 NULL 路径。

| 文件 | 实机 body 字节 / CRC32 | 实机 PE 字节 / CRC32 | 本地对应 |
|---|---|---|---|
| R2 | 22096 / `C1E922F8` | 22016 / `1D66102E` | 归档 R2；RC3 与早期 RC4 共用 |
| P5/P6 GUID | 371816 / `8346283A` | 371712 / `BDB6FE43` | `container-441b61136974` 中的早期 RC4 P6 |

大小、两层 CRC32 及完整 DEPEX 字节都与上述本地模块对应。P5/P6 文件与本地 RC2/RC3 的 P5、较新的 RC4 P6 均不对应。因此不能将这次现象描述为“固件内没有 R2”。

这些是模块指纹，CRC32 不具备抗碰撞保证。实机没有导出完整模块，也没有计算其 SHA256 或整片 SPI 哈希。归档 CAP 的 SHA256 `441b61136974278a0c6fc0d46edc159c1f1557c981ae9e4a4b42b67eb65fba0f` **只标识本地参照包，不能据此断言整份在机固件就是该 CAP**。逐项计算结果见 `i2b-analysis.json`，可运行 `analyze_i2b.py` 重现。

## 依赖结论

实机字节按官方 PI 操作码解析为：

- R2：`PciEnumerationComplete AND VariableWriteArch`。
- P6：`HiiDatabase AND HiiString AND VariableWriteArch`。

PUSH 的 GUID 字节序、AND 栈深和 END 都合法，也与当前构建脚本的依赖字节一致。第二个 P6 HII 依赖是 **HiiString**；HiiPackageList 不参与这两个表达式。没有发现把 AND 写错或错用 GUID 的证据。

I2B 尚未读取这些协议的存在性。共同的 VariableWriteArch 依赖是否未满足仍是假设；不能据此删除依赖或修改 SPI。仅凭当前 LoadedImage/API 缺失，也不能区分未派发、入口失败后卸载或之后被移除。后续应用阶段的查询反映采集时刻，不能还原早期 DXE 派发过程。

VariableWriteArch 是允许 NULL 接口的标记协议。**LocateProtocol 返回 EFI_SUCCESS 即算存在，不能用接口指针非空作为存在条件。** 这已在探针和测试中处理。

## I3a 集成接口

将 `depex_probe.c` 与 `depex_probe.h` 加入 I3a 构建，并在其 D 诊断路径调用：

```c
typedef void (*DP_APPEND)(void *context, const char *text, size_t bytes);
ES depex_probe(ST *st, DP_APPEND append, void *context);
```

接口使用 I3a 的 `efi_min.h`；输出回调应将指定长度的 ASCII 字节追加到已有日志。每次输出上限 8192 字节。模块不依赖 libc，不申请内存，不写变量，不调用 BMC、PCI 或被定位到的协议方法。

它执行五次 LocateProtocol（上述四个实际依赖，加仅供对照的 HiiPackageList），及一次 GetVariable。表达式结果记录为 `DP_R2_DEPEX_AT_CAPTURE` 和 `DP_P6_DEPEX_AT_CAPTURE`：0 为假，1 为真，2 为未知。EFI_NOT_FOUND 属于可解释观察；其他错误会使本次结果标记不完整。

变量是 `NetworkStackVar`，GUID `d1405d16-7afc-4695-bb12-41459d3695a2`。缓冲固定为 64 字节，记录返回长度、属性、状态；只在成功且长度与哨兵检查通过时导出原始字节。官方 HERO 3107 的 SnpDxe 入口读取 8 字节，并以第 0 字节决定是否继续安装网络驱动。本探针仅记录，不更改它，也不解读其余字节。出处和指令字节复核见 `provenance.json`。

## 已完成验证

`build.py` 已将实际 C 模块编译为 x64 目标对象和宿主测试 DLL。`test_probe.py` 的 9 个测试全部通过，覆盖 NULL 标记、缺失依赖、三值逻辑、无关 HiiPackageList、变量原文与属性、缺失变量、超长/损坏响应、64 字节边界、无效参数与重入。

以上 9 项属于离线服务替身测试；探针后续的实机结果单列在下一节。`mock-probe-transcript.txt` 明确是模拟输出，不能当作 .71 现况。I2B 的真实硬件证据保留在原路径，未被改写。

## I3B 后续实机结果（2026-11-08）

新证据是 `analysis/hero_ipmi_continued_live_20261108/hero71-i3b-preflight.TXT`。本目录的 `analyze_i3b.py` 使用 I3B 原始解码器重新校验全部 67 个 QR 字节帧，再与该 TXT 逐字节比较：34068 字节，CRC32 `BA49E292`，SHA256 `426ba4de451d8459c3b9900d0da32db3a93bd8dc8266a28a479307ed762a2c05`。完整结果见 `i3b-live-analysis.json`。

| 协议 | LocateProtocol 返回 | 接口 | 采集时存在 |
|---|---|---|---|
| PciEnumerationComplete | EFI_SUCCESS | NULL | 是 |
| VariableWriteArch | EFI_SUCCESS | NULL | 是 |
| HiiDatabase | EFI_SUCCESS | 非 NULL | 是 |
| HiiString | EFI_SUCCESS | 非 NULL | 是 |
| HiiPackageList（对照项） | EFI_SUCCESS | 非 NULL | 是 |

R2 和 P6 的实际 DEPEX 表达式在此时均为真。“当前缺少 VariableWriteArch”这一解释已被这次查询排除；没有依据通过删除此依赖修复。两个 NULL 接口恰好验证了按状态码判断标记协议存在性的必要性。

NetworkStackVar 返回成功，长度 8，属性 `0x7`，原文 `0101010000010000`，第 0 字节为 1。因此在此时，已分析的 SnpDxe 入口不会因为变量不存在或首字节为零而退出。该观察不能保证网络驱动后续初始化必然成功。

本次记录还包含 `I3B_INVENTORY_SOURCE_EXACT=1` 及 `I3B_PREFLIGHT_READY_NO_WRITES_SENT`。这些是 I3B 采集/预检状态；它们不等于 R2/P6 已加载或全功能验证通过。

与 I2B 合并判断：文件内容存在且对应归档模块，随后依赖查询也满足，但 I2B 时目标 LoadedImage/API 未发现。I3B 没有重新测量这两份模块的哈希或目标 API，也不能重建此前 DXE 历史。下一步需要从实际对应版本的加载和入口返回路径继续找证据；入口失败、未派发、加载策略或之后卸载都仍是待证实解释。本次没有改写固件或调用任何控制操作。
