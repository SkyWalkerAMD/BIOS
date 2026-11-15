EXP02 的原厂 capsule 固件签名已被数学验证为无效。原版两级签名均通过；EXP02 仅保留的认证层签名通过，覆盖固件内容的签名失败。纯 Python 按标准实现验签与本机 OpenSSL 4.0.2 独立验签的四项结果一致。因此，EXP02 不能宣称已具备原厂认证的正式可刷写资格；实际更新器是否执行该验证尚未测试。

输入被固定为原版 CAP `aba26bf927de341f1859dd6b5f35645564d5aea104fb26bcc7b5a98bcd96b0b3`、EXP02 `95a95856ae9ed393c8ab313ae7763edf9d30534f423f77c894d11d7be6a46a0e`。生产驱动 `da52a08f0e477867f4f08e3d1514b156be1ac67fa3bc9c47d09272a869aaf2e2` 和现有固件集成验证报告也被绑定。本次没有连接设备、写固件、修改输入文件或尝试绕过保护。

封装为 AMI Aptio signed capsule：GUID `4A3CA68B-7723-48FB-803D-578CC1FEC44D`，头长 4096 字节，固件体为 64 MiB。头内存在 `WIN_CERTIFICATE_UEFI_GUID` 和两组 RSA-2048/SHA-256 数据。这些字段的位置可与 [UEFITool 的公开解析结构](https://github.com/LongSoft/UEFITool/blob/new_engine/common/ffs.h)及 [UEFI 的证书结构](https://uefi.org/specs/UEFI/2.11/32_Secure_Boot_and_Driver_Signing.html)对照。该 AMI 扩展的实际编码通过 RSASSA-PSS 验证，不能照搬 UEFI 单块 PKCS1-v1_5 示例。

对这两个固定输入，验证出的签名关系如下。算法实现依据 [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017.html)，使用 SHA-256、MGF1-SHA-256、8 字节 salt、指数 65537。

| 验证层 | 被签名消息 | 原版 | EXP02 |
|---|---|---|---|
| 固件层 | ROM 区域表中 `attributes & 0x200` 的区域按表序拼接，再追加 `CAP[0x458:0x680]`，包括 24 字节零终止项 | 通过 | **失败** |
| 认证层 | `CAP[0x20:0x248]`，包含认证头和第一组 RSA 数据 | 通过 | 通过 |

固件层覆盖的区域编号是 `0, 2, 3, 4, 5, 6, 11, 13, 18, 19`。这是通过原版实际签名验证及负例验证得出的本映像规则，不是对所有 AMI 版本的通用格式承诺。根公钥还与原固件 `3FEEC852-F14C-4E7F-97FD-4C3A8C5BBECC` FFS 的 256 字节 raw 数据逐字节一致；本次未读取实机信任锚或验证更新器调用该密钥的运行路径。

唯一变化的 ROM 区域为编号 13：CAP 偏移 `0x3181000`、长度 `0x59F000`，它明确被固件层签名覆盖。全部 3,523,425 个变化字节位于其中，首末变化偏移为 `0x3181088` 和 `0x34E0A5A`。签名消息摘要从 `31f25b39c8134ad91186fc8acfb2f9ca97dc52afb889fad12195b843975f4ef4` 变成 `5b04661093da9c42664e85cf8c4e22219252b7224069797972b875a95ec86b42`。保留原头、更新 FFS 校验和或改文件名均不会使这一原厂签名重新有效。

负例均仅在内存副本中执行：翻转被签名 DXE 的一个字节会使固件层失败；翻转本签名范围之外的 microcode 区域字节不会改变这层验签结果；翻转认证层签名字节会使认证层失败。这也表明该签名范围不能笼统写成“整个 64 MiB 映像”。

Boot Guard 的结论仍为**硬件状态及改动覆盖关系未知**。发行 CAP 的 FIT 指针指向物理地址 `0xFF84F100`、CAP 偏移 `0x3850100`；FIT 只有三项：表头和两项 microcode（type `0, 1, 1`），没有启动 ACM、KM 或 BPM 条目。原版与 EXP02 的 FIT 相同。KM/BPM 类型含义依据 [Intel FIT 1.6](https://cdrdv2-public.intel.com/599500/599500_FW_Interface_Table_BIOS_Spec_Rev1p6.pdf)；硬件根信任与 manifest/IBB 的关系参见 [Intel 的密钥使用说明](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/resources/key-usage-in-integrated-firmware-images.html)。没有可解析的 BPM，就不能给出本板实际 IBB/Post-IBB 范围，也不能从发行包中缺少条目推出实机关闭了 Boot Guard。

BIOS Guard 也没有取得可验证的实机策略或更新包覆盖证据。[Intel 的 Xeon 说明](https://www.intel.com/content/www/us/en/developer/articles/technical/xeon-processor-scalable-family-technical-overview.html)区分启动验证与 BIOS 更新保护；该通用资料不是这块主板启用状态的证明。原始及修改映像的标记扫描、原版解压后的 2057 个叶节点扫描没有发现 KM/BPM 等标记，但这些扫描仅属辅助观察，不能证明硬件保护不存在。ME 内的 OEM Key Manifest 分区也不能直接当作 BIOS FIT 的 Boot Guard KM。

下一步所需证据是厂商授权的自定义固件签名/更新路径、带来源记录的实机只读 SPI/BIOS 捕获及平台对应的安全状态、该型号更新和恢复机制的明确支持条件，以及已有集成审计尚未完成的真实持久化、冷启动、直接 Del 进入及授权保存验证。此处没有把 RAM 测试或 OVMF 模拟等同于这些验收结果，也没有向任何更新器提交候选映像。

复核命令为 `python verify_capsule_static.py` 和 `python crosscheck_capsule_openssl.py`。结果分别保存在 `capsule_static_review.json` 与 `openssl_signature_crosscheck.json`，其中绑定了脚本、输入、公开派生材料及 OpenSSL 可执行文件的哈希。OpenSSL 调用仅使用公开模数和已有签名，不含私钥或签名操作。
