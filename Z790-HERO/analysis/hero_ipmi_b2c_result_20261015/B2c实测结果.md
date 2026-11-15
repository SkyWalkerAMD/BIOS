# B2c 实测结果：通信恢复已确认，等待执行 I

2026-10-15 上传日志，46,815 字节，SHA-256 `f78c02fbfe358459a2fd4354ef7ac2dd06c4e81e310bac1893ad2197b5c761a1`。原文件保存在本目录，没有覆盖其他同名日志或历史测试包。

## 已确认的结果

| 项目 | 实机结果 |
|---|---|
| 主板 / BIOS | ROG MAXIMUS Z790 HERO / 3107 |
| 启动状态 | 连续三个 C1；按 K 前仍为 C1 |
| KCS 恢复 | 一次 60 → 00 → 68 握手，3 次写入均成功 |
| 握手返回 | 残留输出 00；接口错误状态字节 01；最终回到 00 |
| 恢复后 | 三个连续 00；Get Device ID 成功，身份与 A2 完全一致 |
| 标准 IPMI 请求 | 163 次，传输、PCI 调用及完成码全部成功 |
| 两次目录扫描 | 各 41 条 SDR、39 个传感器；候选主板目标各 0/16 |
| VERSION_ERR | 两次均为有效置位，response `14 2D 00 00 C0 10 80` |
| I 初始化 | 提示可用，但本次未执行，无 OEM 请求 |
| F 风扇实验 | 一次尝试在检查阶段被拒绝，没有发送任何 F 指令 |
| 退出 | PCI Command 0000 → 0002 → 0000，恢复读回确认 |

恢复时 89/88 的 bit 3 是 Command/Data 标志，本版已正确处理。01 是 GET_STATUS/ABORT 取得的接口状态字节，含义为 Aborted By Command；不能由此追溯最初 C1 的来源，也不能把残留字节 00 当作这个错误码。

163 次标准请求包括 Get Device ID 1 次、SDR 仓库信息 2 次、记录读取 82 次、传感器读取 78 次。两次目录中的 39 个传感器不包含约定的 16 个主板目标，不能把卡自身/PSU 等项目计为 HERO 目标监控成功。

第 337 行已有 I 选项，第 341 行是 `initialize_fan()` 检查失败的提示，随后只执行了 R。没有 `OEM_STEP`、`FAN_STEP` 或 netfn 30 请求。因此阻塞 F 的直接条件是尚未完成当前会话需要的初始化，不是一次已经发出的风扇指令失败。

当前状态与以前 A2 / B1 初始化前一致。以前 B1 初始化后的主板目录此刻已不在当前目录中，但两次实测间发生的操作没有完整记录，不能单凭本日志确定何时或为何失去这些状态。

## 下一次使用同一个 B2c

1. E/P 读取；只有提示 K 时才按 K。
2. 看到 `I = send the candidate OEM sequence ONCE` 后，按键盘字母 **I**（i 的大写，不是数字 1 或字母 L）。无需回车。
3. 等待 `OEM_SEQUENCE_ACCEPTED acknowledged=4/4` 及初始化后扫描；仅当程序提供 F 选项时按 F。如果初始化报错或不提供 F，保留日志。
4. F 完成后等待约 30 秒，按 R 再读取。检查 BMC 网页的 MB_CHA_FAN1，记录实际读数。
5. Q 结束记录，日志关闭后再 Q 返回启动菜单。提供本次新日志。

I 会重新执行此前 B1 验证过的四条候选初始化；F 会修改单项转速映射并启用该传感器扫描。Q 不回滚 BMC 修改。无需更换 B2c、降级 BIOS 或重新刷写固件。

**本次新增里程碑是实机 KCS 错误恢复及恢复后的正常通信。风扇映射、有效 RPM 和自动 BIOS 集成仍待验证。**

协议依据：[IPMI v2.0 rev 1.1，9.10 / 9.18 节](https://www.intel.com/content/dam/www/public/us/en/documents/product-briefs/ipmi-second-gen-interface-spec-v2-rev1-1.pdf)、[Linux v6.12 KCS 状态定义及错误处理](https://github.com/torvalds/linux/blob/v6.12/drivers/char/ipmi/ipmi_kcs_sm.c)。
