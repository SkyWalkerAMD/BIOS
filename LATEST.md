# 最新 BIOS 与测试进展

本页收录本地最新完整镜像和仍在测试的组件。实验候选、NOFLASH、UNBOUND、TESTONLY、TCG-ONLY 均保持明确标记。

## 完整镜像与参考基线

| 工程 | 版本 | 下载 | 状态 |
|---|---|---|---|
| Z790-HERO | 3107 / RC5 R5 S23 CANDIDATE05 | [下载](https://github.com/SkyWalkerAMD/BIOS/releases/download/local-bios-progress-20261115/Z790-HERO-latest-local-progress.zip) | 实验固件候选；最终 CAP 刷写、冷启动菜单、F10 写入和官方恢复均未完成验收。 |
| W790-ACE | 1904 / CANDIDATE05 / USB FlashBack 当前主线 | [下载](https://github.com/SkyWalkerAMD/BIOS/releases/download/local-bios-progress-20261115/W790-ACE-latest-local-progress.zip) | 当前 USB FlashBack 实验候选；最终接受、原生 Setup 整体运行和可恢复刷写尚未完成验收。旧 e330 工程签名文件不是默认候选。 |
| W790E-SAGE-SE | 1904 / NATIVE12 | [下载](https://github.com/SkyWalkerAMD/BIOS/releases/download/local-bios-progress-20261115/W790E-SAGE-SE-latest-local-progress.zip) | 最新已找到的完整集成审查镜像，INTERNAL / UNSIGNED / NOT RELEASE READY；NATIVE13 等更新源码属于后续组件和安装器进展，不是新的完整 BIOS 交付。 |
| W890E-SAGE-SE | 0603 / 原厂分析基线 | [下载](https://github.com/SkyWalkerAMD/BIOS/releases/download/local-bios-progress-20261115/W890E-SAGE-SE-latest-local-progress.zip) | 本地保存的原厂分析基线；项目仍为部分分析，没有已完成的修改版 BIOS。不声称这是厂商当前在线最新版本。 |
| ProArt-Z790-CREATOR-WIFI | IPMI 3002 / 供体参考基线 | [下载](https://github.com/SkyWalkerAMD/BIOS/releases/download/local-bios-progress-20261115/ProArt-Z790-CREATOR-WIFI-latest-local-progress.zip) | 本地保存的 IPMI 供体参考固件，不属于独立修改版交付。不声称这是厂商当前在线最新版本。 |

## 最新测试组件

[下载最新测试组件与对应源码](https://github.com/SkyWalkerAMD/BIOS/releases/download/local-bios-progress-20261115/BIOS-latest-test-components.zip)

包内包含 11 个二进制／启动介质和 2,465 个此前已公开的相关源码文件。它们不是 11 份完整 BIOS。

| 工程 | 测试进展 |
|---|---|
| HERO | R5 传感器、P6 S23 |
| W790 ACE | 当前 CANDIDATE05 驱动 |
| W790E SAGE SE | NATIVE13 RAMTEST09 EFI / NOFLASH ISO、Provider15 Diagnostic09 |
| W890E SAGE SE | Delta07 诊断、Runtime02、Recovery03、Management04、TCG-only Installer04；更新的 UI08／导航08 等源码同包收录 |

W790E 的 NATIVE13 是更新的组件与安装器进展，没有用它冒充新的完整 BIOS。W890 的实验组件也不表示已经有完成适配的修改版 CAP。

## 校验与来源

[完整固件清单](FIRMWARE-MANIFEST.json) · [测试组件清单](TEST-COMPONENTS-MANIFEST.json) · [工程总览](PROJECTS.md)

ACE 当前主候选为保留原厂头的 9b038...，不是旧带外路线 e330... 工程签名 CAP。修改后的厂商内容签名、FlashBack 接受及恢复验收不能因保留原厂头而视为已通过。

本次整理没有运行这些二进制、连接设备或执行刷写。原厂基线仅指本地分析所用版本，不声称是官网当前最新版本。
