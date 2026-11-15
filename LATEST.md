# 最新 BIOS 进展与下载

本页仅列本地最新完整镜像进展及必要的原厂参考基线。实验候选不是可直接刷写的正式版。

| 工程 | 版本 | 下载 | 状态 |
|---|---|---|---|
| Z790-HERO | 3107 / RC5 R5 S23 CANDIDATE05 | [下载](https://github.com/SkyWalkerAMD/BIOS/releases/download/local-bios-progress-20261115/Z790-HERO-latest-local-progress.zip) | 实验固件候选；最终 CAP 刷写、冷启动菜单、F10 写入和官方恢复均未完成验收。 |
| W790-ACE | 1904 / CANDIDATE05 | [下载](https://github.com/SkyWalkerAMD/BIOS/releases/download/local-bios-progress-20261115/W790-ACE-latest-local-progress.zip) | 工程签名、非 OEM、NOT FLASH READY；本地数学验签不等于厂商更新接受或可恢复刷写。 |
| W790E-SAGE-SE | 1904 / NATIVE12 | [下载](https://github.com/SkyWalkerAMD/BIOS/releases/download/local-bios-progress-20261115/W790E-SAGE-SE-latest-local-progress.zip) | 最新已找到的完整集成审查镜像，INTERNAL / UNSIGNED / NOT RELEASE READY；NATIVE13 等更新源码属于后续组件和安装器进展，不是新的完整 BIOS 交付。 |
| W890E-SAGE-SE | 0603 / 原厂分析基线 | [下载](https://github.com/SkyWalkerAMD/BIOS/releases/download/local-bios-progress-20261115/W890E-SAGE-SE-latest-local-progress.zip) | 本地保存的原厂分析基线；项目仍为部分分析，没有已完成的修改版 BIOS。不声称这是厂商当前在线最新版本。 |
| ProArt-Z790-CREATOR-WIFI | IPMI 3002 / 供体参考基线 | [下载](https://github.com/SkyWalkerAMD/BIOS/releases/download/local-bios-progress-20261115/ProArt-Z790-CREATOR-WIFI-latest-local-progress.zip) | 本地保存的 IPMI 供体参考固件，不属于独立修改版交付。不声称这是厂商当前在线最新版本。 |

[完整文件来源和 SHA-256](FIRMWARE-MANIFEST.json) · [工程线总览](PROJECTS.md)

每个包包含固件镜像、状态说明和 SHA256SUMS。W790E 的 NATIVE13 是更新的组件／安装器进展，当前未找到新的完整 NATIVE13 BIOS，因此没有用它替代 NATIVE12 完整审查镜像。W890 没有已完成修改版，明确提供原厂 0603 分析基线。

原始记录、旧版源码和本次整理之前的目录结构可在 Git 历史中追溯。原始固件输入及完整重建环境仍需按工程说明补齐。
