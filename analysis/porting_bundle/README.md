# 静态分析资料，不是可刷写 BIOS

本目录导出了 ProArt Z790 IPMI 3002 相对普通 ProArt 3002 新增的 52 个候选 FFS。它不是完整移植结果，也不是建议全部插入 HERO 的模块清单。

已发现明确的跨主板 Setup 字段冲突，详见同包 `IPMI移植分析.md` 和 `setup_collision.json`。未生成整板 CAP，未进行任何刷写或目标主板启动测试。

`ServerSetup.donor_default.bin` 仅包含变量数据体，不能直接当作 NVAR 记录写入。

`manifest.json` 记录模块校验值、来源路径和依赖表达式。已验证全部导出 FFS 的结构校验和及与源文件一致；尚未验证其移植兼容性。
