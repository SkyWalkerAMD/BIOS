原生 SendForm 黑屏差异审查已冻结。实机按 M 前的三页二维码（1901 B，CRC 5086171C）已重新从 PNG 解码并逐字节核对；随后截图可确认 800×600 黑色画面，不能据此认定 CPU hold。

旧 OVMF 测试执行真实 provider 和 OVMF 表单浏览器，但用显式 body fixture 代替 ASUS 原始页面构建/渲染/输入链。它没有覆盖这次关键厂商路径。

现已确认原厂静态 SUBTITLE 控件先带 HII=-1、原 render 稍后赋值；冻结 guard 提前拒绝这种真实构造结果。这是可复现兼容缺陷，尚不是黑屏现场的执行轨迹。另发现原 SendForm 不总把 ActionRequest 写成 NONE，06 已用 NONE 初值避免正常返回误判；该差异不能解释返回前黑屏。

06 候选2092c11a… / ISO1841d9a2…用于单独验证无guard/provider时同一独立HII包的原厂SendForm。其动作回调均拒绝，生命周期回调拒绝也可能影响厂商行为。测试结果不能替代密码、永久菜单或直接Del/F2启动集成验收。

本轮新 REA analyze_function 超时，原日志及关闭结果保留；没有声称取得新的反编译结果。证据来自已有REA输出、精确SAGE指令映射、原始字节、独立包结构解析和现有冻结测试。
