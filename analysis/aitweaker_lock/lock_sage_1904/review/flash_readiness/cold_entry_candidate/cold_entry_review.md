当前 e41 / EXP03 仍不能证明“每次直接 Del 首次进入 Setup 都已经有锁”。本轮没有修改驱动或固件，也没有连接设备。

原厂 DXE Core 的 BEFORE 排序确实可以把密码驱动排在 AMITSE 前，但前一个驱动加载或入口失败后，Core 仍继续启动 AMITSE。本地执行原厂指令已复现这点。首次发现 stage5 时，e41 的 UI 和变量钩子均未安装；初次 AllocatePages 失败即使尚无任何目标写入，也会锁存 attempted，后续条件恢复仍不重试。46 项边界/反例断言通过，含这些失败路径的复现；另有 15 项原厂通知/加载顺序断言通过。这些不是 61 项冷启动通过率。

正常原厂 BDS 顺序中，EndOfDxe 早于 BootManager→Setup，因而成功初始化时存在提前安装机会。但它不强制所有前提已就绪，更不提供“密码驱动失败则只关闭超频入口”的屏障。[PI DXE Dispatcher](https://uefi.org/specs/PI/1.8/V2_DXE_Dispatcher.html)；通知还受 TPL 约束。[UEFI Boot Services](https://uefi.org/specs/UEFI/2.10_A/07_Services_Boot_Services.html)

可继续落地的方向是把默认拒绝的选择性守卫静态置于 AMITSE / Setup 文件中，再让独立 DXE 提供当前会话的密码授权。DXE 缺失时，守卫仍拒绝 Ai Tweaker 和已识别的 OC 入口；有效的 Main、Security 和其他非 OC 页面继续调用原厂处理函数。不能用整机停机、重启或无限等待替代用户要求的栏目锁。

设计已列出九个具体修补点和验证顺序，但尚未实现。两个关键限制是：AMITSE 的11fbc空桩被16个指针共用，必须仅改导航专用槽7d4f8；原厂 app+5a 退出清理在特定既有状态下会调用 ResetSystem，不能未经验证就把“结束当前页面”当成无副作用返回。原 PE 也没有新节头空间，添加守卫代码需要完整验证布局、重定位、执行权限和压缩容器余量。

REA 已成功打开原版 Core，但 analyze_function 在180秒超时，close_binary 成功。本轮未声称取得新的反编译结果；主要证据来自绑定原始 SHA 的机器码、Capstone 解码与 Unicorn 有界执行。
