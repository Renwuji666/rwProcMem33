# rwProcMemHwbp_module

该目录用于合并 rwProcMem 与 hwBreakpoint 的功能（单模块）。

要点：
- rwProcMem 原命令号保持不变
- 断点相关命令从 `0x40` 起（见 `hwbp_module.h`）
- 仅使用一个 `/proc/<key>/<key>` 节点鉴权与分发
- 断点内部读取指令使用强读接口（同模块内调用）
