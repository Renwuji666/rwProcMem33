#ifndef VERSION_CONTROL_H_
#define VERSION_CONTROL_H_
#include <linux/version.h>

// 独立内核模块入口模式
#define CONFIG_MODULE_GUIDE_ENTRY

// 生成proc用户层交互节点文件
#define CONFIG_USE_PROC_FILE_NODE
// 隐蔽通信密钥
#define CONFIG_PROC_NODE_AUTH_KEY "e84523d7b60d5d341a7c4d1861773ecd"

// 调试打印模式
#define CONFIG_DEBUG_PRINTK

// 动态寻址模式
#define CONFIG_KALLSYMS_LOOKUP_NAME

// 使用CPU单步标志模式（真单步）
#define CONFIG_USE_SINGLE_STEP_MODE

// 精准命中记录模式（单步模式时自动关闭）
#define CONFIG_MODIFY_HIT_NEXT_MODE

// 代码追踪默认设置
#define CONFIG_TRACE_MAX_SIZE 8192
#define CONFIG_TRACE_DEFAULT_SIZE 1024
#define CONFIG_TRACE_MAX_STEP 1024
#define CONFIG_TRACE_DEFAULT_STEP 64

// 反PTRACE侦测模式
#define CONFIG_ANTI_PTRACE_DETECTION_MODE

#ifdef CONFIG_USE_SINGLE_STEP_MODE
#undef CONFIG_MODIFY_HIT_NEXT_MODE
#endif

#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif
#ifndef MY_LINUX_VERSION_CODE
// 默认跟随当前编译内核版本，但对 4.19.x 统一映射到 4.19.113 的适配分支
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,19,0)) && (LINUX_VERSION_CODE < KERNEL_VERSION(5,4,0))
#define MY_LINUX_VERSION_CODE KERNEL_VERSION(4,19,113)
#else
#define MY_LINUX_VERSION_CODE LINUX_VERSION_CODE
#endif
#endif

#ifdef CONFIG_DEBUG_PRINTK
#define printk_debug printk
#else
static inline void printk_debug(char *fmt, ...) {}
#endif

#endif /* VERSION_CONTROL_H_ */
