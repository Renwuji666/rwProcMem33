#ifndef _HWBP_PROC_H_
#define _HWBP_PROC_H_
#include <linux/module.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/compat.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/ksm.h>
#include <linux/mutex.h>
#include <linux/ktime.h>
#include <linux/pid.h>
#include <linux/slab.h> //kmalloc与kfree
#include "ver_control.h"
#include "arm64_register_helper.h"
#include "cvector.h"
#ifdef CONFIG_USE_PROC_FILE_NODE
#include <linux/proc_fs.h>
#include "hide_procfs_dir.h"
#endif
//////////////////////////////////////////////////////////////////

enum {
	CMD_OPEN_PROCESS, 				// 打开进程
	CMD_CLOSE_PROCESS, 				// 关闭进程
	CMD_READ_PROCESS_MEM, 			// 读取进程内存
	CMD_GET_NUM_BRPS, 				// 获取CPU硬件执行断点支持数量
	CMD_GET_NUM_WRPS, 				// 获取CPU硬件访问断点支持数量
	CMD_INST_PROCESS_HWBP,			// 安装进程硬件断点
	CMD_UNINST_PROCESS_HWBP,		// 卸载进程硬件断点
	CMD_SUSPEND_PROCESS_HWBP,		// 暂停进程硬件断点
	CMD_RESUME_PROCESS_HWBP,		// 恢复进程硬件断点
	CMD_GET_HWBP_HIT_COUNT,			// 获取硬件断点命中地址数量
	CMD_GET_HWBP_HIT_DETAIL,		// 获取硬件断点命中详细信息
	CMD_CLEAR_HWBP_HIT,				// 清空硬件断点命中缓存
	CMD_SET_HOOK_PC,				// 设置无条件Hook跳转
	CMD_HIDE_KERNEL_MODULE,			// 隐藏驱动
	CMD_SET_TRACE_ENABLE,			// 开关代码追踪
	CMD_SET_TRACE_MODE,			// 设置追踪模式
	CMD_SET_TRACE_BUFFER_SIZE,		// 设置追踪缓冲大小
	CMD_SET_TRACE_STEP_COUNT,		// 设置追踪步数
	CMD_SET_STEP_SIMULATE,			// 指令模拟步进
	CMD_GET_TRACE_COUNT,			// 获取追踪记录数量
	CMD_GET_TRACE_DATA,			// 获取追踪记录数据
};

struct hwBreakpointProcDev {
#ifdef CONFIG_USE_PROC_FILE_NODE
	struct proc_dir_entry *proc_parent;
	struct proc_dir_entry *proc_entry;
#endif
	bool is_hidden_module; //是否已经隐藏过驱动列表了
};
static struct hwBreakpointProcDev *g_hwBreakpointProc_devp;

static ssize_t hwBreakpointProc_read(struct file* filp, char __user* buf, size_t size, loff_t* ppos);
static int hwBreakpointProc_release(struct inode *inode, struct file *filp);

#ifdef CONFIG_USE_PROC_FILE_NODE
#if MY_LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
static const struct file_operations hwBreakpointProc_proc_ops = {
    .read    = hwBreakpointProc_read,
	.release = hwBreakpointProc_release,
};
#else
static const struct proc_ops hwBreakpointProc_proc_ops = {
    .proc_read    = hwBreakpointProc_read,
	.proc_release = hwBreakpointProc_release,
};
#endif
#endif

#pragma pack(1)
struct my_user_pt_regs {
	uint64_t regs[31];
	uint64_t sp;
	uint64_t pc;
	uint64_t pstate;
	uint64_t orig_x0;
	uint64_t syscallno;
};
struct HWBP_HIT_ITEM {
	uint64_t task_id;
	uint64_t hit_addr;
	uint64_t hit_time;
	struct my_user_pt_regs regs_info;
};
#pragma pack()


enum {
	TRACE_MODE_PC = 0,
	TRACE_MODE_FULL = 1,
};

#pragma pack(1)
struct TRACE_ITEM_PC {
	uint64_t task_id;
	uint64_t hit_time;
	uint64_t pc;
	uint64_t pstate;
	uint64_t far;
	uint64_t esr;
	uint32_t insn;
};
struct TRACE_ITEM_FULL {
	uint64_t task_id;
	uint64_t hit_time;
	struct my_user_pt_regs regs_info;
	uint64_t far;
	uint64_t esr;
	uint32_t insn;
};
#pragma pack()
struct HWBP_HANDLE_INFO {
	uint64_t task_id;
	struct task_struct *task;
	struct perf_event * sample_hbp;
	struct perf_event_attr original_attr;
	struct perf_event_attr sim_next_attr;
	bool sim_next_active;
	bool is_32bit_task;
#ifdef CONFIG_MODIFY_HIT_NEXT_MODE
	struct perf_event_attr next_instruction_attr;
#endif
	struct mutex hit_lock;
	bool step_pending;
	size_t step_remaining;
	size_t hit_total_count;
	cvector hit_item_arr;
	void *trace_buf;
	size_t trace_capacity;
	size_t trace_item_size;
	size_t trace_head;
	size_t trace_count;
};

#endif /* _HWBP_PROC_H_ */
