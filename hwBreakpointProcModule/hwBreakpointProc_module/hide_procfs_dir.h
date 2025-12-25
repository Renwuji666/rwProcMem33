#ifndef _HIDE_PROCFS_DIR_H_
#define _HIDE_PROCFS_DIR_H_

#include "ver_control.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/moduleparam.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/version.h>

static char g_hide_dir_name[256] = {0};

static filldir_t old_filldir;

/* 统一使用 int 返回值，兼容 4.19 的 filldir_t */
static int my_filldir(struct dir_context *ctx,
                      const char *name,
                      int namelen,
                      loff_t offset,
                      u64 ino,
                      unsigned int d_type)
{
    if (namelen == strlen(g_hide_dir_name) &&
        !strncmp(name, g_hide_dir_name, namelen))
    {
        return 0;
    }
    return old_filldir(ctx, name, namelen, offset, ino, d_type);
}

static int handler_pre(struct kprobe *kp, struct pt_regs *regs)
{
    struct dir_context *ctx = (struct dir_context *)regs->regs[1];
    old_filldir = ctx->actor;
    ctx->actor = my_filldir;
    return 0;
}

static struct kprobe kp_hide_procfs_dir = {
    .symbol_name = "proc_root_readdir",
    .pre_handler = handler_pre,
};

static bool start_hide_procfs_dir(const char* hide_dir_name)
{
    int ret;
    strlcpy(g_hide_dir_name, hide_dir_name, sizeof(g_hide_dir_name));
    ret = register_kprobe(&kp_hide_procfs_dir);
    if (ret) {
        printk_debug("[hide_procfs_dir] register_kprobe failed: %d\n", ret);
        return false;
    }
    printk_debug("[hide_procfs_dir] kprobe installed, hiding \"%s\"\n", g_hide_dir_name);
    return true;
}

static void stop_hide_procfs_dir(void)
{
    unregister_kprobe(&kp_hide_procfs_dir);
    printk_debug("[hide_procfs_dir] kprobe removed\n");
}

#endif  // _HIDE_PROCFS_DIR_H_
