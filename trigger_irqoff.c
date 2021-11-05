/**
 *	Trigger a irqoff with latency 
 *
 *	Author	Rong Tao <rongtao@cestc.cn>
 *	Time	2021.11.05
 */
#include <linux/irqflags.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sizes.h>
#include <linux/stacktrace.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/delay.h>

static void disable_hardirq(unsigned long latency)
{
    local_irq_disable();
    mdelay(latency);
    local_irq_enable();
}

static int my_set(const char *val, const struct kernel_param *kp)
{
		int n = 0, ret;

		ret = kstrtoint(val, 10, &n);
		if (ret != 0 || n < 1 || n > 1000)
			return -EINVAL;

		return param_set_int(val, kp);
}

static const struct kernel_param_ops param_ops = {
		.set	= my_set,
		.get	= param_get_int,
};

static int latency_ms = 100;
module_param_cb(latency_ms, &param_ops, &latency_ms, 0664);

static int __init trigger_init(void)
{
	printk(KERN_INFO "trigger local_irq.\n");
	disable_hardirq(latency_ms);
	return 0;
}

static void __exit trigger_exit(void)
{
	printk(KERN_INFO "trigger local_irq done.\n");
}

module_init(trigger_init);
module_exit(trigger_exit);

MODULE_AUTHOR("Rong Tao");
MODULE_LICENSE("GPL");
