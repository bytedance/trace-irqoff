# Trace-irqoff

## 我们的需求是什么

在实际问题中，业务经常会遇到网络延迟高问题，这种问题分析下来。基本是如下几种可能原因：

- 中断关闭时间太长
- softirq 关闭时间太长

以上是我们根据经验猜测可能出现的原因，实际问题中，我迫切的需要确定是否以上原因导致问题。如果是的话，具体是什么原因导致以上两种情况发生呢？因此，我们迫切需要定位具体的元凶，使其现形。所以，我们的需求是开发一个工具可以追踪和定位中断或者软中断关闭的时间。**这款工具现在已经开发完成，名为：Interrupts-off or softirqs-off latency tracer，简称 trace-irqoff。**

## 如何安装

安装 trace-irqoff 工具很简单，git clone代码后执行如下命令即可安装。

```bash
make -j8
make install
```

## 如何使用

安装 trace-irqoff 工具成功后。会创建如下 **/proc/trace_irqoff** 目录。

```bash
root@n18-061-206:/proc/trace_irqoff# ls
distribute  enable  sampling_period  trace_latency
```

/proc/trace_irqoff 目录下存在 4 个文件，分别：distribute, enable, sampling_period 和 trace_latency。工具安装后，默认是关闭状态，我们需要手动打开 trace。

##### 1. 打开 trace

```bash
echo 1 > /proc/trace_irqoff/enable
```

##### 2. 关闭 trace

```bash
echo 0 > /proc/trace_irqoff/enable
```

##### 3. 设置 trace 阈值

trace-irqoff 工具只会针对关闭中断或者软中断时间超过阈值的情况下记录堆栈信息。因此我们可以通过如下命令查看当前 trace 的阈值：

```bash
cat /proc/trace_irqoff/trace_latency
trace_irqoff_latency: 50ms
 hardirq:
 softirq:
```

默认阈值是 50ms，如第 2 行所示。第 4 行输出 hardirq: 代表下面的栈是可能关闭中断超过阈值的栈。同理，第 6 行是软中断关闭时间超过阈值的栈。

如果需要修改阈值至 100ms 可通过如下命令（写入值单位是 ms）：

```bash
echo 100 > /proc/trace_irqoff/trace_latency
```

##### 4. 清除栈信息

当然如果需要清除 /proc/trace_irqoff 记录的栈信息。可以执行如下命令（不会修改阈值为 0）：

```bash
echo 0 > /proc/trace_irqoff/trace_latency
```

##### 5. 查看中断关闭次数的统计信息

如果我们需要知道中断被关闭一定的时间的次数，可以通过如下命令获取统计信息。

```bash
root@n18-061-206:/proc/trace_irqoff# cat distribute
hardirq-off:
     msecs      : count   distribution
    20 -> 39    : 1     |**********                              |
    40 -> 79    : 0     |                                        |
    80 -> 159   : 4     |****************************************|
   160 -> 319   : 2     |********************                    |
   320 -> 639   : 1     |**********                              |
softirq-off:
     msecs      : count   distribution
    20 -> 39    : 0     |                                        |
    40 -> 79    : 0     |                                        |
    80 -> 159   : 0     |                                        |
   160 -> 319   : 1     |****************************************|
```

> 在这个例子中，我们看到hardirq被关闭时间x ∈ [80, 159] ms，次数4次。softirq被关闭时间x ∈ [160, 319] ms，次数1次

如果没有任何信息输出，这说明没有任何地方关闭中断时间超过20ms。

##### 6. 修改采样周期

从上面一节我们可以看到，中断关闭时间分布图最小粒度是 20ms。这是因为采样周期是 10ms。根据采样定理，大于等于 2 倍采样周期时间才能反映真实情况。如果需要提高统计粒度，可修改采样周期时间。例如修改采样周期为 1ms，可执行如下命令（必须在 tracer 关闭的情况下操作有效）：

```bash
# 单位 ms，可设置最小的采样周期是 1ms。
echo 1 > /proc/trace_irqoff/sampling_period
```

## 案例分析

##### 1. hardirq 关闭

我们使用如下示意测试程序，关闭中断 100ms。查看 trace_irqoff 文件内容。

```c
static void disable_hardirq(unsigned long latency)
{
    local_irq_disable();
    mdelay(latency);
    local_irq_enanle();
}
```

通过模块测试以上代码，然后查看栈信息。

```bash
cat /proc/trace_irqoff/trace_latency
trace_irqoff_latency: 50ms
 hardirq:
 cpu: 17
   COMMAND: bash PID: 22840 LATENCY: 107ms
   trace_irqoff_hrtimer_handler+0x39/0x99 [trace_irqoff]
   __hrtimer_run_queues+0xfa/0x270
   hrtimer_interrupt+0x101/0x240
   smp_apic_timer_interrupt+0x5e/0x120
   apic_timer_interrupt+0xf/0x20
   disable_hardirq+0x5b/0x70
   proc_reg_write+0x36/0x60
   __vfs_write+0x33/0x190
   vfs_write+0xb0/0x190
   ksys_write+0x52/0xc0
   do_syscall_64+0x4f/0xe0
   entry_SYSCALL_64_after_hwframe+0x44/0xa9
 softirq:
```

我们可以看到 hardirq 一栏记录 cpu17 执行 bash 命令，关闭中断 107ms（误差 10ms 之内）。其栈信息对应disable_hardirq() 函数中。第 20 行 softirq 一栏没有信息，说明没有记录 softirq 被关闭的栈。

##### 2. softirq 关闭

我们使用如下示意测试程序，关闭 softirq 100ms。查看 trace_irqoff 文件内容。

```c
static void disable_softirq(unsigned long latency)
{
    local_bh_disable();
    mdelay(latency);
    local_bh_enanle();
}
```

通过模块测试以上代码，然后查看栈信息。

```bash
cat /proc/trace_irqoff/trace_latency
trace_irqoff_latency: 50ms
 hardirq:
 softirq:
 cpu: 17
   COMMAND: bash PID: 22840 LATENCY: 51+ms
   trace_irqoff_hrtimer_handler+0x97/0x99 [trace_irqoff]
   __hrtimer_run_queues+0xfa/0x270
   hrtimer_interrupt+0x101/0x240
   smp_apic_timer_interrupt+0x5e/0x120
   apic_timer_interrupt+0xf/0x20
   delay_tsc+0x3c/0x50
   disable_softirq+0x4b/0x80
   proc_reg_write+0x36/0x60
   __vfs_write+0x33/0x190
   vfs_write+0xb0/0x190
   ksys_write+0x52/0xc0
   do_syscall_64+0x4f/0xe0
   entry_SYSCALL_64_after_hwframe+0x44/0xa9

   COMMAND: bash PID: 22840 LATENCY: 106ms
   trace_irqoff_timer_handler+0x3a/0x60 [trace_irqoff]
   call_timer_fn+0x29/0x120
   run_timer_softirq+0x16c/0x400
   __do_softirq+0x108/0x2b8
   do_softirq_own_stack+0x2a/0x40
   do_softirq.part.21+0x56/0x60
   __local_bh_enable_ip+0x60/0x70
   disable_softirq+0x62/0x80
   proc_reg_write+0x36/0x60
   __vfs_write+0x33/0x190
   vfs_write+0xb0/0x190
   ksys_write+0x52/0xc0
   do_syscall_64+0x4f/0xe0
   entry_SYSCALL_64_after_hwframe+0x44/0xa9
```

针对 softirq 关闭情况，有 2 个栈与之对应。我们注意到第 9 行的函数名称和第 24 行的函数名称是不一样的。第 9 行的栈是硬件中断 handler 捕捉到软中断关闭，第 24 行是软中断 handler 捕捉到软中断被关闭。正常情况下，我们以 24 行开始的栈为分析目标即可。当 24 行的栈是无效的时候，可以看第 9 行的栈。这里注意：第 9 行的 lantency 提示信息 **51+ms** 是阈值信息。并非实际 latency（所以我在后面添加一个'+'字符，表示latency大于51ms）。实际的 latency 是第 24 行显示的 106ms。下面就看下为什么 2 个栈是有必要的。

##### 3. ksoftirqd 延迟

我们看一个曾经处理的一个实际问题。

```bash
cat /proc/trace_irqoff/trace_latency
trace_irqoff_latency: 300ms
 hardirq:
 softirq:
 cpu: 4
   COMMAND: lxcfs PID: 4058797 LATENCY: 303+ms
   trace_irqoff_record+0x12b/0x1b0 [trace_irqoff]
   trace_irqoff_hrtimer_handler+0x97/0x99 [trace_irqoff]
   __hrtimer_run_queues+0xdc/0x220
   hrtimer_interrupt+0xa6/0x1f0
   smp_apic_timer_interrupt+0x62/0x120
   apic_timer_interrupt+0x7d/0x90
   memcg_sum_events.isra.26+0x3f/0x60
   memcg_stat_show+0x323/0x460
   seq_read+0x11f/0x3f0
   __vfs_read+0x33/0x160
   vfs_read+0x91/0x130
   SyS_read+0x52/0xc0
   do_syscall_64+0x68/0x100
   entry_SYSCALL_64_after_hwframe+0x3d/0xa2

   COMMAND: ksoftirqd/4 PID: 34 LATENCY: 409ms
   trace_irqoff_record+0x12b/0x1b0 [trace_irqoff]
   trace_irqoff_timer_handler+0x3a/0x60 [trace_irqoff]
   call_timer_fn+0x2e/0x130
   run_timer_softirq+0x1d4/0x420
   __do_softirq+0x108/0x2a9
   run_ksoftirqd+0x1e/0x40
   smpboot_thread_fn+0xfe/0x150
   kthread+0xfc/0x130
   ret_from_fork+0x1f/0x30
```

我们看到下面的进程 ksoftirqd/4 的栈，延迟时间是 409ms。ksoftirqd 进程是 kernel 中处理 softirq 的进程。因此这段栈对我们是没有意义的，因为元凶已经错过了。所以此时，我们可以借鉴上面的栈信息，我们看到当 softirq 被延迟 303ms 的时候，当前 CPU 正在执行的进程是 lxcfs。并且栈是 memory cgroup 相关。因此，我们基本可以判断 lxcfs 进程执行时间过长，由于 kernel 态不支持抢占，因此导致 ksoftirqd 进程没有机会得到运行。

