# 实验报告
  
  
## 一. 实验目的
*使用调试跟踪工具，追踪Linux操作系统的启动过程  

*至少找出两个启动过程中的关键事件  


## 二. 实验步骤  
###1.安装配置qemu  
  > sudo apt-get install qemu  
  
###2.安装配置gdb
  > sudo apt-get install gdb

###3.使用Linux系统环境搭载MenuOS（一个精简后的Linux系统）

  建立LinuxKernel目录  
  > mkdir LinuxKernel  
  
  下载[linux内核源代码](http://www.kernel.org)并解压到上述目录中  
  准备编译内核  
  > cd ~/LinuxKernel/linux-3.18.102  
  > make i386_defconfig  
  > make #编译时间较长
  
  制作根文件系统
  
  > cd ~/LinuxKernel/
  > mkdir rootfs
  > git clone https://github.com/mengning/menu.git  
  > cd menu  
  > gcc -o init linktable.c menu.c test.c -m32 -static –lpthread  
  > cd ../rootfs  
  > cp ../menu/init ./  
  > find . | cpio -o -Hnewc |gzip -9 > ../rootfs.img  
  
  启动MenuOS
  > cd ~/LinuxKernel/
  > qemu-system-x86_64 -kernel linux-3.18.102/arch/x86/boot/bzImage -initrd rootfs.img 
  
  重新编译配置Linux
  > make menuconfig
  
  选择*kernel hacking*后，选择*compile the kernel with debug info*
  > kernel hacking ->[*]compile the kernel with debug info  
  
  再次编译
  > make
  
  启动
  > cd ~/LinuxKernel/
  > qemu-system-x86_64 -kernel linux-3.18.102/arch/x86/boot/bzImage -initrd rootfs.img 
  
  完成！
  
###4.跟踪调试Linux内核代码
  启动，并在MenuOS开始运行之前暂停
  > qemu-system-x86_64 -kernel linux-3.18.102/arch/x86/boot/bzImage -initrd rootfs.img -s -S  
  
  打开另外一个终端  
  
  > gdb  
  > (gdb）file linux-3.18.6/vmlinux  
  > (gdb）target remote:1234 
  
  在start_kernel()函数处设断点，开始单步执行，跟踪调试至该函数的执行
  > (gdb) b start_kernel
  
  仔细分析查阅start_kernel中每一个函数的功能，筛选出其中较为关键的事件
## 三. 实验工具
  1.GDB调试工具：用来跟踪调试Linux内核代码  
  
  2.QEMU模拟处理器：用来执行Linux内核代码，模拟Linux启动过程
  
## 四. 实验结果  

*通过跟踪执行start_kernel函数的执行，筛选出以下关键事件：*

###1.-setup_arch函数的执行  
 -start_kernel是通用的内核启动函数，但是在初始化内核过程中，必然有一些参数是依赖于特定于硬件体系结构的，这些依赖特定于硬件体系结构的设置必须通过调用setup_arch函数来完成。这也是setup_arch重要的原因。
 
###2.-内核线程的创建与启动  
-创建并启动内核线程这个任务主要由rest_init这个函数来完成的，过程中还用到kernel_init *(kernel_init函数将完成设备驱动程序的初始化，并调用init_post函数启动用户空间的init进程)* 和init_post等函数。这个过程首先创建init内核线程（pid为1），将它挂起，等待创建kthreadd线程。然后创建kthreadd内核线程*（它的作用是管理和调度其它内核线程。
它循环运行一个叫做kthreadd的函数，该函数的作用是运行kthread_create_list全局链表中维护的内核线程。调用kthread_create_list创建一个kthread，它会被加入到kthread_create_list链表中。被执行过的kthread会从kthread_create_list链表中删除。且kthreadd会不断调用scheduler函数让出CPU。此线程不可关闭。）*在以上的过程中，内核创建了两个内核线程，一个是内核线程的管理者，另一个是内核初始化线程init,均为系统运行过程中的重要线程。  
  
  
  -**rest_init函数代码如下：**  
  
  ``` c
      /*
     * We need to finalize in a non-__init function or else race conditions
     * between the root thread and the init thread may cause start_kernel to
     * be reaped by free_initmem before the root thread has proceeded to
     * cpu_idle.
     *
     * gcc-3.4 accidentally inlines this function, so use noinline.
     */
     
    static noinline void __init_refok rest_init(void)
    {
        int pid;

        rcu_scheduler_starting();	//内核RCU锁机制调度启动
        /*    
         * We need to spawn init first so that it obtains pid 1, however  
         * the init task will end up wanting to create kthreads, which, if  
         * we schedule it before we create kthreadd, will OOPS.  
         */
        kernel_thread(kernel_init, NULL, CLONE_FS | CLONE_SIGHAND);	//创建kernel_init内核线程，PID=1
        numa_default_policy();
        pid = kernel_thread(kthreadd, NULL, CLONE_FS | CLONE_FILES);	//创建kthread内核线程,PID=2
        rcu_read_lock();
        kthreadd_task = find_task_by_pid_ns(pid, &init_pid_ns);	//获取kthread线程信息
        rcu_read_unlock();
        complete(&kthreadd_done);	//通过complete通知kernel_init线程kthread线程已创建成功

        /*
         * The boot idle thread must execute schedule()
         * at least once to get things moving:
         */
        init_idle_bootup_task(current);	//设置当前进程为idle进程类
        preempt_enable_no_resched();	//使能抢占，但不重新调度
        schedule();				//执行调度，切换进程

        /* Call into cpu_idle with preempt disabled */
        preempt_disable();			//进程调度完成，禁用抢占
        cpu_idle();				//内核本体进入idle状态，用循环消耗空闲的CPU时间
    }
  ```

  
###3.用户空间进程的启动  
  -在kernel_init函数的最后调用init_post函数，激活了init进程，启动了用户空间进程。至此，内核的初始化结束，正式进入了用户空间的初始化过程！
  
  -**init_post函数如下：**  
  
  ``` c
      /* This is a non __init function. Force it to be noinline otherwise gcc
     * makes it inline to init() and it becomes part of init.text section
     */
    static noinline int init_post(void)
    {
        /* need to finish all async __init code before freeing the memory */
        async_synchronize_full();
        free_initmem();		//释放所有init.*段中的内存
        mark_rodata_ro();
        system_state = SYSTEM_RUNNING;	//设置系统状态为运行状态
        numa_default_policy();


        current->signal->flags |= SIGNAL_UNKILLABLE;	//设置当前进程（init）为不可杀进程

        if (ramdisk_execute_command) {
            run_init_process(ramdisk_execute_command);
            printk(KERN_WARNING "Failed to execute %s\n",
                    ramdisk_execute_command);
        }

        /*
         * We try each of these until one succeeds.
         *
         * The Bourne shell can be used instead of init if we are
         * trying to recover a really broken machine.
         */
        if (execute_command) {
            run_init_process(execute_command);
            printk(KERN_WARNING "Failed to execute %s. Attempting "
                        "defaults...\n", execute_command);
        }
        run_init_process("/sbin/init");
        run_init_process("/etc/init");
        run_init_process("/bin/init");
        run_init_process("/bin/sh");
     
     
        //检查完ramdisk_execute_command和execute_command为空的情况下，顺序执行四个初始化程序。
        //如果都没有找到就打印出错信息，出现该错误的可能原因是：
        //1. 启动参数配置有问题：指定了init进程，但是没找到，默认四个程序不在文件系统中；
        //2. 文件系统挂载有问题；
        //3. init程序没有执行权限。
        panic("No init found. Try passing init= option to kernel. "
         "See Linux Documentation/init.txt for guidance.");
    }
  ```
  
  ###cpu_startup_entry函数  
  -rest_init函数最后执行cpu_startup_entry函数，该函数会调用cpu_idle_loop函数，并在其中的while(1)一直循环下去，作为idle进程(pid=0)，并在系统没有任何需要执行的进程时，调度此进程。
  -**cpu_startup_entry函数如下：**
  ``` c
  void cpu_startup_entry(enum cpuhp_state state)
{
    /*
    * This #ifdef needs to die, but it's too late in the cycle to
    * make this generic (arm and sh have never invoked the canary
    * init for the non boot cpus!). Will be fixed in 3.11
    */
#ifdef CONFIG_X86
    /*
    * If we're the non-boot CPU, nothing set the stack canary up
    * for us. The boot CPU already has it initialized but no harm
    * in doing it again. This is a good place for updating it, as
    * we wont ever return from this function (so the invalid
    * canaries already on the stack wont ever trigger).
    */
    boot_init_stack_canary();
#endif
    arch_cpu_idle_prepare();
    **cpu_idle_loop();**
}
  ```

