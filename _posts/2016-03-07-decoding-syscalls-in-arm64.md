---
layout: post
title: Decoding Syscalls in ARM64
---

Eventually as you are reverse-engineering an `ARM` binary you will come across a function that looks like the following:

![]({{ site.baseurl }}assets/Screen Shot 2016-03-06 at 10.26.42 PM.png)

*Even if you understand what this code is doing (as I suspect you may) read on, as this post intends to bring to light several security models specific to the `ARMv8-a` architecture.*

To understand what this code is doing, you need to understand a few concepts first. Since this is an `ARM` specific blog, this is what we will focus on. Specifically in the context of the `ARMv8-a` architecture. An extremely helpful overview of this architecture can be found [here](https://quequero.org/2014/04/introduction-to-arm-architecture/) - I suggest you read it before continuing.

### Exception Levels

The most important concept is rather new, these are the **Exception Levels** `ARMv8-a` uses for privilege separation (such as `rings` in the `Intel` architecture) there are 4 levels, notably:

|Exception Level| Description | Usage* | Status |
|---|---|---|---|
| **EL0** | Unprivileged | Applications are executed here | Required |
| **EL1** | Privileged | Linux (or other OS) Kernel | Required |
| **EL2** | Hypervisor | *Virtualization* | *Optional* |
| **EL3** | Secure Monitor | *Security States* | *Optional* |

*: `aarch64` does not dictate **how** software can use the exception levels, these are simply a common usage model.

Now, as you can imagine, applications running in **EL0** may need to access or modify the system in some way. The Linux kernel provides a <del>safe</del> portable way to access these system-level functions. This Application Programming Interface or `API` between the *unprivileged* **EL0** and the *privileged* **EL1** execution levels are called **system calls** or `syscalls`.

The `ARMv8-a` architecture has strict rules about how to leverage `syscalls`, as you can imagine abuse of this `API` is commmon and could lead to an *unprivileged* application modifying the system beyond what it should be allowed to. This technique has been used countless times to gain `root` on a device or escalate privileges of a user. One of the biggest issues with mobile devices is there is not much quality control for software that interfaces with the kernel, things like device drivers get abused far too often. 

Before we get into exceptions, it should be noted that `ARMv8-a` has a (harrowingly complicated) **Security Model**, whose general principles are as follows. If **EL3** is implemented in the system there are two `security states` **Secure** and **Non-Secure** each with their own physical memory address space. If **EL3** is not implemented, **AND** does not include **EL2** then it's `IMPLEMENTATION DEFINED`. If **EL2** is present then it is Non-Secure state. Changing states occurs in the same fashion as the exceptions described below. 

### Exceptions

`ARMv8-a` can operate in two `execution states` `Aarch64` and `Aarch32` (compatible with `ARMv7-a`). It is possible to move between these two states using what the architecture defines as `interprocessing` though it is not useful for this exercise.

In `Aarch64` state, you can change exception levels only by taking an exception, or returning from one. Perhaps the best way to explain it is with pseudo-code:

#### 64-bit:

	if state == aarch64 && take_exception {
		 target_exception_level = exception_level or exception_level+1
	}
	
	if state == aarch64 && return_from_exception {
		target_exception_level = exception_level or exception_level-1
	}
	

There are a few types of exceptions `ARMv8-a` allows that will interrupt the processor and change the control flow of the program. These are: 

- `SVC` Supervisor Call attempts to access **EL1** from **EL0**.
- `HVC` Hypervisor Call attempts to access **EL2**
- `SMC` Secure Monitor Call attempts to access **EL3**
- `HLT` Halting Software Breakpoint Instruction
- `BRK` Software Breakpoint Instruction

The `SVC` instruction is the most common, and the one we are dealing with in the following example. This instruction causes a Supervisor Call exception, which provides this *unprivileged* program the ability to make a system call to the *privileged* operating system. When `SVC` is executed, the `target_exception_level` becomes `EL1` from `EL0`.

![]({{ site.baseurl }}assets/Screen Shot 2016-03-06 at 10.26.42 PM.png)

Let's walk-through this function to see what's going on:

**`MOV		X8, #0x40`**

Moves the immediate value 0x40 into the X8 register.
	
While this looks like a simple instruction there's a lot going on here that you may not be familiar with. Prefacing a call to the kernel (SVC 0) we have to setup that call, which generally means you need two things: 

- a system call, defined by a number (in our case 0x40)
- a register to place the return value (typically X0)

It is also important to note, that (quite annoyingly) these syscall numbers change based on the architecture you are executing the instruction. In this case, 0x40 is defined in the arm64 kernel as a call to **write**. And of course since ARM is a load/store based architecture we require **X8** to act as a catalyst to move the value since we can not write the value directly to memory (like you can in other architectures.)
	
*Note: In ARMv7 the R7 register was used, which you can remember by: v7 uses R7, v8 uses X8.*

**`SVC		0`**

Generates supervisor call exception, targeting EL1
	
The call looks like this: 
`AArch64.TakeException(EL1, exception, preferred_exception_return, vect_offset);`Now is a good time to break and talk about what `vect_offset` is:

<hr>

#### Exception Vector Tables

From [ARM Infocenter](http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.den0024a/CHDEEDDC.html):

> When an exception occurs, the processor must execute handler code which corresponds to the exception. The location in memory where the handler is stored is called the exception vector. In the ARM architecture, exception vectors are stored in a table, called the **exception vector table**. Each Exception level has its own vector table, that is, there is one for each of EL3, EL2 and EL1. The **table contains instructions to be executed**, rather than a set of addresses. Vectors for individual exceptions are located at fixed offsets from the beginning of the table. The virtual address of each table base is set by the Vector Based Address Registers `VBAR_EL3`, `VBAR_EL2` and `VBAR_EL1`.This means that after `SVC 0` is called, `AArch64.TakeException()` executes using `VBAR_EL1` + `vect_offset` `0x280` to retrieve the exception handler instructions to carry out the exception - *see Table 10.2 in the infocenter reference for information about calculating offsets*.

Accessing `VBAR_EL1` is done through the `MRS` instruction and looks like this for our example:

![]({{ site.baseurl }}assets/Screen Shot 2016-03-08 at 12.21.15 AM.png)<hr>	
**`CMN		X0, #1, LSL#12`**

**`CINV	X0, X0, HI`**

**`B.HI	loc_42B4B8`**

ARM has a number of potential conditions set by the 4-bit prefix in an instruction word. The prefix we are intersted in is the **HI** condition as shown by our instructions. The **HI** condition is met when the Carry flag is set and the Zero flag is false, which simply means there was a non-zero value returned from the system call into **X0**.

The above instructions are checking the returned value from the system call, stored in X0, for a non-zero value (an error) and setting the HI condition to branch accordingly into **loc_42B4B8**.

![]({{ site.baseurl }}assets/Screen Shot 2016-03-08 at 12.25.02 AM.png)
	
**`RET`**

	Branches to the address stored in the Link Register (LR)

Now that you understand what is happening with this function it is a good idea to rename it in IDA so that you can identify when a function is calling the `sys_getppid` handler!

![]({{ site.baseurl }}assets/Screen Shot 2016-03-06 at 10.33.07 PM.png)

![]({{ site.baseurl }}assets/Screen Shot 2016-03-06 at 10.29.19 PM.png)

I left some details out about the above process because this was meant as an intro. Some of the topics I did not discuss are `Exception Syndrome Registers`, `Exception Link Registers`, and `PSTATE`.

**NOTE: To learn more about exceptions in `ARMv8-a` check out `Chapter D1` in the `Aarch64 Reference Manual`** 

Huge thanks to reddit user [SidJenkins](https://www.reddit.com/user/SidJenkins) who explained why I'm an idiot WRT to ARM syscall values, and the conditional compare instructions. You can see the comment thread [here](https://www.reddit.com/r/lowlevel/comments/49qmuq/decoding_syscalls_in_arm64_arm_ninja/) as well as a better technical description about how the **CMN** and **CINV** instructions function in this use-case.

A great tip by @michalmalik to use the `man` pages to reference [Architecture Calling Conventions](http://man7.org/linux/man-pages/man2/syscall.2.html) in case you forget what registers are used. Thanks Michal! 


