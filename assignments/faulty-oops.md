# AESD Assignment 7  
## Output and Analysis of a Kernel Oops error caused by module 'faulty'  

The command that was run was 'echo “hello_world” > /dev/faulty'  

### Output  
  
```
Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000
Mem abort info:
  ESR = 0x96000045
  EC = 0x25: DABT (current EL), IL = 32 bits
  SET = 0, FnV = 0
  EA = 0, S1PTW = 0
  FSC = 0x05: level 1 translation fault
Data abort info:
  ISV = 0, ISS = 0x00000045
  CM = 0, WnR = 1
user pgtable: 4k pages, 39-bit VAs, pgdp=0000000042060000
[0000000000000000] pgd=0000000000000000, p4d=0000000000000000, pud=0000000000000000
Internal error: Oops: 96000045 [#2] SMP
Modules linked in: hello(O) faulty(O) scull(O)
CPU: 0 PID: 160 Comm: sh Tainted: G      D    O      5.15.18 #1
Hardware name: linux,dummy-virt (DT)
pstate: 80000005 (Nzcv daif -PAN -UAO -TCO -DIT -SSBS BTYPE=--)
pc : faulty_write+0x14/0x20 [faulty]
lr : vfs_write+0xa8/0x2b0
sp : ffffffc008d0bd80
x29: ffffffc008d0bd80 x28: ffffff80020d8000 x27: 0000000000000000
x26: 0000000000000000 x25: 0000000000000000 x24: 0000000000000000
x23: 0000000040001000 x22: 0000000000000012 x21: 0000005586632a50
x20: 0000005586632a50 x19: ffffff80020f0800 x18: 0000000000000000
x17: 0000000000000000 x16: 0000000000000000 x15: 0000000000000000
x14: 0000000000000000 x13: 0000000000000000 x12: 0000000000000000
x11: 0000000000000000 x10: 0000000000000000 x9 : 0000000000000000
x8 : 0000000000000000 x7 : 0000000000000000 x6 : 0000000000000000
x5 : 0000000000000001 x4 : ffffffc0006f7000 x3 : ffffffc008d0bdf0
x2 : 0000000000000012 x1 : 0000000000000000 x0 : 0000000000000000
Call trace:
 faulty_write+0x14/0x20 [faulty]
 ksys_write+0x68/0x100
 __arm64_sys_write+0x20/0x30
 invoke_syscall+0x54/0x130
 el0_svc_common.constprop.0+0x44/0xf0
 do_el0_svc+0x40/0xa0
 el0_svc+0x20/0x60
 el0t_64_sync_handler+0xe8/0xf0
 el0t_64_sync+0x1a0/0x1a4
Code: d2800001 d2800000 d503233f d50323bf (b900003f) 
---[ end trace c2320eec8e8bd8d2 ]---
```


### Analysis  

This is a Kernel Oops message indicating an unexpected error in the Linux kernel. 

`Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000` - This indicates that the kernel tried to access memory at 0x0 and attempted to dereference a NULL pointer.  

`ESR = 0x96000045` - Gives information about the exception. Some of the fields are as follows:

EC = 0x25 : Data abort (DABT). 
IL, bit[25] = 1, indicates 32-bit trapped instruction
EC, bits[31:28] = 9, instruction abort
EA = 0, effective address unknown
FSC = 0x05, translation fault at level 1 of the page table.

`Data abort info:`
  `ISV = 0` : ISS field is invalid
  `ISS = 0x00000045` : additional information about the error if valid
  `CM = 0` : Fault did not occur during cache maintainence
  `WnR = 1` : Fault occured during a write operation

```
user pgtable: 4k pages, 39-bit VAs, pgdp=0000000042060000
[0000000000000000] pgd=0000000000000000, p4d=0000000000000000, pud=0000000000000000 
``` 
 This indicates that the page table had 4k pages, adn 39 bit virtual addresses. The log indicates that the PGD, P4D, and PUD entries for the virtual address 0000000000000000 are all 0, which means that the translation table for this virtual address is not present, leading to a page fault.

`Modules linked in: hello(O) faulty(O) scull(O)` - Indicates the loaded modules

```
CPU: 0 PID: 160 Comm: sh Tainted: G      D    O      5.15.18 #1
Hardware name: linux,dummy-virt (DT)
pstate: 80000005 (Nzcv daif -PAN -UAO -TCO -DIT -SSBS BTYPE=--)
pc : faulty_write+0x14/0x20 [faulty]
lr : vfs_write+0xa8/0x2b0
sp : ffffffc008d0bd80
x29: ffffffc008d0bd80 x28: ffffff80020d8000 x27: 0000000000000000
x26: 0000000000000000 x25: 0000000000000000 x24: 0000000000000000
x23: 0000000040001000 x22: 0000000000000012 x21: 0000005586632a50
x20: 0000005586632a50 x19: ffffff80020f0800 x18: 0000000000000000
x17: 0000000000000000 x16: 0000000000000000 x15: 0000000000000000
x14: 0000000000000000 x13: 0000000000000000 x12: 0000000000000000
x11: 0000000000000000 x10: 0000000000000000 x9 : 0000000000000000
x8 : 0000000000000000 x7 : 0000000000000000 x6 : 0000000000000000
x5 : 0000000000000001 x4 : ffffffc0006f7000 x3 : ffffffc008d0bdf0
x2 : 0000000000000012 x1 : 0000000000000000 x0 : 0000000000000000
Call trace:
 faulty_write+0x14/0x20 [faulty]
 ksys_write+0x68/0x100
 __arm64_sys_write+0x20/0x30
 invoke_syscall+0x54/0x130
 el0_svc_common.constprop.0+0x44/0xf0
 do_el0_svc+0x40/0xa0
 el0_svc+0x20/0x60
 el0t_64_sync_handler+0xe8/0xf0
 el0t_64_sync+0x1a0/0x1a4
Code: d2800001 d2800000 d503233f d50323bf (b900003f) 
---[ end trace c2320eec8e8bd8d2 ]---
```

 This indicates the process that caused the kernel fault was running with PID = 160, and command = sh. 
 The exeception occured in the fualty module, during faulty_write. The PC, LR and SP regster states, along with the call trace are indicated. 
