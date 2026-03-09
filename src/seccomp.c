/*
 * seccomp.c - seccomp-bpf syscall filtering
 */

#include "sandlock.h"

int apply_seccomp(void) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) return -1;
    
    #define BLOCK(syscall) seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(syscall), 0)
    
    if (config.block_network) {
        BLOCK(socket); BLOCK(connect); BLOCK(bind); BLOCK(listen);
        BLOCK(accept); BLOCK(accept4); BLOCK(sendto); BLOCK(recvfrom);
        BLOCK(sendmsg); BLOCK(recvmsg); BLOCK(socketpair);
    }
    
    if (config.block_fork) {
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone),
            1, SCMP_A0(SCMP_CMP_MASKED_EQ, 0x10000, 0));
    }
    
    if (config.block_dangerous) {
        // Debug/trace
        BLOCK(ptrace); BLOCK(process_vm_readv); BLOCK(process_vm_writev);
        
        // Kernel interfaces
        BLOCK(userfaultfd); BLOCK(perf_event_open); BLOCK(bpf);
        BLOCK(io_uring_setup); BLOCK(io_uring_enter); BLOCK(io_uring_register);
        
        // Keys
        BLOCK(keyctl); BLOCK(add_key); BLOCK(request_key);
        
        // Namespaces
        BLOCK(unshare); BLOCK(setns);
        
        // Filesystem
        BLOCK(mount); BLOCK(umount2); BLOCK(chroot); BLOCK(pivot_root);
        BLOCK(symlink); BLOCK(symlinkat); BLOCK(link); BLOCK(linkat);
        
        // System
        BLOCK(reboot); BLOCK(kexec_load); BLOCK(kexec_file_load);
        BLOCK(init_module); BLOCK(finit_module); BLOCK(delete_module);
        BLOCK(acct); BLOCK(swapon); BLOCK(swapoff);
        BLOCK(sethostname); BLOCK(setdomainname);
        
        // Time
        BLOCK(settimeofday); BLOCK(clock_settime); BLOCK(adjtimex);
        
        // Hardware
        BLOCK(ioperm); BLOCK(iopl); BLOCK(modify_ldt);
        
        // Mount API
        BLOCK(open_tree); BLOCK(move_mount); BLOCK(fsopen);
        BLOCK(fspick); BLOCK(fsconfig); BLOCK(fsmount);
        
        // Monitoring
        BLOCK(inotify_init); BLOCK(inotify_init1); BLOCK(inotify_add_watch);
        BLOCK(fanotify_init); BLOCK(fanotify_mark);
        
        // Misc
        BLOCK(personality); BLOCK(quotactl); BLOCK(nfsservctl);
        
        // Kill restrictions
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(kill),
            1, SCMP_A0(SCMP_CMP_EQ, -1));
        BLOCK(tkill); BLOCK(tgkill);
    }
    
    #undef BLOCK
    
    int rc = seccomp_load(ctx);
    seccomp_release(ctx);
    return rc;
}
