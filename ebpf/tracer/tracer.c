#include "common.h"
#include "file.h"
#include "process.h"
#include "network.h"

char __license[] SEC("license") = "GPL";


SEC("kprobe/__x64_sys_execve")
int kprobe_syscall_execve(struct pt_regs *ctx) {
    if (!process_in_scope()) {
        return 0;
    }

    if (!process_is_interesting()) {
        return 0;
    }

    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);
    if (!ctx2) {
        return 0;
    }

    uintptr_t argv = (uintptr_t)READ_KERN(PT_REGS_PARM2(ctx2));
    
    struct syscall_cache_t syscall = {
        .type = EXEC_SYSCALL,
        .exec = {
            .args = argv
        }
    };

    cache_syscall(&syscall);
    return 0;
}

SEC("kprobe/__x64_sys_execveat")
int kprobe_syscall_execveat(struct pt_regs *ctx) {
    if (!process_in_scope()) {
        return 0;
    }

    if (!process_is_interesting()) {
        return 0;
    }

    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);
    if (!ctx2) {
        return 0;
    }

    uintptr_t argv = (uintptr_t)READ_KERN(PT_REGS_PARM3(ctx2));    

    struct syscall_cache_t syscall = {
        .type = EXEC_SYSCALL,
        .exec = {
            .args = argv
        }
    };

    cache_syscall(&syscall);
    return 0;
}

SEC("lsm/task_kill")
int BPF_PROG(task_kill, struct task_struct *p, struct kernel_siginfo *info,
	 int sig, const struct cred *cred)
{
    if (!process_in_scope()) {
        return 0;
    }

    // bpf_printk("lsm_hook: task: task_kill1\n");

    if (!process_is_interesting()) {
        return 0;
    }

	// bpf_printk("lsm_hook: task: task_kill\n");
    // bpf_printk("p_tgid %d", get_task_tgid_nr_ns(p));

    struct task_struct *current = (struct task_struct *)bpf_get_current_task();
    struct process_event *event = bpf_ringbuf_reserve(&process_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->type = PROCESS_EVENT_TYPE_KILL;
    event->flag = 0;
    event->parent_pid = get_task_parent_pid(current);
    event->parent_tgid = get_task_parent_tgid(current);
    event->ns_parent_pid = get_task_parent_pid_nr_ns(current);
    event->ns_parent_tgid = get_task_parent_tgid_nr_ns(current);
    event->child_pid = get_task_pid(current);
    event->child_tgid = get_task_tgid(current);
    event->ns_child_pid = get_task_pid_nr_ns(current);
    event->ns_child_tgid = get_task_tgid_nr_ns(current);
    event->time = bpf_ktime_get_ns();
    event->u.kill_event.signal = (u32)sig;
    event->u.kill_event.syscall = (u32)get_current_task_syscall_id();
    event->u.kill_event.target_ns_tgid = get_task_tgid_nr_ns(p);

    // bpf_printk("current_tgid %d",event->ns_child_tgid);
    // bpf_printk("parent_tgid %d", event->ns_parent_tgid);

    handle_process_stop_policy_for_kill_operations(event);
    
    // FIXME: drop the kill event if it is not enforced.
    if (!(event->flag & EVENT_FLAG_PROCESS_STOPPED)) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    } else {
        bpf_ringbuf_submit(event, 0);
        return -1;
    }
}

// SEC("tracepoint/syscalls/sys_enter_kill")
// int tracepoint_sys_enter_kill(struct trace_event_raw_sys_enter *ctx) {
//     if (!process_in_scope()) {
//         return 0;
//     }

//     if (!process_is_interesting()) {
//         return 0;
//     }

//     long int syscall_id = ctx->id;
//     pid_t tgid = (pid_t)ctx->args[0];
//     int sig = (int)ctx->args[1];

//     bpf_printk("kill: send %d to process %d", sig, tgid);

//     struct task_struct *current = (struct task_struct *)bpf_get_current_task();

//     struct process_event *event = bpf_ringbuf_reserve(&process_events, sizeof(*event), 0);
//     if (!event)
//         return 0;

//     event->type = PROCESS_EVENT_TYPE_KILL;
//     event->flag = 0;
//     event->parent_pid = get_task_parent_pid(current);
//     event->parent_tgid = get_task_parent_tgid(current);
//     event->ns_parent_pid = get_task_parent_pid_nr_ns(current);
//     event->ns_parent_tgid = get_task_parent_tgid_nr_ns(current);
//     event->child_pid = get_task_pid(current);
//     event->child_tgid = get_task_tgid(current);
//     event->ns_child_pid = get_task_pid_nr_ns(current);
//     event->ns_child_tgid = get_task_tgid_nr_ns(current);
//     event->time = bpf_ktime_get_ns();
//     event->u.kill_event.signal = (u32)sig;
//     // event->u.kill_event.ns_tgid = (u32)tgid;
//     event->u.kill_event.syscall = (u32)syscall_id;

//     handle_process_stop_policy_for_kill_operations(event);
    
//     // FIXME: drop the kill event if it is not enforced.
//     if(!(event->flag & EVENT_FLAG_PROCESS_STOPPED)) {
//         bpf_ringbuf_discard(event, 0);
//     } else {
//         bpf_ringbuf_submit(event, 0);
//     }

//     return 0;
// }

// https://elixir.bootlin.com/linux/v5.15/source/kernel/fork.c#L2594
// https://elixir.bootlin.com/linux/v5.15/source/include/trace/events/sched.h#L369
SEC("raw_tracepoint/sched_process_fork")
int tracepoint__sched__sched_process_fork(struct bpf_raw_tracepoint_args *ctx) {
    if (!process_in_scope()) {
        return 0;
    }

    // bpf_printk("sched_process_fork");

    if (!process_is_interesting()) {
        return 0;
    }

    // TP_PROTO(struct task_struct *parent, struct task_struct *child)
    struct task_struct *parent = (struct task_struct *)ctx->args[0];
    struct task_struct *child = (struct task_struct *)ctx->args[1];

    u32 parent_tgid = get_task_tgid(parent);
    u32 child_tgid = get_task_tgid(child);

    // ignore kernel thread
    if (parent_tgid == child_tgid) {
        return 0;
    }

    process_fork(parent, child);

    struct process_event *event = bpf_ringbuf_reserve(&process_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->type = PROCESS_EVENT_TYPE_FORK;
    event->flag = 0;
    event->parent_pid = get_task_pid(parent);
    event->parent_tgid = parent_tgid;
    event->ns_parent_pid = get_task_pid_nr_ns(parent);
    event->ns_parent_tgid = get_task_tgid_nr_ns(parent);
    event->child_pid = get_task_pid(child);
    event->child_tgid = child_tgid;
    event->ns_child_pid = get_task_pid_nr_ns(child);
    event->ns_child_tgid = get_task_tgid_nr_ns(child);
    event->time = bpf_ktime_get_ns();

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// https://elixir.bootlin.com/linux/v5.15/source/fs/exec.c#L1749
// https://elixir.bootlin.com/linux/v5.15/source/include/trace/events/sched.h#L397
SEC("raw_tracepoint/sched_process_exec")
int tracepoint__sched__sched_process_exec(struct bpf_raw_tracepoint_args *ctx) {
    if (!process_in_scope()) {
        return 0;
    }

    if (!process_is_interesting()) {
        return 0;
    }

    // TP_PROTO(struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
    struct task_struct *current = (struct task_struct *)ctx->args[0];
    struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];

    if (!bprm) {
        return 0; 
    }
      
    struct process_exec_event *exec_event = get_process_exec_event_buf(0);
    if (exec_event) {
        init_process_exec_event_from_linux_binprm(bprm, NULL, PROCESS_EVENT_TYPE_EXEC, exec_event);
    }
    
    struct process_event *event = bpf_ringbuf_reserve(&process_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->type = PROCESS_EVENT_TYPE_EXEC;
    event->flag = 0;
    event->parent_pid = get_task_parent_pid(current);
    event->parent_tgid = get_task_parent_tgid(current);
    event->ns_parent_pid = get_task_parent_pid_nr_ns(current);
    event->ns_parent_tgid = get_task_parent_tgid_nr_ns(current);
    event->child_pid = get_task_pid(current);
    event->child_tgid = get_task_tgid(current);
    event->ns_child_pid = get_task_pid_nr_ns(current);
    event->ns_child_tgid = get_task_tgid_nr_ns(current);
    event->time = bpf_ktime_get_ns();

    if (exec_event) {
        bpf_probe_read(&event->u.exec_event, sizeof(event->u.exec_event), exec_event);
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("raw_tracepoint/sched_process_exit")
int tracepoint__sched__sched_process_exit(struct bpf_raw_tracepoint_args *ctx) {
    if (!process_in_scope()) {
        return 0;
    }

    if (!process_is_interesting()) {
        return 0;
    }


    struct task_struct *current = (struct task_struct *)ctx->args[0];

    struct signal_struct *s = BPF_CORE_READ(current, signal);
    atomic_t live = BPF_CORE_READ(s, live);

    // ensure the group (of all threads) is exit 
    if (live.counter == 0) {
        process_exit(current);

        struct process_event *event = bpf_ringbuf_reserve(&process_events, sizeof(*event), 0);
        struct task_struct *parent = BPF_CORE_READ(current, parent);

        if (!event)
            return 0;

        event->type = PROCESS_EVENT_TYPE_EXIT;
        event->flag = 0;
        event->parent_pid = get_task_parent_pid(current);
        event->parent_tgid = get_task_parent_tgid(current);
        event->ns_parent_pid = get_task_pid_nr_ns(parent);
        event->ns_parent_tgid = get_task_tgid_nr_ns(parent);
        event->child_pid = get_task_pid(current);
        event->child_tgid = get_task_tgid(current);
        event->ns_child_pid = get_task_pid_nr_ns(current);
        event->ns_child_tgid = get_task_tgid_nr_ns(current);
        event->time = bpf_ktime_get_ns();

        // bpf_printk("process %d exited", event->ns_child_pid);

        bpf_ringbuf_submit(event, 0);
        return 0;
    }

    // clear file access of a process ???

    return 0;
}


SEC("kprobe/security_bprm_check")
int kprobe_security_bprm_check(struct pt_regs *ctx) {
    if (!process_in_scope()) {
        return 0;
    }

    if (!process_is_interesting()) {
        return 0;
    }

    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(current_task, parent);

    struct linux_binprm *bprm = (struct linux_binprm *) PT_REGS_PARM1(ctx);
    struct process_exec_event *exec_event = get_process_exec_event_buf(0);

    struct syscall_cache_t* cached_syscall = get_cached_syscall(EXEC_SYSCALL);

    if (exec_event) {
        init_process_exec_event_from_linux_binprm(bprm, cached_syscall, PROCESS_EVENT_TYPE_BPRM_CHECK, exec_event);
    }

    struct process_event *event = bpf_ringbuf_reserve(&process_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->type = PROCESS_EVENT_TYPE_BPRM_CHECK;
    event->flag = 0;
    BPF_CORE_READ_INTO(&event->parent_pid, parent, pid);
    BPF_CORE_READ_INTO(&event->parent_tgid, parent, tgid);
    event->ns_parent_pid = get_task_pid_nr_ns(parent);
    event->ns_parent_tgid = get_task_tgid_nr_ns(parent);
    BPF_CORE_READ_INTO(&event->child_pid, current_task, pid);
    BPF_CORE_READ_INTO(&event->child_tgid, current_task, tgid);
    event->ns_child_pid = get_task_pid_nr_ns(current_task);
    event->ns_child_tgid = get_task_tgid_nr_ns(current_task);
    event->time = bpf_ktime_get_ns();

    if (exec_event) {
        bpf_probe_read(&event->u.exec_event, sizeof(event->u.exec_event), exec_event);
    }

    handle_process_stop_policy_for_exec_operations(event);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("uretprobe//bin/bash:readline")
int BPF_KRETPROBE(bash_readline_ret, const void *ret) {
    struct readline_event *event;
    struct task_struct *current_task;
    struct task_struct *parent_task;

    if (!ret)
        return 0;

    event = bpf_ringbuf_reserve(&readline_events, sizeof(*event), 0);
    if (!event)
        return 0;

    bpf_get_current_comm(&event->task_comm, sizeof(event->task_comm));

    current_task = (struct task_struct *)bpf_get_current_task();

    event->tgid = get_current_tgid();
    event->parent_tgid = get_task_parent_tgid(current_task);
    event->ns_tgid = get_task_tgid_nr_ns(current_task);
    parent_task = BPF_CORE_READ(current_task, parent);
    event->ns_parent_tgid = get_task_tgid_nr_ns(parent_task);
    bpf_probe_read_user_str(&event->readline, sizeof(event->readline), ret);
    event->time = bpf_ktime_get_ns();

    bpf_ringbuf_submit(event, 0);
    return 0;
};


/** https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_SOCK_OPS
 * The program is invoked with this op when a socket is in the 'connect' state, 
 * it has sent out a SYN message, but is not yet established. 
 * This is just a notification, return value is discarded. */
// static inline void bpf_sockops_tcp_connect_cb(struct bpf_sock_ops *skops) {
//     struct socket_event *event;
//     u32 fam;
//     struct task_struct *current_task, *parent_task;

//     fam = skops->family;
//     if (fam != AF_INET && fam != AF_INET6) {
//         return;
//     }

//     event = bpf_ringbuf_reserve(&socket_events, sizeof(*event), 0);
//     if (!event) {
//         return;
//     }

//     event->family = fam;
//     event->lport = skops->local_port;
//     event->rport = bpf_ntohl(skops->remote_port);
    
//     // bpf_printk("local_p = %u, remote_p = %u \n", event->lport, event->rport);

//     if (fam == AF_INET) {
//         event->laddr = bpf_ntohl(skops->local_ip4);
//         event->raddr = bpf_ntohl(skops->remote_ip4);
//     } else {
//         int i = 0;
//         // llvm optimizer vs bpf verifier :(
//         u32 *p1, *p2, *p3, *p4;
        
//         // bpf_printk("ipv6_l: %u, %u\n", skops->local_ip6[0], skops->local_ip6[1]);
//         // bpf_printk("ipv6_l: %u, %u\n", skops->local_ip6[2], skops->local_ip6[3]);

//         p1 = (u32 *)event->laddr6;
//         p2 = (u32 *)(event->laddr6 + 4);
//         p3 = (u32 *)(event->laddr6 + 8);
//         p4 = (u32 *)(event->laddr6 + 12);

//         *p1 = skops->local_ip6[0];
//         *p2 = skops->local_ip6[1];
//         *p3 = skops->local_ip6[2];
//         *p4 = skops->local_ip6[3];


//         // bpf_printk("ipv6_r: %u, %u\n", skops->remote_ip6[0], skops->remote_ip6[1]);
//         // bpf_printk("ipv6_r: %u, %u\n", skops->remote_ip6[2], skops->remote_ip6[3]);
        
//         p1 = (u32 *)event->raddr6;
//         p2 = (u32 *)(event->raddr6 + 4);
//         p3 = (u32 *)(event->raddr6 + 8);
//         p4 = (u32 *)(event->raddr6 + 12);

//         *p1 = skops->remote_ip6[0];
//         *p2 = skops->remote_ip6[1];
//         *p3 = skops->remote_ip6[2];
//         *p4 = skops->remote_ip6[3];
//     }

//     current_task = (struct task_struct *) bpf_get_current_task();
//     parent_task = BPF_CORE_READ(current_task, parent);
//     event->tgid = BPF_CORE_READ(current_task, tgid);
//     event->parent_tgid = get_task_parent_tgid(current_task);
//     event->ns_tgid = get_task_tgid_nr_ns(current_task);
//     event->ns_parent_tgid = get_task_tgid_nr_ns(parent_task);
//     event->time = bpf_ktime_get_ns();

//     bpf_ringbuf_submit(event, 0);
// }


// SEC("sockops")
// int bpf_sockops_cb(struct bpf_sock_ops *skops) {
// 	u32 op;

//     op = skops->op;

// 	if (op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB
//         && op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {    
//         return 0;
//     }

//     bpf_sockops_tcp_connect_cb(skops);

// 	return 0;
// }


SEC("kprobe/security_socket_connect")
int kprobe_security_socket_connect(struct pt_regs *ctx) {
    if (!process_in_scope()) {
        return 0;
    }

    if (!process_is_interesting()) {
        return 0;
    }

    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();    

    // bpf_printk("security_socket_connect");

    u64 addr_len = PT_REGS_PARM3(ctx);
    
    struct socket *sock = (struct socket *) PT_REGS_PARM1(ctx);
    if (!sock)
        return 0;

    struct sockaddr *address = (struct sockaddr *) PT_REGS_PARM2(ctx);
    if (!address)
        return 0;

    u32 type = BPF_CORE_READ(sock, type);

    sa_family_t sa_fam = BPF_CORE_READ(address, sa_family);
    if (sa_fam != AF_INET && sa_fam != AF_INET6) {
        return 0;
    }

    struct socket_event *event;
    event = bpf_ringbuf_reserve(&socket_events, sizeof(*event), 0);
    if (!event)
        return 0;

    struct task_struct *parent_task = BPF_CORE_READ(current_task, parent);

    event->time = bpf_ktime_get_ns();
    event->flag = 0;
    event->type = SOCKET_EVENT_TYPE_CONNECT;
    parent_task = BPF_CORE_READ(current_task, parent);
    event->tgid = BPF_CORE_READ(current_task, tgid);
    event->parent_tgid = get_task_parent_tgid(current_task);
    event->ns_tgid = get_task_tgid_nr_ns(current_task);
    event->ns_parent_tgid = get_task_tgid_nr_ns(parent_task);

    if (sa_fam == AF_INET) {
        bpf_probe_read(&event->u.addr4, bpf_core_type_size(struct sockaddr_in), address);
        event->u.addr4.sin_addr.s_addr = bpf_ntohl(event->u.addr4.sin_addr.s_addr);
        event->u.addr4.sin_port = bpf_ntohs(event->u.addr4.sin_port);
    } else {
        bpf_probe_read(&event->u.addr6, bpf_core_type_size(struct sockaddr_in6), address);
        event->u.addr6.sin6_port = bpf_ntohs(event->u.addr4.sin_port);
    }

    handle_process_stop_policy_for_net_operations(event, SOCKET_EVENT_TYPE_CONNECT);
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kprobe/security_socket_listen")
int kprobe_security_socket_listen(struct pt_regs *ctx) {
    if (!process_in_scope()) {
        return 0;
    }

    if (!process_is_interesting()) {
        return 0;
    }

    // bpf_printk("security_socket_listen");    

    struct socket *sock = (struct socket *) PT_REGS_PARM1(ctx);
    // FIXME: local or remote
    submit_socket_event_from_socket(sock, SOCKET_EVENT_TYPE_LISTEN);
    return 0;
}

SEC("kprobe/security_socket_accept")
int kprobe_security_socket_accept(struct pt_regs *ctx) {
    if (!process_in_scope()) {
        return 0;
    }

    if (!process_is_interesting()) {
        return 0;
    }

    // bpf_printk("security_socket_accept");    

    struct socket *sock = (struct socket *) PT_REGS_PARM1(ctx);
    struct socket *new_sock = (struct socket *) PT_REGS_PARM2(ctx);
    // FIXME: local or remote
    submit_socket_event_from_socket(sock, SOCKET_EVENT_TYPE_ACCEPT);

    struct syscall_cache_t syscall = {
        .type = ACCPET_SYSCALL,
        .accpet = {
            .new_sock = (uintptr_t)new_sock
        }
    };

    cache_syscall(&syscall);
    return 0;
}

static inline void on_accept_exit(struct pt_regs *regs) {
    struct syscall_cache_t *syscall = get_cached_syscall(ACCPET_SYSCALL);
    if (!syscall) {
        return;
    }

    struct socket *sock = (struct socket *)syscall->accpet.new_sock;
    submit_socket_event_from_socket(sock, SOCKET_EVENT_TYPE_ACCEPT_EXIT);

    return;
}


SEC("raw_tracepoint/sys_exit")
int tracepoint__raw_syscalls__sys_exit(struct bpf_raw_tracepoint_args *ctx) {
    if (!process_in_scope()) {
        return 0;
    }

    if (!process_is_interesting()) {
        return 0;
    }

    struct pt_regs *regs = (struct pt_regs *) ctx->args[0];
    int id = get_syscall_id_from_regs(regs);

    // TODO: tail call
    if (id == SYSCALL_ACCEPT || id == SYSCALL_ACCEPT4) {
        on_accept_exit(regs);
    }

    return 0;
}


SEC("kprobe/security_inet_conn_established")
int kprobe_security_inet_conn_established (struct pt_regs *ctx) {
    if (!process_in_scope()) {
        return 0;
    }

    if (!process_is_interesting()) {
        return 0;
    }

    // bpf_printk("security_inet_conn_established"); 

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    submit_socket_event_from_sock(sk, SOCKET_EVENT_TYPE_INET_CONN_ESTABLISHED);

    return 0;    
}

SEC("kprobe/security_sock_rcv_skb")
int kprobe_security_sock_rcv_skb(struct pt_regs *ctx) {
    if (!process_in_scope()) {
        return 0;
    }

    if (!process_is_interesting()) {
        return 0;
    }

    // bpf_printk("security_sock_rcv_skb");    

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    submit_socket_event_from_sock(sk, SOCKET_EVENT_TYPE_SOCK_RCV_SKB);

    return 0;    
}


SEC("kprobe/inet_csk_accept")
int kprobe_inet_csk_accept(struct pt_regs *ctx) {
    if (!process_in_scope()) {
        return 0;
    }

    if (!process_is_interesting()) {
        return 0;
    }

    // bpf_printk("inet_csk_accept");    

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    submit_socket_event_from_sock(sk, SOCKET_EVENT_TYPE_INET_CSK_ACCEPT);

    return 0;
}


SEC("kprobe/security_sk_clone")
int kprobe_security_sk_clone(struct pt_regs *ctx) {
    if (!process_in_scope()) {
        return 0;
    }

    if (!process_is_interesting()) {
        return 0;
    }

    // bpf_printk("security_sk_clone");    

    struct socket *sock = (struct socket *) PT_REGS_PARM1(ctx);
    struct socket *new_sock = (struct socket *) PT_REGS_PARM2(ctx);
    // FIXME: local or remote
    submit_socket_event_from_socket(new_sock, SOCKET_EVENT_TYPE_SK_CLONE);

    return 0;
}

// https://github.com/castai/egressd/blob/9ae8d4bd6c9b6e59e8280c931fea52ba85272530/ebpf/c/egressd.c
SEC("cgroup_skb/ingress")
int bpf_dns_handler(struct __sk_buff *ctx) {
    if (ctx->protocol != bpf_htons(ETH_P_IP))
        return 1;

    struct bpf_sock *sk = ctx->sk;
    if (!sk)
        return 1;

    sk = bpf_sk_fullsock(sk);
    if (!sk)
        return 1;

    struct iphdr ip;
    if (bpf_skb_load_bytes_relative(ctx, 0, &ip, sizeof(ip), BPF_HDR_START_NET)) {
        return 1;
    }

    if (ip.protocol != IPPROTO_UDP) {
        return 1;
    }

    struct udphdr udp;
    if (bpf_skb_load_bytes_relative(ctx, sizeof(ip), &udp, sizeof(udp), BPF_HDR_START_NET)) {
        return 1;
    }

    if (udp.source != bpf_ntohs(53)) {
        return 1;
    }

    net_event_context_t neteventctx;
    neteventctx.bytes = ctx->len;
    neteventctx.time = bpf_ktime_get_ns();

    u64 flags = BPF_F_CURRENT_CPU;
    u32 data_size = ctx->len;
    // What does that mean???
    // https://lore.kernel.org/bpf/20240802001319.vBZnaVZrlD_QCxThMxVglFobRG0gpEBQb-EToPHNK-Y@z/T/
    flags |= (u64) data_size << 32;

    bpf_perf_event_output(ctx,
                          &dns_events,
                          flags,
                          &neteventctx,
                          sizeof(net_event_context_t));

    return 1;
}

// SEC("lsm/file_permission")
// int BPF_PROG(handle_file_permission, struct file *file, int mask, int ret) {
//     u32 key = 0;
//     u32 *mnt_ns_id;
//     u32 cur_mnt_ns_id;
//     struct task_struct *current_task;
//     struct task_struct *parent_task;
//     struct file_event *event;
//     struct path f_path;
//     struct buffers *path_buf;
//     struct buf_offset buf_off;
//     // struct pt_regs *regs;
//     // int syscall;

//     // skip if child process is not in the target mount namespace
//     mnt_ns_id = bpf_map_lookup_elem(&mnt_ns_id_list, &key);
//     if (!mnt_ns_id) {
//         return ret;
//     }

//     current_task = bpf_get_current_task_btf();
//     cur_mnt_ns_id = get_task_mnt_ns_id(current_task);
//     if (cur_mnt_ns_id != *mnt_ns_id) {
//         return ret;
//     }

//     path_buf = (struct buffers *) get_buf(0);
//     if (!path_buf) {
//         return ret;
//     }

//     f_path = BPF_CORE_READ(file, f_path);

//     if (!prepend_path(&f_path, path_buf, &buf_off)) {
//         return ret;
//     }

//     event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
//     if (!event) {
//         return ret;
//     }

//     event->acc_mode = mask;
//     event->tgid = get_current_tgid();
//     event->parent_tgid = get_task_parent_tgid(current_task);
//     bpf_probe_read_kernel_str(&event->path, 
//     MAX_PATH_LEN - (buf_off.offset & (MAX_PATH_LEN - 1)), 
//     &path_buf->buf[(buf_off.offset & (MAX_PATH_LEN - 1))]);
//     event->ns_tgid = get_task_tgid_nr_ns(current_task);
//     parent_task = BPF_CORE_READ(current_task, parent);
//     event->ns_parent_tgid = get_task_tgid_nr_ns(parent_task);
//     event->time = bpf_ktime_get_ns();

//     // regs = (struct pt_regs *) bpf_task_pt_regs(current_task);    
//     // // In x86_64 orig_ax has the syscall interrupt stored here
//     // syscall = regs->orig_ax;
//     // bpf_printk("file operation by syscall %lu \n", syscall);

//     bpf_ringbuf_submit(event, 0);

//     // do not change the return value
//     return ret;
// }

// static inline bool is_in_cache(u32 tgid, struct buffers *path_buf, struct buf_offset *buf_off) {
//     struct path_block *block;

//     block = bpf_map_lookup_elem(&file_event_cache, &tgid);
// }

SEC("kprobe/security_file_open")
int kprobe_security_file_open(struct pt_regs *ctx) {
    struct task_struct *current_task;
    struct task_struct *parent_task;
    struct file_event *event;
    struct path f_path;
    struct path_buffer_t *path_buf;
    struct buf_offset buf_off;
    u32 perm;
    u32 ns_tgid;
    
    if (!process_in_scope()) {
        return 0;
    }

    if (!process_is_interesting()) {
        return 0;
    }

    current_task = (struct task_struct *)bpf_get_current_task();

    struct file *file = (struct file *) PT_REGS_PARM1(ctx);
    u32 inode = get_inode_nr_from_file(file);
    u64 ctime = get_ctime_nanosec_from_file(file);

    perm = map_file_to_perms(file);

    // Only cache-skip read-only opens. Write opens must always be checked:
    // ctime granularity can be too coarse (e.g. Linux multigrain timestamps)
    // to distinguish two rapid successive writes to the same file, so
    // caching writes by (inode, ctime) can silently drop the stop-policy
    // check and event submission for a write that should be enforced.
    if (!(perm & (MAY_WRITE | MAY_APPEND)) && query_file_access(inode, ctime)) {
        return 0;
    }

    int syscall_id = get_current_task_syscall_id();

    path_buf = (struct path_buffer_t *) get_path_buf(0);
    if (!path_buf) {
        return 0;
    }

    f_path = BPF_CORE_READ(file, f_path);

    if (!prepend_path(&f_path, path_buf, &buf_off)) {
        return 0;
    }

    ns_tgid = get_task_tgid_nr_ns(current_task);

    event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    cache_file_access(inode, ctime);

    event->time = bpf_ktime_get_ns();
    event->flag = 0;
    event->tgid = get_current_tgid();
    event->parent_tgid = get_task_parent_tgid(current_task);
    event->ns_tgid = ns_tgid;
    parent_task = BPF_CORE_READ(current_task, parent);
    event->ns_parent_tgid = get_task_tgid_nr_ns(parent_task);
    
    event->type = FILE_EVENT_TYPE_FILE_OPEN;
    event->u.f_open.acc_mode = perm;
    event->u.f_open.syscall = syscall_id;
    event->u.f_open.dev = get_dev_from_file(file);
    event->u.f_open.inode = inode;
    event->u.f_open.ctime = ctime;
    bpf_probe_read_kernel_str(&event->u.f_open.path, 
    MAX_PATH_LEN - (buf_off.offset & (MAX_PATH_LEN - 1)), 
    &path_buf->buf[(buf_off.offset & (MAX_PATH_LEN - 1))]);

    handle_process_stop_policy_for_file_operations(event);

    bpf_ringbuf_submit(event, 0);

    return 0;
}


SEC("kprobe/security_inode_unlink")
int kprobe_security_inode_unlink(struct pt_regs *ctx) {
    if (!process_in_scope()) {
        return 0;
    }

    if (!process_is_interesting()) {
        return 0;
    }
    
    // struct inode *dir = (struct inode *)PT_REGS_PARM1(ctx);
    struct dentry *dentry = (struct dentry *) PT_REGS_PARM2(ctx);

    if (!is_overlayfs(dentry)) {
        return 0;
    }


    u32 inode = get_inode_nr_from_dentry(dentry);
    u64 ctime = get_ctime_nanosec_from_dentry(dentry);

    if (query_file_access(inode, ctime)) {
        return 0;
    }

    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();

    int syscall_id = get_current_task_syscall_id();

    struct path_buffer_t *path_buf = (struct path_buffer_t *) get_path_buf(0);
    if (!path_buf) {
        return 0;
    }

    struct buf_offset buf_off;
    if (!get_dentry_path_str(dentry, path_buf, &buf_off)) {
        return 0;
    }
    
    struct file_event *event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    cache_file_access(inode, ctime);

    event->time = bpf_ktime_get_ns();
    event->flag = 0;
    event->tgid = get_current_tgid();
    event->parent_tgid = get_task_parent_tgid(current_task);
    event->ns_tgid = get_task_tgid_nr_ns(current_task);
    struct task_struct * parent_task = BPF_CORE_READ(current_task, parent);
    event->ns_parent_tgid = get_task_tgid_nr_ns(parent_task);

    event->type = FILE_EVENT_INODE_UNLINK;
    event->u.inode_unlink_event.syscall = syscall_id;
    event->u.inode_unlink_event.dev = get_dev_from_dentry(dentry);
    event->u.inode_unlink_event.inode = inode;
    event->u.inode_unlink_event.ctime = ctime;
    bpf_probe_read_kernel_str(&event->u.inode_unlink_event.path, 
    MAX_PATH_LEN - (buf_off.offset & (MAX_PATH_LEN - 1)), 
    &path_buf->buf[(buf_off.offset & (MAX_PATH_LEN - 1))]);

    handle_process_stop_policy_for_file_operations(event);

    bpf_ringbuf_submit(event, 0);

    return 0;
}


SEC("kprobe/security_inode_rename")
int kprobe_security_inode_rename(struct pt_regs *ctx) {
    if (!process_in_scope()) {
        return 0;
    }

    if (!process_is_interesting()) {
        return 0;
    }
    
    struct dentry *old_dentry = (struct dentry *) PT_REGS_PARM2(ctx);
    struct dentry *new_dentry = (struct dentry *) PT_REGS_PARM4(ctx);


    // int old_numlower = get_overlay_numlower(old_dentry);
    // int new_numlower = get_overlay_numlower(new_dentry);
    u32 old_is_overlayfs = is_overlayfs(old_dentry);
    u32 new_is_overlayfs = is_overlayfs(new_dentry);


    // filter out file event in other file system
    if (!old_is_overlayfs || !old_is_overlayfs) {
        return 0;
    }

    // bpf_printk("old_numberlow %d, is_overlayfs %d \n", old_numlower, old_is_overlay);
    // bpf_printk("new_numlower %d, is_overlayfs %d \n", new_numlower, new_is_overlay);

    u32 inode = get_inode_nr_from_dentry(old_dentry);
    u64 ctime = get_ctime_nanosec_from_dentry(old_dentry);

    if (query_file_access(inode, ctime)) {
        return 0;
    }

    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();

    int syscall_id = get_current_task_syscall_id();

    struct path_buffer_t *old_path_buf = (struct path_buffer_t *) get_path_buf(0);
    if (!old_path_buf) {
        return 0;
    }

    struct path_buffer_t *new_path_buf = (struct path_buffer_t *) get_path_buf(1);
    if (!new_path_buf) {
        return 0;
    }

    struct buf_offset old_buf_off;
    if (!get_dentry_path_str(old_dentry, old_path_buf, &old_buf_off)) {
        return 0;
    }

    struct buf_offset new_buf_off;
    if (!get_dentry_path_str(new_dentry, new_path_buf, &new_buf_off)) {
        return 0;
    }
    
    struct file_event *event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    cache_file_access(inode, ctime);

    event->time = bpf_ktime_get_ns();
    event->flag = 0;
    event->tgid = get_current_tgid();
    event->parent_tgid = get_task_parent_tgid(current_task);
    event->ns_tgid = get_task_tgid_nr_ns(current_task);
    struct task_struct * parent_task = BPF_CORE_READ(current_task, parent);
    event->ns_parent_tgid = get_task_tgid_nr_ns(parent_task);

    event->type = FILE_EVENT_INODE_RENAME;
    event->u.inode_unlink_event.syscall = syscall_id;
    // FIXME: changed or not changed ?
    event->u.inode_unlink_event.dev = get_dev_from_dentry(old_dentry);
    event->u.inode_unlink_event.inode = get_inode_nr_from_dentry(old_dentry);
    event->u.inode_unlink_event.ctime = get_ctime_nanosec_from_dentry(old_dentry);
    bpf_probe_read_kernel_str(&event->u.inode_rename_event.old_path, 
    MAX_PATH_LEN - (old_buf_off.offset & (MAX_PATH_LEN - 1)), 
    &old_path_buf->buf[(old_buf_off.offset & (MAX_PATH_LEN - 1))]);
    bpf_probe_read_kernel_str(&event->u.inode_rename_event.new_path, 
    MAX_PATH_LEN - (new_buf_off.offset & (MAX_PATH_LEN - 1)), 
    &new_path_buf->buf[(new_buf_off.offset & (MAX_PATH_LEN - 1))]);

    handle_process_stop_policy_for_file_operations(event);

    bpf_ringbuf_submit(event, 0);

    return 0;
}


SEC("kprobe/security_inode_link")
int kprobe_security_inode_link(struct pt_regs *ctx) {
    // TODO
    return 0;
}

SEC("kprobe/security_inode_symlink")
int kprobe_security_inode_symlink(struct pt_regs *ctx) {
    // TODO
    return 0;
}


SEC("kprobe/security_inode_mkdir")
int kprobe_security_inode_mkdir(struct pt_regs *ctx) {
    // TODO
    return 0;
}


SEC("kprobe/security_inode_rmdir")
int kprobe_security_inode_rmdir(struct pt_regs *ctx) {
    // TODO
    return 0;
}