#ifndef BPF_TRACER_COMMON_HEADER
#define BPF_TRACER_COMMON_HEADER

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "syscall.h"

#define barrier() asm volatile("" ::: "memory")

#define MAX_PATH_LEN 4096
#define MAX_FILENAME_LEN 256
#define MAX_PATH_DEPTH 30

#define SIGINT 2
#define SIGKILL 9
#define SIGTERM 15
#define SIGSTOP 19

#define TASK_COMM_LEN 16

#define PF_KTHREAD 0x00200000 /* I am a kernel thread */


#define PAGE_SHIFT 12
#define PAGE_SIZE  (1UL) << PAGE_SHIFT
#define PAGE_MASK  (~(PAGE_SIZE - 1))

#define TOP_OF_KERNEL_STACK_PADDING 0

#define KASAN_STACK_ORDER  0
#define THREAD_SIZE_ORDER (2 + KASAN_STACK_ORDER)
#define THREAD_SIZE       (PAGE_SIZE << THREAD_SIZE_ORDER)


#define READ_KERN(ptr)                                                  \
    ({                                                                  \
        typeof(ptr) _val;                                               \
        __builtin_memset((void *)&_val, 0, sizeof(_val));               \
        bpf_probe_read((void *)&_val, sizeof(_val), &ptr);              \
        _val;                                                           \
    })


// get the container from a field
#undef container_of
#define container_of(ptr, type, member)                                        \
  ({                                                                           \
    const typeof(((type *)0)->member) *__mptr = (ptr);                         \
    (type *)((char *)__mptr - offsetof(type, member));                         \
  })


static inline u32 get_current_tgid(void);
static inline u32 get_task_tgid(struct task_struct *task);
static inline u32 get_task_pid(struct task_struct *task);
static inline u32 get_task_parent_tgid(struct task_struct *task);
static inline u32 get_task_parent_pid(struct task_struct *task);
static inline u32 get_task_tgid_nr_ns(struct task_struct *task);
static inline u32 get_task_pid_nr_ns(struct task_struct *task);
static inline int get_task_flags(struct task_struct *task);
static inline int get_syscall_id_from_regs(struct pt_regs *regs);
static inline struct pt_regs *get_current_task_pt_regs(void);
static inline int get_current_task_syscall_id(void);

//------------- flags of event -----------

#define EVENT_FLAG_PROCESS_STOPPED (1 << 0)
#define EVENT_FLAG_PROCESS_MAY_ATTACK_ROOT_PROCESS (1 << 1) 

//------------- interesting mount namespace id map -----------

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, u32);
} mnt_ns_id_list SEC(".maps");

static inline u32 get_task_mnt_ns_id(struct task_struct *task) {
  struct mnt_namespace *mnt_ns = BPF_CORE_READ(task, nsproxy, mnt_ns);
  u32 inum = 0;
  bpf_core_read(&inum, sizeof(inum), &mnt_ns->ns.inum);
  return inum;
}

static __always_inline int process_in_scope() {
    u32 cur_mnt_ns_id;
    u32 key = 0;
    u32 *mnt_ns_id;

    mnt_ns_id = (u32 *)bpf_map_lookup_elem(&mnt_ns_id_list, &key);
    if (!mnt_ns_id)
        return 0;

    struct task_struct *current_task = (struct task_struct *) bpf_get_current_task();
    cur_mnt_ns_id = get_task_mnt_ns_id(current_task);
    if (cur_mnt_ns_id != *mnt_ns_id)
        return 0;

    return 1;
}

//------------- interesting tgids map -----------

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 16 * 1024);
  __type(key, u32); // get_current_tgid()
  __type(value, u32); // process level
} interesting_pids_map SEC(".maps");

static inline int process_is_interesting () {
  u32 tgid = get_current_tgid();
  
  // TODO: may use the value of *e ?
  u32 *e = (u32 *)bpf_map_lookup_elem(&interesting_pids_map, &tgid);
  if (!e) {
    return 0;
  }

  return 1;
}

//------------- syscall cache -----------

#define EXEC_SYSCALL 1
#define ACCPET_SYSCALL 2

struct syscall_cache_t {
  u64 type;
  union {
    struct {
      uintptr_t args;
    } exec;

    struct {
      uintptr_t new_sock;
    } accpet;
  };
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 1024);
  __type(key, u64);
  __type(value, struct syscall_cache_t);
} syscall_cache SEC(".maps");

static inline void cache_syscall(struct syscall_cache_t *syscall) {
  u64 key = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&syscall_cache, &key, syscall, BPF_ANY);
}

static inline struct syscall_cache_t *get_cached_syscall(u64 type) {
  u64 key = bpf_get_current_pid_tgid();
  struct syscall_cache_t *syscall = (struct syscall_cache_t *) bpf_map_lookup_elem(&syscall_cache, &key);
  if (!syscall) {
      return NULL;
  }
  if (!type || syscall->type == type) {
      return syscall;
  }
  return NULL;
}

//------------- process context cache -----------

//------------- task context cache -----------

#define ACCEPT_EVENT 1

struct task_context_t {
  u64 type;
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 1024);
  __type(key, u64); // bpf_get_current_pid_tgid()
  __type(value, struct task_context_t);
} task_context_map SEC(".maps");

static inline void init_task_context(struct task_context_t *ctx) {
  u64 key = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&task_context_map, &key, ctx, BPF_NOEXIST);
}

static inline struct task_context_t * get_task_context() {
  u64 key = bpf_get_current_pid_tgid();
  struct task_context_t *ctx = (struct task_context_t *) bpf_map_lookup_elem(&task_context_map, &key);
  return ctx;
}

//------------- process stop policy -----------

#define PROCESS_STOP_TYPE_EXEC 1
#define PROCESS_STOP_TYPE_NET 2
#define PROCESS_STOP_TYPE_FILE 3
#define PROCESS_STOP_TYPE_KILL 4

#define PROCESS_STOP_COMMON_ALWAYS_STOP 1

#define PROCESS_STOP_NET_CONNECT (1 << 0)
#define PROCESS_STOP_NET_LISTEN (1 << 1)
#define PROCESS_STOP_NET_ACCEPT (1 << 2)
#define PROCESS_STOP_NET_ACCEPT_EXIT (1 << 3)

#define PROCESS_STOP_KILL_ROOT_PROCESS (1 << 0)

#define PROCESS_STOP_FILE_ACCESS_CORE_FILES (1 << 0)



#define MAX_CORE_FILE_PATH_PATTERNS_COUNT 16
#define MAX_PATH_PATTERN_LENGTH 64

struct path_pattern {
  u8 prefix[MAX_PATH_PATTERN_LENGTH];
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries, MAX_CORE_FILE_PATH_PATTERNS_COUNT);
  __type(key, u32);
  __type(value, struct path_pattern);
} core_file_path_patterns SEC(".maps");


static inline struct path_pattern* get_core_file_path_pattern(u32 id) {
  return (struct path_pattern*) bpf_map_lookup_elem(&core_file_path_patterns, &id);
}


struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32); // tgid
  __type(value, u32); // level
} process_trace_level SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 16 * 1024);
  __type(key, u32); // tgid
  __type(value, u8);
} process_enforcement_map SEC(".maps");

struct process_stop_policy_t {
    u32 common;

    union {
        u8 buffer[12];

        struct {
          
        } exec;

        struct {
          u32 flag;
          u32 ns_root_tgid;
        } kill;

        struct {

        } net;

        struct {
          u32 flag;
          u32 file_perm;
          u32 ns_root_tgid;
        } file;
    };
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 1024);
  __type(key, u16); // event type
  __type(value, struct process_stop_policy_t);
} process_stop_policy SEC(".maps");

static inline int is_enforced_process() {
  u32 tgid = get_current_tgid();

  // bpf_printk("query process %d", tgid);
  
  u8 *e = (u8 *)bpf_map_lookup_elem(&process_enforcement_map, &tgid);
  if (!e) {
    return 0;
  }

  return 1;
}

static inline void increment_enforcement_op() {
  u32 tgid = get_current_tgid();

  // bpf_printk("query process %d", tgid);
  
  u8 *e = (u8 *)bpf_map_lookup_elem(&process_enforcement_map, &tgid);
  if (!e) {
    return;
  }

  // increment enforcement operations
  u8 new_eop = *e + 1;
  bpf_map_update_elem(&process_enforcement_map, &tgid, &new_eop, BPF_ANY);
}

static inline struct process_stop_policy_t* get_process_stop_policy(u16 type){
    struct process_stop_policy_t *policy = (struct process_stop_policy_t *) bpf_map_lookup_elem(&process_stop_policy, &type);
    return policy;
}


static inline void process_fork(struct task_struct *parent, struct task_struct *child) {
  u32 parent_tgid = get_task_tgid(parent);
  u32 child_tgid = get_task_tgid(child);

  if (parent_tgid == child_tgid) {
    return;
  }

  // bpf_printk("parent_tgid: %d, child_tgid: %d", parent_tgid, child_tgid);

  u32 *e = (u32 *)bpf_map_lookup_elem(&interesting_pids_map, &parent_tgid);
  if (!e) {
    return;
  }

  // process level increment
  u32 child_level = *e + 1;
  bpf_map_update_elem(&interesting_pids_map, &child_tgid, &child_level, BPF_ANY);

  u32 idx = 0;
  u32 *trace_level = (u32 *)bpf_map_lookup_elem(&process_trace_level, &idx);
  if (!trace_level) {
    return;
  }

  // bpf_printk("e %d, l: %d", *e, *trace_level);

  // add to enforced map if lower than process trace level
  if (*trace_level == 0 || *e < *trace_level) {
    u8 value = 0;
    bpf_map_update_elem(&process_enforcement_map, &child_tgid, &value, BPF_ANY);
  }
}


static inline void process_exit(struct task_struct *task) {
    u32 tgid = get_task_tgid(task);

    bpf_map_delete_elem(&interesting_pids_map, &tgid);
    bpf_map_delete_elem(&process_enforcement_map, &tgid);
}

//------------- common helpers -----------

static inline u32 get_current_tgid(void) {
  return bpf_get_current_pid_tgid() >> 32;
}

static inline u32 get_current_pid(void) {
  return bpf_get_current_pid_tgid() & 0xffffffff;
}

static inline u32 get_task_tgid(struct task_struct *task) {
  return BPF_CORE_READ(task, tgid);   
}

static inline u32 get_task_pid(struct task_struct *task) {
  return BPF_CORE_READ(task, pid);
}

static inline u32 get_task_parent_tgid(struct task_struct *task) {
  return BPF_CORE_READ(task, parent, tgid);
}

static inline u32 get_task_parent_pid(struct task_struct *task) {
  return BPF_CORE_READ(task, parent, pid);
}

// https://elixir.bootlin.com/linux/v5.15/source/kernel/pid.c#L492
static inline u32 get_task_tgid_nr_ns(struct task_struct *task) {
  struct upid upid;
  unsigned int level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
  struct pid *ns_pid = (struct pid *)BPF_CORE_READ(task, group_leader, thread_pid);
  bpf_probe_read_kernel(&upid, sizeof(upid), &ns_pid->numbers[level]);

  return upid.nr;
}

static inline u32 get_task_pid_nr_ns(struct task_struct *task) {
  struct upid upid;
  unsigned int level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
  struct pid *ns_pid = (struct pid *)BPF_CORE_READ(task, thread_pid);
  bpf_probe_read_kernel(&upid, sizeof(upid), &ns_pid->numbers[level]);

  return upid.nr;
}

static inline u32 get_task_parent_tgid_nr_ns(struct task_struct *task) {
  struct upid upid;
  struct task_struct *parent = BPF_CORE_READ(task, parent);

  unsigned int level = BPF_CORE_READ(parent, nsproxy, pid_ns_for_children, level);
  struct pid *ns_pid = (struct pid *)BPF_CORE_READ(parent, group_leader, thread_pid);
  bpf_probe_read_kernel(&upid, sizeof(upid), &ns_pid->numbers[level]);

  return upid.nr;
}

static inline u32 get_task_parent_pid_nr_ns(struct task_struct *task) {
  struct upid upid;
  struct task_struct *parent = BPF_CORE_READ(task, parent);

  unsigned int level = BPF_CORE_READ(parent, nsproxy, pid_ns_for_children, level);
  struct pid *ns_pid = (struct pid *)BPF_CORE_READ(parent, thread_pid);
  bpf_probe_read_kernel(&upid, sizeof(upid), &ns_pid->numbers[level]);

  return upid.nr;
}

static inline int get_task_flags(struct task_struct *task)
{
  return BPF_CORE_READ(task, flags);
}

static inline int get_syscall_id_from_regs(struct pt_regs *regs) {
  return BPF_CORE_READ(regs, orig_ax);
}


static inline struct pt_regs *get_current_task_pt_regs(void) {
  struct task_struct *task;

    // Use the bpf_task_pt_regs helper if possible
    if (bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_get_current_task_btf) &&
        bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_task_pt_regs)) {
        task = bpf_get_current_task_btf();
        return (struct pt_regs *) bpf_task_pt_regs(task);
    }

    // Helper not available, extract registers manually
    task = (struct task_struct *) bpf_get_current_task();

    void *__ptr = BPF_CORE_READ(task, stack) + THREAD_SIZE - TOP_OF_KERNEL_STACK_PADDING;
    return ((struct pt_regs *) __ptr) - 1;
}

static inline int get_current_task_syscall_id(void) {
  struct task_struct *curr = (struct task_struct *) bpf_get_current_task();
  if (get_task_flags(curr) & PF_KTHREAD) {
      return -1;
  }

  struct pt_regs *regs = get_current_task_pt_regs();
  int id = get_syscall_id_from_regs(regs);

  return id;
}

#endif