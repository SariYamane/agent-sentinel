#ifndef BPF_TRACER_FILE_HEADER
#define BPF_TRACER_FILE_HEADER

// for bypass bpf verifier :(
#define MAX_BUFFER_LEN MAX_PATH_LEN * 2

// https://elixir.bootlin.com/linux/v5.15/source/include/linux/fs.h#L98
#define     MAY_EXEC        0x00000001
#define     MAY_WRITE       0x00000002
#define     MAY_READ        0x00000004
#define     MAY_APPEND      0x00000008
#define     MAY_ACCESS      0x00000010
#define     MAY_OPEN        0x00000020
#define     MAY_CHDIR       0x00000040
#define     MAY_NOT_BLOCK   0x00000080

#define     FMODE_READ      0x1
#define     FMODE_WRITE     0x2
#define     FMODE_LSEEK     0x4
#define     FMODE_PREAD     0x8
#define     FMODE_PWRITE    0x10
#define     FMODE_EXEC      0x20
#define     FMODE_NDELAY    0x40
#define     FMODE_EXCL      0x80

#define O_RDONLY      0x00000000
#define O_WRONLY      0x00000001
#define O_RDWR        0x00000002
#define O_CREAT       0x00000040
#define O_EXCL        0x00000080
#define O_NOCTTY      0x00000100
#define O_TRUNC       0x00000200
#define O_APPEND      0x00000400
#define O_NONBLOCK    0x00000800
#define O_DIRECTORY   0x00010000

#define OVERLAYFS_SUPER_MAGIC	0x794c7630

#define FILE_EVENT_TYPE_FILE_OPEN 0
#define FILE_EVENT_INODE_UNLINK 1
#define FILE_EVENT_INODE_RENAME 2

struct inode___older_v66 {
    struct timespec64 i_ctime;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 4096);
} file_events SEC(".maps");


struct file_open_event {
    u64 ctime;
    u32 dev;
    u32 inode;
    u32 syscall;
    u32 acc_mode;
    u8 path[MAX_PATH_LEN];
};

struct inode_unlink_event {
    u64 ctime;
    u32 dev;
    u32 inode;
    u32 syscall;
    u8 path[MAX_PATH_LEN];
}; 

struct inode_rename_event {
    u64 ctime;
    u32 dev;
    u32 inode;
    u32 syscall;
    u8 old_path[MAX_PATH_LEN];
    u8 new_path[MAX_PATH_LEN];
};

struct file_event {
    u64 time;
    u32 flag;
    u32 tgid;
    u32 parent_tgid;
    u32 ns_tgid;
    u32 ns_parent_tgid;
    u32 type;
    // header above
    union {
        u8 buffer[8216];
        struct file_open_event f_open;
        struct inode_unlink_event inode_unlink_event;
        struct inode_rename_event inode_rename_event;
    } u;
};

struct file_event *unused_file_event __attribute__((unused));

// struct path_block
// {
//     u8 path[MAX_PATH_LEN];
// };


// struct {
//     __uint(type, BPF_MAP_TYPE_LRU_HASH);
//     __type(key, u32);
//     __type(value, struct path_block);
//     __uint(max_entries, 1024);
// } file_event_cache SEC(".map");

struct path_buffer_t {
  char buf[MAX_BUFFER_LEN];
};

// maps for large memeory use
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, struct path_buffer_t);
  __uint(max_entries, 2);
} path_buffers SEC(".maps");

struct buf_offset {
    int offset;
};

static __always_inline struct path_buffer_t *get_path_buf(int idx) {
  return bpf_map_lookup_elem(&path_buffers, &idx);
}


//------------- file access cache -----------

struct file_id_t {
    // dev_t device;
    u32 inode;
    u64 ctime;
};

struct file_access_t {
    u32 last_access_tgid;
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 1024);
  __type(key, struct file_id_t); // bpf_get_current_pid_tgid()
  __type(value, struct file_access_t);
} file_access_map SEC(".maps");


static inline void cache_file_access(u32 inode, u64 ctime) {
    u64 tgid = get_current_tgid();

    struct file_id_t id = {
        .inode = inode,
        .ctime = ctime
    };

    struct file_access_t *access = (struct file_access_t *) bpf_map_lookup_elem(&file_access_map, &id);
    
    if (access) {
        access->last_access_tgid = tgid;
    } else {
        struct file_access_t i_access;
        i_access.last_access_tgid = tgid;
        bpf_map_update_elem(&file_access_map, &id, &i_access, BPF_ANY);
    }
}


static inline bool query_file_access(u32 inode, u64 ctime) {
    u64 tgid = get_current_tgid();

    struct file_id_t id = {
        .inode = inode,
        .ctime = ctime
    };

    struct file_access_t *access = (struct file_access_t *) bpf_map_lookup_elem(&file_access_map, &id);
    if (access && access->last_access_tgid == tgid) {
        return true;
    }

    return false;    // int sig_ret = bpf_send_signal(SIGSTOP);
    // if (sig_ret == 0) {
    //     event->flag |= EVENT_FLAG_PROCESS_STOPPED;
    // }
}

//------------- process stop policy for file operations -----------
static __noinline int is_prefix_path_matched(u8 *prefix, u8 *path) {
    for (int i = 0; i < MAX_PATH_PATTERN_LENGTH; i++) {
        if (prefix[i] == '\0')
            break;

        if (prefix[i] != path[i])
            return 0;
    }

    return 1;
}


static inline int handle_process_stop_policy_for_file_operations(struct file_event *event) {
    if (!is_enforced_process()) {
        return 0;
    }
    
    struct process_stop_policy_t *policy= get_process_stop_policy(PROCESS_STOP_TYPE_FILE);

    if (!policy) {
        return 0;
    }

    // bpf_printk("policy, %d, %d", policy->common, policy->file.file_perm);

    int stop = 0;

    if (policy->common & PROCESS_STOP_COMMON_ALWAYS_STOP) {
        stop = 1;
    } else if (event->type == FILE_EVENT_TYPE_FILE_OPEN) {
        // for file_open
        if (event->u.f_open.acc_mode & policy->file.file_perm) {
            stop = 1;
        }

        // bpf_printk("file policy: %d", policy->file.flag);

        if (policy->file.ns_root_tgid != event->ns_tgid 
            && (policy->file.flag & PROCESS_STOP_FILE_ACCESS_CORE_FILES)) {
            for (u32 id = 0; id < MAX_CORE_FILE_PATH_PATTERNS_COUNT; id++) {
                struct path_pattern *pattern = get_core_file_path_pattern(id);
                
                if (pattern == NULL) {
                    break;
                }

                // bpf_printk("file policy: %s", &pattern->prefix);
                // bpf_printk("file policy: %s", &event->u.f_open.path);

                if (is_prefix_path_matched(pattern->prefix, event->u.f_open.path)) {
                    stop = 1;
                    event->flag |= EVENT_FLAG_PROCESS_MAY_ATTACK_ROOT_PROCESS;
                    break;
                }
            }
        }

    } else if ((policy->file.file_perm & MAY_WRITE)) {
        // TODO: current inode changes are all in write mode
        stop = 1;
    }

    if (stop) {
        int sig_ret = bpf_send_signal(SIGSTOP);
        if (!sig_ret) {
            event->flag |= EVENT_FLAG_PROCESS_STOPPED;
            // increment_enforcement_op();
        }
    }

    return 0;   
}


//------------- file helpers ----------- 


static inline struct mount *real_mount(struct vfsmount *mnt) {
    return container_of(mnt, struct mount, mnt);
}

// modified version based on
// https://github.com/kubearmor/KubeArmor/blob/6642be54c3f846ecb4009d201b27f54a5971ec0c/KubeArmor/BPF/shared.h#L166
static __noinline bool prepend_path(struct path *path, struct path_buffer_t *string_p, struct buf_offset *buf_off) {
    char slash = '/';
    char null = '\0';
    int offset = MAX_PATH_LEN;

    if (path == NULL || string_p == NULL) {
        return false;
    }

    struct dentry *dentry = path->dentry;
    struct vfsmount *vfsmnt = path->mnt;

    struct mount *mnt = real_mount(vfsmnt);

    struct dentry *parent;
    struct dentry *mnt_root;
    struct mount *m;
    struct qstr d_name;

#pragma unroll
    for (int i = 0; i < MAX_PATH_DEPTH; i++) {
        parent = BPF_CORE_READ(dentry, d_parent);
        mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);

        if (dentry == mnt_root) {
            m = BPF_CORE_READ(mnt, mnt_parent);
            if (mnt != m) {
                dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
                mnt = BPF_CORE_READ(mnt, mnt_parent);
                vfsmnt = &mnt->mnt;
                continue;
            }
            break;
        }

        if (dentry == parent) {
            break;
        }

        // get d_name
        d_name = BPF_CORE_READ(dentry, d_name);

        offset -= (d_name.len + 1);
        if (offset < 0)
        break;

        int sz = bpf_probe_read_str(
            &(string_p->buf[(offset) & (MAX_PATH_LEN - 1)]),
            (d_name.len + 1) & (MAX_PATH_LEN - 1), d_name.name);
        if (sz > 1) {
            bpf_probe_read(
                &(string_p->buf[(offset + d_name.len) & (MAX_PATH_LEN - 1)]),
                1, &slash);
        } else {
            offset += (d_name.len + 1);
        }

        dentry = parent;
    }

    if (offset == MAX_PATH_LEN) {
        return false;
    }

    bpf_probe_read(&(string_p->buf[MAX_PATH_LEN - 1]), 1, &null);
    offset--;

    bpf_probe_read(&(string_p->buf[offset & (MAX_PATH_LEN - 1)]), 1,
                    &slash);

    buf_off->offset = offset;
    return true;
}


static __noinline bool get_dentry_path_str(struct dentry *dentry, struct path_buffer_t *string_p, struct buf_offset *buf_off) {
    char slash = '/';
    char null = '\0';
    int offset = MAX_PATH_LEN;

    struct dentry *parent;
    struct mount *m;
    struct qstr d_name;

#pragma unroll
    for (int i = 0; i < MAX_PATH_DEPTH; i++) {
        parent = BPF_CORE_READ(dentry, d_parent);

        if (dentry == parent) {
            break;
        }

        // get d_name
        d_name = BPF_CORE_READ(dentry, d_name);

        offset -= (d_name.len + 1);
        if (offset < 0)
        break;

        int sz = bpf_probe_read_str(
            &(string_p->buf[(offset) & (MAX_PATH_LEN - 1)]),
            (d_name.len + 1) & (MAX_PATH_LEN - 1), d_name.name);
        if (sz > 1) {
            bpf_probe_read(
                &(string_p->buf[(offset + d_name.len) & (MAX_PATH_LEN - 1)]),
                1, &slash);
        } else {
            offset += (d_name.len + 1);
        }

        dentry = parent;
    }

    if (offset == MAX_PATH_LEN) {
        return false;
    }

    bpf_probe_read(&(string_p->buf[MAX_PATH_LEN - 1]), 1, &null);
    offset--;

    bpf_probe_read(&(string_p->buf[offset & (MAX_PATH_LEN - 1)]), 1,
                    &slash);

    buf_off->offset = offset;
    return true;
}


static inline u32 map_file_to_perms(struct file *file) {
  u32 perms = 0;
  unsigned int flags = BPF_CORE_READ(file, f_flags);
  fmode_t mode = BPF_CORE_READ(file, f_mode);

  if (mode & FMODE_WRITE)
    perms |= MAY_WRITE;
  if (mode & FMODE_READ)
    perms |= MAY_READ;
  if ((flags & O_APPEND) && (perms & MAY_WRITE))
    perms = (perms & ~MAY_WRITE) | MAY_APPEND;
  /* trunc implies write permission */
  if (flags & O_TRUNC)
    perms |= MAY_WRITE;
  if (flags & O_CREAT)
    perms |= MAY_WRITE;

  return perms;
}

static inline u32 get_inode_nr_from_file(struct file *file)
{
    return BPF_CORE_READ(file, f_inode, i_ino);
}

static inline u32 get_inode_nr_from_dentry(struct dentry *dentry)
{
    return BPF_CORE_READ(dentry, d_inode, i_ino);
}

static inline u32 get_dev_from_file(struct file *file)
{
    return BPF_CORE_READ(file, f_inode, i_sb, s_dev);
}

static inline u32 get_dev_from_dentry(struct dentry *dentry)
{
    return BPF_CORE_READ(dentry, d_inode, i_sb, s_dev);
}


static inline u64 get_time_nanosec_timespec(struct timespec64 *ts)
{
    time64_t sec = BPF_CORE_READ(ts, tv_sec);
    if (sec < 0)
        return 0;

    long ns = BPF_CORE_READ(ts, tv_nsec);

    return (sec * 1000000000L) + ns;
}


static inline u64 get_ctime_nanosec_from_inode(struct inode *inode)
{
    struct timespec64 ts = {};

    // // Kernel >= 6.11
    if (bpf_core_field_exists(inode->i_ctime_sec) && bpf_core_field_exists(inode->i_ctime_nsec)) {
        ts.tv_sec = BPF_CORE_READ(inode, i_ctime_sec);
        ts.tv_nsec = BPF_CORE_READ(inode, i_ctime_nsec);
    }
    // // Kernel 6.6 - 6.10
    // else if (bpf_core_field_exists(((struct inode___older_v611 *) inode)->__i_ctime)) {
    //     struct inode___older_v611 *old_inode_v611 = (void *) inode;
    //     ts = BPF_CORE_READ(old_inode_v611, __i_ctime);
    // }
    // // Kernel < 6.6
    else {
        struct inode___older_v66 *old_inode_v66 = (void *) inode;
        ts = BPF_CORE_READ(old_inode_v66, i_ctime);
    }

    return get_time_nanosec_timespec(&ts);
}


static inline u64 get_ctime_nanosec_from_file(struct file *file)
{
    struct inode *f_inode = BPF_CORE_READ(file, f_inode);
    return get_ctime_nanosec_from_inode(f_inode);
}

static inline u64 get_ctime_nanosec_from_dentry(struct dentry *dentry)
{
    struct inode *d_inode = BPF_CORE_READ(dentry, d_inode);
    return get_ctime_nanosec_from_inode(d_inode);
}


static inline int get_overlay_numlower(struct dentry *dentry) {
    int numlower;
    void *fsdata;
    bpf_probe_read(&fsdata, sizeof(void *), &dentry->d_fsdata);

    // bpf_probe_read(&numlower, sizeof(int), fsdata + offsetof(struct ovl_entry, numlower));
    // TODO: make it a constant and change its value based on the current kernel version. 16 is only good for kernels 4.13+
    bpf_probe_read(&numlower, sizeof(int), fsdata + 16);
    return numlower;
}


static inline u32 is_overlayfs(struct dentry *dentry)
{
    return BPF_CORE_READ(dentry, d_sb, s_magic) == OVERLAYFS_SUPER_MAGIC;
}


// #define MAX_FILE_ACCESS_CACHE_SIZE 9 

// struct file_access_t {
//     struct file_id_t files[MAX_FILE_ACCESS_CACHE_SIZE];
//     u32 num;
// };

// struct {
//   __uint(type, BPF_MAP_TYPE_LRU_HASH);
//   __uint(max_entries, 1024);
//   __type(key, u64); // bpf_get_current_pid_tgid()
//   __type(value, struct file_access_t);
// } file_access_map SEC(".maps");

// static inline void cache_file_access(u32 inode, u64 ctime) {
//     u64 key = bpf_get_current_pid_tgid();

//     struct file_access_t *access = (struct file_access_t *) bpf_map_lookup_elem(&file_access_map, &key);

//     if (access) {
//         if (access->num >= MAX_FILE_ACCESS_CACHE_SIZE) {
//             return;
//         }
//         access->num++;
//         access->files[(access->num & (MAX_FILE_ACCESS_CACHE_SIZE - 1))].inode = inode;
//         access->files[(access->num & (MAX_FILE_ACCESS_CACHE_SIZE - 1))].ctime = ctime;
//     } else {
//         struct file_access_t i_access;
//         __builtin_memset(&i_access, 0, sizeof(i_access));
//         i_access.num = 1;
//         i_access.files[0].inode = inode;
//         i_access.files[0].ctime = ctime;
//         bpf_map_update_elem(&file_access_map, &key, &i_access, BPF_ANY);
//     }
// }

// static inline bool query_file_access(u32 inode, u64 ctime) {
//     u64 key = bpf_get_current_pid_tgid();

//     struct file_access_t *access = (struct file_access_t *) bpf_map_lookup_elem(&file_access_map, &key);
//     if (!access) {
//         return false;
//     }

//     int i;
// #pragma unroll
//     for (i = 0; i < MAX_FILE_ACCESS_CACHE_SIZE; i++) {
//         if (access->files[i].inode == inode && access->files[i].ctime == ctime) {
//             return true;
//         }
//     }

//     return false;
// }

// static inline void clear_file_access() {
//     u64 key = bpf_get_current_pid_tgid();

//     struct file_access_t *access = (struct file_access_t *) bpf_map_lookup_elem(&file_access_map, &key);
//     if (!access) {
//         return;
//     }

//     access->num = 0;
// }

#endif