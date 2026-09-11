#ifndef _CKERNEL_DRIVER_H_
#define _CKERNEL_DRIVER_H_

struct kernfs_node;

int ckernel_mbm_start(struct kernfs_node *online_kn,
                      struct kernfs_node *offline_kn);

void ckernel_mbm_stop(void);

void ck_init_rules(struct ckernel *ck);
bool ck_check_path(struct ckernel *ck, const struct path *path);
bool ck_skip_check_path(struct ckernel *ck, const struct path *path);

bool ck_check_file(struct ckernel *ck, const struct file *file);
bool ck_skip_check_file(struct ckernel *ck, const struct file *file);

bool ck_net_fast_allow(struct ckernel *ck, int family, int type);
bool ck_skip_net_fast_allow(struct ckernel *ck, int family, int type);

int ck_do_file_inc(u64 n);
int ck_do_file_dec(u64 n);
int ck_skip_file_inc(u64 n);
int ck_skip_file_dec(u64 n);

int ck_vfs_domain_init(struct ckernel *ck, bool object_enabled,
		       bool ref_enabled, bool lease_enabled);
void ck_vfs_domain_destroy(struct ckernel *ck);
int ck_shmem_cache_init(struct ckernel *ck, bool enabled);
void ck_shmem_cache_refresh_stats(struct ckernel *ck);
void ck_shmem_cache_destroy(struct ckernel *ck);
int ck_socket_domain_init(struct ckernel *ck, bool enabled,
			  bool stock_enabled);
void ck_socket_domain_destroy(struct ckernel *ck);

#endif
