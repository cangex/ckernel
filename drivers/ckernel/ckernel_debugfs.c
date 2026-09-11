#include <linux/debugfs.h>

static struct dentry *dir;
static u32 debug_value = 0;

int ckernel_debugfs_init(void)
{
	dir = debugfs_create_dir("ckernel", NULL);
	debugfs_create_u32("value", 0644, dir, &debug_value);
	return 0;
}

void ckernel_debugfs_exit(void)
{
	debugfs_remove_recursive(dir);
}
