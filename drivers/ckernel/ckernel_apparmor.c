#include <linux/ckernel.h>
#include <linux/socket.h>
#include <linux/net.h>

#include "ckernel_driver.h"

/*
 * Lightweight hash for path matching.
 * Used to quickly identify trusted paths without full string comparison.
 */
u64 ck_hash(const char *path)
{
	return full_name_hash(NULL, path, strlen(path));
}

/*
 * Initialize default fast-path rules.
 *
 * These rules represent commonly accessed and low-risk system paths
 * where AppArmor checks can be safely skipped.
 *
 * Current implementation uses a static rule set. Future work includes
 * dynamic/adaptive rule management.
 */
void ck_init_rules(struct ckernel *ck)
{
	static char * const protected_paths[] = {
		"/proc",
		"/sys",
		"/sys/fs",
		"/sys/fs/cgroup",
		"/etc/shadow",
		"/etc/gshadow",
		"/etc/passwd",
	};
	int i;

	hash_init(ck->path_table);

	for (i = 0; i < ARRAY_SIZE(protected_paths); i++) {
		struct ck_rule *r;
		u64 h = ck_hash(protected_paths[i]);

		r = kmalloc(sizeof(*r), GFP_KERNEL);
		if (!r)
			continue;

		r->hash = h;
		r->path = protected_paths[i];

		hash_add(ck->path_table, &r->node, h);
	}
}

bool ck_skip_check_path(struct ckernel *ck, const struct path *path)
{
	return false;
}

/*
 * Fast path decision for a given path.
 *
 * Returns:
 *   true  -> safe, skip AppArmor
 *   false -> fallback to full AppArmor check
 *
 * Algorithm:
 *   - Resolve full path
 *   - Iteratively check each prefix (/a, /a/b, /a/b/c)
 *   - If any prefix matches rule table, deny fast-path (conservative)
 *
 * NOTE:
 *   Current design treats rule match as "protected path".
 */
bool ck_check_path(struct ckernel *ck, const struct path *path)
{
	char buf[PATH_MAX];
	char *full;
	char *end;

	full = d_path(path, buf, PATH_MAX);
	if (IS_ERR(full))
		return false;

	/* Check every complete prefix, from /a through /a/b/c. */
	end = full;
	while ((end = strchr(end + 1, '/'))) {
		struct ck_rule *rule;
		u64 h;
		char saved = *end;

		*end = '\0';
		h = ck_hash(full);
		hash_for_each_possible(ck->path_table, rule, node, h) {
			if (rule->hash == h && !strcmp(rule->path, full)) {
				*end = saved;
				return false;
			}
		}
		*end = saved;
	}

	{
		struct ck_rule *rule;
		u64 h = ck_hash(full);

		hash_for_each_possible(ck->path_table, rule, node, h) {
			if (rule->hash == h && !strcmp(rule->path, full))
				return false;
		}
	}

	return true;
}

bool ck_skip_check_file(struct ckernel *ck, const struct file *file)
{
	return false;
}

bool ck_check_file(struct ckernel *ck, const struct file *file)
{
	return ck_check_path(ck, &file->f_path);
}

bool ck_skip_net_fast_allow(struct ckernel *ck, int family, int type)
{
	return false;
}

/*
 * Network fast-path policy:
 *   - Deny raw sockets and packet sockets
 *   - Allow others to bypass AppArmor
 */
bool ck_net_fast_allow(struct ckernel *ck, int family, int type)
{
	/* deny packet socket */
	if (family == AF_PACKET)
		return false;

	/* deny raw socket */
	if (type == SOCK_RAW)
		return false;

	return true;
}
