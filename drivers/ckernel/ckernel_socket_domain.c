// SPDX-License-Identifier: GPL-2.0
#include <linux/ckernel.h>
#include <linux/net.h>
#include <net/sock.h>

#include "ckernel_driver.h"

static bool ck_socket_token_check(struct ckernel *ck,
				  const struct socket *sock)
{
	if (!sock || !sock->sk || !READ_ONCE(ck->socket_token_enabled))
		return false;

	if (READ_ONCE(sock->sk->sk_ckernel_cookie) == READ_ONCE(ck->cookie))
		return true;

	if (READ_ONCE(ck->socket_stock_enabled))
		ck_socket_stock_count(ck, CK_SOCKET_STOCK_MISS);
	else
		atomic_long_inc(&ck->socket_token_misses);
	return false;
}

static void ck_socket_token_learn(struct ckernel *ck,
				  const struct socket *sock)
{
	u64 cookie;

	if (!sock || !sock->sk || !READ_ONCE(ck->socket_token_enabled))
		return;

	cookie = READ_ONCE(ck->cookie);
	if (!cookie)
		return;

	/* The capability follows the sock lifetime and cannot be cache-evicted. */
	WRITE_ONCE(sock->sk->sk_ckernel_cookie, cookie);
	if (READ_ONCE(ck->socket_stock_enabled))
		ck_socket_stock_count(ck, CK_SOCKET_STOCK_LEARN);
	else
		atomic_long_inc(&ck->socket_token_learns);
}

int ck_socket_domain_init(struct ckernel *ck, bool enabled,
			  bool stock_enabled)
{
	ck->socket_token_enabled = false;
	ck->socket_token_domain = NULL;
	ck->ck_socket_token_check = NULL;
	ck->ck_socket_token_learn = NULL;
	atomic_long_set(&ck->socket_token_learns, 0);
	atomic_long_set(&ck->socket_token_misses, 0);
	atomic_long_set(&ck->socket_token_evictions, 0);
	ck->socket_stock_enabled = false;
	ck->socket_stock_stats = NULL;

	if (!enabled)
		return 0;
	if (stock_enabled) {
		ck->socket_stock_stats = alloc_percpu(
			struct ck_socket_stock_stats);
		if (!ck->socket_stock_stats)
			return -ENOMEM;
		WRITE_ONCE(ck->socket_stock_enabled, true);
	}

	ck->ck_socket_token_check = ck_socket_token_check;
	ck->ck_socket_token_learn = ck_socket_token_learn;
	WRITE_ONCE(ck->socket_token_enabled, true);
	return 0;
}

void ck_socket_domain_destroy(struct ckernel *ck)
{
	WRITE_ONCE(ck->socket_stock_enabled, false);
	WRITE_ONCE(ck->socket_token_enabled, false);
	ck->ck_socket_token_check = NULL;
	ck->ck_socket_token_learn = NULL;
	WRITE_ONCE(ck->socket_token_domain, NULL);
	if (ck->socket_stock_stats)
		free_percpu(ck->socket_stock_stats);
	ck->socket_stock_stats = NULL;
}
