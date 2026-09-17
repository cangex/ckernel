// SPDX-License-Identifier: GPL-2.0
#include "../../../container_interference/include/cis_trigger.h"
#include <stdio.h>

int main(void)
{
	const char *positive[]={"native_queued_spin_lock_slowpath","queued_spin_lock_slowpath.constprop.0",
		"mutex_optimistic_spin","mutex_spin_on_owner","__mutex_lock_slowpath","__mutex_lock_common.isra.0"};
	const char *negative[]={"_raw_spin_lock","mutex_lock","mutex_unlock","mutex_trylock",
		"lockref_get","lockref_put_or_lock","rwsem_down_write_slowpath","unknown"};
	unsigned int i;
	for(i=0;i<sizeof(positive)/sizeof(*positive);i++)
		if(!cis_fast_lock_candidate_symbol(positive[i])) return 1;
	for(i=0;i<sizeof(negative)/sizeof(*negative);i++)
		if(cis_fast_lock_candidate_symbol(negative[i])) return 1;
	puts("CIS_FAST_TEST supported_slowpath_candidates_only PASS");
	return 0;
}
