# SPDX-License-Identifier: GPL-2.0
obj-y += core.o control.o task.o locality.o stats.o
obj-$(CONFIG_CKERNEL_M_MAPLE) += maple_pool.o
obj-$(CONFIG_CKERNEL_M_KUNIT_TEST) += core_test.o
ifeq ($(CONFIG_CKERNEL_M_MAPLE),y)
obj-$(CONFIG_CKERNEL_M_KUNIT_TEST) += maple_pool_test.o
endif
