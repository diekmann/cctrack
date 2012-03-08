/* cnic.c: Broadcom CNIC core network driver.
 *
 * Copyright (c) 2006-2009 Broadcom Corporation
 *
 * Portions Copyright (c) VMware, Inc. 2009, All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Original skeleton written by: John(Zongxi) Chen (zongxi@broadcom.com)
 * Modified and maintained by: Michael Chan <mchan@broadcom.com>
 */

#include <linux/version.h>
#if (LINUX_VERSION_CODE < 0x020612)
#include <linux/config.h>
#endif

#include <linux/module.h>

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/in.h>
#include <linux/dma-mapping.h>
#include <asm/byteorder.h>
#include <linux/delay.h>
#include <linux/ethtool.h>
#include <linux/if_vlan.h>
#if defined(CONFIG_VLAN_8021Q) || defined(CONFIG_VLAN_8021Q_MODULE)
#define BCM_VLAN 1
#endif
#include <net/ip.h>
#include <net/tcp.h>
#if !defined (__VMKLNX__)
#include <net/arp.h>
#include <net/neighbour.h>
#include <net/route.h>
#include <net/ipv6.h>
#include <net/ip6_route.h>
#include <net/ip6_checksum.h>
#include <net/addrconf.h>
#ifdef HAVE_NETEVENT
#include <net/netevent.h>
#endif
#include <scsi/iscsi_proto.h>
#endif /* !defined (__VMKLNX__) */

#if !defined (__VMKLNX__)
#define NEW_BNX2X_HSI 1
#endif /* !defined (__VMKLNX__) */

#include "cnic_if.h"
#include "bnx2.h"
#include "../../bnx2x/src/bnx2x_reg.h"
#include "../../bnx2x/src/bnx2x_fw_defs.h"
#include "../../bnx2x/src/bnx2x_hsi.h"
#include "../../current/driver/57xx_iscsi_constants.h"
#include "../../current/driver/57xx_iscsi_hsi.h"
#include "cnic.h"
#include "cnic_defs.h"

#define DRV_MODULE_NAME		"cnic"
#define PFX DRV_MODULE_NAME	": "

static char version[] __devinitdata =
	"Broadcom NetXtreme II CNIC Driver " DRV_MODULE_NAME " v" CNIC_MODULE_VERSION " (" CNIC_MODULE_RELDATE ")\n";

MODULE_AUTHOR("Michael Chan <mchan@broadcom.com> and John(Zongxi) "
	      "Chen (zongxi@broadcom.com");
MODULE_DESCRIPTION("Broadcom NetXtreme II CNIC Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(CNIC_MODULE_VERSION);

static LIST_HEAD(cnic_dev_list);
static DEFINE_RWLOCK(cnic_dev_lock);
static DEFINE_MUTEX(cnic_lock);

static struct cnic_ulp_ops *cnic_ulp_tbl[MAX_CNIC_ULP_TYPE];

static int cnic_service_bnx2(void *, void *);
static int cnic_service_bnx2x(void *, void *);
static int cnic_ctl(void *, struct cnic_ctl_info *);

static struct cnic_ops cnic_bnx2_ops = {
	.cnic_owner	= THIS_MODULE,
	.cnic_handler	= cnic_service_bnx2,
	.cnic_ctl	= cnic_ctl,
};

static struct cnic_ops cnic_bnx2x_ops = {
	.cnic_owner	= THIS_MODULE,
	.cnic_handler	= cnic_service_bnx2x,
	.cnic_ctl	= cnic_ctl,
};

static inline void cnic_hold(struct cnic_dev *dev)
{
	atomic_inc(&dev->ref_count);
}

static inline void cnic_put(struct cnic_dev *dev)
{
	atomic_dec(&dev->ref_count);
}

static inline void csk_hold(struct cnic_sock *csk)
{
	atomic_inc(&csk->ref_count);
}

static inline void csk_put(struct cnic_sock *csk)
{
	atomic_dec(&csk->ref_count);
}

static struct cnic_dev *cnic_from_netdev(struct net_device *netdev)
{
	struct cnic_dev *cdev;

	read_lock(&cnic_dev_lock);
	list_for_each_entry(cdev, &cnic_dev_list, list) {
		if (netdev == cdev->netdev) {
			cnic_hold(cdev);
			read_unlock(&cnic_dev_lock);
			return cdev;
		}
	}
	read_unlock(&cnic_dev_lock);
	return NULL;
}

static inline void ulp_get(struct cnic_ulp_ops *ulp_ops)
{
	atomic_inc(&ulp_ops->ref_count);
}

static inline void ulp_put(struct cnic_ulp_ops *ulp_ops)
{
	atomic_dec(&ulp_ops->ref_count);
}

static void cnic_ctx_wr(struct cnic_dev *dev, u32 cid_addr, u32 off, u32 val)
{
	struct cnic_local *cp = dev->cnic_priv;
	struct cnic_eth_dev *ethdev = cp->ethdev;
	struct drv_ctl_info info;
	struct drv_ctl_io *io = &info.data.io;

	info.cmd = DRV_CTL_CTX_WR_CMD;
	io->cid_addr = cid_addr;
	io->offset = off;
	io->data = val;
	ethdev->drv_ctl(dev->netdev, &info);
}

static void cnic_ctx_tbl_wr(struct cnic_dev *dev, u32 off, dma_addr_t addr)
{
	struct cnic_local *cp = dev->cnic_priv;
	struct cnic_eth_dev *ethdev = cp->ethdev;
	struct drv_ctl_info info;
	struct drv_ctl_io *io = &info.data.io;

	info.cmd = DRV_CTL_CTXTBL_WR_CMD;
	io->offset = off;
	io->dma_addr = addr;
	ethdev->drv_ctl(dev->netdev, &info);
}

static void cnic_reg_wr_ind(struct cnic_dev *dev, u32 off, u32 val)
{
	struct cnic_local *cp = dev->cnic_priv;
	struct cnic_eth_dev *ethdev = cp->ethdev;
	struct drv_ctl_info info;
	struct drv_ctl_io *io = &info.data.io;

	info.cmd = DRV_CTL_IO_WR_CMD;
	io->offset = off;
	io->data = val;
	ethdev->drv_ctl(dev->netdev, &info);
}

static u32 cnic_reg_rd_ind(struct cnic_dev *dev, u32 off)
{
	struct cnic_local *cp = dev->cnic_priv;
	struct cnic_eth_dev *ethdev = cp->ethdev;
	struct drv_ctl_info info;
	struct drv_ctl_io *io = &info.data.io;

	info.cmd = DRV_CTL_IO_RD_CMD;
	io->offset = off;
	ethdev->drv_ctl(dev->netdev, &info);
	return io->data;
}

static void cnic_kwq_completion(struct cnic_dev *dev, u32 count)
{
	struct cnic_local *cp = dev->cnic_priv;
	struct cnic_eth_dev *ethdev = cp->ethdev;
	struct drv_ctl_info info;

	info.cmd = DRV_CTL_COMPLETION_CMD;
	info.data.comp.comp_count = count;
	ethdev->drv_ctl(dev->netdev, &info);
}

static int cnic_get_l5_cid(struct cnic_local *cp, u32 cid, u32 *l5_cid)
{
	u32 i;

	for (i = 0; i < MAX_ISCSI_TBL_SZ; i++) {
		if (cp->ctx_tbl[i].cid == cid) {
			*l5_cid = i;
			return 0;
		}
	}
	return -EINVAL;
}


static int cnic_in_use(struct cnic_sock *csk)
{
	return (test_bit(SK_F_INUSE, &csk->flags));
}

static int cnic_offld_prep(struct cnic_sock *csk)
{
	if (!test_bit(SK_F_CONNECT_START, &csk->flags))
		return 0;

	if (test_and_set_bit(SK_F_OFFLD_SCHED, &csk->flags))
		return 0;

	return 1;
}

static int cnic_close_prep(struct cnic_sock *csk)
{
	if (test_and_clear_bit(SK_F_OFFLD_COMPLETE, &csk->flags))
		return 1;

	return 0;
}

static int cnic_abort_prep(struct cnic_sock *csk)
{
	while (test_and_set_bit(SK_F_OFFLD_SCHED, &csk->flags))
		msleep(1);

	if (cnic_close_prep(csk)) {
		csk->state = L4_KCQE_OPCODE_VALUE_RESET_COMP;
		return 1;
	}

	return 0;
}

int cnic_register_driver(int ulp_type, struct cnic_ulp_ops *ulp_ops)
{
	struct cnic_dev *dev;

	if (ulp_type >= MAX_CNIC_ULP_TYPE) {
		printk(KERN_ERR PFX "cnic_register_driver: Bad type %d\n",
		       ulp_type);
		return -EINVAL;
	}
	mutex_lock(&cnic_lock);
	if (cnic_ulp_tbl[ulp_type]) {
		printk(KERN_ERR PFX "cnic_register_driver: Type %d has already "
				    "been registered\n", ulp_type);
		mutex_unlock(&cnic_lock);
		return -EBUSY;
	}

#if !defined (__VMKLNX__)
	read_lock(&cnic_dev_lock);
#endif /* !defined (__VMKLNX__) */
	list_for_each_entry(dev, &cnic_dev_list, list) {
		struct cnic_local *cp = dev->cnic_priv;

		clear_bit(ULP_F_INIT, &cp->ulp_flags[ulp_type]);
	}
#if !defined (__VMKLNX__)
	read_unlock(&cnic_dev_lock);
#endif /* !defined (__VMKLNX__) */

	atomic_set(&ulp_ops->ref_count, 0);
	rcu_assign_pointer(cnic_ulp_tbl[ulp_type], ulp_ops);
	mutex_unlock(&cnic_lock);

	/* Prevent race conditions with netdev_event */
#if !defined (__VMKLNX__)
	rtnl_lock();
	read_lock(&cnic_dev_lock);
#endif /* !defined (__VMKLNX__) */
	list_for_each_entry(dev, &cnic_dev_list, list) {
		struct cnic_local *cp = dev->cnic_priv;

		if (!test_and_set_bit(ULP_F_INIT, &cp->ulp_flags[ulp_type]))
			ulp_ops->cnic_init(dev);
	}
#if !defined (__VMKLNX__)
	read_unlock(&cnic_dev_lock);
	rtnl_unlock();
#endif /* !defined (__VMKLNX__) */

	return 0;
}

int cnic_unregister_driver(int ulp_type)
{
	struct cnic_dev *dev;
	struct cnic_ulp_ops *ulp_ops;
	int i = 0;

	if (ulp_type >= MAX_CNIC_ULP_TYPE) {
		printk(KERN_ERR PFX "cnic_unregister_driver: Bad type %d\n",
		       ulp_type);
		return -EINVAL;
	}
	mutex_lock(&cnic_lock);
	ulp_ops = cnic_ulp_tbl[ulp_type];
	if (!ulp_ops) {
		printk(KERN_ERR PFX "cnic_unregister_driver: Type %d has not "
				    "been registered\n", ulp_type);
		goto out_unlock;
	}
#if !defined (__VMKLNX__)
	read_lock(&cnic_dev_lock);
#endif /* !defined (__VMKLNX__) */
	list_for_each_entry(dev, &cnic_dev_list, list) {
		struct cnic_local *cp = dev->cnic_priv;
		
		if (rcu_dereference(cp->ulp_ops[ulp_type])) {
			printk(KERN_ERR PFX "cnic_unregister_driver: Type %d "
			       "still has devices registered\n", ulp_type);
#if !defined (__VMKLNX__)
			read_unlock(&cnic_dev_lock);
#endif /* !defined (__VMKLNX__) */
			goto out_unlock;
		}
	}
#if !defined (__VMKLNX__)
	read_unlock(&cnic_dev_lock);
#endif /* !defined (__VMKLNX__) */

	rcu_assign_pointer(cnic_ulp_tbl[ulp_type], NULL);

	mutex_unlock(&cnic_lock);
	synchronize_rcu();
	while ((atomic_read(&ulp_ops->ref_count) != 0) && (i < 20)) {
		msleep(100);
		i++;
	}

	if (atomic_read(&ulp_ops->ref_count) != 0)
		printk(KERN_WARNING PFX "%s: Failed waiting for ref count to go"
			" to zero.\n", dev->netdev->name);
	return 0;

out_unlock:
	mutex_unlock(&cnic_lock);
	return -EINVAL;
}

EXPORT_SYMBOL(cnic_register_driver);
EXPORT_SYMBOL(cnic_unregister_driver);

static int cnic_register_netdev(struct cnic_dev *dev)
{
	struct cnic_local *cp = dev->cnic_priv;
	struct cnic_eth_dev *ethdev = cp->ethdev;
	int err;

	if (!ethdev)
		return -ENODEV;

	if (ethdev->drv_state & CNIC_DRV_STATE_REGD)
		return 0;

	err = ethdev->drv_register_cnic(dev->netdev, cp->cnic_ops, dev);
	if (err)
		printk(KERN_ERR PFX "%s: register_cnic failed\n",
		       dev->netdev->name);

	return err;
}

static void cnic_unregister_netdev(struct cnic_dev *dev)
{
	struct cnic_local *cp = dev->cnic_priv;
	struct cnic_eth_dev *ethdev = cp->ethdev;

	if (!ethdev)
		return;

	if (ethdev->drv_state & CNIC_DRV_STATE_REGD)
		ethdev->drv_unregister_cnic(dev->netdev);
}

static int cnic_start_hw(struct cnic_dev *);
static void cnic_stop_hw(struct cnic_dev *);

static int cnic_register_device(struct cnic_dev *dev, int ulp_type,
				void *ulp_ctx)
{
	struct cnic_local *cp = dev->cnic_priv;
	struct cnic_ulp_ops *ulp_ops;

	if (ulp_type >= MAX_CNIC_ULP_TYPE) {
		printk(KERN_ERR PFX "cnic_register_device: Bad type %d\n",
		       ulp_type);
		return -EINVAL;
	}
	mutex_lock(&cnic_lock);
	if (cnic_ulp_tbl[ulp_type] == NULL) {
		printk(KERN_ERR PFX "cnic_register_device: Driver with type %d "
				    "has not been registered\n", ulp_type);
		mutex_unlock(&cnic_lock);
		return -EAGAIN;
	}
	if (rcu_dereference(cp->ulp_ops[ulp_type])) {
		printk(KERN_ERR PFX "cnic_register_device: Type %d has already "
		       "been registered to this device\n", ulp_type);
		mutex_unlock(&cnic_lock);
		return -EBUSY;
	}

	clear_bit(ULP_F_START, &cp->ulp_flags[ulp_type]);
	cp->ulp_handle[ulp_type] = ulp_ctx;
	ulp_ops = cnic_ulp_tbl[ulp_type];
	rcu_assign_pointer(cp->ulp_ops[ulp_type], ulp_ops);
	cnic_hold(dev);
	if (!dev->use_count) {
		if (!test_bit(CNIC_F_IF_GOING_DOWN, &dev->flags)) {
			if (dev->netdev->flags & IFF_UP)
				set_bit(CNIC_F_IF_UP, &dev->flags);
		}
	}
	dev->use_count++;

	if (dev->use_count == 1) {
		if (test_bit(CNIC_F_IF_UP, &dev->flags)) {
			if (cnic_register_netdev(dev) == 0)
				cnic_start_hw(dev);
		}
	}

	if (test_bit(CNIC_F_CNIC_UP, &dev->flags))
		if (!test_and_set_bit(ULP_F_START, &cp->ulp_flags[ulp_type]))
			ulp_ops->cnic_start(cp->ulp_handle[ulp_type]);

	mutex_unlock(&cnic_lock);

	return 0;

}

static int cnic_unregister_device(struct cnic_dev *dev, int ulp_type)
{
	struct cnic_local *cp = dev->cnic_priv;
	int i = 0;

	if (ulp_type >= MAX_CNIC_ULP_TYPE) {
		printk(KERN_ERR PFX "cnic_unregister_device: Bad type %d\n",
		       ulp_type);
		return -EINVAL;
	}
	mutex_lock(&cnic_lock);
	if (rcu_dereference(cp->ulp_ops[ulp_type])) {
		dev->use_count--;
		rcu_assign_pointer(cp->ulp_ops[ulp_type], NULL);
		if (dev->use_count == 0) {
			cnic_stop_hw(dev);
		}
		cnic_put(dev);
	} else {
		printk(KERN_ERR PFX "cnic_unregister_device: device not "
		       "registered to this ulp type %d\n", ulp_type);
		mutex_unlock(&cnic_lock);
		return -EINVAL;
	}
	mutex_unlock(&cnic_lock);

	synchronize_rcu();

	while (test_bit(ULP_F_CALL_PENDING, &cp->ulp_flags[ulp_type]) &&
	       i < 20) {
		msleep(100);
		i++;
	}
	if (test_bit(ULP_F_CALL_PENDING, &cp->ulp_flags[ulp_type]))
		printk(KERN_WARNING PFX "%s: Failed waiting for ULP up call"
					" to complete.\n", dev->netdev->name);

	return 0;
}

static int cnic_init_id_tbl(struct cnic_id_tbl *id_tbl, u32 size, u32 start_id,
			    u32 next)
{
	id_tbl->start = start_id;
	id_tbl->max = size;
	id_tbl->next = next;
	spin_lock_init(&id_tbl->lock);
	id_tbl->table = kzalloc(DIV_ROUND_UP(size, 32) * 4, GFP_KERNEL);
	if (!id_tbl->table)
		return -ENOMEM;

	return 0;
}

static u32 cnic_free_id_tbl(struct cnic_id_tbl *id_tbl)
{
	kfree(id_tbl->table);
	id_tbl->table = NULL;
	return id_tbl->next;
}

/* Returns -1 if not successful */
static u32 cnic_alloc_new_id(struct cnic_id_tbl *id_tbl)
{
	u32 id;

	spin_lock(&id_tbl->lock);
	id = find_next_zero_bit(id_tbl->table, id_tbl->max, id_tbl->next);
	if (id >= id_tbl->max) {
		id = -1;
		if (id_tbl->next != 0) {
			id = find_first_zero_bit(id_tbl->table, id_tbl->next);
			if (id >= id_tbl->next)
				id = -1;
		}
	}

	if (id < id_tbl->max) {
		set_bit(id, id_tbl->table);
		id_tbl->next = (id + 1) & (id_tbl->max - 1);
		id += id_tbl->start;
	}

	spin_unlock(&id_tbl->lock);

	return id;
}

void cnic_free_id(struct cnic_id_tbl *id_tbl, u32 id)
{
	if (id == -1)
		return;

	id -= id_tbl->start;
	if (id >= id_tbl->max)
		return;

	clear_bit(id, id_tbl->table);
}

static void cnic_free_dma(struct cnic_dev *dev, struct cnic_dma *dma)
{
	int i;

	if (!dma->pg_arr)
		return;

	for (i = 0; i < dma->num_pages; i++) {
		if (dma->pg_arr[i]) {
			pci_free_consistent(dev->pcidev, BCM_PAGE_SIZE,
					    dma->pg_arr[i], dma->pg_map_arr[i]);
			dma->pg_arr[i] = NULL;
		}
	}
	if (dma->pgtbl) {
		pci_free_consistent(dev->pcidev, dma->pgtbl_size,
				    dma->pgtbl, dma->pgtbl_map);
		dma->pgtbl = NULL;
	}
	kfree(dma->pg_arr);
	dma->pg_arr = NULL;
	dma->num_pages = 0;
}

static void cnic_setup_page_tbl(struct cnic_dev *dev, struct cnic_dma *dma)
{
	int i;
	u32 *page_table = dma->pgtbl;

	for (i = 0; i < dma->num_pages; i++) {
		/* Each entry needs to be in big endian format. */
		*page_table = (u32) ((u64) dma->pg_map_arr[i] >> 32);
		page_table++;
		*page_table = (u32) dma->pg_map_arr[i];
		page_table++;
	}
}

static void cnic_setup_page_tbl_le(struct cnic_dev *dev, struct cnic_dma *dma)
{
	int i;
	u32 *page_table = dma->pgtbl;

	for (i = 0; i < dma->num_pages; i++) {
		/* Each entry needs to be in little endian format. */
		*page_table = dma->pg_map_arr[i] & 0xffffffff;
		page_table++;
		*page_table = (u32) ((u64) dma->pg_map_arr[i] >> 32);
		page_table++;
	}
}

static int cnic_alloc_dma(struct cnic_dev *dev, struct cnic_dma *dma,
			  int pages, int use_pg_tbl)
{
	int i, size;
	struct cnic_local *cp = dev->cnic_priv;

	size = pages * (sizeof(void *) + sizeof(dma_addr_t));
	dma->pg_arr = kzalloc(size, GFP_ATOMIC);
	if (dma->pg_arr == NULL)
		return -ENOMEM;

	dma->pg_map_arr = (dma_addr_t *) (dma->pg_arr + pages);
	dma->num_pages = pages;

	for (i = 0; i < pages; i++) {
		dma->pg_arr[i] = pci_alloc_consistent(dev->pcidev,
						      BCM_PAGE_SIZE,
						      &dma->pg_map_arr[i]);
		if (dma->pg_arr[i] == NULL)
			goto error;
	}
	if (!use_pg_tbl)
		return 0;

	dma->pgtbl_size = ((pages * 8) + BCM_PAGE_SIZE - 1) &
			  ~(BCM_PAGE_SIZE - 1);
	dma->pgtbl = pci_alloc_consistent(dev->pcidev, dma->pgtbl_size,
					  &dma->pgtbl_map);
	if (dma->pgtbl == NULL)
		goto error;

	cp->setup_pgtbl(dev, dma);

	return 0;

error:
	cnic_free_dma(dev, dma);
	return -ENOMEM;
}

static void cnic_free_contex(struct cnic_dev *dev)
{
	struct cnic_local *cp = dev->cnic_priv;
	int i;

	for (i = 0; i < cp->ctx_blks; i++) {
		if (cp->ctx_arr[i].ctx) {
			pci_free_consistent(dev->pcidev, cp->ctx_blk_size,
					    cp->ctx_arr[i].ctx,
					    cp->ctx_arr[i].mapping);
			cp->ctx_arr[i].ctx = NULL;
		}
	}
}

static void cnic_free_resc(struct cnic_dev *dev)
{
	struct cnic_local *cp = dev->cnic_priv;

	cnic_free_contex(dev);
	kfree(cp->ctx_arr);
	cp->ctx_arr = NULL;
	cp->ctx_blks = 0;

	cnic_free_dma(dev, &cp->gbl_buf_info);
	cnic_free_dma(dev, &cp->conn_buf_info);
	cnic_free_dma(dev, &cp->kwq_info);
	cnic_free_dma(dev, &cp->kwq_16_data_info);
	cnic_free_dma(dev, &cp->kcq_info);
	kfree(cp->iscsi_tbl);
	cp->iscsi_tbl = NULL;
	kfree(cp->ctx_tbl);
	cp->ctx_tbl = NULL;

	cnic_free_id_tbl(&cp->cid_tbl);
}

static int cnic_alloc_context(struct cnic_dev *dev)
{
	struct cnic_local *cp = dev->cnic_priv;

	if (CHIP_NUM(cp) == CHIP_NUM_5709) {
		int i, k, arr_size;

		cp->ctx_blk_size = BCM_PAGE_SIZE;
		cp->cids_per_blk = BCM_PAGE_SIZE / 128;
		arr_size = BNX2_MAX_CID / cp->cids_per_blk *
			   sizeof(struct cnic_ctx);
		cp->ctx_arr = kmalloc(arr_size, GFP_KERNEL);
		if (cp->ctx_arr == NULL)
			return -ENOMEM;

		memset(cp->ctx_arr, 0, arr_size);

		k = 0;
		for (i = 0; i < 2; i++) {
			u32 j, reg, off, lo, hi;

			if (i == 0)
				off = BNX2_PG_CTX_MAP;
			else
				off = BNX2_ISCSI_CTX_MAP;

			reg = cnic_reg_rd_ind(dev, off);
			lo = reg >> 16;
			hi = reg & 0xffff;
			for (j = lo; j < hi; j += cp->cids_per_blk, k++)
				cp->ctx_arr[k].cid = j;
		}

		cp->ctx_blks = k;
		if (cp->ctx_blks >= (BNX2_MAX_CID / cp->cids_per_blk)) {
			cp->ctx_blks = 0;
			return -ENOMEM;
		}

		for (i = 0; i < cp->ctx_blks; i++) {
			cp->ctx_arr[i].ctx =
				pci_alloc_consistent(dev->pcidev, BCM_PAGE_SIZE,
						     &cp->ctx_arr[i].mapping);
			if (cp->ctx_arr[i].ctx == NULL)
				return -ENOMEM;
		}
	}
	return 0;
}

static int cnic_alloc_bnx2_resc(struct cnic_dev *dev)
{
	struct cnic_local *cp = dev->cnic_priv;
	int ret;

	ret = cnic_alloc_dma(dev, &cp->kwq_info, KWQ_PAGE_CNT, 1);
	if (ret)
		goto error;
	cp->kwq = (struct kwqe **) cp->kwq_info.pg_arr;

	ret = cnic_alloc_dma(dev, &cp->kcq_info, KCQ_PAGE_CNT, 1);
	if (ret)
		goto error;
	cp->kcq = (struct kcqe **) cp->kcq_info.pg_arr;

	ret = cnic_alloc_context(dev);
	if (ret)
		goto error;

	return 0;
	
error:
	cnic_free_resc(dev);
	return ret;
}

static int cnic_alloc_bnx2x_context(struct cnic_dev *dev)
{
	struct cnic_local *cp = dev->cnic_priv;
	int ctx_blk_size = cp->ethdev->ctx_blk_size;
	int total_mem, blks, i;

	total_mem = BNX2X_ISCSI_CONTEXT_MEM_SIZE * MAX_ISCSI_TBL_SZ;
	blks = total_mem / ctx_blk_size;
	if (total_mem % ctx_blk_size)
		blks++;

	if (blks > cp->ethdev->ctx_tbl_len)
		return -ENOMEM;

	cp->ctx_arr = kzalloc(blks * sizeof(struct cnic_ctx), GFP_KERNEL);
	if (cp->ctx_arr == NULL)
		return -ENOMEM;

	cp->ctx_blks = blks;
	cp->ctx_blk_size = ctx_blk_size;
	if (BNX2X_CHIP_IS_E1H(cp->chip_id))
		cp->ctx_align = 0;
	else
		cp->ctx_align = ctx_blk_size;

	cp->cids_per_blk = ctx_blk_size / BNX2X_ISCSI_CONTEXT_MEM_SIZE;

	for (i = 0; i < blks; i++) {
		cp->ctx_arr[i].ctx =
			pci_alloc_consistent(dev->pcidev, cp->ctx_blk_size,
					     &cp->ctx_arr[i].mapping);
		if (cp->ctx_arr[i].ctx == NULL)
			return -ENOMEM;

		if (cp->ctx_align && cp->ctx_blk_size == ctx_blk_size) {
			if (cp->ctx_arr[i].mapping & (cp->ctx_align - 1)) {
				cnic_free_contex(dev);
				cp->ctx_blk_size += cp->ctx_align;
				i = -1;
				continue;
			}
		}
	}
	return 0;
}

static int cnic_alloc_bnx2x_resc(struct cnic_dev *dev)
{
	struct cnic_local *cp = dev->cnic_priv;
	int i, j, n, ret, pages;
	struct cnic_dma *kwq_16_dma = &cp->kwq_16_data_info;

	cp->iscsi_tbl = kzalloc(sizeof(struct cnic_iscsi) * MAX_ISCSI_TBL_SZ,
				GFP_KERNEL);
	if (!cp->iscsi_tbl)
		goto error;

	cp->ctx_tbl = kzalloc(sizeof(struct cnic_context) *
				  MAX_CNIC_L5_CONTEXT, GFP_KERNEL);
	if (!cp->ctx_tbl)
		goto error;

	for (i = 0; i < MAX_ISCSI_TBL_SZ; i++) {
		cp->ctx_tbl[i].proto.iscsi = &cp->iscsi_tbl[i];
		cp->ctx_tbl[i].ulp_proto_id = CNIC_ULP_ISCSI;
	}

	pages = PAGE_ALIGN(MAX_CNIC_L5_CONTEXT * CNIC_KWQ16_DATA_SIZE) /
		PAGE_SIZE;

	ret = cnic_alloc_dma(dev, kwq_16_dma, pages, 0);
	if (ret)
		return -ENOMEM;

	n = PAGE_SIZE / CNIC_KWQ16_DATA_SIZE;
	for (i = 0, j = 0; i < MAX_ISCSI_TBL_SZ; i++) {
		long off = CNIC_KWQ16_DATA_SIZE * (i % n);

		cp->ctx_tbl[i].kwqe_data = kwq_16_dma->pg_arr[j] + off;
		cp->ctx_tbl[i].kwqe_data_mapping = kwq_16_dma->pg_map_arr[j] +
						   off;

		if ((i % n) == (n - 1))
			j++;
	}

	ret = cnic_alloc_dma(dev, &cp->kcq_info, KCQ_PAGE_CNT, 0);
	if (ret)
		goto error;
	cp->kcq = (struct kcqe **) cp->kcq_info.pg_arr;

	for (i = 0; i < KCQ_PAGE_CNT; i++) {
		struct bnx2x_bd_chain_next *next =
			(struct bnx2x_bd_chain_next *)
			&cp->kcq[i][MAX_KCQE_CNT];
		int j = i + 1;

		if (j >= KCQ_PAGE_CNT)
			j = 0;
		next->addr_hi = (u64) cp->kcq_info.pg_map_arr[j] >> 32;
		next->addr_lo = cp->kcq_info.pg_map_arr[j] & 0xffffffff;
	}

	pages = PAGE_ALIGN(BNX2X_ISCSI_NUM_CONNECTIONS *
			   BNX2X_ISCSI_CONN_BUF_SIZE) / PAGE_SIZE;
	ret = cnic_alloc_dma(dev, &cp->conn_buf_info, pages, 1);
	if (ret)
		goto error;

	pages = PAGE_ALIGN(BNX2X_ISCSI_GLB_BUF_SIZE) / PAGE_SIZE;
	ret = cnic_alloc_dma(dev, &cp->gbl_buf_info, pages, 0);
	if (ret)
		goto error;

	ret = cnic_alloc_bnx2x_context(dev);
	if (ret)
		goto error;

	return 0;

error:
	cnic_free_resc(dev);
	return -ENOMEM;
}

static inline u32 cnic_kwq_avail(struct cnic_local *cp)
{
	return (cp->max_kwq_idx -
		((cp->kwq_prod_idx - cp->kwq_con_idx) & cp->max_kwq_idx));
}

static int cnic_submit_bnx2_kwqes(struct cnic_dev *dev, struct kwqe *wqes[],
				  u32 num_wqes)
{
	struct cnic_local *cp = dev->cnic_priv;
	struct kwqe *prod_qe;
	u16 prod, sw_prod, i;

	if (!test_bit(CNIC_F_CNIC_UP, &dev->flags))
		return -EAGAIN;		/* bnx2 is down */

	spin_lock_bh(&cp->cnic_ulp_lock);
	if (num_wqes > cnic_kwq_avail(cp) &&
	    !(cp->cnic_local_flags & CNIC_LCL_FL_KWQ_INIT)) {
		spin_unlock_bh(&cp->cnic_ulp_lock);
		return -EAGAIN;
	}

	cp->cnic_local_flags &= ~CNIC_LCL_FL_KWQ_INIT;

	prod = cp->kwq_prod_idx;
	sw_prod = prod & MAX_KWQ_IDX;
	for (i = 0; i < num_wqes; i++) {
		prod_qe = &cp->kwq[KWQ_PG(sw_prod)][KWQ_IDX(sw_prod)];
		memcpy(prod_qe, wqes[i], sizeof(struct kwqe));
		prod++;
		sw_prod = prod & MAX_KWQ_IDX;
	}
	cp->kwq_prod_idx = prod;

	CNIC_WR16(dev, cp->kwq_io_addr, cp->kwq_prod_idx);

	spin_unlock_bh(&cp->cnic_ulp_lock);
	return 0;
}

static void *cnic_get_kwqe_16_data(struct cnic_local *cp, u32 l5_cid,
				   union l5cm_specific_data *l5_data)
{
	struct cnic_context *ctx = &cp->ctx_tbl[l5_cid];
	dma_addr_t map;

	map = ctx->kwqe_data_mapping;
	l5_data->phy_address.lo = (u64) map & 0xffffffff;
	l5_data->phy_address.hi = (u64) map >> 32;
	return ctx->kwqe_data;
}

static int cnic_submit_kwqe_16(struct cnic_dev *dev, u32 cmd, u32 cid,
				u32 type, union l5cm_specific_data *l5_data)
{
	struct cnic_local *cp = dev->cnic_priv;
	struct l5cm_spe kwqe;
	struct kwqe_16 *kwq[1];
	int ret;

	kwqe.hdr.conn_and_cmd_data =
		cpu_to_le32(((cmd << SPE_HDR_CMD_ID_SHIFT) |
			     BNX2X_HW_CID(cid, cp->func)));
	kwqe.hdr.type = cpu_to_le16(type);
	kwqe.hdr.reserved = 0;
	kwqe.data.phy_address.lo = cpu_to_le32(l5_data->phy_address.lo);
	kwqe.data.phy_address.hi = cpu_to_le32(l5_data->phy_address.hi);

	kwq[0] = (struct kwqe_16 *) &kwqe;
	spin_lock_bh(&cp->cnic_ulp_lock);
	ret = cp->ethdev->drv_submit_kwqes_16(dev->netdev, kwq, 1);
	spin_unlock_bh(&cp->cnic_ulp_lock);

	if (ret == 1)
		return 0;

	return -EBUSY;
}

static void cnic_reply_bnx2x_kcqes(struct cnic_dev *dev, int ulp_type,
				   struct kcqe *cqes[], u32 num_cqes)
{
	struct cnic_local *cp = dev->cnic_priv;
	struct cnic_ulp_ops *ulp_ops;

	rcu_read_lock();
	ulp_ops = rcu_dereference(cp->ulp_ops[ulp_type]);
	if (likely(ulp_ops)) {
		ulp_ops->indicate_kcqes(cp->ulp_handle[ulp_type],
					  cqes, num_cqes);
	}
	rcu_read_unlock();
}

static int cnic_bnx2x_iscsi_init1(struct cnic_dev *dev, struct kwqe *kwqe)
{
	struct cnic_local *cp = dev->cnic_priv;
	struct iscsi_kwqe_init1 *req1 = (struct iscsi_kwqe_init1 *) kwqe;
	int func = cp->func, pages;
	int hq_bds;

	cp->num_iscsi_tasks = req1->num_tasks_per_conn;
	cp->num_ccells = req1->num_ccells_per_conn;
	cp->task_array_size = BNX2X_ISCSI_TASK_CONTEXT_SIZE *
			      cp->num_iscsi_tasks;
	cp->r2tq_size = cp->num_iscsi_tasks * BNX2X_ISCSI_MAX_PENDING_R2TS *
			BNX2X_ISCSI_R2TQE_SIZE;
	cp->hq_size = cp->num_ccells * BNX2X_ISCSI_HQ_BD_SIZE;
	pages = PAGE_ALIGN(cp->hq_size) / PAGE_SIZE;
	hq_bds = pages * (PAGE_SIZE / BNX2X_ISCSI_HQ_BD_SIZE);
	cp->num_cqs = req1->num_cqs;

	if (!dev->max_iscsi_conn)
		return 0;

	/* init Tstorm RAM */
	CNIC_WR16(dev, BAR_TSTRORM_INTMEM + TSTORM_ISCSI_RQ_SIZE_OFFSET(func),
		  req1->rq_num_wqes);
	CNIC_WR16(dev, BAR_TSTRORM_INTMEM + TSTORM_ISCSI_PAGE_SIZE_OFFSET(func),
		  PAGE_SIZE);
	CNIC_WR8(dev, BAR_TSTRORM_INTMEM +
		 TSTORM_ISCSI_PAGE_SIZE_LOG_OFFSET(func), PAGE_SHIFT);
	CNIC_WR16(dev, BAR_TSTRORM_INTMEM +
		  TSTORM_ISCSI_NUM_OF_TASKS_OFFSET(func),
		  req1->num_tasks_per_conn);

	/* init Ustorm RAM */
	CNIC_WR16(dev, BAR_USTRORM_INTMEM +
		  USTORM_ISCSI_RQ_BUFFER_SIZE_OFFSET(func),
		  req1->rq_buffer_size);
	CNIC_WR16(dev, BAR_USTRORM_INTMEM + USTORM_ISCSI_PAGE_SIZE_OFFSET(func),
		  PAGE_SIZE);
	CNIC_WR8(dev, BAR_USTRORM_INTMEM +
		 USTORM_ISCSI_PAGE_SIZE_LOG_OFFSET(func), PAGE_SHIFT);
	CNIC_WR16(dev, BAR_USTRORM_INTMEM +
		  USTORM_ISCSI_NUM_OF_TASKS_OFFSET(func),
		  req1->num_tasks_per_conn);
	CNIC_WR16(dev, BAR_USTRORM_INTMEM + USTORM_ISCSI_RQ_SIZE_OFFSET(func),
		  req1->rq_num_wqes);
	CNIC_WR16(dev, BAR_USTRORM_INTMEM + USTORM_ISCSI_CQ_SIZE_OFFSET(func),
		  req1->cq_num_wqes);
	CNIC_WR16(dev, BAR_USTRORM_INTMEM + USTORM_ISCSI_R2TQ_SIZE_OFFSET(func),
		  cp->num_iscsi_tasks * BNX2X_ISCSI_MAX_PENDING_R2TS);

	/* init Xstorm RAM */
	CNIC_WR16(dev, BAR_XSTRORM_INTMEM + XSTORM_ISCSI_PAGE_SIZE_OFFSET(func),
		  PAGE_SIZE);
	CNIC_WR8(dev, BAR_XSTRORM_INTMEM +
		 XSTORM_ISCSI_PAGE_SIZE_LOG_OFFSET(func), PAGE_SHIFT);
	CNIC_WR16(dev, BAR_XSTRORM_INTMEM +
		  XSTORM_ISCSI_NUM_OF_TASKS_OFFSET(func),
		  req1->num_tasks_per_conn);
	CNIC_WR16(dev, BAR_XSTRORM_INTMEM + XSTORM_ISCSI_HQ_SIZE_OFFSET(func),
		  hq_bds);
	CNIC_WR16(dev, BAR_XSTRORM_INTMEM + XSTORM_ISCSI_SQ_SIZE_OFFSET(func),
		  req1->num_tasks_per_conn);
	CNIC_WR16(dev, BAR_XSTRORM_INTMEM + XSTORM_ISCSI_R2TQ_SIZE_OFFSET(func),
		  cp->num_iscsi_tasks * BNX2X_ISCSI_MAX_PENDING_R2TS);

	/* init Cstorm RAM */
	CNIC_WR16(dev, BAR_CSTRORM_INTMEM + CSTORM_ISCSI_PAGE_SIZE_OFFSET(func),
		  PAGE_SIZE);
	CNIC_WR8(dev, BAR_CSTRORM_INTMEM +
		 CSTORM_ISCSI_PAGE_SIZE_LOG_OFFSET(func), PAGE_SHIFT);
	CNIC_WR16(dev, BAR_CSTRORM_INTMEM +
		  CSTORM_ISCSI_NUM_OF_TASKS_OFFSET(func),
		  req1->num_tasks_per_conn);
	CNIC_WR16(dev, BAR_CSTRORM_INTMEM + CSTORM_ISCSI_CQ_SIZE_OFFSET(func),
		  req1->cq_num_wqes);
	CNIC_WR16(dev, BAR_CSTRORM_INTMEM + CSTORM_ISCSI_HQ_SIZE_OFFSET(func),
		  hq_bds);

	return 0;
}

static int cnic_bnx2x_iscsi_init2(struct cnic_dev *dev, struct kwqe *kwqe)
{
	struct iscsi_kwqe_init2 *req2 = (struct iscsi_kwqe_init2 *) kwqe;
	struct cnic_local *cp = dev->cnic_priv;
	int func = cp->func;
	struct iscsi_kcqe kcqe;
	struct kcqe *cqes[1];

	memset(&kcqe, 0, sizeof(kcqe));
	if (!dev->max_iscsi_conn) {
		kcqe.completion_status =
			ISCSI_KCQE_COMPLETION_STATUS_ISCSI_NOT_SUPPORTED;
		goto done;
	}

	CNIC_WR(dev, BAR_TSTRORM_INTMEM +
		TSTORM_ISCSI_ERROR_BITMAP_OFFSET(func), req2->error_bit_map[0]);
	CNIC_WR(dev, BAR_TSTRORM_INTMEM +
		TSTORM_ISCSI_ERROR_BITMAP_OFFSET(func) + 4,
		req2->error_bit_map[1]);

	CNIC_WR16(dev, BAR_USTRORM_INTMEM +
		  USTORM_ISCSI_CQ_SQN_SIZE_OFFSET(func), req2->max_cq_sqn);
	CNIC_WR(dev, BAR_USTRORM_INTMEM +
		USTORM_ISCSI_ERROR_BITMAP_OFFSET(func), req2->error_bit_map[0]);
	CNIC_WR(dev, BAR_USTRORM_INTMEM +
		USTORM_ISCSI_ERROR_BITMAP_OFFSET(func) + 4,
		req2->error_bit_map[1]);

	CNIC_WR16(dev, BAR_CSTRORM_INTMEM +
		  CSTORM_ISCSI_CQ_SQN_SIZE_OFFSET(func), req2->max_cq_sqn);

	kcqe.completion_status = ISCSI_KCQE_COMPLETION_STATUS_SUCCESS;

done:
	kcqe.op_code = ISCSI_KCQE_OPCODE_INIT;
	cqes[0] = (struct kcqe *) &kcqe;
	cnic_reply_bnx2x_kcqes(dev, CNIC_ULP_ISCSI, cqes, 1);

	return 0;
}

static void cnic_free_bnx2x_conn_resc(struct cnic_dev *dev, u32 l5_cid)
{
	struct cnic_local *cp = dev->cnic_priv;
	struct cnic_context *ctx = &cp->ctx_tbl[l5_cid];

	if (ctx->ulp_proto_id == CNIC_ULP_ISCSI) {
		struct cnic_iscsi *iscsi = ctx->proto.iscsi;

		cnic_free_dma(dev, &iscsi->hq_info);
		cnic_free_dma(dev, &iscsi->r2tq_info);
		cnic_free_dma(dev, &iscsi->task_array_info);
	}
	cnic_free_id(&cp->cid_tbl, ctx->cid);
	ctx->cid = 0;
}

static int cnic_alloc_bnx2x_conn_resc(struct cnic_dev *dev, u32 l5_cid)
{
	u32 cid;
	int ret, pages;
	struct cnic_local *cp = dev->cnic_priv;
	struct cnic_context *ctx = &cp->ctx_tbl[l5_cid];
	struct cnic_iscsi *iscsi = ctx->proto.iscsi;

	cid = cnic_alloc_new_id(&cp->cid_tbl);
	if (cid == -1) {
		ret = -ENOMEM;
		goto error;
	}

	ctx->cid = cid;
	pages = PAGE_ALIGN(cp->task_array_size) / PAGE_SIZE;

	ret = cnic_alloc_dma(dev, &iscsi->task_array_info, pages, 1);
	if (ret)
		goto error;

	pages = PAGE_ALIGN(cp->r2tq_size) / PAGE_SIZE;
	ret = cnic_alloc_dma(dev, &iscsi->r2tq_info, pages, 1);
	if (ret)
		goto error;

	pages = PAGE_ALIGN(cp->hq_size) / PAGE_SIZE;
	ret = cnic_alloc_dma(dev, &iscsi->hq_info, pages, 1);
	if (ret)
		goto error;

	return 0;

error:
	cnic_free_bnx2x_conn_resc(dev, l5_cid);
	return ret;
}

static struct iscsi_context *cnic_get_bnx2x_ctx(struct cnic_dev *dev, u32 cid,
						int init,
						struct regpair *ctx_addr)
{
	struct cnic_local *cp = dev->cnic_priv;
	struct cnic_eth_dev *ethdev = cp->ethdev;
	int blk = (cid - ethdev->starting_cid) / cp->cids_per_blk;
	int off = (cid - ethdev->starting_cid) % cp->cids_per_blk;
	unsigned long align_off = 0;
	dma_addr_t ctx_map;
	struct iscsi_context *ctx;

	if (cp->ctx_align) {
		unsigned long mask = cp->ctx_align - 1;

		if (cp->ctx_arr[blk].mapping & mask)
			align_off = cp->ctx_align -
				    (cp->ctx_arr[blk].mapping & mask);
	}
	ctx_map = cp->ctx_arr[blk].mapping + align_off +
		(off * BNX2X_ISCSI_CONTEXT_MEM_SIZE);
	ctx = (struct iscsi_context *) (cp->ctx_arr[blk].ctx + align_off +
		(off * BNX2X_ISCSI_CONTEXT_MEM_SIZE));
	if (init)
		memset(ctx, 0, sizeof(*ctx));

	ctx_addr->lo = ctx_map & 0xffffffff;
	ctx_addr->hi = (u64) ctx_map >> 32;
	return ctx;
}

static int cnic_setup_bnx2x_ctx(struct cnic_dev *dev, struct kwqe *wqes[],
				u32 num)
{
	struct cnic_local *cp = dev->cnic_priv;
	struct iscsi_kwqe_conn_offload1 *req1 =
			(struct iscsi_kwqe_conn_offload1 *) wqes[0];
	struct iscsi_kwqe_conn_offload2 *req2 =
			(struct iscsi_kwqe_conn_offload2 *) wqes[1];
	struct iscsi_kwqe_conn_offload3 *req3;
	struct cnic_context *ctx = &cp->ctx_tbl[req1->iscsi_conn_id];
	struct cnic_iscsi *iscsi = ctx->proto.iscsi;
	u32 cid = ctx->cid;
	u32 hw_cid = BNX2X_HW_CID(cid, cp->func);
	struct iscsi_context *ictx;
	struct regpair context_addr;
	int i, j, n = 2, n_max;

	ctx->ctx_flags = 0;
	if (!req2->num_additional_wqes)
		return -EINVAL;

	n_max = req2->num_additional_wqes + 2;

	ictx = cnic_get_bnx2x_ctx(dev, cid, 1, &context_addr);
	if (ictx == NULL)
		return -ENOMEM;

	req3 = (struct iscsi_kwqe_conn_offload3 *) wqes[n++];

	ictx->xstorm_ag_context.hq_prod = 1;

	ictx->xstorm_st_context.iscsi.first_burst_length =
		ISCSI_DEF_FIRST_BURST_LEN;
	ictx->xstorm_st_context.iscsi.max_send_pdu_length =
		ISCSI_DEF_MAX_RECV_SEG_LEN;
	ictx->xstorm_st_context.iscsi.sq_pbl_base.lo =
		req1->sq_page_table_addr_lo;
	ictx->xstorm_st_context.iscsi.sq_pbl_base.hi =
		req1->sq_page_table_addr_hi;
	ictx->xstorm_st_context.iscsi.sq_curr_pbe.lo = req2->sq_first_pte.hi;
	ictx->xstorm_st_context.iscsi.sq_curr_pbe.hi = req2->sq_first_pte.lo;
	ictx->xstorm_st_context.iscsi.hq_pbl_base.lo =
		iscsi->hq_info.pgtbl_map & 0xffffffff;
	ictx->xstorm_st_context.iscsi.hq_pbl_base.hi =
		(u64) iscsi->hq_info.pgtbl_map >> 32;
	ictx->xstorm_st_context.iscsi.hq_curr_pbe_base.lo =
		iscsi->hq_info.pgtbl[0];
	ictx->xstorm_st_context.iscsi.hq_curr_pbe_base.hi =
		iscsi->hq_info.pgtbl[1];
	ictx->xstorm_st_context.iscsi.r2tq_pbl_base.lo =
		iscsi->r2tq_info.pgtbl_map & 0xffffffff;
	ictx->xstorm_st_context.iscsi.r2tq_pbl_base.hi =
		(u64) iscsi->r2tq_info.pgtbl_map >> 32;
	ictx->xstorm_st_context.iscsi.r2tq_curr_pbe_base.lo =
		iscsi->r2tq_info.pgtbl[0];
	ictx->xstorm_st_context.iscsi.r2tq_curr_pbe_base.hi =
		iscsi->r2tq_info.pgtbl[1];
	ictx->xstorm_st_context.iscsi.task_pbl_base.lo =
		iscsi->task_array_info.pgtbl_map & 0xffffffff;
	ictx->xstorm_st_context.iscsi.task_pbl_base.hi =
		(u64) iscsi->task_array_info.pgtbl_map >> 32;
	ictx->xstorm_st_context.iscsi.task_pbl_cache_idx =
		BNX2X_ISCSI_PBL_NOT_CACHED;
/*	ictx->xstorm_st_context.iscsi.max_outstanding_r2ts =
		ISCSI_DEFAULT_MAX_OUTSTANDING_R2T;*/
	ictx->xstorm_st_context.iscsi.flags.flags |=
		XSTORM_ISCSI_CONTEXT_FLAGS_B_IMMEDIATE_DATA;
	ictx->xstorm_st_context.iscsi.flags.flags |=
		XSTORM_ISCSI_CONTEXT_FLAGS_B_INITIAL_R2T;

	ictx->tstorm_st_context.iscsi.hdr_bytes_2_fetch = ISCSI_HEADER_SIZE;
	/* TSTORM requires the base address of RQ DB & not PTE */
	ictx->tstorm_st_context.iscsi.rq_db_phy_addr.lo =
		req2->rq_page_table_addr_lo & PAGE_MASK;
	ictx->tstorm_st_context.iscsi.rq_db_phy_addr.hi =
		req2->rq_page_table_addr_hi;
	ictx->tstorm_st_context.iscsi.iscsi_conn_id = req1->iscsi_conn_id;
	ictx->tstorm_st_context.tcp.cwnd = 0x5A8;
	ictx->tstorm_st_context.tcp.flags2 |=
		TSTORM_TCP_ST_CONTEXT_SECTION_DA_EN;

	ictx->timers_context.flags |= ISCSI_TIMERS_BLOCK_CONTEXT_CONN_VALID_FLG;

	ictx->ustorm_st_context.ring.rq.pbl_base.lo =
		req2->rq_page_table_addr_lo;
	ictx->ustorm_st_context.ring.rq.pbl_base.hi =
		req2->rq_page_table_addr_hi;
	ictx->ustorm_st_context.ring.rq.curr_pbe.lo = req3->qp_first_pte[0].hi;
	ictx->ustorm_st_context.ring.rq.curr_pbe.hi = req3->qp_first_pte[0].lo;
	ictx->ustorm_st_context.ring.r2tq.pbl_base.lo =
		iscsi->r2tq_info.pgtbl_map & 0xffffffff;
	ictx->ustorm_st_context.ring.r2tq.pbl_base.hi =
		(u64) iscsi->r2tq_info.pgtbl_map >> 32;
	ictx->ustorm_st_context.ring.r2tq.curr_pbe.lo =
		iscsi->r2tq_info.pgtbl[0];
	ictx->ustorm_st_context.ring.r2tq.curr_pbe.hi =
		iscsi->r2tq_info.pgtbl[1];
	ictx->ustorm_st_context.ring.cq_pbl_base.lo =
		req1->cq_page_table_addr_lo;
	ictx->ustorm_st_context.ring.cq_pbl_base.hi =
		req1->cq_page_table_addr_hi;
	ictx->ustorm_st_context.ring.cq[0].cq_sn = ISCSI_INITIAL_SN;
	ictx->ustorm_st_context.ring.cq[0].curr_pbe.lo = req2->cq_first_pte.hi;
	ictx->ustorm_st_context.ring.cq[0].curr_pbe.hi = req2->cq_first_pte.lo;
	ictx->ustorm_st_context.task_pbe_cache_index =
		BNX2X_ISCSI_PBL_NOT_CACHED;
	ictx->ustorm_st_context.task_pdu_cache_index =
		BNX2X_ISCSI_PDU_HEADER_NOT_CACHED;

	for (i = 1, j = 1; i < cp->num_cqs; i++, j++) {
		if (j == 3) {
			if (n >= n_max)
				break;
			req3 = (struct iscsi_kwqe_conn_offload3 *) wqes[n++];
			j = 0;
		}
		ictx->ustorm_st_context.ring.cq[i].cq_sn = ISCSI_INITIAL_SN;
		ictx->ustorm_st_context.ring.cq[i].curr_pbe.lo =
			req3->qp_first_pte[j].hi;
		ictx->ustorm_st_context.ring.cq[i].curr_pbe.hi =
			req3->qp_first_pte[j].lo;
	}

	ictx->ustorm_st_context.task_pbl_base.lo =
		iscsi->task_array_info.pgtbl_map & 0xffffffff;
	ictx->ustorm_st_context.task_pbl_base.hi =
		(u64) iscsi->task_array_info.pgtbl_map >> 32;
	ictx->ustorm_st_context.tce_phy_addr.lo =
		iscsi->task_array_info.pgtbl[0];
	ictx->ustorm_st_context.tce_phy_addr.hi =
		iscsi->task_array_info.pgtbl[1];
	ictx->ustorm_st_context.iscsi_conn_id = req1->iscsi_conn_id;
	ictx->ustorm_st_context.num_cqs = cp->num_cqs;
	ictx->ustorm_st_context.negotiated_rx |= ISCSI_DEF_MAX_RECV_SEG_LEN;
	ictx->ustorm_st_context.negotiated_rx_and_flags |=
		ISCSI_DEF_MAX_BURST_LEN;
	ictx->ustorm_st_context.negotiated_rx |=
		ISCSI_DEFAULT_MAX_OUTSTANDING_R2T <<
		USTORM_ISCSI_ST_CONTEXT_MAX_OUTSTANDING_R2TS_SHIFT;

	ictx->cstorm_st_context.hq_pbl_base.lo =
		iscsi->hq_info.pgtbl_map & 0xffffffff;
	ictx->cstorm_st_context.hq_pbl_base.hi =
		(u64) iscsi->hq_info.pgtbl_map >> 32;
	ictx->cstorm_st_context.hq_curr_pbe.lo = iscsi->hq_info.pgtbl[0];
	ictx->cstorm_st_context.hq_curr_pbe.hi = iscsi->hq_info.pgtbl[1];
	ictx->cstorm_st_context.task_pbl_base.lo =
		iscsi->task_array_info.pgtbl_map & 0xffffffff;
	ictx->cstorm_st_context.task_pbl_base.hi =
		(u64) iscsi->task_array_info.pgtbl_map >> 32;
	/* CSTORM and USTORM initialization is different, CSTORM requires
	 * CQ DB base & not PTE addr */
	ictx->cstorm_st_context.cq_db_base.lo =
		req1->cq_page_table_addr_lo & PAGE_MASK;
	ictx->cstorm_st_context.cq_db_base.hi = req1->cq_page_table_addr_hi;
	ictx->cstorm_st_context.iscsi_conn_id = req1->iscsi_conn_id;
	ictx->cstorm_st_context.cq_proc_en_bit_map = (1 << cp->num_cqs) - 1;
	for (i = 0; i < cp->num_cqs; i++) {
		ictx->cstorm_st_context.cq_c_prod_sqn_arr.sqn[i] =
			ISCSI_INITIAL_SN;
		ictx->cstorm_st_context.cq_c_sqn_2_notify_arr.sqn[i] =
			ISCSI_INITIAL_SN;
	}

	ictx->xstorm_ag_context.cdu_reserved =
		CDU_RSRVD_VALUE_TYPE_A(hw_cid, CDU_REGION_NUMBER_XCM_AG,
				       ISCSI_CONNECTION_TYPE);
	ictx->ustorm_ag_context.cdu_usage =
		CDU_RSRVD_VALUE_TYPE_A(hw_cid, CDU_REGION_NUMBER_UCM_AG,
				       ISCSI_CONNECTION_TYPE);
	return 0;

}

static int cnic_bnx2x_iscsi_ofld1(struct cnic_dev *dev, struct kwqe *wqes[],
				   u32 num, int *work)
{
	struct iscsi_kwqe_conn_offload1 *req1;
	struct iscsi_kwqe_conn_offload2 *req2;
	struct cnic_local *cp = dev->cnic_priv;
	struct iscsi_kcqe kcqe;
	struct kcqe *cqes[1];
	u32 l5_cid;
	int ret;

	if (num < 2) {
		*work = num;
		return -EINVAL;
	}

	req1 = (struct iscsi_kwqe_conn_offload1 *) wqes[0];
	req2 = (struct iscsi_kwqe_conn_offload2 *) wqes[1];
	if ((num - 2) < req2->num_additional_wqes) {
		*work = num;
		return -EINVAL;
	}
	*work = 2 + req2->num_additional_wqes;;

	l5_cid = req1->iscsi_conn_id;
	if (l5_cid >= MAX_ISCSI_TBL_SZ)
		return -EINVAL;

	memset(&kcqe, 0, sizeof(kcqe));
	kcqe.op_code = ISCSI_KCQE_OPCODE_OFFLOAD_CONN;
	kcqe.iscsi_conn_id = l5_cid;
	kcqe.completion_status = ISCSI_KCQE_COMPLETION_STATUS_CTX_ALLOC_FAILURE;

	if (atomic_inc_return(&cp->iscsi_conn) > dev->max_iscsi_conn) {
		atomic_dec(&cp->iscsi_conn);
		ret = 0;
		goto done;
	}
	ret = cnic_alloc_bnx2x_conn_resc(dev, l5_cid);
	if (ret) {
		atomic_dec(&cp->iscsi_conn);
		ret = 0;
		goto done;
	}
	ret = cnic_setup_bnx2x_ctx(dev, wqes, num);
	if (ret < 0) {
		cnic_free_bnx2x_conn_resc(dev, l5_cid);
		atomic_dec(&cp->iscsi_conn);
		goto done;
	}

	kcqe.completion_status = ISCSI_KCQE_COMPLETION_STATUS_SUCCESS;
	kcqe.iscsi_conn_context_id = BNX2X_HW_CID(cp->ctx_tbl[l5_cid].cid,
						  cp->func);

done:
	cqes[0] = (struct kcqe *) &kcqe;
	cnic_reply_bnx2x_kcqes(dev, CNIC_ULP_ISCSI, cqes, 1);
	return ret;
}


static int cnic_bnx2x_iscsi_update(struct cnic_dev *dev, struct kwqe *kwqe)
{
	struct cnic_local *cp = dev->cnic_priv;
	struct iscsi_kwqe_conn_update *req =
		(struct iscsi_kwqe_conn_update *) kwqe;
	void *data;
	union l5cm_specific_data l5_data;
	u32 l5_cid, cid = BNX2X_SW_CID(req->context_id);
	int ret;

	if (cnic_get_l5_cid(cp, cid, &l5_cid) != 0)
		return -EINVAL;

	data = cnic_get_kwqe_16_data(cp, l5_cid, &l5_data);
	if (!data)
		return -ENOMEM;

	memcpy(data, kwqe, sizeof(struct kwqe));

	ret = cnic_submit_kwqe_16(dev, ISCSI_RAMROD_CMD_ID_UPDATE_CONN,
			req->context_id, ISCSI_CONNECTION_TYPE, &l5_data);
	return ret;
}

static int cnic_bnx2x_iscsi_destroy(struct cnic_dev *dev, struct kwqe *kwqe)
{
	struct cnic_local *cp = dev->cnic_priv;
	struct iscsi_kwqe_conn_destroy *req =
		(struct iscsi_kwqe_conn_destroy *) kwqe;
	union l5cm_specific_data l5_data;
	u32 l5_cid = req->reserved0;
	struct cnic_context *ctx = &cp->ctx_tbl[l5_cid];
	int ret = 0;
	struct iscsi_kcqe kcqe;
	struct kcqe *cqes[1];

	if (!(ctx->ctx_flags & CTX_FL_OFFLD_START))
		goto skip_cfc_delete;

	while (!time_after(jiffies, ctx->timestamp + (2 * HZ)))
		msleep(250);

	init_waitqueue_head(&ctx->waitq);
	ctx->wait_cond = 0;
	memset(&l5_data, 0, sizeof(l5_data));
	ret = cnic_submit_kwqe_16(dev, RAMROD_CMD_ID_ETH_CFC_DEL,
				  req->context_id,
				  ETH_CONNECTION_TYPE |
				  (1 << SPE_HDR_COMMON_RAMROD_SHIFT),
				  &l5_data);
	if (ret == 0)
		wait_event(ctx->waitq, ctx->wait_cond);

skip_cfc_delete:
	cnic_free_bnx2x_conn_resc(dev, l5_cid);

	atomic_dec(&cp->iscsi_conn);

	memset(&kcqe, 0, sizeof(kcqe));
	kcqe.op_code = ISCSI_KCQE_OPCODE_DESTROY_CONN;
	kcqe.iscsi_conn_id = l5_cid;
	kcqe.completion_status = ISCSI_KCQE_COMPLETION_STATUS_SUCCESS;
	kcqe.iscsi_conn_context_id = req->context_id;

	cqes[0] = (struct kcqe *) &kcqe;
	cnic_reply_bnx2x_kcqes(dev, CNIC_ULP_ISCSI, cqes, 1);

	return ret;
}

static void cnic_init_storm_conn_bufs(struct cnic_dev *dev,
				      struct l4_kwq_connect_req1 *kwqe1,
				      struct l4_kwq_connect_req3 *kwqe3,
				      struct l5cm_active_conn_buffer *conn_buf)
{
	struct l5cm_conn_addr_params *conn_addr = &conn_buf->conn_addr_buf;
	struct l5cm_xstorm_conn_buffer *xstorm_buf =
		&conn_buf->xstorm_conn_buffer;
	struct l5cm_tstorm_conn_buffer *tstorm_buf =
		&conn_buf->tstorm_conn_buffer;
	struct regpair context_addr;
	u32 cid = BNX2X_SW_CID(kwqe1->cid);
	struct in6_addr src_ip, dst_ip;
	int i;
	u32 *addrp;

	addrp = (u32 *) &conn_addr->local_ip_addr;
	for (i = 0; i < 4; i++, addrp++)
		src_ip.in6_u.u6_addr32[i] = cpu_to_be32(*addrp);

	addrp = (u32 *) &conn_addr->remote_ip_addr;
	for (i = 0; i < 4; i++, addrp++)
		dst_ip.in6_u.u6_addr32[i] = cpu_to_be32(*addrp);

	cnic_get_bnx2x_ctx(dev, cid, 0, &context_addr);

	xstorm_buf->context_addr.hi = context_addr.hi;
	xstorm_buf->context_addr.lo = context_addr.lo;
	xstorm_buf->mss = 0xffff;
	xstorm_buf->rcv_buf = kwqe3->rcv_buf;
	if (kwqe1->tcp_flags & L4_KWQ_CONNECT_REQ1_NAGLE_ENABLE)
		xstorm_buf->params |= L5CM_XSTORM_CONN_BUFFER_NAGLE_ENABLE;
	xstorm_buf->pseudo_header_checksum =
		swab16(~csum_ipv6_magic(&src_ip, &dst_ip, 0, IPPROTO_TCP, 0));

	if (!(kwqe1->tcp_flags & L4_KWQ_CONNECT_REQ1_NO_DELAY_ACK))
		tstorm_buf->params |=
			L5CM_TSTORM_CONN_BUFFER_DELAYED_ACK_ENABLE;
	if (kwqe3->ka_timeout) {
		tstorm_buf->ka_enable = 1;
		tstorm_buf->ka_timeout = kwqe3->ka_timeout;
		tstorm_buf->ka_interval = kwqe3->ka_interval;
		tstorm_buf->ka_max_probe_count = kwqe3->ka_max_probe_count;
	}
	tstorm_buf->rcv_buf = kwqe3->rcv_buf;
	tstorm_buf->snd_buf = kwqe3->snd_buf;
	tstorm_buf->max_rt_time = 0xffffffff;
}

static void cnic_init_bnx2x_mac(struct cnic_dev *dev, u8 *mac)
{
	struct cnic_local *cp = dev->cnic_priv;
	int func = CNIC_FUNC(cp);

	CNIC_WR8(dev, BAR_XSTRORM_INTMEM +
		 XSTORM_ISCSI_LOCAL_MAC_ADDR0_OFFSET(func), mac[0]);
	CNIC_WR8(dev, BAR_XSTRORM_INTMEM +
		 XSTORM_ISCSI_LOCAL_MAC_ADDR1_OFFSET(func), mac[1]);
	CNIC_WR8(dev, BAR_XSTRORM_INTMEM +
		 XSTORM_ISCSI_LOCAL_MAC_ADDR2_OFFSET(func), mac[2]);
	CNIC_WR8(dev, BAR_XSTRORM_INTMEM +
		 XSTORM_ISCSI_LOCAL_MAC_ADDR3_OFFSET(func), mac[3]);
	CNIC_WR8(dev, BAR_XSTRORM_INTMEM +
		 XSTORM_ISCSI_LOCAL_MAC_ADDR4_OFFSET(func), mac[4]);
	CNIC_WR8(dev, BAR_XSTRORM_INTMEM +
		 XSTORM_ISCSI_LOCAL_MAC_ADDR5_OFFSET(func), mac[5]);

	CNIC_WR8(dev, BAR_TSTRORM_INTMEM +
		 TSTORM_ISCSI_TCP_VARS_LSB_LOCAL_MAC_ADDR_OFFSET(func), mac[5]);
	CNIC_WR8(dev, BAR_TSTRORM_INTMEM +
		 TSTORM_ISCSI_TCP_VARS_LSB_LOCAL_MAC_ADDR_OFFSET(func) + 1,
		 mac[4]);
	CNIC_WR8(dev, BAR_TSTRORM_INTMEM +
		 TSTORM_ISCSI_TCP_VARS_MSB_LOCAL_MAC_ADDR_OFFSET(func), mac[3]);
	CNIC_WR8(dev, BAR_TSTRORM_INTMEM +
		 TSTORM_ISCSI_TCP_VARS_MSB_LOCAL_MAC_ADDR_OFFSET(func) + 1,
		 mac[2]);
	CNIC_WR8(dev, BAR_TSTRORM_INTMEM +
		 TSTORM_ISCSI_TCP_VARS_MSB_LOCAL_MAC_ADDR_OFFSET(func) + 2,
		 mac[1]);
	CNIC_WR8(dev, BAR_TSTRORM_INTMEM +
		 TSTORM_ISCSI_TCP_VARS_MSB_LOCAL_MAC_ADDR_OFFSET(func) + 3,
		 mac[0]);
}

static void cnic_bnx2x_set_tcp_timestamp(struct cnic_dev *dev, int tcp_ts)
{
	struct cnic_local *cp = dev->cnic_priv;
	u8 xstorm_flags = XSTORM_L5CM_TCP_FLAGS_WND_SCL_EN;
	u16 tstorm_flags = 0;

	if (tcp_ts) {
		xstorm_flags |= XSTORM_L5CM_TCP_FLAGS_TS_ENABLED;
		tstorm_flags |= TSTORM_L5CM_TCP_FLAGS_TS_ENABLED;
	}

	CNIC_WR8(dev, BAR_XSTRORM_INTMEM +
		 XSTORM_ISCSI_TCP_VARS_FLAGS_OFFSET(cp->func), xstorm_flags);

	CNIC_WR16(dev, BAR_TSTRORM_INTMEM +
		  TSTORM_ISCSI_TCP_VARS_FLAGS_OFFSET(cp->func), tstorm_flags);
}

static int cnic_bnx2x_connect(struct cnic_dev *dev, struct kwqe *wqes[],
			      u32 num, int *work)
{
	struct cnic_local *cp = dev->cnic_priv;
	struct l4_kwq_connect_req1 *kwqe1 =
		(struct l4_kwq_connect_req1 *) wqes[0];
	struct l4_kwq_connect_req3 *kwqe3;
	struct l5cm_active_conn_buffer *conn_buf;
	struct l5cm_conn_addr_params *conn_addr;
	union l5cm_specific_data l5_data;
	u32 l5_cid = kwqe1->pg_cid;
	struct cnic_sock *csk = &cp->csk_tbl[l5_cid];
	struct cnic_context *ctx = &cp->ctx_tbl[l5_cid];
#if !defined (__VMKLNX__)
	struct neighbour *neigh = csk->dst->neighbour;
#endif /* !defined (__VMKLNX__) */
	int ret;

	if (num < 2) {
		*work = num;
		return -EINVAL;
	}

	if (kwqe1->conn_flags & L4_KWQ_CONNECT_REQ1_IP_V6)
		*work = 3;
	else
		*work = 2;

	if (num < *work) {
		*work = num;
		return -EINVAL;
	}

	if (sizeof(*conn_buf) > CNIC_KWQ16_DATA_SIZE) {
		printk(KERN_ERR PFX "%s: conn_buf size too big\n",
			       dev->netdev->name);
		return -ENOMEM;
	}
	conn_buf = cnic_get_kwqe_16_data(cp, l5_cid, &l5_data);
	if (!conn_buf)
		return -ENOMEM;

	memset(conn_buf, 0, sizeof(*conn_buf));

	conn_addr = &conn_buf->conn_addr_buf;
#if defined (__VMKLNX__)
	conn_addr->remote_addr_0 = csk->ha[0];
	conn_addr->remote_addr_1 = csk->ha[1];
	conn_addr->remote_addr_2 = csk->ha[2];
	conn_addr->remote_addr_3 = csk->ha[3];
	conn_addr->remote_addr_4 = csk->ha[4];
	conn_addr->remote_addr_5 = csk->ha[5];


	/* Use the stored MAC address */
	cnic_init_bnx2x_mac(dev, cp->srcMACAddr);
#else /* !defined (__VMKLNX__) */
	conn_addr->remote_addr_0 = neigh->ha[0];
	conn_addr->remote_addr_1 = neigh->ha[1];
	conn_addr->remote_addr_2 = neigh->ha[2];
	conn_addr->remote_addr_3 = neigh->ha[3];
	conn_addr->remote_addr_4 = neigh->ha[4];
	conn_addr->remote_addr_5 = neigh->ha[5];
#endif /* defined (__VMKLNX__) */

	if (kwqe1->conn_flags & L4_KWQ_CONNECT_REQ1_IP_V6) {
		struct l4_kwq_connect_req2 *kwqe2 =
			(struct l4_kwq_connect_req2 *) wqes[1];

		conn_addr->local_ip_addr.ip_addr_hi_hi = kwqe2->src_ip_v6_4;
		conn_addr->local_ip_addr.ip_addr_hi_lo = kwqe2->src_ip_v6_3;
		conn_addr->local_ip_addr.ip_addr_lo_hi = kwqe2->src_ip_v6_2;

		conn_addr->remote_ip_addr.ip_addr_hi_hi = kwqe2->dst_ip_v6_4;
		conn_addr->remote_ip_addr.ip_addr_hi_lo = kwqe2->dst_ip_v6_3;
		conn_addr->remote_ip_addr.ip_addr_lo_hi = kwqe2->dst_ip_v6_2;
		conn_addr->params |= L5CM_CONN_ADDR_PARAMS_IP_VERSION;
	}
	kwqe3 = (struct l4_kwq_connect_req3 *) wqes[*work - 1];

	conn_addr->local_ip_addr.ip_addr_lo_lo = kwqe1->src_ip;
	conn_addr->remote_ip_addr.ip_addr_lo_lo = kwqe1->dst_ip;
	conn_addr->local_tcp_port = kwqe1->src_port;
	conn_addr->remote_tcp_port = kwqe1->dst_port;

	conn_addr->pmtu = kwqe3->pmtu;
	cnic_init_storm_conn_bufs(dev, kwqe1, kwqe3, conn_buf);

	CNIC_WR16(dev, BAR_XSTRORM_INTMEM +
		  XSTORM_ISCSI_LOCAL_VLAN_OFFSET(cp->func), csk->vlan_id);

	cnic_bnx2x_set_tcp_timestamp(dev,
		kwqe1->tcp_flags & L4_KWQ_CONNECT_REQ1_TIME_STAMP);

	ret = cnic_submit_kwqe_16(dev, L5CM_RAMROD_CMD_ID_TCP_CONNECT,
			kwqe1->cid, ISCSI_CONNECTION_TYPE, &l5_data);
	if (!ret)
		ctx->ctx_flags |= CTX_FL_OFFLD_START;

	return ret;
}

static int cnic_bnx2x_close(struct cnic_dev *dev, struct kwqe *kwqe)
{
	struct l4_kwq_close_req *req = (struct l4_kwq_close_req *) kwqe;
	union l5cm_specific_data l5_data;
	int ret;

	memset(&l5_data, 0, sizeof(l5_data));
	ret = cnic_submit_kwqe_16(dev, L5CM_RAMROD_CMD_ID_CLOSE,
			req->cid, ISCSI_CONNECTION_TYPE, &l5_data);
	return ret;
}

static int cnic_bnx2x_reset(struct cnic_dev *dev, struct kwqe *kwqe)
{
	struct l4_kwq_reset_req *req = (struct l4_kwq_reset_req *) kwqe;
	union l5cm_specific_data l5_data;
	int ret;

	memset(&l5_data, 0, sizeof(l5_data));
	ret = cnic_submit_kwqe_16(dev, L5CM_RAMROD_CMD_ID_ABORT,
			req->cid, ISCSI_CONNECTION_TYPE, &l5_data);
	return ret;
}
static int cnic_bnx2x_offload_pg(struct cnic_dev *dev, struct kwqe *kwqe)
{
	struct l4_kwq_offload_pg *req = (struct l4_kwq_offload_pg *) kwqe;
	struct l4_kcq kcqe;
	struct kcqe *cqes[1];

	memset(&kcqe, 0, sizeof(kcqe));
	kcqe.pg_host_opaque = req->host_opaque;
	kcqe.pg_cid = req->host_opaque;
	kcqe.op_code = L4_KCQE_OPCODE_VALUE_OFFLOAD_PG;
	cqes[0] = (struct kcqe *) &kcqe;
	cnic_reply_bnx2x_kcqes(dev, CNIC_ULP_L4, cqes, 1);
	return 0;
}

static int cnic_bnx2x_update_pg(struct cnic_dev *dev, struct kwqe *kwqe)
{
	struct l4_kwq_update_pg *req = (struct l4_kwq_update_pg *) kwqe;
	struct l4_kcq kcqe;
	struct kcqe *cqes[1];

	memset(&kcqe, 0, sizeof(kcqe));
	kcqe.pg_host_opaque = req->pg_host_opaque;
	kcqe.pg_cid = req->pg_cid;
	kcqe.op_code = L4_KCQE_OPCODE_VALUE_UPDATE_PG;
	cqes[0] = (struct kcqe *) &kcqe;
	cnic_reply_bnx2x_kcqes(dev, CNIC_ULP_L4, cqes, 1);
	return 0;
}

static int cnic_submit_bnx2x_kwqes(struct cnic_dev *dev, struct kwqe *wqes[],
				   u32 num_wqes)
{
	int i, work, ret;
	u32 opcode;
	struct kwqe *kwqe;

	if (!test_bit(CNIC_F_CNIC_UP, &dev->flags))
		return -EAGAIN;		/* bnx2 is down */

	for (i = 0; i < num_wqes; ) {
		kwqe = wqes[i];
		opcode = KWQE_OPCODE(kwqe->kwqe_op_flag);
		work = 1;

		switch (opcode) {
		case ISCSI_KWQE_OPCODE_INIT1:
			ret = cnic_bnx2x_iscsi_init1(dev, kwqe);
			break;
		case ISCSI_KWQE_OPCODE_INIT2:
			ret = cnic_bnx2x_iscsi_init2(dev, kwqe);
			break;
		case ISCSI_KWQE_OPCODE_OFFLOAD_CONN1:
			ret = cnic_bnx2x_iscsi_ofld1(dev, &wqes[i],
						     num_wqes - i, &work);
			break;
		case ISCSI_KWQE_OPCODE_UPDATE_CONN:
			ret = cnic_bnx2x_iscsi_update(dev, kwqe);
			break;
		case ISCSI_KWQE_OPCODE_DESTROY_CONN:
			ret = cnic_bnx2x_iscsi_destroy(dev, kwqe);
			break;
		case L4_KWQE_OPCODE_VALUE_CONNECT1:
			ret = cnic_bnx2x_connect(dev, &wqes[i], num_wqes - i,
						 &work);
			break;
		case L4_KWQE_OPCODE_VALUE_CLOSE:
			ret = cnic_bnx2x_close(dev, kwqe);
			break;
		case L4_KWQE_OPCODE_VALUE_RESET:
			ret = cnic_bnx2x_reset(dev, kwqe);
			break;
		case L4_KWQE_OPCODE_VALUE_OFFLOAD_PG:
			ret = cnic_bnx2x_offload_pg(dev, kwqe);
			break;
		case L4_KWQE_OPCODE_VALUE_UPDATE_PG:
			ret = cnic_bnx2x_update_pg(dev, kwqe);
			break;
		case L4_KWQE_OPCODE_VALUE_UPLOAD_PG:
			ret = 0;
			break;
		default:
			ret = 0;
			printk(KERN_ERR PFX "%s: Unknown type of KWQE(0x%x)\n",
			       dev->netdev->name, opcode);
			break;
		}
		if (ret < 0)
			printk(KERN_ERR PFX "%s: KWQE(0x%x) failed\n",
			       dev->netdev->name, opcode);
		i += work;
	}
	return 0;
}

static void service_kcqes(struct cnic_dev *dev, int num_cqes)
{
	struct cnic_local *cp = dev->cnic_priv;
	int i, j;

	i = 0;
	j = 1;
	while (num_cqes) {
		struct cnic_ulp_ops *ulp_ops;
		int ulp_type;
		u32 kcqe_op_flag = cp->completed_kcq[i]->kcqe_op_flag;
		u32 kcqe_layer = kcqe_op_flag & KCQE_FLAGS_LAYER_MASK;

		if (unlikely(kcqe_op_flag & KCQE_RAMROD_COMPLETION))
			cnic_kwq_completion(dev, 1);

		while (j < num_cqes) {
			u32 next_op = cp->completed_kcq[i + j]->kcqe_op_flag;

			if ((next_op & KCQE_FLAGS_LAYER_MASK) != kcqe_layer)
				break;

			if (unlikely(next_op & KCQE_RAMROD_COMPLETION))
				cnic_kwq_completion(dev, 1);
			j++;
		}

		if (kcqe_layer == KCQE_FLAGS_LAYER_MASK_L5_RDMA)
			ulp_type = CNIC_ULP_RDMA;
		else if (kcqe_layer == KCQE_FLAGS_LAYER_MASK_L5_ISCSI)
			ulp_type = CNIC_ULP_ISCSI;
		else if (kcqe_layer == KCQE_FLAGS_LAYER_MASK_L4)
			ulp_type = CNIC_ULP_L4;
		else {
			printk(KERN_ERR PFX "%s: Unknown type of KCQE(0x%x)\n",
			       dev->netdev->name, kcqe_op_flag);
			goto end;
		}

		rcu_read_lock();
		ulp_ops = rcu_dereference(cp->ulp_ops[ulp_type]);
		if (likely(ulp_ops)) {
			ulp_ops->indicate_kcqes(cp->ulp_handle[ulp_type],
						  cp->completed_kcq + i, j);
		}
		rcu_read_unlock();
end:
		num_cqes -= j;
		i += j;
		j = 1;
	}
	return;
}

static u16 cnic_bnx2_next_idx(u16 idx)
{
	return (idx + 1);
}

static u16 cnic_bnx2_hw_idx(u16 idx)
{
	return idx;
}

static u16 cnic_bnx2x_next_idx(u16 idx)
{
	idx++;
	if ((idx & MAX_KCQE_CNT) == MAX_KCQE_CNT)
		idx++;

	return idx;
}

static u16 cnic_bnx2x_hw_idx(u16 idx)
{
	if ((idx & MAX_KCQE_CNT) == MAX_KCQE_CNT)
		idx++;
	return idx;
}

static int cnic_get_kcqes(struct cnic_dev *dev, u16 hw_prod, u16 *sw_prod)
{
	struct cnic_local *cp = dev->cnic_priv;
	u16 i, ri, last;
	struct kcqe *kcqe;
	int kcqe_cnt = 0, last_cnt = 0;

	i = ri = last = *sw_prod;
	ri &= MAX_KCQ_IDX;

	while ((i != hw_prod) && (kcqe_cnt < MAX_COMPLETED_KCQE)) {
		kcqe = &cp->kcq[KCQ_PG(ri)][KCQ_IDX(ri)];
		cp->completed_kcq[kcqe_cnt++] = kcqe;
		i = cp->next_idx(i);
		ri = i & MAX_KCQ_IDX;
		if (likely(!(kcqe->kcqe_op_flag & KCQE_FLAGS_NEXT))) {
			last_cnt = kcqe_cnt;
			last = i;
		}
	}

	*sw_prod = last;
	return last_cnt;
}

static int cnic_service_bnx2(void *data, void *status_blk)
{
	struct cnic_dev *dev = data;
	struct status_block *sblk = status_blk;
	struct cnic_local *cp = dev->cnic_priv;
	u32 status_idx = sblk->status_idx;
	u16 hw_prod, sw_prod;
	int kcqe_cnt;

	if (unlikely(!test_bit(CNIC_F_CNIC_UP, &dev->flags)))
		return status_idx;

	cp->kwq_con_idx = *cp->kwq_con_idx_ptr;

	hw_prod = sblk->status_completion_producer_index;
	sw_prod = cp->kcq_prod_idx;
	while (sw_prod != hw_prod) {
		kcqe_cnt = cnic_get_kcqes(dev, hw_prod, &sw_prod);
		if (kcqe_cnt == 0)
			goto done;

		service_kcqes(dev, kcqe_cnt);

		/* Tell compiler that status_blk fields can change. */
		barrier();
		if (status_idx != sblk->status_idx) {
			status_idx = sblk->status_idx;
			cp->kwq_con_idx = *cp->kwq_con_idx_ptr;
			hw_prod = sblk->status_completion_producer_index;
		} else
			break;
	}

done:
	CNIC_WR16(dev, cp->kcq_io_addr, sw_prod);

	cp->kcq_prod_idx = sw_prod;
	return status_idx;
}

static void cnic_service_bnx2_msix(unsigned long data)
{
	struct cnic_dev *dev = (struct cnic_dev *) data;
	struct cnic_local *cp = dev->cnic_priv;
	struct status_block_msix *status_blk = cp->bnx2_status_blk;
	u32 status_idx = status_blk->status_idx;
	u16 hw_prod, sw_prod;
	int kcqe_cnt;

	cp->kwq_con_idx = status_blk->status_cmd_consumer_index;

	hw_prod = status_blk->status_completion_producer_index;
	sw_prod = cp->kcq_prod_idx;
	while (sw_prod != hw_prod) {
		kcqe_cnt = cnic_get_kcqes(dev, hw_prod, &sw_prod);
		if (kcqe_cnt == 0)
			goto done;

		service_kcqes(dev, kcqe_cnt);

		/* Tell compiler that status_blk fields can change. */
		barrier();
		if (status_idx != status_blk->status_idx) {
			status_idx = status_blk->status_idx;
			cp->kwq_con_idx = status_blk->status_cmd_consumer_index;
			hw_prod = status_blk->status_completion_producer_index;
		} else
			break;
	}

done:
	CNIC_WR16(dev, cp->kcq_io_addr, sw_prod);

	cp->kcq_prod_idx = sw_prod;
	cp->last_status_idx = status_idx;
	CNIC_WR(dev, BNX2_PCICFG_INT_ACK_CMD, cp->int_num |
		BNX2_PCICFG_INT_ACK_CMD_INDEX_VALID | cp->last_status_idx);
}

#if (LINUX_VERSION_CODE >= 0x20613)
static irqreturn_t cnic_irq(int irq, void *dev_instance)
#else
static irqreturn_t cnic_irq(int irq, void *dev_instance, struct pt_regs *regs)
#endif
{
	struct cnic_dev *dev = dev_instance;
	struct cnic_local *cp = dev->cnic_priv;
	u16 prod = cp->kcq_prod_idx & MAX_KCQ_IDX;

	if (cp->ack_int)
		cp->ack_int(dev);

	prefetch(cp->status_blk);
	prefetch(&cp->kcq[KCQ_PG(prod)][KCQ_IDX(prod)]);

	if (likely(test_bit(CNIC_F_CNIC_UP, &dev->flags)))
		tasklet_schedule(&cp->cnic_irq_task);

	return IRQ_HANDLED;
}

static inline void cnic_ack_bnx2x_int(struct cnic_dev *dev, u8 id, u8 storm,
				      u16 index, u8 op, u8 update)
{
	struct cnic_local *cp = dev->cnic_priv;
	u32 hc_addr = (HC_REG_COMMAND_REG + CNIC_PORT(cp) * 32 +
		       COMMAND_REG_INT_ACK);
	struct igu_ack_register igu_ack;

	igu_ack.status_block_index = index;
	igu_ack.sb_id_and_flags =
			((id << IGU_ACK_REGISTER_STATUS_BLOCK_ID_SHIFT) |
			 (storm << IGU_ACK_REGISTER_STORM_ID_SHIFT) |
			 (update << IGU_ACK_REGISTER_UPDATE_INDEX_SHIFT) |
			 (op << IGU_ACK_REGISTER_INTERRUPT_MODE_SHIFT));

	CNIC_WR(dev, hc_addr, (*(u32 *)&igu_ack));
}

static void cnic_ack_bnx2x_msix(struct cnic_dev *dev)
{
	struct cnic_local *cp = dev->cnic_priv;

	cnic_ack_bnx2x_int(dev, cp->status_blk_num, CSTORM_ID, 0,
			   IGU_INT_DISABLE, 0);
}

static void cnic_service_bnx2x_bh(unsigned long data)
{
	struct cnic_dev *dev = (struct cnic_dev *) data;
	struct cnic_local *cp = dev->cnic_priv;
	u16 hw_prod, sw_prod;
#ifdef NEW_BNX2X_HSI
	struct cstorm_status_block_c *sblk =
		&cp->bnx2x_status_blk->c_status_block;
#else
	struct cstorm_status_block *sblk =
		&cp->bnx2x_status_blk->c_status_block;
#endif
	u32 status_idx = sblk->status_block_index;
	int kcqe_cnt;

	if (unlikely(!test_bit(CNIC_F_CNIC_UP, &dev->flags)))
		return;

	hw_prod = sblk->index_values[HC_INDEX_C_ISCSI_EQ_CONS];
	hw_prod = cp->hw_idx(hw_prod);
	sw_prod = cp->kcq_prod_idx;
	while (sw_prod != hw_prod) {
		u32 kcq_diff;
		if(hw_prod < sw_prod)
			kcq_diff = (65536 + hw_prod) - sw_prod;
		else
			kcq_diff = hw_prod - sw_prod;

		if (kcq_diff > MAX_KCQ_IDX)
			printk(KERN_WARNING PFX
				"%s: kcq abs(hw_prod(%d) - sw_prod(%d))"
				" > MAX_KCQ_IDX(%lu)\n",
				dev->netdev->name,
				hw_prod, sw_prod, MAX_KCQ_IDX);

		kcqe_cnt = cnic_get_kcqes(dev, hw_prod, &sw_prod);
		if (kcqe_cnt == 0)
			goto done;

		CNIC_WR16(dev, cp->kcq_io_addr, sw_prod + MAX_KCQ_IDX);
		service_kcqes(dev, kcqe_cnt);

		/* Tell compiler that sblk fields can change. */
		barrier();
		if (status_idx == sblk->status_block_index)
			break;

		status_idx = sblk->status_block_index;
		hw_prod = sblk->index_values[HC_INDEX_C_ISCSI_EQ_CONS];
		hw_prod = cp->hw_idx(hw_prod);
	}

done:
	cnic_ack_bnx2x_int(dev, cp->status_blk_num, CSTORM_ID,
			   status_idx, IGU_INT_ENABLE, 1);

	cp->kcq_prod_idx = sw_prod;
	return;
}

static int cnic_service_bnx2x(void *data, void *status_blk)
{
	struct cnic_dev *dev = data;
	struct cnic_local *cp = dev->cnic_priv;
	u16 prod = cp->kcq_prod_idx & MAX_KCQ_IDX;

	if (likely(test_bit(CNIC_F_CNIC_UP, &dev->flags))) {
		prefetch(cp->status_blk);
		prefetch(&cp->kcq[KCQ_PG(prod)][KCQ_IDX(prod)]);

		tasklet_schedule(&cp->cnic_irq_task);
	}
	return 0;
}

static void cnic_ulp_stop(struct cnic_dev *dev)
{
	struct cnic_local *cp = dev->cnic_priv;
	int if_type;

	for (if_type = 0; if_type < MAX_CNIC_ULP_TYPE; if_type++) {
		struct cnic_ulp_ops *ulp_ops;

		mutex_lock(&cnic_lock);
		ulp_ops = cp->ulp_ops[if_type];
		if (!ulp_ops) {
			mutex_unlock(&cnic_lock);
			continue;
		}
		set_bit(ULP_F_CALL_PENDING, &cp->ulp_flags[if_type]);
		mutex_unlock(&cnic_lock);

		if (test_and_clear_bit(ULP_F_START, &cp->ulp_flags[if_type]))
			ulp_ops->cnic_stop(cp->ulp_handle[if_type]);

		clear_bit(ULP_F_CALL_PENDING, &cp->ulp_flags[if_type]);
	}
}

static void cnic_ulp_start(struct cnic_dev *dev)
{
	struct cnic_local *cp = dev->cnic_priv;
	int if_type;

	for (if_type = 0; if_type < MAX_CNIC_ULP_TYPE; if_type++) {
		struct cnic_ulp_ops *ulp_ops;

		mutex_lock(&cnic_lock);
		ulp_ops = cp->ulp_ops[if_type];
		if (!ulp_ops || !ulp_ops->cnic_start) {
			mutex_unlock(&cnic_lock);
			continue;
		}
		set_bit(ULP_F_CALL_PENDING, &cp->ulp_flags[if_type]);
		mutex_unlock(&cnic_lock);

		if (!test_and_set_bit(ULP_F_START, &cp->ulp_flags[if_type]))
			ulp_ops->cnic_start(cp->ulp_handle[if_type]);

		clear_bit(ULP_F_CALL_PENDING, &cp->ulp_flags[if_type]);
	}
}

static int cnic_ctl(void *data, struct cnic_ctl_info *info)
{
	struct cnic_dev *dev = data;
#if defined (__VMKLNX__)
	int i;
#endif /* defined (__VMKLNX__) */

	switch (info->cmd) {
	case CNIC_CTL_STOP_CMD:
		cnic_hold(dev);

		if (test_bit(CNIC_F_IF_UP, &dev->flags)) {
			clear_bit(CNIC_F_IF_UP, &dev->flags);
			cnic_ulp_stop(dev);
#if !defined (__VMKLNX__)
			cnic_stop_hw(dev);
#endif /* !defined (__VMKLNX__) */
		}

#if defined (__VMKLNX__)
		i = 0;
		while ((atomic_read(&dev->ref_count) > 1) && i < 100) {
			msleep(100);
			i++;
		}
		if (atomic_read(&dev->ref_count) > 1)
			printk(KERN_ERR PFX "%s: cnic device did not unregister"
				    " during stop event.\n", dev->netdev->name);
#endif  /* defined (__VMKLNX__) */
		cnic_put(dev);
		break;
	case CNIC_CTL_START_CMD:
		cnic_hold(dev);

		set_bit(CNIC_F_IF_UP, &dev->flags);
		if (dev->use_count) {
			if (!cnic_start_hw(dev))
				cnic_ulp_start(dev);
		}
		cnic_put(dev);
		break;
	case CNIC_CTL_COMPLETION_CMD: {
		u32 cid = BNX2X_SW_CID(info->data.comp.cid);
		u32 l5_cid;
		struct cnic_local *cp = dev->cnic_priv;
		
		if (cnic_get_l5_cid(cp, cid, &l5_cid) == 0) {
			struct cnic_context *ctx = &cp->ctx_tbl[l5_cid];

			ctx->wait_cond = 1;
			wake_up(&ctx->waitq);
		}
		break;
	}
	default:
		return -EINVAL;
	}
	return 0;
}

static void cnic_ulp_init(struct cnic_dev *dev)
{
	int i;
	struct cnic_local *cp = dev->cnic_priv;

	for (i = 0; i < MAX_CNIC_ULP_TYPE_EXT; i++) {
		struct cnic_ulp_ops *ulp_ops;

		mutex_lock(&cnic_lock);
		ulp_ops = cnic_ulp_tbl[i];
		if (!ulp_ops || !ulp_ops->cnic_init) {
			mutex_unlock(&cnic_lock);
			continue;
		}
		ulp_get(ulp_ops);
		mutex_unlock(&cnic_lock);

		if (!test_and_set_bit(ULP_F_INIT, &cp->ulp_flags[i]))
			ulp_ops->cnic_init(dev);

		ulp_put(ulp_ops);
	}
}

static void cnic_ulp_exit(struct cnic_dev *dev)
{
	int i;
	struct cnic_local *cp = dev->cnic_priv;

	for (i = 0; i < MAX_CNIC_ULP_TYPE_EXT; i++) {
		struct cnic_ulp_ops *ulp_ops;

		mutex_lock(&cnic_lock);
		ulp_ops = cnic_ulp_tbl[i];
		if (!ulp_ops || !ulp_ops->cnic_exit) {
			mutex_unlock(&cnic_lock);
			continue;
		}
		ulp_get(ulp_ops);
		mutex_unlock(&cnic_lock);

		if (test_and_clear_bit(ULP_F_INIT, &cp->ulp_flags[i]))
			ulp_ops->cnic_exit(dev);

		ulp_put(ulp_ops);
	}
}

static int cnic_queue_work(struct cnic_local *cp, u32 work_type, void *data)
{
	struct cnic_work_node *node;
	int bytes = sizeof(u32 *);

	spin_lock_bh(&cp->wr_lock);

	node = &cp->cnic_work_ring[cp->cnic_wr_prod];
	node->work_type = work_type;
	if (work_type == WORK_TYPE_KCQE)
		bytes = sizeof(struct kcqe);
	if (work_type == WORK_TYPE_REDIRECT)
		bytes = sizeof(struct cnic_redirect_entry);
	memcpy(&node->work_data, data, bytes);
	cp->cnic_wr_prod++;
	cp->cnic_wr_prod &= WORK_RING_SIZE_MASK;

	spin_unlock_bh(&cp->wr_lock);
	return 0;
}

static int cnic_cm_offload_pg(struct cnic_sock *csk)
{
	struct cnic_dev *dev = csk->dev;
	struct l4_kwq_offload_pg *l4kwqe;
	struct kwqe *wqes[1];
#if defined (__VMKLNX__)
	struct cnic_local *cp = dev->cnic_priv;
#else  /* !defined (__VMKLNX__) */
	struct neighbour *neigh = csk->dst->neighbour;
	struct net_device *netdev = neigh->dev;
#endif /* defined (__VMKLNX__) */

#ifndef HAVE_NETEVENT
#if !defined (__VMKLNX__)
	memcpy(csk->old_ha, &neigh->ha[0], 6);
#endif /* !defined (__VMKLNX__) */
#endif
	l4kwqe = (struct l4_kwq_offload_pg *) &csk->kwqe1;
	memset(l4kwqe, 0, sizeof(*l4kwqe));
	wqes[0] = (struct kwqe *) l4kwqe;

	l4kwqe->op_code = L4_KWQE_OPCODE_VALUE_OFFLOAD_PG;
	l4kwqe->flags =
		L4_LAYER_CODE << L4_KWQ_OFFLOAD_PG_LAYER_CODE_SHIFT;
	l4kwqe->l2hdr_nbytes = ETH_HLEN;
#if defined (__VMKLNX__)
	l4kwqe->da0 = csk->ha[0];
	l4kwqe->da1 = csk->ha[1];
	l4kwqe->da2 = csk->ha[2];
	l4kwqe->da3 = csk->ha[3];
	l4kwqe->da4 = csk->ha[4];
	l4kwqe->da5 = csk->ha[5];

	l4kwqe->sa0 = cp->srcMACAddr[0];
	l4kwqe->sa1 = cp->srcMACAddr[1];
	l4kwqe->sa2 = cp->srcMACAddr[2];
	l4kwqe->sa3 = cp->srcMACAddr[3];
	l4kwqe->sa4 = cp->srcMACAddr[4];
	l4kwqe->sa5 = cp->srcMACAddr[5];
#else  /* !defined (__VMKLNX__) */
	l4kwqe->da0 = neigh->ha[0];
	l4kwqe->da1 = neigh->ha[1];
	l4kwqe->da2 = neigh->ha[2];
	l4kwqe->da3 = neigh->ha[3];
	l4kwqe->da4 = neigh->ha[4];
	l4kwqe->da5 = neigh->ha[5];

	l4kwqe->sa0 = netdev->dev_addr[0];
	l4kwqe->sa1 = netdev->dev_addr[1];
	l4kwqe->sa2 = netdev->dev_addr[2];
	l4kwqe->sa3 = netdev->dev_addr[3];
	l4kwqe->sa4 = netdev->dev_addr[4];
	l4kwqe->sa5 = netdev->dev_addr[5];
#endif /* defined (__VMKLNX__) */

	l4kwqe->etype = ETH_P_IP;
        
        /* All offloaded connections shall show an ipid of 0x8000+ */
        l4kwqe->ipid_start = 0x8000;
        l4kwqe->ipid_count = 0;
	l4kwqe->host_opaque = csk->l5_cid;

	if (csk->vlan_id) {
		l4kwqe->pg_flags |= L4_KWQ_OFFLOAD_PG_VLAN_TAGGING;
		l4kwqe->vlan_tag = csk->vlan_id;
		l4kwqe->l2hdr_nbytes += 4;
	}

	return (dev->submit_kwqes(dev, wqes, 1));
}

#if !defined (__VMKLNX__)
static int cnic_cm_update_pg(struct cnic_sock *csk)
{
	struct cnic_dev *dev = csk->dev;
	struct l4_kwq_update_pg *l4kwqe;
	struct kwqe *wqes[1];
	struct neighbour *neigh = csk->dst->neighbour;

#ifndef HAVE_NETEVENT
	memcpy(csk->old_ha, &neigh->ha[0], 6);
#endif
	l4kwqe = (struct l4_kwq_update_pg *) &csk->kwqe1;
	memset(l4kwqe, 0, sizeof(*l4kwqe));
	wqes[0] = (struct kwqe *) l4kwqe;

	l4kwqe->opcode = L4_KWQE_OPCODE_VALUE_UPDATE_PG;
	l4kwqe->flags =
		L4_LAYER_CODE << L4_KWQ_UPDATE_PG_LAYER_CODE_SHIFT;
	l4kwqe->pg_cid = csk->pg_cid;
	l4kwqe->da0 = neigh->ha[0];
	l4kwqe->da1 = neigh->ha[1];
	l4kwqe->da2 = neigh->ha[2];
	l4kwqe->da3 = neigh->ha[3];
	l4kwqe->da4 = neigh->ha[4];
	l4kwqe->da5 = neigh->ha[5];

	l4kwqe->pg_host_opaque = csk->l5_cid;
	l4kwqe->pg_valids = L4_KWQ_UPDATE_PG_VALIDS_DA;

	return (dev->submit_kwqes(dev, wqes, 1));
}
#endif /* !defined (__VMKLNX__) */

static int cnic_cm_upload_pg(struct cnic_sock *csk)
{
	struct cnic_dev *dev = csk->dev;
	struct l4_kwq_upload *l4kwqe;
	struct kwqe *wqes[1];

	l4kwqe = (struct l4_kwq_upload *) &csk->kwqe1;
	memset(l4kwqe, 0, sizeof(*l4kwqe));
	wqes[0] = (struct kwqe *) l4kwqe;

	l4kwqe->opcode = L4_KWQE_OPCODE_VALUE_UPLOAD_PG;
	l4kwqe->flags =
		L4_LAYER_CODE << L4_KWQ_UPLOAD_LAYER_CODE_SHIFT;
	l4kwqe->cid = csk->pg_cid;

	return (dev->submit_kwqes(dev, wqes, 1));
}

#ifdef HAVE_NETEVENT
static void cnic_redirect(struct cnic_local *cp, struct dst_entry *new,
			  struct dst_entry *old)
{
	int i, found = 0;

	for (i = 0; i < MAX_CM_SK_TBL_SZ && !found; i++) {
		struct cnic_sock *csk;
		struct cnic_redirect_entry cnic_redir;

		csk = &cp->csk_tbl[i];
		csk_hold(csk);
		if (cnic_in_use(csk) && csk->dst == old) {
			found = 1;
			dst_hold(new);
			dst_hold(old);

			cnic_redir.old_dst = old;
			cnic_redir.new_dst = new;
			cnic_queue_work(cp, WORK_TYPE_REDIRECT, &cnic_redir);
			tasklet_schedule(&cp->cnic_task);
		}
		csk_put(csk);
	}
}

static void cnic_update_neigh(struct cnic_local *cp, struct neighbour *neigh)
{
	int i, found = 0;

	for (i = 0; i < MAX_CM_SK_TBL_SZ && !found; i++) {
		struct cnic_sock *csk;

		csk = &cp->csk_tbl[i];
		csk_hold(csk);
		if (cnic_in_use(csk) && csk->dst) {
			if (csk->dst->neighbour == neigh) {
				found = 1;
				neigh_hold(neigh);

				cnic_queue_work(cp, WORK_TYPE_NEIGH_UPDATE,
						&neigh);
				tasklet_schedule(&cp->cnic_task);
			}
		}
		csk_put(csk);
	}
}

static int cnic_net_callback(struct notifier_block *this, unsigned long event,
	void *ptr)
{
	struct cnic_local *cp = container_of(this, struct cnic_local, cm_nb);

	if (event == NETEVENT_NEIGH_UPDATE) {
		struct neighbour *neigh = ptr;

		cnic_update_neigh(cp, neigh);

	} else if (event == NETEVENT_REDIRECT) {
		struct netevent_redirect *netevent = ptr;
		struct dst_entry *old_dst = netevent->old;
		struct dst_entry *new_dst = netevent->new;

		cnic_redirect(cp, new_dst, old_dst);
	}
	return 0;
}
#endif

static int cnic_cm_conn_req(struct cnic_sock *csk)
{
	struct cnic_dev *dev = csk->dev;
	struct l4_kwq_connect_req1 *l4kwqe1;
	struct l4_kwq_connect_req2 *l4kwqe2;
	struct l4_kwq_connect_req3 *l4kwqe3;
	struct kwqe *wqes[3];
	u8 tcp_flags = 0;
	int num_wqes = 2;

	l4kwqe1 = (struct l4_kwq_connect_req1 *) &csk->kwqe1;
	l4kwqe2 = (struct l4_kwq_connect_req2 *) &csk->kwqe2;
	l4kwqe3 = (struct l4_kwq_connect_req3 *) &csk->kwqe3;
	memset(l4kwqe1, 0, sizeof(*l4kwqe1));
	memset(l4kwqe2, 0, sizeof(*l4kwqe2));
	memset(l4kwqe3, 0, sizeof(*l4kwqe3));

	l4kwqe3->op_code = L4_KWQE_OPCODE_VALUE_CONNECT3;
	l4kwqe3->flags =
		L4_LAYER_CODE << L4_KWQ_CONNECT_REQ3_LAYER_CODE_SHIFT;
	l4kwqe3->ka_timeout = csk->ka_timeout;
	l4kwqe3->ka_interval = csk->ka_interval;
	l4kwqe3->ka_max_probe_count = csk->ka_max_probe_count;
	l4kwqe3->tos = csk->tos;
	l4kwqe3->ttl = csk->ttl;
	l4kwqe3->snd_seq_scale = csk->snd_seq_scale;
	l4kwqe3->pmtu = csk->pmtu;
	l4kwqe3->rcv_buf = csk->rcv_buf;
	l4kwqe3->snd_buf = csk->snd_buf;
	l4kwqe3->seed = csk->seed;

	wqes[0] = (struct kwqe *) l4kwqe1;
	if (test_bit(SK_F_IPV6, &csk->flags)) {
		wqes[1] = (struct kwqe *) l4kwqe2;
		wqes[2] = (struct kwqe *) l4kwqe3;
		num_wqes = 3;

		l4kwqe1->conn_flags = L4_KWQ_CONNECT_REQ1_IP_V6;
		l4kwqe2->op_code = L4_KWQE_OPCODE_VALUE_CONNECT2;
		l4kwqe2->flags =
			L4_KWQ_CONNECT_REQ2_LINKED_WITH_NEXT |
			L4_LAYER_CODE << L4_KWQ_CONNECT_REQ2_LAYER_CODE_SHIFT;
		l4kwqe2->src_ip_v6_2 = be32_to_cpu(csk->src_ip[1]);
		l4kwqe2->src_ip_v6_3 = be32_to_cpu(csk->src_ip[2]);
		l4kwqe2->src_ip_v6_4 = be32_to_cpu(csk->src_ip[3]);
		l4kwqe2->dst_ip_v6_2 = be32_to_cpu(csk->dst_ip[1]);
		l4kwqe2->dst_ip_v6_3 = be32_to_cpu(csk->dst_ip[2]);
		l4kwqe2->dst_ip_v6_4 = be32_to_cpu(csk->dst_ip[3]);
		l4kwqe3->mss = l4kwqe3->pmtu - sizeof(struct ipv6hdr) -
			       sizeof(struct tcphdr);
	} else {
		wqes[1] = (struct kwqe *) l4kwqe3;
		l4kwqe3->mss = l4kwqe3->pmtu - sizeof(struct iphdr) -
			       sizeof(struct tcphdr);
	}

	l4kwqe1->op_code = L4_KWQE_OPCODE_VALUE_CONNECT1;
	l4kwqe1->flags =
		(L4_LAYER_CODE << L4_KWQ_CONNECT_REQ1_LAYER_CODE_SHIFT) |
		 L4_KWQ_CONNECT_REQ3_LINKED_WITH_NEXT;
	l4kwqe1->cid = csk->cid;
	l4kwqe1->pg_cid = csk->pg_cid;
	l4kwqe1->src_ip = be32_to_cpu(csk->src_ip[0]);
	l4kwqe1->dst_ip = be32_to_cpu(csk->dst_ip[0]);
	l4kwqe1->src_port = be16_to_cpu(csk->src_port);
	l4kwqe1->dst_port = be16_to_cpu(csk->dst_port);
	if (csk->tcp_flags & SK_TCP_NO_DELAY_ACK)
		tcp_flags |= L4_KWQ_CONNECT_REQ1_NO_DELAY_ACK;
	if (csk->tcp_flags & SK_TCP_KEEP_ALIVE)
		tcp_flags |= L4_KWQ_CONNECT_REQ1_KEEP_ALIVE;
	if (csk->tcp_flags & SK_TCP_NAGLE)
		tcp_flags |= L4_KWQ_CONNECT_REQ1_NAGLE_ENABLE;
	if (csk->tcp_flags & SK_TCP_TIMESTAMP)
		tcp_flags |= L4_KWQ_CONNECT_REQ1_TIME_STAMP;
	if (csk->tcp_flags & SK_TCP_SACK)
		tcp_flags |= L4_KWQ_CONNECT_REQ1_SACK;
	if (csk->tcp_flags & SK_TCP_SEG_SCALING)
		tcp_flags |= L4_KWQ_CONNECT_REQ1_SEG_SCALING;
	
	l4kwqe1->tcp_flags = tcp_flags;

	return (dev->submit_kwqes(dev, wqes, num_wqes));
}

static int cnic_cm_close_req(struct cnic_sock *csk)
{
	struct cnic_dev *dev = csk->dev;
	struct l4_kwq_close_req *l4kwqe;
	struct kwqe *wqes[1];

	l4kwqe = (struct l4_kwq_close_req *) &csk->kwqe2;
	memset(l4kwqe, 0, sizeof(*l4kwqe));
	wqes[0] = (struct kwqe *) l4kwqe;

	l4kwqe->op_code = L4_KWQE_OPCODE_VALUE_CLOSE;
	l4kwqe->flags = L4_LAYER_CODE << L4_KWQ_CLOSE_REQ_LAYER_CODE_SHIFT;
	l4kwqe->cid = csk->cid;

	return (dev->submit_kwqes(dev, wqes, 1));
}

static int cnic_cm_abort_req(struct cnic_sock *csk)
{
	struct cnic_dev *dev = csk->dev;
	struct l4_kwq_reset_req *l4kwqe;
	struct kwqe *wqes[1];

	l4kwqe = (struct l4_kwq_reset_req *) &csk->kwqe2;
	memset(l4kwqe, 0, sizeof(*l4kwqe));
	wqes[0] = (struct kwqe *) l4kwqe;

	l4kwqe->op_code = L4_KWQE_OPCODE_VALUE_RESET;
	l4kwqe->flags = L4_LAYER_CODE << L4_KWQ_RESET_REQ_LAYER_CODE_SHIFT;
	l4kwqe->cid = csk->cid;

	return (dev->submit_kwqes(dev, wqes, 1));
}

static int cnic_cm_create(struct cnic_dev *dev, int ulp_type, u32 cid,
			  u32 l5_cid, struct cnic_sock **csk, void *context)
{
	struct cnic_local *cp = dev->cnic_priv;
	struct cnic_sock *csk1;

	if (l5_cid >= MAX_CM_SK_TBL_SZ)
		return -EINVAL;
		
	csk1 = &cp->csk_tbl[l5_cid];
	if (atomic_read(&csk1->ref_count))
		return -EAGAIN;

	if (test_and_set_bit(SK_F_INUSE, &csk1->flags))
		return -EBUSY;

	csk1->dev = dev;
	csk1->cid = cid;
	csk1->l5_cid = l5_cid;
	csk1->ulp_type = ulp_type;
	csk1->context = context;

	csk1->ka_timeout = DEF_KA_TIMEOUT;
	csk1->ka_interval = DEF_KA_INTERVAL;
	csk1->ka_max_probe_count = DEF_KA_MAX_PROBE_COUNT;
	csk1->tos = DEF_TOS;
	csk1->ttl = DEF_TTL;
	csk1->snd_seq_scale = DEF_SND_SEQ_SCALE;
	csk1->rcv_buf = DEF_RCV_BUF;
	csk1->snd_buf = DEF_SND_BUF;
	csk1->seed = DEF_SEED;

	*csk = csk1;

	return 0;
}

static void cnic_cm_cleanup(struct cnic_sock *csk)
{
#if !defined (__VMKLNX__)
	if (csk->dst) {
		if (csk->dst->neighbour)
			neigh_release(csk->dst->neighbour);
		dst_release(csk->dst);
		csk->dst = NULL;
	}
	csk->src_port = 0;
#endif /* !defined (__VMKLNX__) */
	if (csk->src_port) {
		struct cnic_dev *dev = csk->dev;
		struct cnic_local *cp = dev->cnic_priv;

		cnic_free_id(&cp->csk_port_tbl, ntohs(csk->src_port));
		csk->src_port = 0;
	}
}

static void cnic_close_conn(struct cnic_sock *csk)
{
	if (test_bit(SK_F_PG_OFFLD_COMPLETE, &csk->flags)) {
		cnic_cm_upload_pg(csk);
		clear_bit(SK_F_PG_OFFLD_COMPLETE, &csk->flags);
	}
	cnic_cm_cleanup(csk);
	smp_mb__before_clear_bit();
	clear_bit(SK_F_OFFLD_SCHED, &csk->flags);
}

static int cnic_cm_destroy(struct cnic_sock *csk)
{
	if (!cnic_in_use(csk))
		return -EINVAL;

	csk_hold(csk);
	clear_bit(SK_F_INUSE, &csk->flags);
	smp_mb__after_clear_bit();
	while (atomic_read(&csk->ref_count) != 1)
		msleep(1);
	cnic_cm_cleanup(csk);

	csk->flags = 0;
	csk_put(csk);
	return 0;
}

static inline u16 cnic_get_vlan(struct net_device *dev,
				struct net_device **vlan_dev)
{
#if !defined (__VMKLNX__)
	if (dev->priv_flags & IFF_802_1Q_VLAN) {
#ifdef VLAN_DEV_INFO
		*vlan_dev = VLAN_DEV_INFO(dev)->real_dev;
		return VLAN_DEV_INFO(dev)->vlan_id;
#else
#ifdef VLAN_TX_COOKIE_MAGIC
		*vlan_dev = vlan_dev_info(dev)->real_dev;
		return vlan_dev_info(dev)->vlan_id;
#else
		*vlan_dev = vlan_dev_real_dev(dev);
		return vlan_dev_vlan_id(dev);
#endif
#endif
	}
#endif /* !defined (__VMKLNX__) */
	*vlan_dev = dev;
	return 0;
}

#if !defined (__VMKLNX__)
static int cnic_get_v4_route(struct sockaddr_in *dst_addr,
			     struct sockaddr_in *src_addr,
			     struct dst_entry **dst)
{
	struct flowi fl;
	int err;
	struct rtable *rt;

	memset(&fl, 0, sizeof(fl));
	fl.nl_u.ip4_u.daddr = dst_addr->sin_addr.s_addr;
	if (src_addr)
		fl.nl_u.ip4_u.saddr = src_addr->sin_addr.s_addr;

#if (LINUX_VERSION_CODE >= 0x020619)
	err = ip_route_output_key(&init_net, &rt, &fl);
#else
	err = ip_route_output_key(&rt, &fl);
#endif
	if (!err)
		*dst = &rt->u.dst;
	return err;
}

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
static struct dst_entry *cnic_ip6_rte_output(struct sock *sk, struct flowi *fl)
{
#if (LINUX_VERSION_CODE >= 0x02061a)
	struct dst_entry *(*fn)(struct net *, struct sock *, struct flowi *);
#else
	struct dst_entry *(*fn)(struct sock *, struct flowi *);
#endif
	struct dst_entry *dst = NULL;

	fn = symbol_get(ip6_route_output);
	if (fn) {
#if (LINUX_VERSION_CODE >= 0x02061a)
		dst = (*fn)(&init_net, sk, fl);
#else
		dst = (*fn)(sk, fl);
#endif
		symbol_put(ip6_route_output);
	}
	return dst;
}

static int cnic_ipv6_addr_type(const struct in6_addr *addr)
{
	int (*fn)(const struct in6_addr *addr);
	int type = 0;

	fn = symbol_get(__ipv6_addr_type);
	if (fn) {
		type = fn(addr) & 0xffff;
		symbol_put(__ipv6_addr_type);
	}
	return type;
}

static int cnic_ipv6_get_saddr(struct dst_entry *dst,
			       const struct in6_addr *daddr,
			       struct in6_addr *saddr)
{
	int rc = -ENOENT;

#if (LINUX_VERSION_CODE >= 0x02061b)
	int (*fn)(struct net *, struct net_device *,
		  const struct in6_addr *daddr, unsigned int prefs,
		  struct in6_addr *saddr);

	fn = symbol_get(ipv6_dev_get_saddr);
	if (fn) {
		rc = fn(&init_net, dst->dev, daddr, 0, saddr);
		symbol_put(ipv6_dev_get_saddr);
	}

#elif (LINUX_VERSION_CODE >= 0x02061a)
	int (*fn)(struct net_device *,
		  const struct in6_addr *daddr, unsigned int prefs,
		  struct in6_addr *saddr);

	fn = symbol_get(ipv6_dev_get_saddr);
	if (fn) {
		rc = fn(dst->dev, daddr, 0, saddr);
		symbol_put(ipv6_dev_get_saddr);
	}

#else
	int (*fn)(struct dst_entry *,
		  struct in6_addr *daddr, struct in6_addr *saddr);

	fn = symbol_get(ipv6_get_saddr);
	if (fn) {
		rc = fn(dst, (struct in6_addr *) daddr, saddr);
		symbol_put(ipv6_get_saddr);
	}
#endif
	return rc;
}

#endif

static int cnic_get_v6_route(struct sockaddr_in6 *dst_addr,
			     struct sockaddr_in6 *src_addr,
			     struct dst_entry **dst)
{
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	struct flowi fl;

	memset(&fl, 0, sizeof(fl));
	ipv6_addr_copy(&fl.fl6_dst, &dst_addr->sin6_addr);
	if (cnic_ipv6_addr_type(&fl.fl6_dst) & IPV6_ADDR_LINKLOCAL)
		fl.oif = dst_addr->sin6_scope_id;

	if (src_addr)
		ipv6_addr_copy(&fl.fl6_src, &src_addr->sin6_addr);

	*dst = cnic_ip6_rte_output(NULL, &fl);
	if (*dst)
		return 0;
#endif

	return -ENETUNREACH;
}
#endif /* !defined (__VMKLNX__) */

#if defined  (__VMKLNX__)
static struct cnic_dev *cnic_cm_select_dev(vmk_IscsiNetHandle iscsiNetHandle,
					   struct sockaddr_in *dst_addr,
					   int ulp_type)
{
	char devName[IFNAMSIZ];
	struct cnic_dev *dev;
	int found = 0;
	VMK_ReturnStatus status;

	status = vmk_IscsiTransportGetUplink(iscsiNetHandle, devName);
	if (status != VMK_OK) 
		return NULL;

	list_for_each_entry(dev, &cnic_dev_list, list) {
		struct cnic_local *cp = dev->cnic_priv;

		if (dev->netdev && test_bit(CNIC_F_IF_UP, &dev->flags)) {
			if (!strcmp(dev->netdev->name, devName)) {
				found = 1;
	                        /* Retrieve the source MAC */
	                        if ((status = vmk_IscsiTransportGetSrcMAC(
                                        iscsiNetHandle,
					cp->srcMACAddr)) != VMK_OK) {
					printk(KERN_ALERT "%s Get SRC MAC failed %d\n",
						dev->netdev->name, status);
					found = 0;
					break;
				}
				/* Next hop (arp) resolve */
				if ((status = vmk_IscsiTransportGetNextHopMAC(
					iscsiNetHandle, 
					cp->nextHopMACAddr)) != VMK_OK) {
					printk(KERN_ALERT "%s Get next hop MAC failed %d\n",
						dev->netdev->name, status);
					found = 0;
					break;
				}
				/* Retrieve the source IP Address */
				if ((status = vmk_IscsiTransportGetSrcIP(
					iscsiNetHandle,
					&cp->srcFamily, 
					cp->srcIPAddr)) != VMK_OK) {
					printk(KERN_ALERT "%s Get SRC IP failed %d\n",
						dev->netdev->name, status);
					found = 0;
					break;
				}
				/* Path MTU */
				if ((status = vmk_IscsiTransportGetPmtu(
					iscsiNetHandle,
					&cp->pmtu)) != VMK_OK) {
					printk(KERN_ALERT "%s Get PMTU failed %d\n",
						dev->netdev->name, status);
					cp->pmtu = 1500;
				}
				/* VLAN Tag */
				if ((status = vmk_IscsiTransportGetVlan(
					iscsiNetHandle,
					&cp->vlan_id)) != VMK_OK) {
					printk(KERN_ALERT "%s Get vlan ID failed %d\n",
						dev->netdev->name, status);
					cp->vlan_id = 0;
				}


				/* Allocate TCP ports, only once per device */
				if (cp->csk_port_tbl.table)
					break;

				cp->cnic_local_port_nr = MAX_CM_SK_TBL_SZ;
				cp->cnic_local_port_min = 1;
				status = vmk_IscsiTransportGetPortReservation(
						iscsiNetHandle,
						&cp->cnic_local_port_nr,
						&cp->cnic_local_port_min);
				if (status == VMK_OK) {
					cnic_init_id_tbl(&cp->csk_port_tbl, 
						cp->cnic_local_port_nr, 
						cp->cnic_local_port_min,
						cp->next_tcp_port);
				} else {
					found = 0; 
					printk(KERN_ALERT "%s TCP port alloc failed %d\n",
						dev->netdev->name, status);
				}
				break;
			}
		}
	}

	if (!found)
		dev = NULL;
	return dev;
}

#else  /* !defined (__VMKLNX__) */
static struct cnic_dev *cnic_cm_select_dev(struct sockaddr_in *dst_addr,
					   int ulp_type)
{
	struct cnic_dev *dev = NULL;
	struct dst_entry *dst;
	struct net_device *netdev = NULL;
	int err = -ENETUNREACH;

	if (dst_addr->sin_family == AF_INET)
		err = cnic_get_v4_route(dst_addr, NULL, &dst);
	else if (dst_addr->sin_family == AF_INET6) {
		struct sockaddr_in6 *dst_addr6 =
			(struct sockaddr_in6 *) dst_addr;

		err = cnic_get_v6_route(dst_addr6, NULL, &dst);
	} else
		return NULL;

	if (err)
		return NULL;

	if (!dst->dev)
		goto done;

	cnic_get_vlan(dst->dev, &netdev);

	dev = cnic_from_netdev(netdev);

done:
	dst_release(dst);
	if (dev)
		cnic_put(dev);
	return dev;
}
#endif  /* defined (__VMKLNX__) */

#if !defined (__VMKLNX__)
static int cnic_resolve_addr(struct cnic_sock *csk)
{
	struct neighbour *neigh = csk->dst->neighbour;
	int err = 0;
#ifndef HAVE_NETEVENT
	int retry = 0;
#endif

	if (neigh->nud_state & NUD_VALID) {
		err = -EINVAL;
		if (cnic_offld_prep(csk))
			err = cnic_cm_offload_pg(csk);
		goto done;
	}

	set_bit(SK_F_NDISC_WAITING, &csk->flags);
	neigh_event_send(neigh, NULL);
#ifndef HAVE_NETEVENT
	while (!(neigh->nud_state & NUD_VALID) && (retry < 3)) {
		msleep(1000);
		retry++;
	}
	if (!(neigh->nud_state & NUD_VALID))
		err = -ETIMEDOUT;
	else {
		err = -EINVAL;
		if (cnic_offld_prep(csk))
			err = cnic_cm_offload_pg(csk);
	}
	clear_bit(SK_F_NDISC_WAITING, &csk->flags);
#endif
done:
	return err;
}

static int cnic_get_route(struct cnic_sock *csk, struct cnic_sockaddr *saddr)
{
	struct cnic_dev *dev = csk->dev;
	int is_v6, err;
	struct dst_entry *dst;
	struct net_device *realdev;

	if (saddr->local.v6.sin6_family == AF_INET6 &&
	    saddr->remote.v6.sin6_family == AF_INET6)
		is_v6 = 1;
	else if (saddr->local.v4.sin_family == AF_INET &&
		 saddr->remote.v4.sin_family == AF_INET)
		is_v6 = 0;
	else
		return -EINVAL;

	clear_bit(SK_F_IPV6, &csk->flags);

	if (is_v6) {
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		set_bit(SK_F_IPV6, &csk->flags);
		err = cnic_get_v6_route(&saddr->remote.v6,
					&saddr->local.v6, &dst);
		if (err)
			return err;

		if (!dst || dst->error || !dst->dev)
			goto err_out;

		cnic_ipv6_get_saddr(dst, &saddr->remote.v6.sin6_addr,
				    &saddr->local.v6.sin6_addr);

		memcpy(&csk->src_ip[0], &saddr->local.v6.sin6_addr,
		       sizeof(struct in6_addr));
		memcpy(&csk->dst_ip[0], &saddr->remote.v6.sin6_addr,
		       sizeof(struct in6_addr));
		csk->src_port = saddr->local.v6.sin6_port;
		csk->dst_port = saddr->remote.v6.sin6_port;
#else
		return -ENETUNREACH;
#endif

	} else {
		err = cnic_get_v4_route(&saddr->remote.v4, &saddr->local.v4,
					&dst);
		if (err)
			return err;

		if (!dst || dst->error || !dst->dev)
			goto err_out;

		csk->dst_ip[0] = saddr->remote.v4.sin_addr.s_addr;
		csk->src_ip[0] = saddr->local.v4.sin_addr.s_addr;
		csk->src_port = saddr->local.v4.sin_port;
		csk->dst_port = saddr->remote.v4.sin_port;

		if (csk->src_ip[0] == 0) {
			csk->src_ip[0] =
				inet_select_addr(dst->dev, csk->dst_ip[0],
						 RT_SCOPE_LINK);
		}
	}

	csk->vlan_id = cnic_get_vlan(dst->dev, &realdev);
	if (realdev != dev->netdev)
		goto err_out;

	csk->dst = dst;
	csk->pmtu = dst_mtu(csk->dst);
	return 0;

err_out:
	dst_release(dst);
	return -ENETUNREACH;
}
#else /* defined (__VMKLNX__) */

static int cnic_get_route(struct cnic_sock *csk, struct cnic_sockaddr *saddr)
{
	struct cnic_dev *dev = csk->dev;
	struct cnic_local *cp = dev->cnic_priv;
	int err;
	int local_port;

	if (saddr->local.v4.sin_family != AF_INET &&
	    saddr->remote.v4.sin_family != AF_INET6)
		return -EINVAL;

	/* Use stored next hop MAC address */
	if (!cp->nextHopMACAddr[0] && !cp->nextHopMACAddr[1] &&
		!cp->nextHopMACAddr[2]) {
		printk(KERN_ALERT "Zero next hop address, aborting\n");
		return -EINVAL;
	}

	if (!cnic_offld_prep(csk))
		return -EINVAL;

	clear_bit(SK_F_IPV6, &csk->flags);

	memcpy(csk->ha, cp->nextHopMACAddr, 6);
	local_port = cnic_alloc_new_id(&cp->csk_port_tbl);
	if (local_port == -1) {
		clear_bit(SK_F_OFFLD_SCHED, &csk->flags);
		return -ENOMEM;
	}

	csk->pmtu = cp->pmtu;

	csk->src_ip[0] = *((vmk_uint32 *)cp->srcIPAddr);
	csk->dst_ip[0] = saddr->remote.v4.sin_addr.s_addr;
	csk->src_port = htons(local_port);
	csk->dst_port = saddr->remote.v4.sin_port;

	csk->vlan_id = cp->vlan_id;

	err = cnic_cm_offload_pg(csk);

	return err;
}
#endif /* !defined (__VMKLNX__) */

static void cnic_init_csk_state(struct cnic_sock *csk)
{
	csk->state = 0;
	clear_bit(SK_F_OFFLD_SCHED, &csk->flags);
	clear_bit(SK_F_CLOSING, &csk->flags);
}

static int cnic_cm_connect(struct cnic_sock *csk, struct cnic_sockaddr *saddr)
{
#if !defined (__VMKLNX__)
	struct neighbour *neigh;
#endif /* !defined (__VMKLNX__) */
	int err = 0;

	if (!cnic_in_use(csk))
		return -EINVAL;

	if (test_and_set_bit(SK_F_CONNECT_START, &csk->flags))
		return -EINVAL;

	cnic_init_csk_state(csk);

	err = cnic_get_route(csk, saddr);
	if (err)
		goto err_out;

#if !defined (__VMKLNX__)
	neigh = csk->dst->neighbour;
	if (!neigh)
		goto err_out;

	neigh_hold(neigh);

	err = cnic_resolve_addr(csk);
	if (!err)
		return 0;

	neigh_release(neigh);

#endif /* !defined (__VMKLNX__) */
err_out:
#if !defined (__VMKLNX__)
	if (csk->dst) {
		dst_release(csk->dst);
		csk->dst = NULL;
	}
#endif /* !defined (__VMKLNX__) */
	clear_bit(SK_F_CONNECT_START, &csk->flags);
	return err;
}

static int cnic_cm_abort(struct cnic_sock *csk)
{
	struct cnic_local *cp = csk->dev->cnic_priv;
	u32 opcode;

	if (!cnic_in_use(csk))
		return -EINVAL;

	clear_bit(SK_F_NDISC_WAITING, &csk->flags);
	clear_bit(SK_F_CONNECT_START, &csk->flags);
	smp_mb__after_clear_bit();
	if (cnic_abort_prep(csk))
		return (cnic_cm_abort_req(csk));

	/* Getting here means that we haven't started connect, or
	 * connect was not successful.
	 */

	csk->state = L4_KCQE_OPCODE_VALUE_RESET_COMP;
	if (test_bit(SK_F_PG_OFFLD_COMPLETE, &csk->flags))
		opcode = csk->state;
	else
		opcode = L5CM_RAMROD_CMD_ID_TERMINATE_OFFLOAD;
	cp->close_conn(csk, opcode);

	return 0;
}

static int cnic_cm_close(struct cnic_sock *csk)
{
	if (!cnic_in_use(csk))
		return -EINVAL;

	if (cnic_close_prep(csk)) {
		csk->state = L4_KCQE_OPCODE_VALUE_CLOSE_COMP;
		return (cnic_cm_close_req(csk));
	}
	return 0;
}

static void cnic_cm_upcall(struct cnic_local *cp, struct cnic_sock *csk,
			   u8 opcode)
{
	struct cnic_ulp_ops *ulp_ops;
	int ulp_type = csk->ulp_type;

	rcu_read_lock();
	ulp_ops = rcu_dereference(cp->ulp_ops[ulp_type]);
	if (ulp_ops) {
		if (opcode == L4_KCQE_OPCODE_VALUE_CONNECT_COMPLETE)
			ulp_ops->cm_connect_complete(csk);
		else if (opcode == L4_KCQE_OPCODE_VALUE_CLOSE_COMP)
			ulp_ops->cm_close_complete(csk);
		else if (opcode == L4_KCQE_OPCODE_VALUE_RESET_RECEIVED)
			ulp_ops->cm_remote_abort(csk);
		else if (opcode == L4_KCQE_OPCODE_VALUE_RESET_COMP)
			ulp_ops->cm_abort_complete(csk);
		else if (opcode == L4_KCQE_OPCODE_VALUE_CLOSE_RECEIVED)
			ulp_ops->cm_remote_close(csk);
	}
	rcu_read_unlock();
}

static int cnic_cm_set_pg(struct cnic_sock *csk)
{
#if !defined (__VMKLNX__)
	struct neighbour *neigh = csk->dst->neighbour;
	int valid = neigh->nud_state & NUD_VALID;

	if (!valid) {
		if (test_and_clear_bit(SK_F_NDISC_WAITING, &csk->flags)) {
			clear_bit(SK_F_CONNECT_START, &csk->flags);
			cnic_cm_cleanup(csk);
			return -ETIMEDOUT;
		}
	}

	if (cnic_offld_prep(csk)) {
		if (test_bit(SK_F_PG_OFFLD_COMPLETE, &csk->flags))
			cnic_cm_update_pg(csk);
		else
			cnic_cm_offload_pg(csk);
	}
	clear_bit(SK_F_NDISC_WAITING, &csk->flags);
#endif /* !defined (__VMKLNX__) */
	return 0;
}

static void cnic_cm_process_neigh(struct cnic_dev *dev, struct neighbour *neigh)
{
#if !defined (__VMKLNX__)
	struct cnic_local *cp = dev->cnic_priv;
	int i;

	for (i = 0; i < MAX_CM_SK_TBL_SZ; i++) {
		struct cnic_sock *csk;
		int abort = 0;

		csk = &cp->csk_tbl[i];
		csk_hold(csk);
		if (cnic_in_use(csk) && csk->dst &&
		    csk->dst->neighbour == neigh) {
			if (cnic_cm_set_pg(csk))
				abort = 1;
		}
		if (abort)
			cnic_cm_upcall(cp, csk,
				L4_KCQE_OPCODE_VALUE_CONNECT_COMPLETE);
		csk_put(csk);
	}
	neigh_release(neigh);
#endif /* !defined (__VMKLNX__) */
}

static void cnic_cm_process_redirect(struct cnic_dev *dev,
				     struct cnic_redirect_entry *redir)
{
#if !defined (__VMKLNX__)
	struct cnic_local *cp = dev->cnic_priv;
	int i;

	for (i = 0; i < MAX_CM_SK_TBL_SZ; i++) {
		struct cnic_sock *csk;
		int abort = 0;

		csk = &cp->csk_tbl[i];
		csk_hold(csk);
		if (cnic_in_use(csk) && csk->dst == redir->old_dst) {
			csk->dst = redir->new_dst;
			dst_hold(csk->dst);
			neigh_hold(csk->dst->neighbour);
			if (redir->old_dst->neighbour);
				neigh_release(redir->old_dst->neighbour);
			dst_release(redir->old_dst);
			if (cnic_cm_set_pg(csk))
				abort = 1;
		}
		if (abort)
			cnic_cm_upcall(cp, csk,
				L4_KCQE_OPCODE_VALUE_CONNECT_COMPLETE);
		csk_put(csk);
	}

	dst_release(redir->new_dst);
	dst_release(redir->old_dst);
#endif /* !defined (__VMKLNX__) */
}

static void cnic_cm_process_offld_pg(struct cnic_dev *dev, struct l4_kcq *kcqe)
{
	struct cnic_local *cp = dev->cnic_priv;
	u32 l5_cid = kcqe->pg_host_opaque;
	u8 opcode = kcqe->op_code;
	struct cnic_sock *csk = &cp->csk_tbl[l5_cid];

	csk_hold(csk);
	if (!cnic_in_use(csk))
		goto done;

	if (opcode == L4_KCQE_OPCODE_VALUE_UPDATE_PG) {
		clear_bit(SK_F_OFFLD_SCHED, &csk->flags);
		goto done;
	}
	/* Possible PG kcqe status:  SUCCESS, OFFLOADED_PG, or CTX_ALLOC_FAIL */
	if (kcqe->status == L4_KCQE_COMPLETION_STATUS_CTX_ALLOC_FAIL) {
		clear_bit(SK_F_OFFLD_SCHED, &csk->flags);
		cnic_cm_upcall(cp, csk,
			       L4_KCQE_OPCODE_VALUE_CONNECT_COMPLETE);
		goto done;
	}

	csk->pg_cid = kcqe->pg_cid;
	set_bit(SK_F_PG_OFFLD_COMPLETE, &csk->flags);
	cnic_cm_conn_req(csk);

done:
	csk_put(csk);
}

static void cnic_cm_process_kcqe(struct cnic_dev *dev, struct kcqe *kcqe)
{
	struct cnic_local *cp = dev->cnic_priv;
	struct l4_kcq *l4kcqe = (struct l4_kcq *) kcqe;
	u8 opcode = l4kcqe->op_code;
	u32 l5_cid;
	struct cnic_sock *csk;

	if (opcode == L4_KCQE_OPCODE_VALUE_OFFLOAD_PG ||
	    opcode == L4_KCQE_OPCODE_VALUE_UPDATE_PG) {
		cnic_cm_process_offld_pg(dev, l4kcqe);
		return;
	}

	l5_cid = l4kcqe->conn_id;
	/* Hack */
	if (opcode & 0x80)
		l5_cid = l4kcqe->cid;
	if (l5_cid >= MAX_CM_SK_TBL_SZ)
		return;

	csk = &cp->csk_tbl[l5_cid];
	csk_hold(csk);

	if (!cnic_in_use(csk)) {
		csk_put(csk);
		return;
	}

	switch (opcode) {
	case L5CM_RAMROD_CMD_ID_TCP_CONNECT:
		if (l4kcqe->status != 0) {
			clear_bit(SK_F_OFFLD_SCHED, &csk->flags);
			cnic_cm_upcall(cp, csk,
				       L4_KCQE_OPCODE_VALUE_CONNECT_COMPLETE);
		}
		break;
	case L4_KCQE_OPCODE_VALUE_CONNECT_COMPLETE:
		if (l4kcqe->status == 0)
			set_bit(SK_F_OFFLD_COMPLETE, &csk->flags);

		smp_mb__before_clear_bit();
		clear_bit(SK_F_OFFLD_SCHED, &csk->flags);
		cnic_cm_upcall(cp, csk, opcode);
		break;

	case L4_KCQE_OPCODE_VALUE_RESET_RECEIVED:
		if (test_bit(CNIC_F_BNX2_CLASS, &dev->flags)) {
			cnic_cm_upcall(cp, csk, opcode);
			break;
		} else if (test_and_clear_bit(SK_F_OFFLD_COMPLETE, &csk->flags))
			csk->state = opcode;
		/* fall through */
	case L4_KCQE_OPCODE_VALUE_CLOSE_COMP:
	case L4_KCQE_OPCODE_VALUE_RESET_COMP:
	case L5CM_RAMROD_CMD_ID_SEARCHER_DELETE:
	case L5CM_RAMROD_CMD_ID_TERMINATE_OFFLOAD:
		cp->close_conn(csk, opcode);
		break;

	case L4_KCQE_OPCODE_VALUE_CLOSE_RECEIVED:
		cnic_cm_upcall(cp, csk, opcode);
		break;
	}
	csk_put(csk);
}

static void cnic_cm_indicate_kcqe(void *data, struct kcqe *kcqe[], u32 num_cqe)
{
	struct cnic_dev *dev = data;
	int i;
	struct cnic_local *cp = dev->cnic_priv;

	for (i = 0; i < num_cqe; i++)
		cnic_queue_work(cp, WORK_TYPE_KCQE, kcqe[i]);

	tasklet_schedule(&cp->cnic_task);
}

static void cnic_cm_indicate_event(void *data, unsigned long event)
{
}

static void cnic_cm_dummy(void *data)
{
}

static struct cnic_ulp_ops cm_ulp_ops = {
	.cnic_start		= cnic_cm_dummy,
	.cnic_stop		= cnic_cm_dummy,
	.indicate_kcqes		= cnic_cm_indicate_kcqe,
	.indicate_netevent	= cnic_cm_indicate_event,
	.indicate_inetevent	= cnic_cm_indicate_event,
};

static void cnic_task(unsigned long data)
{
	struct cnic_local *cp = (struct cnic_local *) data;
	struct cnic_dev *dev = cp->dev;
	u32 cons = cp->cnic_wr_cons;
	u32 prod = cp->cnic_wr_prod;

	while (cons != prod) {
		struct cnic_work_node *node;

		node = &cp->cnic_work_ring[cons];
		if (node->work_type == WORK_TYPE_KCQE)
			cnic_cm_process_kcqe(dev, &node->work_data.kcqe);
		else if (node->work_type == WORK_TYPE_NEIGH_UPDATE)
			cnic_cm_process_neigh(dev, node->work_data.neigh);
		else if (node->work_type == WORK_TYPE_REDIRECT)
			cnic_cm_process_redirect(dev,
				&node->work_data.cnic_redir);
		cons++;
		cons &= WORK_RING_SIZE_MASK;
	}
	cp->cnic_wr_cons = cons;
}

static void cnic_free_dev(struct cnic_dev *dev)
{
	int i = 0;

	while ((atomic_read(&dev->ref_count) != 0) && i < 10) {
		msleep(100);
		i++;
	}
	if (atomic_read(&dev->ref_count) != 0)
		printk(KERN_ERR PFX "%s: Failed waiting for ref count to go"
				    " to zero.\n", dev->netdev->name);

	printk(KERN_INFO PFX "Removed CNIC device: %s\n", dev->netdev->name);
	dev_put(dev->netdev);
	kfree(dev);
}

static void cnic_cm_free_mem(struct cnic_dev *dev)
{
	struct cnic_local *cp = dev->cnic_priv;

	kfree(cp->csk_tbl);
	cp->csk_tbl = NULL;
	cp->next_tcp_port = cnic_free_id_tbl(&cp->csk_port_tbl);
}

static int cnic_cm_alloc_mem(struct cnic_dev *dev)
{
	struct cnic_local *cp = dev->cnic_priv;

	cp->csk_tbl = kmalloc(sizeof(struct cnic_sock) * MAX_CM_SK_TBL_SZ,
			      GFP_KERNEL);
	if (!cp->csk_tbl)
		return -ENOMEM;
	memset(cp->csk_tbl, 0, sizeof(struct cnic_sock) * MAX_CM_SK_TBL_SZ);

	return 0;
}

#ifndef HAVE_NETEVENT
#if !defined (__VMKLNX__)
static void cnic_timer(unsigned long data)
{
	struct cnic_local *cp = (struct cnic_local *) data;
	struct cnic_dev *dev = cp->dev;
	int i, found = 0;
	struct neighbour *neigh = NULL;

	if (!test_bit(CNIC_F_CNIC_UP, &dev->flags))
		return;

	for (i = 0; i < MAX_CM_SK_TBL_SZ && !found; i++) {
		struct cnic_sock *csk;

		csk = &cp->csk_tbl[i];
		csk_hold(csk);
		if (cnic_in_use(csk) && csk->dst &&
		    test_bit(SK_F_PG_OFFLD_COMPLETE, &csk->flags)) {
			neigh = csk->dst->neighbour;
			if (memcmp(csk->old_ha, neigh->ha, 6)) {
				found = 1;
				neigh_hold(neigh);

				cnic_queue_work(cp, WORK_TYPE_NEIGH_UPDATE,
						&neigh);
				tasklet_schedule(&cp->cnic_task);
			}
		}
		csk_put(csk);
	}

	cp->cnic_timer.expires = jiffies + cp->cnic_timer_off;
	add_timer(&cp->cnic_timer);
}
#endif /* !defined (__VMKLNX__) */
#endif

static int cnic_ready_to_close(struct cnic_sock *csk, u32 opcode)
{
	if ((opcode == csk->state) ||
	    (opcode == L4_KCQE_OPCODE_VALUE_RESET_RECEIVED &&
	     csk->state == L4_KCQE_OPCODE_VALUE_CLOSE_COMP)) {
		if (!test_and_set_bit(SK_F_CLOSING, &csk->flags))
			return 1;
	}
	/* 57710+ only  workaround to handle unsolicited RESET_COMP
	 * which will be treated like a RESET RCVD notification
	 * which triggers the clean up procedure
	 */
	else if ((opcode != csk->state) && 
		 (opcode == L4_KCQE_OPCODE_VALUE_RESET_COMP)) {
		if (!test_and_set_bit(SK_F_CLOSING, &csk->flags)) {
			csk->state = L4_KCQE_OPCODE_VALUE_RESET_RECEIVED;
			return 1;
		}
	}
	return 0;
}

static void cnic_close_bnx2_conn(struct cnic_sock *csk, u32 opcode)
{
	struct cnic_dev *dev = csk->dev;
	struct cnic_local *cp = dev->cnic_priv;

	clear_bit(SK_F_CONNECT_START, &csk->flags);
	cnic_close_conn(csk);
	cnic_cm_upcall(cp, csk, opcode);
}

static void cnic_cm_stop_bnx2_hw(struct cnic_dev *dev)
{
}

static int cnic_cm_init_bnx2_hw(struct cnic_dev *dev)
{
	u32 seed;

#if (LINUX_VERSION_CODE >= 0x020612)
	get_random_bytes(&seed, 4);
#else
	seed = 0x12345678;
#endif
	cnic_ctx_wr(dev, 45, 0, seed);
	return 0;
}

static void cnic_close_bnx2x_conn(struct cnic_sock *csk, u32 opcode)
{
	struct cnic_dev *dev = csk->dev;
	struct cnic_local *cp = dev->cnic_priv;
	struct cnic_context *ctx = &cp->ctx_tbl[csk->l5_cid];
	union l5cm_specific_data l5_data;
	u32 cmd = 0;
	int close_complete = 0;

	switch (opcode) {
	case L4_KCQE_OPCODE_VALUE_RESET_RECEIVED:
	case L4_KCQE_OPCODE_VALUE_CLOSE_COMP:
	case L4_KCQE_OPCODE_VALUE_RESET_COMP:
		if (cnic_ready_to_close(csk, opcode))
			cmd = L5CM_RAMROD_CMD_ID_SEARCHER_DELETE;
		break;
	case L5CM_RAMROD_CMD_ID_SEARCHER_DELETE:
		cmd = L5CM_RAMROD_CMD_ID_TERMINATE_OFFLOAD;
		break;
	case L5CM_RAMROD_CMD_ID_TERMINATE_OFFLOAD:
		close_complete = 1;
		break;
	}
	if (cmd) {
		memset(&l5_data, 0, sizeof(l5_data));

		cnic_submit_kwqe_16(dev, cmd, csk->cid, ISCSI_CONNECTION_TYPE,
				    &l5_data);
	} else if (close_complete) {
		ctx->timestamp = jiffies;
		cnic_close_conn(csk);
		cnic_cm_upcall(cp, csk, csk->state);
	}
}

static void cnic_cm_stop_bnx2x_hw(struct cnic_dev *dev)
{
}

static int cnic_cm_init_bnx2x_hw(struct cnic_dev *dev)
{
	struct cnic_local *cp = dev->cnic_priv;
	int func = CNIC_FUNC(cp);
	struct net_device *netdev = dev->netdev;

	cnic_init_bnx2x_mac(dev, netdev->dev_addr);
	cnic_bnx2x_set_tcp_timestamp(dev, 1);

	CNIC_WR16(dev, BAR_XSTRORM_INTMEM +
		  XSTORM_ISCSI_LOCAL_VLAN_OFFSET(func), 0);

	CNIC_WR(dev, BAR_XSTRORM_INTMEM +
		XSTORM_TCP_GLOBAL_DEL_ACK_COUNTER_ENABLED_OFFSET(func), 1);
	CNIC_WR(dev, BAR_XSTRORM_INTMEM +
		XSTORM_TCP_GLOBAL_DEL_ACK_COUNTER_MAX_COUNT_OFFSET(func),
		DEF_MAX_DA_COUNT);

	CNIC_WR8(dev, BAR_XSTRORM_INTMEM +
		 XSTORM_ISCSI_TCP_VARS_TTL_OFFSET(func), DEF_TTL);
	CNIC_WR8(dev, BAR_XSTRORM_INTMEM +
		 XSTORM_ISCSI_TCP_VARS_TOS_OFFSET(func), DEF_TOS);
	CNIC_WR8(dev, BAR_XSTRORM_INTMEM +
		 XSTORM_ISCSI_TCP_VARS_ADV_WND_SCL_OFFSET(func), 2);
	CNIC_WR(dev, BAR_XSTRORM_INTMEM +
		XSTORM_TCP_TX_SWS_TIMER_VAL_OFFSET(func), DEF_SWS_TIMER);

	CNIC_WR(dev, BAR_TSTRORM_INTMEM + TSTORM_TCP_MAX_CWND_OFFSET(func),
		DEF_MAX_CWND);
	return 0;
}

static int cnic_cm_open(struct cnic_dev *dev)
{
	struct cnic_local *cp = dev->cnic_priv;
	int err;

	err = cnic_cm_alloc_mem(dev);
	if (err)
		return err;

	err = cp->start_cm(dev);

	if (err)
		goto err_out;

	spin_lock_init(&cp->wr_lock);

	tasklet_init(&cp->cnic_task, cnic_task, (unsigned long) cp);

#ifdef HAVE_NETEVENT
	cp->cm_nb.notifier_call = cnic_net_callback;
	register_netevent_notifier(&cp->cm_nb);
#else
#if !defined (__VMKLNX__)
	init_timer(&cp->cnic_timer);
	cp->cnic_timer_off = 2 * HZ;
	cp->cnic_timer.expires = jiffies + cp->cnic_timer_off;
	cp->cnic_timer.data = (unsigned long) cp;
	cp->cnic_timer.function = cnic_timer;
	add_timer(&cp->cnic_timer);
#endif /* !defined (__VMKLNX__) */
#endif

	dev->cm_create = cnic_cm_create;
	dev->cm_destroy = cnic_cm_destroy;
	dev->cm_connect = cnic_cm_connect;
	dev->cm_abort = cnic_cm_abort;
	dev->cm_close = cnic_cm_close;
	dev->cm_select_dev = cnic_cm_select_dev;

	cp->ulp_handle[CNIC_ULP_L4] = dev;
	rcu_assign_pointer(cp->ulp_ops[CNIC_ULP_L4], &cm_ulp_ops);
	return 0;

err_out:
	cnic_cm_free_mem(dev);
	return err;
}

static int cnic_cm_shutdown(struct cnic_dev *dev)
{
	struct cnic_local *cp = dev->cnic_priv;
	int i;

	cp->stop_cm(dev);

#ifdef HAVE_NETEVENT
	unregister_netevent_notifier(&cp->cm_nb);
#else
#if !defined (__VMKLNX__)
	del_timer_sync(&cp->cnic_timer);
#endif /* !defined (__VMKLNX__) */
#endif

	tasklet_kill(&cp->cnic_task);

	if (!cp->csk_tbl)
		return 0;

	for (i = 0; i < MAX_CM_SK_TBL_SZ; i++) {
		struct cnic_sock *csk = &cp->csk_tbl[i];

		clear_bit(SK_F_INUSE, &csk->flags);
		cnic_cm_cleanup(csk);
	}
	cnic_cm_free_mem(dev);

	return 0;
}

static void cnic_init_context(struct cnic_dev *dev, u32 cid)
{
	u32 cid_addr;
	int i;

	cid_addr = GET_CID_ADDR(cid);

	for (i = 0; i < CTX_SIZE; i += 4)
		cnic_ctx_wr(dev, cid_addr, i, 0);
}

static int cnic_setup_5709_context(struct cnic_dev *dev, int valid)
{
	struct cnic_local *cp = dev->cnic_priv;
	int ret = 0, i;
	u32 valid_bit = valid ? BNX2_CTX_HOST_PAGE_TBL_DATA0_VALID : 0;

	if (CHIP_NUM(cp) != CHIP_NUM_5709)
		return 0;

	for (i = 0; i < cp->ctx_blks; i++) {
		int j;
		u32 idx = cp->ctx_arr[i].cid / cp->cids_per_blk;
		u32 val;

		memset(cp->ctx_arr[i].ctx, 0, BCM_PAGE_SIZE);

		CNIC_WR(dev, BNX2_CTX_HOST_PAGE_TBL_DATA0,
			(cp->ctx_arr[i].mapping & 0xffffffff) | valid_bit);
		CNIC_WR(dev, BNX2_CTX_HOST_PAGE_TBL_DATA1,
			(u64) cp->ctx_arr[i].mapping >> 32);
		CNIC_WR(dev, BNX2_CTX_HOST_PAGE_TBL_CTRL, idx |
			BNX2_CTX_HOST_PAGE_TBL_CTRL_WRITE_REQ);
		for (j = 0; j < 10; j++) {

			val = CNIC_RD(dev, BNX2_CTX_HOST_PAGE_TBL_CTRL);
			if (!(val & BNX2_CTX_HOST_PAGE_TBL_CTRL_WRITE_REQ))
				break;
			udelay(5);
		}
		if (val & BNX2_CTX_HOST_PAGE_TBL_CTRL_WRITE_REQ) {
			ret = -EBUSY;
			break;
		}
	}
	return ret;
}

static void cnic_free_irq(struct cnic_dev *dev)
{
	struct cnic_local *cp = dev->cnic_priv;
	struct cnic_eth_dev *ethdev = cp->ethdev;

	if (ethdev->drv_state & CNIC_DRV_STATE_USING_MSIX) {
		cp->disable_int_sync(dev);
		tasklet_kill(&cp->cnic_irq_task);
		free_irq(ethdev->irq_arr[0].vector, dev);
	}
}

static int cnic_init_bnx2_irq(struct cnic_dev *dev)
{
	struct cnic_local *cp = dev->cnic_priv;
	struct cnic_eth_dev *ethdev = cp->ethdev;

	if (ethdev->drv_state & CNIC_DRV_STATE_USING_MSIX) {
		int err, i = 0;
		int sblk_num = cp->status_blk_num;
		u32 base = ((sblk_num - 1) * BNX2_HC_SB_CONFIG_SIZE) +
			   BNX2_HC_SB_CONFIG_1;

		CNIC_WR(dev, base, BNX2_HC_SB_CONFIG_1_ONE_SHOT);

		CNIC_WR(dev, base + BNX2_HC_COMP_PROD_TRIP_OFF, (2 << 16) | 8);
		CNIC_WR(dev, base + BNX2_HC_COM_TICKS_OFF, (64 << 16) | 220);
		CNIC_WR(dev, base + BNX2_HC_CMD_TICKS_OFF, (64 << 16) | 220);

		cp->bnx2_status_blk = cp->status_blk;
		cp->last_status_idx = cp->bnx2_status_blk->status_idx;
		tasklet_init(&cp->cnic_irq_task, cnic_service_bnx2_msix,
			     (unsigned long) dev);
		err = request_irq(ethdev->irq_arr[0].vector, cnic_irq, 0,
				  "cnic", dev);
		if (err) {
			tasklet_disable(&cp->cnic_irq_task);
			return err;
		}
		while (cp->bnx2_status_blk->status_completion_producer_index &&
		       i < 10) {
			CNIC_WR(dev, BNX2_HC_COALESCE_NOW,
				1 << (11 + sblk_num));
			udelay(10);
			i++;
			barrier();
		}
		if (cp->bnx2_status_blk->status_completion_producer_index) {
			cnic_free_irq(dev);
			goto failed;
		}

	} else {
		struct status_block *sblk = cp->status_blk;
		u32 hc_cmd = CNIC_RD(dev, BNX2_HC_COMMAND);
		int i = 0;

		while (sblk->status_completion_producer_index && i < 10) {
			CNIC_WR(dev, BNX2_HC_COMMAND,
				hc_cmd | BNX2_HC_COMMAND_COAL_NOW_WO_INT);
			udelay(10);
			i++;
			barrier();
		}
		if (sblk->status_completion_producer_index)
			goto failed;

	}
	return 0;

failed:
	printk(KERN_ERR PFX "%s: " "KCQ index not resetting to 0.\n",
	       dev->netdev->name);
	return -EBUSY;
}

static void cnic_enable_bnx2_int(struct cnic_dev *dev)
{
	struct cnic_local *cp = dev->cnic_priv;
	struct cnic_eth_dev *ethdev = cp->ethdev;

	if (!(ethdev->drv_state & CNIC_DRV_STATE_USING_MSIX))
		return;

	CNIC_WR(dev, BNX2_PCICFG_INT_ACK_CMD, cp->int_num |
		BNX2_PCICFG_INT_ACK_CMD_INDEX_VALID | cp->last_status_idx);
}

static void cnic_disable_bnx2_int_sync(struct cnic_dev *dev)
{
	struct cnic_local *cp = dev->cnic_priv;
	struct cnic_eth_dev *ethdev = cp->ethdev;

	if (!(ethdev->drv_state & CNIC_DRV_STATE_USING_MSIX))
		return;

	CNIC_WR(dev, BNX2_PCICFG_INT_ACK_CMD, cp->int_num |
		BNX2_PCICFG_INT_ACK_CMD_MASK_INT);
	CNIC_RD(dev, BNX2_PCICFG_INT_ACK_CMD);
	synchronize_irq(ethdev->irq_arr[0].vector);
}

static void cnic_get_bnx2_iscsi_info(struct cnic_dev *dev)
{
	u32 max_conn;

	max_conn = cnic_reg_rd_ind(dev, BNX2_FW_MAX_ISCSI_CONN);
	dev->max_iscsi_conn = max_conn;
}

static int cnic_start_bnx2_hw(struct cnic_dev *dev)
{
	struct cnic_local *cp = dev->cnic_priv;
	struct cnic_eth_dev *ethdev = cp->ethdev;
	struct status_block *sblk = cp->status_blk;
	u32 val;
	int err;

	val = CNIC_RD(dev, BNX2_MQ_CONFIG);
	val &= ~BNX2_MQ_CONFIG_KNL_BYP_BLK_SIZE;
	if (BCM_PAGE_BITS > 12)
		val |= (12 - 8)  << 4;
	else
		val |= (BCM_PAGE_BITS - 8)  << 4;

	CNIC_WR(dev, BNX2_MQ_CONFIG, val);

	CNIC_WR(dev, BNX2_HC_COMP_PROD_TRIP, (2 << 16) | 8);
	CNIC_WR(dev, BNX2_HC_COM_TICKS, (64 << 16) | 220);
	CNIC_WR(dev, BNX2_HC_CMD_TICKS, (64 << 16) | 220);

	err = cnic_setup_5709_context(dev, 1);
	if (err)
		return err;

	cnic_init_context(dev, KWQ_CID);
	cnic_init_context(dev, KCQ_CID);

	cp->kwq_cid_addr = GET_CID_ADDR(KWQ_CID);
	cp->kwq_io_addr = MB_GET_CID_ADDR(KWQ_CID) + L5_KRNLQ_HOST_QIDX;

	cp->max_kwq_idx = MAX_KWQ_IDX;
	cp->kwq_prod_idx = 0;
	cp->kwq_con_idx = 0;
	cp->cnic_local_flags |= CNIC_LCL_FL_KWQ_INIT;

	if (CHIP_NUM(cp) == CHIP_NUM_5706 || CHIP_NUM(cp) == CHIP_NUM_5708)
		cp->kwq_con_idx_ptr = &sblk->status_rx_quick_consumer_index15;
	else
		cp->kwq_con_idx_ptr = &sblk->status_cmd_consumer_index;

	/* Initialize the kernel work queue context. */
	val = KRNLQ_TYPE_TYPE_KRNLQ | KRNLQ_SIZE_TYPE_SIZE |
	      (BCM_PAGE_BITS - 8) | KRNLQ_FLAGS_QE_SELF_SEQ;
	cnic_ctx_wr(dev, cp->kwq_cid_addr, L5_KRNLQ_TYPE, val);
	
	val = (BCM_PAGE_SIZE / sizeof(struct kwqe) - 1) << 16;
	cnic_ctx_wr(dev, cp->kwq_cid_addr, L5_KRNLQ_QE_SELF_SEQ_MAX, val);
	
	val = ((BCM_PAGE_SIZE / sizeof(struct kwqe)) << 16) | KWQ_PAGE_CNT;
	cnic_ctx_wr(dev, cp->kwq_cid_addr, L5_KRNLQ_PGTBL_NPAGES, val);
	
	val = (u32) ((u64) cp->kwq_info.pgtbl_map >> 32);
	cnic_ctx_wr(dev, cp->kwq_cid_addr, L5_KRNLQ_PGTBL_HADDR_HI, val);
	
	val = (u32) cp->kwq_info.pgtbl_map;
	cnic_ctx_wr(dev, cp->kwq_cid_addr, L5_KRNLQ_PGTBL_HADDR_LO, val);

	cp->kcq_cid_addr = GET_CID_ADDR(KCQ_CID);
	cp->kcq_io_addr = MB_GET_CID_ADDR(KCQ_CID) + L5_KRNLQ_HOST_QIDX;
	
	cp->kcq_prod_idx = 0;
	
	/* Initialize the kernel complete queue context. */
	val = KRNLQ_TYPE_TYPE_KRNLQ | KRNLQ_SIZE_TYPE_SIZE |
	      (BCM_PAGE_BITS - 8) | KRNLQ_FLAGS_QE_SELF_SEQ;
	cnic_ctx_wr(dev, cp->kcq_cid_addr, L5_KRNLQ_TYPE, val);
	
	val = (BCM_PAGE_SIZE / sizeof(struct kcqe) - 1) << 16;
	cnic_ctx_wr(dev, cp->kcq_cid_addr, L5_KRNLQ_QE_SELF_SEQ_MAX, val);
	
	val = ((BCM_PAGE_SIZE / sizeof(struct kcqe)) << 16) | KCQ_PAGE_CNT;
	cnic_ctx_wr(dev, cp->kcq_cid_addr, L5_KRNLQ_PGTBL_NPAGES, val);
	
	val = (u32) ((u64) cp->kcq_info.pgtbl_map >> 32);
	cnic_ctx_wr(dev, cp->kcq_cid_addr, L5_KRNLQ_PGTBL_HADDR_HI, val);
	
	val = (u32) cp->kcq_info.pgtbl_map;
	cnic_ctx_wr(dev, cp->kcq_cid_addr, L5_KRNLQ_PGTBL_HADDR_LO, val);

	cp->int_num = 0;
	if (ethdev->drv_state & CNIC_DRV_STATE_USING_MSIX) {
		u32 sb_id = cp->status_blk_num;
		u32 sb = BNX2_L2CTX_L5_STATUSB_NUM(sb_id);

		cp->int_num = sb_id << BNX2_PCICFG_INT_ACK_CMD_INT_NUM_SHIFT;
		cnic_ctx_wr(dev, cp->kwq_cid_addr, L5_KRNLQ_HOST_QIDX, sb);
		cnic_ctx_wr(dev, cp->kcq_cid_addr, L5_KRNLQ_HOST_QIDX, sb);
	}

	/* Enable Commnad Scheduler notification when we write to the
	 * host producer index of the kernel contexts. */
	CNIC_WR(dev, BNX2_MQ_KNL_CMD_MASK1, 2);

	/* Enable Command Scheduler notification when we write to either
	 * the Send Queue or Receive Queue producer indexes of the kernel
	 * bypass contexts. */
	CNIC_WR(dev, BNX2_MQ_KNL_BYP_CMD_MASK1, 7);
	CNIC_WR(dev, BNX2_MQ_KNL_BYP_WRITE_MASK1, 7);

	/* Notify COM when the driver post an application buffer. */
	CNIC_WR(dev, BNX2_MQ_KNL_RX_V2P_MASK2, 0x2000);

	/* Set the CP and COM doorbells.  These two processors polls the
	 * doorbell for a non zero value before running.  This must be done
	 * after setting up the kernel queue contexts. */
	val = cnic_reg_rd_ind(dev, BNX2_CP_SCRATCH + 0x20);
	cnic_reg_wr_ind(dev, BNX2_CP_SCRATCH + 0x20, val | 1);

	val = cnic_reg_rd_ind(dev, BNX2_COM_SCRATCH + 0x20);
	cnic_reg_wr_ind(dev, BNX2_COM_SCRATCH + 0x20, val | 1);

	err = cnic_init_bnx2_irq(dev);
	if (err) {
		printk(KERN_ERR PFX "%s: cnic_init_irq failed\n",
		       dev->netdev->name);

		val = cnic_reg_rd_ind(dev, BNX2_CP_SCRATCH + 0x20);
		cnic_reg_wr_ind(dev, BNX2_CP_SCRATCH + 0x20, val & ~0x1);

		val = cnic_reg_rd_ind(dev, BNX2_COM_SCRATCH + 0x20);
		cnic_reg_wr_ind(dev, BNX2_COM_SCRATCH + 0x20, val & ~0x1);

		return err;
	}

	cnic_get_bnx2_iscsi_info(dev);

	return 0;
}

static void cnic_setup_bnx2x_context(struct cnic_dev *dev)
{
	struct cnic_local *cp = dev->cnic_priv;
	struct cnic_eth_dev *ethdev = cp->ethdev;
	u32 start_offset = ethdev->ctx_tbl_offset;
	int i;

	for (i = 0; i < cp->ctx_blks; i++) {
		struct cnic_ctx *ctx = &cp->ctx_arr[i];
		dma_addr_t map = ctx->mapping;

		if (cp->ctx_align) {
			unsigned long mask = cp->ctx_align - 1;

			map = (map + mask) & ~mask;
		}

		cnic_ctx_tbl_wr(dev, start_offset + i, map);
	}
}

static int cnic_init_bnx2x_irq(struct cnic_dev *dev)
{
	struct cnic_local *cp = dev->cnic_priv;
	struct cnic_eth_dev *ethdev = cp->ethdev;
	int err = 0;

	cp->bnx2x_status_blk = cp->status_blk;
	memset(cp->bnx2x_status_blk, 0, sizeof(struct host_status_block));

	tasklet_init(&cp->cnic_irq_task, cnic_service_bnx2x_bh,
		     (unsigned long) dev);
	if (ethdev->drv_state & CNIC_DRV_STATE_USING_MSIX) {
		err = request_irq(ethdev->irq_arr[0].vector, cnic_irq, 0,
				  "cnic", dev);
		if (err)
			tasklet_disable(&cp->cnic_irq_task);
	}
	return err;
}

static void cnic_enable_bnx2x_int(struct cnic_dev *dev)
{
	struct cnic_local *cp = dev->cnic_priv;
	u8 sb_id = cp->status_blk_num;
	int port = CNIC_PORT(cp);

#ifdef NEW_BNX2X_HSI
	CNIC_WR8(dev, BAR_CSTRORM_INTMEM +
		 CSTORM_SB_HC_TIMEOUT_C_OFFSET(port, sb_id,
					       HC_INDEX_C_ISCSI_EQ_CONS),
		 64 / 12);
	CNIC_WR16(dev, BAR_CSTRORM_INTMEM +
		  CSTORM_SB_HC_DISABLE_C_OFFSET(port, sb_id,
					        HC_INDEX_C_ISCSI_EQ_CONS), 0);
#else
	CNIC_WR8(dev, BAR_CSTRORM_INTMEM +
		 CSTORM_SB_HC_TIMEOUT_OFFSET(port, sb_id,
					     HC_INDEX_C_ISCSI_EQ_CONS),
		 64 / 12);
	CNIC_WR16(dev, BAR_CSTRORM_INTMEM +
		  CSTORM_SB_HC_DISABLE_OFFSET(port, sb_id,
					      HC_INDEX_C_ISCSI_EQ_CONS), 0);
#endif
}

static void cnic_disable_bnx2x_int_sync(struct cnic_dev *dev)
{
}

static void cnic_get_bnx2x_iscsi_info(struct cnic_dev *dev)
{
	struct cnic_local *cp = dev->cnic_priv;
	u32 base, addr, val;
	int port = CNIC_PORT(cp);

	dev->max_iscsi_conn = 0;
	base = CNIC_RD(dev, MISC_REG_SHARED_MEM_ADDR);
	if (base < 0xa0000 || base >= 0xc0000)
		return;

	addr = BNX2X_SHMEM_ADDR(base, validity_map[port]);
	val = CNIC_RD(dev, addr);

	if (!(val & SHR_MEM_VALIDITY_LIC_NO_KEY_IN_EFFECT)) {
		u16 val16;

		addr = BNX2X_SHMEM_ADDR(base,
				drv_lic_key[port].max_iscsi_init_conn);
		val16 = CNIC_RD16(dev, addr);

		if (val16)
			val16 ^= 0x1e1e;
		dev->max_iscsi_conn = val16;
	}
	if (BNX2X_CHIP_IS_E1H(cp->chip_id)) {
		int func = CNIC_FUNC(cp);

		addr = BNX2X_SHMEM_ADDR(base,
				mf_cfg.func_mf_config[func].e1hov_tag);
		val = CNIC_RD(dev, addr);
		val &= FUNC_MF_CFG_E1HOV_TAG_MASK;
		if (val != FUNC_MF_CFG_E1HOV_TAG_DEFAULT) {
			addr = BNX2X_SHMEM_ADDR(base,
				mf_cfg.func_mf_config[func].config);
			val = CNIC_RD(dev, addr);
			val &= FUNC_MF_CFG_PROTOCOL_MASK;
			if (val != FUNC_MF_CFG_PROTOCOL_ISCSI)
				dev->max_iscsi_conn = 0;
		}
	}
}

static int cnic_start_bnx2x_hw(struct cnic_dev *dev)
{
	struct cnic_local *cp = dev->cnic_priv;
	struct cnic_eth_dev *ethdev = cp->ethdev;
	int func = CNIC_FUNC(cp), ret, i;
	int port = CNIC_PORT(cp);
	u32 start_cid = ethdev->starting_cid;
	u16 eq_idx;
	u8 sb_id = cp->status_blk_num;

	ret = cnic_init_id_tbl(&cp->cid_tbl, MAX_ISCSI_TBL_SZ, start_cid, 0);

	if (ret)
		return -ENOMEM;

	cp->kcq_io_addr = BAR_CSTRORM_INTMEM +
			  CSTORM_ISCSI_EQ_PROD_OFFSET(func, 0);
	cp->kcq_prod_idx = 0;

	cnic_get_bnx2x_iscsi_info(dev);

	/* Only 1 EQ */
	CNIC_WR16(dev, cp->kcq_io_addr, MAX_KCQ_IDX);
	CNIC_WR(dev, BAR_CSTRORM_INTMEM + 
		CSTORM_ISCSI_EQ_CONS_OFFSET(func, 0), 0);
	CNIC_WR(dev, BAR_CSTRORM_INTMEM +
		CSTORM_ISCSI_EQ_NEXT_PAGE_ADDR_OFFSET(func, 0),
		cp->kcq_info.pg_map_arr[1] & 0xffffffff);
	CNIC_WR(dev, BAR_CSTRORM_INTMEM +
		CSTORM_ISCSI_EQ_NEXT_PAGE_ADDR_OFFSET(func, 0) + 4,
		(u64) cp->kcq_info.pg_map_arr[1] >> 32);
	CNIC_WR(dev, BAR_CSTRORM_INTMEM +
		CSTORM_ISCSI_EQ_NEXT_EQE_ADDR_OFFSET(func, 0),
		cp->kcq_info.pg_map_arr[0] & 0xffffffff);
	CNIC_WR(dev, BAR_CSTRORM_INTMEM +
		CSTORM_ISCSI_EQ_NEXT_EQE_ADDR_OFFSET(func, 0) + 4,
		(u64) cp->kcq_info.pg_map_arr[0] >> 32);
	CNIC_WR8(dev, BAR_CSTRORM_INTMEM +
		CSTORM_ISCSI_EQ_NEXT_PAGE_ADDR_VALID_OFFSET(func, 0), 1);
	CNIC_WR16(dev, BAR_CSTRORM_INTMEM +
		CSTORM_ISCSI_EQ_SB_NUM_OFFSET(func, 0), cp->status_blk_num);
	CNIC_WR8(dev, BAR_CSTRORM_INTMEM +
		CSTORM_ISCSI_EQ_SB_INDEX_OFFSET(func, 0),
		HC_INDEX_C_ISCSI_EQ_CONS);

	for (i = 0; i < cp->conn_buf_info.num_pages; i++) {
		CNIC_WR(dev, BAR_TSTRORM_INTMEM +
			TSTORM_ISCSI_CONN_BUF_PBL_OFFSET(func, i),
			cp->conn_buf_info.pgtbl[2 * i]);
		CNIC_WR(dev, BAR_TSTRORM_INTMEM +
			TSTORM_ISCSI_CONN_BUF_PBL_OFFSET(func, i) + 4,
			cp->conn_buf_info.pgtbl[(2 * i) + 1]);
	}

	CNIC_WR(dev, BAR_USTRORM_INTMEM +
		USTORM_ISCSI_GLOBAL_BUF_PHYS_ADDR_OFFSET(func),
		cp->gbl_buf_info.pg_map_arr[0] & 0xffffffff);
	CNIC_WR(dev, BAR_USTRORM_INTMEM +
		USTORM_ISCSI_GLOBAL_BUF_PHYS_ADDR_OFFSET(func) + 4,
		(u64) cp->gbl_buf_info.pg_map_arr[0] >> 32);

	cnic_setup_bnx2x_context(dev);

#ifdef NEW_BNX2X_HSI
	eq_idx = CNIC_RD16(dev, BAR_CSTRORM_INTMEM +
			   CSTORM_SB_HOST_STATUS_BLOCK_C_OFFSET(port, sb_id) +
			   offsetof(struct cstorm_status_block_c,
				    index_values[HC_INDEX_C_ISCSI_EQ_CONS]));
#else
	eq_idx = CNIC_RD16(dev, BAR_CSTRORM_INTMEM +
			   CSTORM_SB_HOST_STATUS_BLOCK_OFFSET(port, sb_id) +
			   offsetof(struct cstorm_status_block,
				    index_values[HC_INDEX_C_ISCSI_EQ_CONS]));
#endif
	if (eq_idx != 0) {
		printk(KERN_ERR PFX "%s: EQ cons index %x != 0\n",
		       dev->netdev->name, eq_idx);
		return -EBUSY;
	}
	ret = cnic_init_bnx2x_irq(dev);
	if (ret)
		return ret;

	return 0;
}

static int cnic_start_hw(struct cnic_dev *dev)
{
	struct cnic_local *cp = dev->cnic_priv;
	struct cnic_eth_dev *ethdev = cp->ethdev;
	int err;

	if (test_bit(CNIC_F_CNIC_UP, &dev->flags))
		return -EALREADY;

#if !defined (__VMKLNX__)
	if (!try_module_get(ethdev->drv_owner))
		return -EBUSY;
#endif /* !defined (__VMKLNX__) */

	dev->regview = ethdev->io_base;
	cp->chip_id = ethdev->chip_id;
	pci_dev_get(dev->pcidev);
	cp->func = PCI_FUNC(dev->pcidev->devfn);
	cp->status_blk = ethdev->irq_arr[0].status_blk;
	cp->status_blk_num = ethdev->irq_arr[0].status_blk_num;

	err = cp->alloc_resc(dev);
	if (err) {
		printk(KERN_ERR PFX "%s: allocate resource failure\n",
		       dev->netdev->name);
		goto err1;
	}

	err = cp->start_hw(dev);
	if (err)
		goto err1;

	err = cnic_cm_open(dev);
	if (err)
		goto err1;

	set_bit(CNIC_F_CNIC_UP, &dev->flags);

	cp->enable_int(dev);

	return 0;

err1:
	cp->free_resc(dev);
	pci_dev_put(dev->pcidev);
#if !defined (__VMKLNX__)
	module_put(ethdev->drv_owner);
#endif /* !defined (__VMKLNX__) */
	return err;
}

static void cnic_stop_bnx2_hw(struct cnic_dev *dev)
{
	u32 val;

	cnic_disable_bnx2_int_sync(dev);

	val = cnic_reg_rd_ind(dev, BNX2_CP_SCRATCH + 0x20);
	cnic_reg_wr_ind(dev, BNX2_CP_SCRATCH + 0x20, val & ~0x1);

	val = cnic_reg_rd_ind(dev, BNX2_COM_SCRATCH + 0x20);
	cnic_reg_wr_ind(dev, BNX2_COM_SCRATCH + 0x20, val & ~0x1);

	cnic_init_context(dev, KWQ_CID);
	cnic_init_context(dev, KCQ_CID);

	cnic_setup_5709_context(dev, 0);
	cnic_free_irq(dev);

	cnic_free_resc(dev);
}

static void cnic_stop_bnx2x_hw(struct cnic_dev *dev)
{
	struct cnic_local *cp = dev->cnic_priv;
	u8 sb_id = cp->status_blk_num;
	int port = CNIC_PORT(cp);

	cnic_free_irq(dev);
#ifdef NEW_BNX2X_HSI
	CNIC_WR16(dev, BAR_CSTRORM_INTMEM +
		  CSTORM_SB_HOST_STATUS_BLOCK_C_OFFSET(port, sb_id) +
		  offsetof(struct cstorm_status_block_c,
			   index_values[HC_INDEX_C_ISCSI_EQ_CONS]),
		  0);
#else
	CNIC_WR16(dev, BAR_CSTRORM_INTMEM +
		  CSTORM_SB_HOST_STATUS_BLOCK_OFFSET(port, sb_id) +
		  offsetof(struct cstorm_status_block,
			   index_values[HC_INDEX_C_ISCSI_EQ_CONS]),
		  0);
#endif
	CNIC_WR(dev, BAR_CSTRORM_INTMEM + 
		CSTORM_ISCSI_EQ_CONS_OFFSET(cp->func, 0), 0);
	CNIC_WR16(dev, cp->kcq_io_addr, 0);
	cnic_free_resc(dev);
}

static void cnic_stop_hw(struct cnic_dev *dev)
{
	if (test_bit(CNIC_F_CNIC_UP, &dev->flags)) {
		struct cnic_local *cp = dev->cnic_priv;

		clear_bit(CNIC_F_CNIC_UP, &dev->flags);
		rcu_assign_pointer(cp->ulp_ops[CNIC_ULP_L4], NULL);
		synchronize_rcu();
		cnic_cm_shutdown(dev);
		cp->stop_hw(dev);
		pci_dev_put(dev->pcidev);
#if !defined (__VMKLNX__)
		module_put(cp->ethdev->drv_owner);
#endif /* !defined (__VMKLNX__) */
	}
}

static struct cnic_dev *alloc_cnic(struct net_device *dev)
{
	struct cnic_dev *cdev;
	struct cnic_local *cp;
	int alloc_size;

	alloc_size = sizeof(struct cnic_dev) + sizeof(struct cnic_local);

	cdev = kmalloc(alloc_size , GFP_KERNEL);
	if (cdev == NULL) {
		printk(KERN_ERR PFX "%s: allocate dev struct failure\n",
		       dev->name);
		return NULL;
	}
	memset(cdev, 0, alloc_size);

	cdev->netdev = dev;
	cdev->cnic_priv = (char *)cdev + sizeof(struct cnic_dev);
	cdev->register_device = cnic_register_device;
	cdev->unregister_device = cnic_unregister_device;
	cp = cdev->cnic_priv;
	cp->dev = cdev;

	spin_lock_init(&cp->cnic_ulp_lock);
	printk(KERN_INFO PFX "Added CNIC device: %s\n", dev->name);

	return cdev;
}

static struct cnic_dev *init_bnx2_cnic(struct net_device *dev)
{
	struct pci_dev *pdev;
	struct cnic_dev *cdev;
	struct cnic_local *cp;
	struct cnic_eth_dev *ethdev = NULL;
	struct cnic_eth_dev *(*probe)(struct net_device *) = NULL;

#if defined (__VMKLNX__)
	probe = vmk_ModuleGetSymbol("bnx2_cnic_probe");
#else  /* !defined (__VMKLNX__) */
	probe = symbol_get(bnx2_cnic_probe);
#endif  /* defined (__VMKLNX__) */
	if (probe) {
		ethdev = (*probe)(dev);
#if !defined (__VMKLNX__)
		symbol_put(bnx2_cnic_probe);
#endif  /* defined (__VMKLNX__) */
	}
	if (!ethdev)
		return NULL;

	pdev = ethdev->pdev;
	if (!pdev)
		return NULL;

	dev_hold(dev);
	pci_dev_get(pdev);
	if (pdev->device == PCI_DEVICE_ID_NX2_5709 ||
	    pdev->device == PCI_DEVICE_ID_NX2_5709S) {
		u8 rev;

		pci_read_config_byte(pdev, PCI_REVISION_ID, &rev);
		if (rev < 0x10) {
			pci_dev_put(pdev);
			goto cnic_err;
		}
	}
	pci_dev_put(pdev);

	cdev = alloc_cnic(dev);
	if (cdev == NULL)
		goto cnic_err;

	set_bit(CNIC_F_BNX2_CLASS, &cdev->flags);
	cdev->submit_kwqes = cnic_submit_bnx2_kwqes;

	cp = cdev->cnic_priv;
	cp->ethdev = ethdev;
	cdev->pcidev = pdev;

	cp->cnic_ops = &cnic_bnx2_ops;
	cp->start_hw = cnic_start_bnx2_hw;
	cp->stop_hw = cnic_stop_bnx2_hw;
	cp->setup_pgtbl = cnic_setup_page_tbl;
	cp->alloc_resc = cnic_alloc_bnx2_resc;
	cp->free_resc = cnic_free_resc;
	cp->start_cm = cnic_cm_init_bnx2_hw;
	cp->stop_cm = cnic_cm_stop_bnx2_hw;
	cp->enable_int = cnic_enable_bnx2_int;
	cp->disable_int_sync = cnic_disable_bnx2_int_sync;
	cp->close_conn = cnic_close_bnx2_conn;
	cp->next_idx = cnic_bnx2_next_idx;
	cp->hw_idx = cnic_bnx2_hw_idx;
	return cdev;

cnic_err:
	dev_put(dev);
	return NULL;
}

static struct cnic_dev *init_bnx2x_cnic(struct net_device *dev)
{
	struct pci_dev *pdev;
	struct cnic_dev *cdev;
	struct cnic_local *cp;
	struct cnic_eth_dev *ethdev = NULL;
	struct cnic_eth_dev *(*probe)(struct net_device *) = NULL;

#if defined (__VMKLNX__)
	probe = vmk_ModuleGetSymbol("bnx2x_cnic_probe");
#else /* !defined (__VMKLNX__) */
	probe = symbol_get(bnx2x_cnic_probe);
#endif  /* defined (__VMKLNX__) */
	if (probe) {
		ethdev = (*probe)(dev);
#if !defined (__VMKLNX__)
		symbol_put(bnx2x_cnic_probe);
#endif  /* defined (__VMKLNX__) */
	}
	if (!ethdev)
		return NULL;

	pdev = ethdev->pdev;
	if (!pdev)
		return NULL;

	dev_hold(dev);
	cdev = alloc_cnic(dev);
	if (cdev == NULL) {
		dev_put(dev);
		return NULL;
	}

	set_bit(CNIC_F_BNX2X_CLASS, &cdev->flags);
	cdev->submit_kwqes = cnic_submit_bnx2x_kwqes;

	cp = cdev->cnic_priv;
	cp->ethdev = ethdev;
	cdev->pcidev = pdev;

	cp->cnic_ops = &cnic_bnx2x_ops;
	cp->start_hw = cnic_start_bnx2x_hw;
	cp->stop_hw = cnic_stop_bnx2x_hw;
	cp->setup_pgtbl = cnic_setup_page_tbl_le;
	cp->alloc_resc = cnic_alloc_bnx2x_resc;
	cp->free_resc = cnic_free_resc;
	cp->start_cm = cnic_cm_init_bnx2x_hw;
	cp->stop_cm = cnic_cm_stop_bnx2x_hw;
	cp->enable_int = cnic_enable_bnx2x_int;
	cp->disable_int_sync = cnic_disable_bnx2x_int_sync;
	cp->ack_int = cnic_ack_bnx2x_msix;
	cp->close_conn = cnic_close_bnx2x_conn;
	cp->next_idx = cnic_bnx2x_next_idx;
	cp->hw_idx = cnic_bnx2x_hw_idx;
	return cdev;
}

static struct cnic_dev *is_cnic_dev(struct net_device *dev)
{
	struct ethtool_drvinfo drvinfo;
	struct cnic_dev *cdev = NULL;

	if (dev->ethtool_ops && dev->ethtool_ops->get_drvinfo) {
		memset(&drvinfo, 0, sizeof(drvinfo));
		dev->ethtool_ops->get_drvinfo(dev, &drvinfo);
		
		if (!strcmp(drvinfo.driver, "bnx2"))
			cdev = init_bnx2_cnic(dev);
		if (!strcmp(drvinfo.driver, "bnx2x"))
			cdev = init_bnx2x_cnic(dev);
		if (cdev) {
#if !defined (__VMKLNX__)
			write_lock(&cnic_dev_lock);
#endif /* !defined (__VMKLNX__) */
			list_add(&cdev->list, &cnic_dev_list);
#if !defined (__VMKLNX__)
			write_unlock(&cnic_dev_lock);
#endif /* !defined (__VMKLNX__) */
		}
	}
	return cdev;
}

/**
 * IP event handler
 */
#if !defined (__VMKLNX__)
static int cnic_ip_event(struct notifier_block *this, unsigned long event,
						 void *ptr)
{
	struct in_ifaddr *ifa = (struct in_ifaddr *) ptr;
	struct net_device *netdev = (struct net_device *) ifa->ifa_dev->dev;
	struct cnic_dev *dev;
	int if_type;
	u32 my_dev = 0;

	read_lock(&cnic_dev_lock);
	list_for_each_entry(dev, &cnic_dev_list, list) {
		if (netdev == dev->netdev) {
			my_dev = 1;
			cnic_hold(dev);
			break;
		}
	}
	read_unlock(&cnic_dev_lock);

	if (my_dev) {
		struct cnic_local *cp = dev->cnic_priv;

		rcu_read_lock();
		for (if_type = 0; if_type < MAX_CNIC_ULP_TYPE; if_type++) {
			struct cnic_ulp_ops *ulp_ops;

			ulp_ops = rcu_dereference(cp->ulp_ops[if_type]);
			if (ulp_ops) {
				void *ctx = cp->ulp_handle[if_type];

				ulp_ops->indicate_inetevent(ctx, event);
			}
		}
		rcu_read_unlock();

		cnic_put(dev);
	}

	return NOTIFY_DONE;
}

/**
 * netdev event handler
 */
static int cnic_netdev_event(struct notifier_block *this, unsigned long event,
							 void *ptr)
{
	struct net_device *netdev = ptr;
	struct cnic_dev *dev;
	int if_type;
	int new_dev = 0;

	dev = cnic_from_netdev(netdev);

	if (!dev && (event == NETDEV_REGISTER || event == NETDEV_UP)) {
		/* Check for the hot-plug device */
		dev = is_cnic_dev(netdev);
		if (dev) {
			new_dev = 1;
			cnic_hold(dev);
		}
	}
	if (dev) {
		struct cnic_local *cp = dev->cnic_priv;

		if (new_dev)
			cnic_ulp_init(dev);
		else if (event == NETDEV_UNREGISTER)
			cnic_ulp_exit(dev);

		if (event == NETDEV_UP) {
			if (cnic_register_netdev(dev) != 0) {
				cnic_put(dev);
				goto done;
			}
			set_bit(CNIC_F_IF_UP, &dev->flags);
			if (dev->use_count) {
				if (!cnic_start_hw(dev))
					cnic_ulp_start(dev);
			}
		}

		rcu_read_lock();
		for (if_type = 0; if_type < MAX_CNIC_ULP_TYPE; if_type++) {
			struct cnic_ulp_ops *ulp_ops;
			void *ctx;

			ulp_ops = rcu_dereference(cp->ulp_ops[if_type]);
			if (!ulp_ops || !ulp_ops->indicate_netevent)
				continue;

			ctx = cp->ulp_handle[if_type];

			ulp_ops->indicate_netevent(ctx, event);
		}
		rcu_read_unlock();

		if (event == NETDEV_GOING_DOWN) {
			clear_bit(CNIC_F_IF_UP, &dev->flags);
			set_bit(CNIC_F_IF_GOING_DOWN, &dev->flags);
			cnic_ulp_stop(dev);
			cnic_stop_hw(dev);
		} else if (event == NETDEV_DOWN) {
			clear_bit(CNIC_F_IF_GOING_DOWN, &dev->flags);
			cnic_unregister_netdev(dev);
		} else if (event == NETDEV_UNREGISTER) {
			write_lock(&cnic_dev_lock);
			list_del_init(&dev->list);
			write_unlock(&cnic_dev_lock);

			cnic_put(dev);
			cnic_free_dev(dev);
			goto done;
		}
		cnic_put(dev);
	}
done:
	return NOTIFY_DONE;
}

static struct notifier_block cnic_ip_notifier = {
	cnic_ip_event,
	0
};

static struct notifier_block cnic_netdev_notifier = {
	cnic_netdev_event,
	0
};
#endif /* !defined (__VMKLNX__) */

static void cnic_release(void)
{
	struct cnic_dev *dev;

	while (!list_empty(&cnic_dev_list)) {
		dev = list_entry(cnic_dev_list.next, struct cnic_dev, list);
		if (test_bit(CNIC_F_CNIC_UP, &dev->flags))
			cnic_stop_hw(dev);

		cnic_unregister_netdev(dev);
		list_del_init(&dev->list);
		cnic_free_dev(dev);
	}
}

static int __init cnic_init(void)
{
	int rc = 0;
#if defined (__VMKLNX__)
	struct net_device *dev;
#endif  /* defined (__VMKLNX__) */

	printk(KERN_INFO "%s", version);

#if defined (__VMKLNX__)
	/* Find Teton devices */
#if (LINUX_VERSION_CODE >= 0x020618)
	for_each_netdev(&init_net, dev)
#elif (LINUX_VERSION_CODE >= 0x20616)
	for_each_netdev(dev)
#else
	for (dev = dev_base; dev; dev = dev->next)
#endif
		is_cnic_dev(dev);

#else  /* !defined (__VMKLNX__) */

	rc = register_inetaddr_notifier(&cnic_ip_notifier);
	if (rc)
		cnic_release();
	rc = register_netdevice_notifier(&cnic_netdev_notifier);
	if (rc) {
		unregister_inetaddr_notifier(&cnic_ip_notifier);
		cnic_release();
	}
#endif  /* defined (__VMKLNX__) */
	return rc;
}

static void __exit cnic_exit(void)
{
#if !defined (__VMKLNX__)
	unregister_inetaddr_notifier(&cnic_ip_notifier);
	unregister_netdevice_notifier(&cnic_netdev_notifier);
#endif  /* !defined (__VMKLNX__) */
	cnic_release();
	return;
}

module_init(cnic_init);
module_exit(cnic_exit);
