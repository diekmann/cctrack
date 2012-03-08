/*******************************************************************************

   Copyright(c) 2008 - 2011 - Luca Deri <deri@ntop.org>
   Copyright(c) 2011 - Silicom Ltd

   This program is free software; you can redistribute it and/or modify it
   under the terms and conditions of the GNU General Public License,
   version 2, as published by the Free Software Foundation.

   This program is distributed in the hope it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
   FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
   more details.

   You should have received a copy of the GNU General Public License along with
   this program; if not, write to the Free Software Foundation, Inc.,
   51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

   The full GNU General Public License is included in this distribution in
  the file called "COPYING".

*******************************************************************************/

#include "../../../../../kernel/linux/pf_ring.h"

static u_int8_t dna_debug = 0;

/* Forward */
static inline void ixgbe_irq_disable(struct ixgbe_adapter *adapter);
void ixgbe_irq_enable_queues(struct ixgbe_adapter *adapter, u64 qmask);
void ixgbe_irq_disable_queues(struct ixgbe_adapter *adapter, u64 qmask);
static inline void ixgbe_release_rx_desc(struct ixgbe_ring *rx_ring, u32 val);

/* ****************************** */

void reserve_memory(unsigned long base, unsigned long len) {
  struct page *page, *page_end;

  if(unlikely(dna_debug)) printk("[DNA] reserve_memory()\n");

  page_end = virt_to_page(base + len - 1);
  for(page = virt_to_page(base); page <= page_end; page++)
    SetPageReserved(page);
}

/* ****************************** */

void unreserve_memory(unsigned long base, unsigned long len) {
  struct page *page, *page_end;

  if(unlikely(dna_debug)) printk("[DNA] unreserve_memory()\n");

  page_end = virt_to_page(base + len - 1);
  for(page = virt_to_page(base); page <= page_end; page++)
    ClearPageReserved(page);
}

/* ********************************** */

static unsigned long alloc_contiguous_memory(u_int *tot_mem_len, u_int *mem_order) {
  unsigned long mem;

  if(unlikely(dna_debug)) printk("[DNA] alloc_contiguous_memory(%d)\n", *tot_mem_len);

  *mem_order = get_order(*tot_mem_len);
  *tot_mem_len = PAGE_SIZE << *mem_order;

  mem = __get_free_pages(GFP_ATOMIC, *mem_order);

  if(mem) {
    if(unlikely(dna_debug))
      printk("[DNA] alloc_contiguous_memory: success (%d,%lu,%d)\n",
	     *tot_mem_len, mem, *mem_order);
    reserve_memory(mem, *tot_mem_len);
  } else {
    if(unlikely(dna_debug))
      printk("[DNA] alloc_contiguous_memory: failure (len=%d,order=%d)\n",
	     *tot_mem_len, *mem_order);
  }

  return(mem);
}

/* ********************************** */

static void free_contiguous_memory(unsigned long mem,
				   u_int tot_mem_len, u_int mem_order) {
  if(unlikely(dna_debug))
    printk("[DNA] free_contiguous_memory(%lu,%d,%d)\n",
	   mem, tot_mem_len, mem_order);

  if(mem != 0) {
    unreserve_memory(mem, tot_mem_len);
    free_pages(mem, mem_order);
  }
}

/* ********************************** */

static void print_adv_rx_descr(union ixgbe_adv_rx_desc	*descr) {
  if(likely(!dna_debug)) return;

  printk("[hdr_addr 0x%llx][pkt_addr 0x%llx]\n",
	 le64_to_cpu(descr->read.hdr_addr),
	 le64_to_cpu(descr->read.pkt_addr));
  printk("  stat_err 0x%x\n", le32_to_cpu(descr->wb.upper.status_error));
  printk("  length   %d\n", le16_to_cpu(descr->wb.upper.length));
  printk("  vlan     %d\n", le16_to_cpu(descr->wb.upper.vlan));
  printk("  pkt_info 0x%x\n",
	 le16_to_cpu(descr->wb.lower.lo_dword.hs_rss.pkt_info));
  printk("  hdr_info 0x%x\n",
	 le16_to_cpu(descr->wb.lower.lo_dword.hs_rss.hdr_info));
  printk("  ip_id    0x%x\n",
	 le16_to_cpu(descr->wb.lower.hi_dword.csum_ip.ip_id));
  printk("  csum     0x%x\n",
	 le16_to_cpu(descr->wb.lower.hi_dword.csum_ip.csum));
}

/* ********************************** */

/* Reset the ring when we shutdown */
void dna_cleanup_rx_ring(struct ixgbe_ring *rx_ring) {
  struct ixgbe_adapter	  *adapter = netdev_priv(rx_ring->netdev);
  struct ixgbe_hw	  *hw = &adapter->hw;
  union ixgbe_adv_rx_desc *rx_desc, *shadow_rx_desc;
  u32 tail = IXGBE_READ_REG(hw, IXGBE_RDT(rx_ring->reg_idx)), count = rx_ring->count;
  u32 head = IXGBE_READ_REG(hw, IXGBE_RDH(rx_ring->reg_idx));
  
  if(unlikely(dna_debug))
    printk("[DNA] dna_cleanup_rx_ring(%d): [head=%u][tail=%u]\n", rx_ring->queue_index, head, tail);

  /* We now point to the next slot where packets will be received */
  if(++tail == rx_ring->count) tail = 0;

  while(count > 0) {
    if(tail == head) break; /* Do not go beyond head */

    rx_desc = IXGBE_RX_DESC_ADV(rx_ring, tail);
    shadow_rx_desc = IXGBE_RX_DESC_ADV(rx_ring, tail + rx_ring->count);
    
    if(rx_desc->wb.upper.status_error != 0) {
      print_adv_rx_descr(rx_desc);
      break;
    }

    /* Writeback */
    rx_desc->wb.upper.status_error = 0;
    rx_desc->read.hdr_addr = shadow_rx_desc->read.hdr_addr, rx_desc->read.pkt_addr = shadow_rx_desc->read.pkt_addr;
    IXGBE_WRITE_REG(hw, IXGBE_RDT(rx_ring->reg_idx), tail);

    if(unlikely(dna_debug))
      printk("[DNA] dna_cleanup_rx_ring(%d): idx=%d\n", rx_ring->queue_index, tail);

    if(++tail == rx_ring->count) tail = 0;
    count--;
  }
}
/* ********************************** */

void notify_function_ptr(void *data, u_int8_t device_in_use) {
  struct ixgbe_ring	*rx_ring = (struct ixgbe_ring*)data;
  struct ixgbe_adapter	*adapter = netdev_priv(rx_ring->netdev);

  if(unlikely(dna_debug))
    printk("%s(): device_in_use = %d\n",__FUNCTION__, device_in_use);

  /* I need interrupts for purging buckets when queues are not in use */
  ixgbe_irq_enable_queues(adapter, ((u64)1 << rx_ring->q_vector->v_idx));

  if(likely(device_in_use)) {
    /* We start using this device */
    try_module_get(THIS_MODULE); /* ++ */
    rx_ring->dna.queue_in_use = 1;

    if(unlikely(dna_debug))
      printk("[DNA] %s(): %s@%d is IN use\n", __FUNCTION__,
	     rx_ring->netdev->name, rx_ring->queue_index);

    if(adapter->hw.mac.type != ixgbe_mac_82598EB)
      ixgbe_irq_disable_queues(adapter, ((u64)1 << rx_ring->q_vector->v_idx));
  } else {
    /* We're done using this device */

    dna_cleanup_rx_ring(rx_ring);

    module_put(THIS_MODULE);  /* -- */

    rx_ring->dna.queue_in_use = 0;

    if(adapter->hw.mac.type != ixgbe_mac_82598EB)
      ixgbe_irq_enable_queues(adapter, ((u64)1 << rx_ring->q_vector->v_idx));
    
    if(unlikely(dna_debug))
      printk("[DNA] %s(): %s@%d is NOT IN use\n", __FUNCTION__,
	     rx_ring->netdev->name, rx_ring->queue_index);
  }
}

/* ********************************** */

int wait_packet_function_ptr(void *data, int mode)
{
  struct ixgbe_ring		*rx_ring = (struct ixgbe_ring*)data;
  struct ixgbe_adapter	*adapter = netdev_priv(rx_ring->netdev);
  struct ixgbe_hw		*hw = &adapter->hw;
  struct ixgbe_q_vector	*q_vector = rx_ring->q_vector;

  if(unlikely(dna_debug))
    printk("%s(): enter [mode=%d/%s][queueId=%d][next_to_clean=%u][next_to_use=%d]\n",
	   __FUNCTION__, mode, mode == 1 ? "enable int" : "disable int",
	   rx_ring->queue_index, rx_ring->next_to_clean, rx_ring->next_to_use);

  if(mode == 1 /* Enable interrupt */) {
    union ixgbe_adv_rx_desc *rx_desc;
    u32	staterr;
    u8	reg_idx = rx_ring->reg_idx;
    u16	i = IXGBE_READ_REG(hw, IXGBE_RDT(reg_idx));

    /* Very important: update the value from the register set from userland */
    if(++i == rx_ring->count)
      i = 0;

    rx_ring->next_to_clean = i;

    rx_desc = IXGBE_RX_DESC_ADV(rx_ring, i);
    prefetch(rx_desc);
    staterr = le32_to_cpu(rx_desc->wb.upper.status_error);

    if(unlikely(dna_debug)) {
      printk("%s(): Check if a packet is arrived [idx=%d][staterr=%d][len=%d]\n",
	     __FUNCTION__, i, staterr, rx_desc->wb.upper.length);

      print_adv_rx_descr(rx_desc);
    }

    if(!(staterr & IXGBE_RXD_STAT_DD)) {
      rx_ring->dna.rx_tx.rx.interrupt_received = 0;

      if(!rx_ring->dna.rx_tx.rx.interrupt_enabled) {
	if(adapter->hw.mac.type != ixgbe_mac_82598EB)
	  ixgbe_irq_enable_queues(adapter, ((u64)1 << q_vector->v_idx));

	if(unlikely(dna_debug)) printk("%s(): Enabled interrupts, queue = %d\n", __FUNCTION__, q_vector->v_idx);
	rx_ring->dna.rx_tx.rx.interrupt_enabled = 1;

	if(unlikely(dna_debug))
	  printk("%s(): Packet not arrived yet: enabling "
		 "interrupts, queue=%d, i=%d\n",
		 __FUNCTION__,q_vector->v_idx, i);
      }

      /* Refresh the value */
      staterr = le32_to_cpu(rx_desc->wb.upper.status_error);
    }

    if(unlikely(dna_debug))
      printk("%s(): Packet received: %d\n", __FUNCTION__, staterr & IXGBE_RXD_STAT_DD);

    return(staterr & IXGBE_RXD_STAT_DD);
  } else {
    /* Disable interrupts */

    if(adapter->hw.mac.type != ixgbe_mac_82598EB)
      ixgbe_irq_disable_queues(adapter, ((u64)1 << q_vector->v_idx));

    rx_ring->dna.rx_tx.rx.interrupt_enabled = 0;

    if(unlikely(dna_debug))
      printk("%s(): Disabled interrupts, queue = %d\n", __FUNCTION__, q_vector->v_idx);
    return(0);
  }
}

/* ********************************** */

#define IXGBE_PCI_DEVICE_CACHE_LINE_SIZE	0x0C
#define PCI_DEVICE_CACHE_LINE_SIZE_BYTES	8

void dna_ixgbe_alloc_tx_buffers(struct ixgbe_ring *tx_ring, struct pfring_hooks *hook) {
  union ixgbe_adv_tx_desc *tx_desc, *shadow_tx_desc;
  struct ixgbe_tx_buffer *bi;
  u16 i;
  // struct ixgbe_adapter 	*adapter = netdev_priv(tx_ring->netdev);

  /* Check if the memory has been already allocated */
  if(tx_ring->dna.rx_tx.tx.packet_memory != 0) return;

  /* nothing to do or no valid netdev defined */
  if (!netdev_ring(tx_ring))
    return;

  /* We suppose that RX and TX are in sync */

  if(unlikely(dna_debug))
    printk("%s(): tx_ring->dna.rx_tx.tx.tot_packet_memory=%d\n",
	   __FUNCTION__, tx_ring->dna.tot_packet_memory);

  tx_ring->dna.rx_tx.tx.packet_memory  =
    alloc_contiguous_memory(&tx_ring->dna.tot_packet_memory,
			    &tx_ring->dna.mem_order);

  if (tx_ring->dna.rx_tx.tx.packet_memory == 0) {
    printk("\n\n%s() ERROR: not enough memory for TX DMA ring!!\n\n\n",
	   __FUNCTION__);
    return;
  }

  if(unlikely(dna_debug))
    printk("[DNA] %s(): Successfully allocated TX %u bytes at "
	   "0x%08lx [slot_len=%d]\n",__FUNCTION__,
	   tx_ring->dna.tot_packet_memory,
	   tx_ring->dna.rx_tx.tx.packet_memory,
	   tx_ring->dna.packet_slot_len);

  for(i=0; i < tx_ring->count; i++) {
    u_int offset;
    char *pkt;

    offset = i * tx_ring->dna.packet_slot_len;
    pkt = (char *)(tx_ring->dna.rx_tx.tx.packet_memory + offset);

    bi      = &tx_ring->tx_buffer_info[i];
    bi->skb = NULL;
    tx_desc = IXGBE_TX_DESC_ADV(tx_ring, i);

    if(unlikely(dna_debug))
      printk("%s(): Mapping TX slot %d of %d [pktaddr=%p][tx_desc=%p][offset=%u]\n",
	     __FUNCTION__, i, tx_ring->dna.packet_num_slots,
	     pkt, tx_desc, offset);

    bi->dma = pci_map_single(to_pci_dev(tx_ring->dev), pkt,
			     tx_ring->dna.packet_slot_len,
			     PCI_DMA_TODEVICE);

    tx_desc->read.buffer_addr = cpu_to_le64(bi->dma);
    shadow_tx_desc = IXGBE_TX_DESC_ADV(tx_ring, i + tx_ring->count);
    memcpy(shadow_tx_desc, tx_desc, sizeof(union ixgbe_adv_tx_desc));
  } /* for */
}

/* ********************************** */

void dna_reset_rx_ring(struct ixgbe_ring *rx_ring) {
  /*
    rx_ring->next_to_use   = the slot where the next incoming packet will be copied
    rx_ring->next_to_clean = the slot where the next incoming packet will be read
  */
  ixgbe_release_rx_desc(rx_ring, rx_ring->count-1 /* 0 */);

  rx_ring->next_to_clean = 0;
}

/* ********************************** */

void dna_ixgbe_alloc_rx_buffers(struct ixgbe_ring *rx_ring) {
  union ixgbe_adv_rx_desc *rx_desc, *shadow_rx_desc;
  struct ixgbe_rx_buffer *bi;
  u16 i;
  struct ixgbe_adapter 	*adapter = netdev_priv(rx_ring->netdev);
  struct ixgbe_hw	*hw = &adapter->hw;
  u16			 cache_line_size;
  struct ixgbe_ring     *tx_ring = adapter->tx_ring[rx_ring->queue_index];
  struct pfring_hooks *hook = (struct pfring_hooks*)rx_ring->netdev->pfring_ptr;

  /* Check if the memory has been already allocated */
  if(rx_ring->dna.rx_tx.rx.packet_memory != 0) return;

  /* nothing to do or no valid netdev defined */
  if (!netdev_ring(rx_ring))
    return;

  init_waitqueue_head(&rx_ring->dna.rx_tx.rx.packet_waitqueue);

  cache_line_size = cpu_to_le16(IXGBE_READ_PCIE_WORD(hw, IXGBE_PCI_DEVICE_CACHE_LINE_SIZE));
  cache_line_size &= 0x00FF;
  cache_line_size *= PCI_DEVICE_CACHE_LINE_SIZE_BYTES;

  if(unlikely(dna_debug))
    printk("%s(): pci cache line size %d\n",__FUNCTION__, cache_line_size);

  rx_ring->dna.packet_slot_len  = ALIGN(rx_ring->rx_buf_len, cache_line_size);
  rx_ring->dna.packet_num_slots = rx_ring->count;

  if (ring_is_ps_enabled(rx_ring)) {
    /* data will be put in this buffer */
    /* Original fuction allocate PAGE_SIZE/2 for this buffer*/
    rx_ring->dna.packet_slot_len  += PAGE_SIZE/2;
  }

  if(unlikely(dna_debug))
    printk("%s(): rx_ring->dna.packet_slot_len=%d\n",__FUNCTION__,
	   rx_ring->dna.packet_slot_len);

  rx_ring->dna.tot_packet_memory = rx_ring->dna.packet_slot_len * rx_ring->dna.packet_num_slots;

  if(unlikely(dna_debug))
    printk("%s(): rx_ring->dna.tot_packet_memory=%d\n",
	   __FUNCTION__, rx_ring->dna.tot_packet_memory);

  rx_ring->dna.rx_tx.rx.packet_memory  =
    alloc_contiguous_memory(&rx_ring->dna.tot_packet_memory,
			    &rx_ring->dna.mem_order);

  if (rx_ring->dna.rx_tx.rx.packet_memory == 0) {
    printk("\n\n%s() ERROR: not enough memory for RX DMA ring!!\n\n\n",
	   __FUNCTION__);
    return;
  }

  if(unlikely(dna_debug))
    printk("[DNA] %s(): Successfully allocated RX %u bytes at "
	   "0x%08lx [slot_len=%d]\n",__FUNCTION__,
	   rx_ring->dna.tot_packet_memory,
	   rx_ring->dna.rx_tx.rx.packet_memory,
	   rx_ring->dna.packet_slot_len);

  for(i=0; i < rx_ring->count; i++) {
    u_int offset;
    char *pkt;

    offset = i * rx_ring->dna.packet_slot_len;
    pkt = (char *)(rx_ring->dna.rx_tx.rx.packet_memory + offset);

    bi      = &rx_ring->rx_buffer_info[i];
    bi->skb = NULL;
    rx_desc = IXGBE_RX_DESC_ADV(rx_ring, i);

    if(unlikely(dna_debug))
      printk("%s(): Mapping RX slot %d of %d [pktaddr=%p][rx_desc=%p][offset=%u]\n",
	     __FUNCTION__, i, rx_ring->dna.packet_num_slots,
	     pkt, rx_desc, offset);

    bi->dma = pci_map_single(to_pci_dev(rx_ring->dev), pkt,
			     rx_ring->dna.packet_slot_len,
			     PCI_DMA_FROMDEVICE);

    /* See Datasheet v2.3 - 7.1.6 */
    if (!ring_is_ps_enabled(rx_ring)) {
      /* Standard MTU */
      rx_desc->read.hdr_addr = 0;
      rx_desc->read.pkt_addr = cpu_to_le64(bi->dma);
    } else {
      /* Jumbo frames */
      rx_desc->read.hdr_addr = cpu_to_le64(bi->dma);
      rx_desc->read.pkt_addr = cpu_to_le64(bi->dma + rx_ring->dna.packet_slot_len);
    }

    rx_desc->wb.upper.status_error = 0;

    shadow_rx_desc = IXGBE_RX_DESC_ADV(rx_ring, i + rx_ring->count);
    memcpy(shadow_rx_desc, rx_desc, sizeof(union ixgbe_adv_rx_desc));

    if(unlikely(dna_debug)) {
      print_adv_rx_descr(rx_desc);
      print_adv_rx_descr(shadow_rx_desc);
    }
    ixgbe_release_rx_desc(rx_ring, i);
  } /* for */

    /* Shadow */
  rx_desc = IXGBE_RX_DESC_ADV(rx_ring, 0);

  /* Register with PF_RING */
  dna_reset_rx_ring(rx_ring);

  if(unlikely(dna_debug))
  printk("[DNA] next_to_clean=%u/next_to_use=%u [register=%d]\n",
	 rx_ring->next_to_clean, rx_ring->next_to_use, IXGBE_READ_REG(hw, IXGBE_RDT(rx_ring->reg_idx)));

  /* Allocate TX memory */
  tx_ring->dna.tot_packet_memory = rx_ring->dna.tot_packet_memory;
  tx_ring->dna.packet_slot_len = rx_ring->dna.packet_slot_len;
  tx_ring->dna.packet_num_slots = rx_ring->dna.packet_num_slots;
  tx_ring->dna.mem_order = rx_ring->dna.mem_order;
  dna_ixgbe_alloc_tx_buffers(tx_ring, hook);

  hook->ring_dna_device_handler(add_device_mapping,
				/* RX */
				rx_ring->dna.rx_tx.rx.packet_memory,
				rx_ring->dna.packet_num_slots,
				rx_ring->dna.packet_slot_len,
				rx_ring->dna.tot_packet_memory,
				rx_ring->desc, /* Packet descriptors */
				rx_ring->count, /* # of items */
				sizeof(union ixgbe_adv_rx_desc),
				/* Double because of the shadow descriptors */
				2 * rx_ring->size, /* tot len (bytes) */
				/* TX */
				tx_ring->dna.rx_tx.tx.packet_memory,
				tx_ring->desc, /* Packet descriptors */
				rx_ring->queue_index, /* Channel Id */
				(void*)rx_ring->netdev->mem_start,
				rx_ring->netdev->mem_end - rx_ring->netdev->mem_start,
				rx_ring->netdev,
				intel_ixgbe,
				rx_ring->netdev->dev_addr, /* 6 bytes MAC address */
				&rx_ring->dna.rx_tx.rx.packet_waitqueue,
				&rx_ring->dna.rx_tx.rx.interrupt_received,
				(void*)rx_ring,
				wait_packet_function_ptr,
				notify_function_ptr);

  printk("[DNA] ixgbe: %s: Enabled DNA on queue %d [size=%u][count=%d]\n",
	 rx_ring->netdev->name, rx_ring->queue_index, rx_ring->size, rx_ring->count);

#if 0
  if(adapter->hw.mac.type != ixgbe_mac_82598EB)
    ixgbe_irq_disable_queues(rx_ring->q_vector->adapter, ((u64)1 << rx_ring->queue_index));
#endif
}

#undef IXGBE_PCI_DEVICE_CACHE_LINE_SIZE
#undef PCI_DEVICE_CACHE_LINE_SIZE_BYTES

/* ********************************** */

static int dna_ixgbe_rx_dump(struct ixgbe_ring *rx_ring) {
  int j, found=0;

  for(j=0; j<rx_ring->count; j++) {
    union ixgbe_adv_rx_desc *rx_desc = IXGBE_RX_DESC_ADV(rx_ring, j);

    if(rx_desc->wb.upper.status_error) {
      printk("[%d][status=%u]\n", j, rx_desc->wb.upper.status_error);
      // for(i=0; i<16; i++) printf("%02X ", ptr[i+offset] & 0xFF);
      found++;
    }
  }

  return(found);
}

/* ********************************** */

static int dna_ixgbe_clean_rx_irq(struct ixgbe_q_vector *q_vector,
				  struct ixgbe_ring *rx_ring, int budget) {
  union ixgbe_adv_rx_desc	*rx_desc, *shadow_rx_desc;
  u32				staterr;
  u16				i, num_laps = 0, last_cleaned_idx;
  struct ixgbe_adapter	        *adapter = q_vector->adapter;
  struct ixgbe_hw		*hw = &adapter->hw;
  unsigned int total_rx_packets = 0;

  last_cleaned_idx  = i = IXGBE_READ_REG(hw, IXGBE_RDT(rx_ring->reg_idx));
  if(++i == rx_ring->count)
    i = 0;

  rx_ring->next_to_clean = i;

  //i = IXGBE_READ_REG(hw, IXGBE_RDT(rx_ring->reg_idx));
  rx_desc = IXGBE_RX_DESC_ADV(rx_ring, i);
  staterr = le32_to_cpu(rx_desc->wb.upper.status_error);

  if(rx_ring->dna.queue_in_use) {
    /*
      A userland application is using the queue so it's not time to
      mess up with indexes but just to wakeup apps (if waiting)
    */

    if(staterr & IXGBE_RXD_STAT_DD) {
      if(unlikely(dna_debug))
	printk(KERN_INFO "DNA: got a packet [index=%d]!\n", i);

      if(waitqueue_active(&rx_ring->dna.rx_tx.rx.packet_waitqueue)) {
	wake_up_interruptible(&rx_ring->dna.rx_tx.rx.packet_waitqueue);
	rx_ring->dna.rx_tx.rx.interrupt_received = 1;

	if(unlikely(dna_debug))
	  printk("%s(%s): woken up ring=%d, [slot=%d] XXX\n",
		 __FUNCTION__, rx_ring->netdev->name,
		 rx_ring->reg_idx, i);
      }
    }

    // goto dump_stats;
    return(budget);
  }

  /* Only 82598 needs kernel housekeeping (82599 does not need that thanks
     to the drop bit), as the drop flag does not seem to work
  */
  if(adapter->hw.mac.type != ixgbe_mac_82598EB)
    return(budget);

  if( /* staterr || */ dna_debug) {
    if(strcmp(rx_ring->netdev->name, "eth7") == 0)
      printk("[DNA] %s(): %s@%d [used=%d][idx=%d][next_to_use=%u][#unused=%d][staterr=%d][full=%d][pkt_ptr=%llu]\n", __FUNCTION__,
	     rx_ring->netdev->name, rx_ring->queue_index,
	     rx_ring->dna.queue_in_use, i, rx_ring->next_to_use,
	     ixgbe_desc_unused(rx_ring), staterr, dna_ixgbe_rx_dump(rx_ring), rx_desc->read.pkt_addr);
  }

  /*
    This RX queue is not in use

    IMPORTANT
    We need to poll queues not in use as otherwise they will stop the operations
    also on queues where there is an application running that consumes the packets
  */
  while(staterr & IXGBE_RXD_STAT_DD) {
    shadow_rx_desc = IXGBE_RX_DESC_ADV(rx_ring, i+rx_ring->count);
    rx_desc->wb.upper.status_error = 0, last_cleaned_idx = i;
    rx_desc->read.hdr_addr = shadow_rx_desc->read.hdr_addr, rx_desc->read.pkt_addr = shadow_rx_desc->read.pkt_addr;

    rmb();

    // REMOVE BELOW
    // ixgbe_release_rx_desc(rx_ring, i); /* Not needed */

    i++, num_laps++, budget--;
    if(i == rx_ring->count)
      i = 0;

    rx_desc = IXGBE_RX_DESC_ADV(rx_ring, i);
    prefetch(rx_desc);
    staterr = le32_to_cpu(rx_desc->wb.upper.status_error);

    if(budget == 0) break;
  }

  rx_ring->stats.packets += total_rx_packets;
  // rx_ring->stats.bytes += total_rx_bytes;
  q_vector->rx.total_packets += total_rx_packets;
  // q_vector->rx.total_bytes += total_rx_bytes;

  /* Update register */
  rx_ring->next_to_clean = i, IXGBE_WRITE_REG(&adapter->hw, IXGBE_RDT(rx_ring->reg_idx), last_cleaned_idx);

  if(unlikely(dna_debug)) {
    int j=0, full = 0, other = 0, null_dma = 0;
    struct ixgbe_rx_buffer *bi;

    for(j=0; j<rx_ring->count; j++) {
      rx_desc = IXGBE_RX_DESC_ADV(rx_ring, j);
      prefetch(rx_desc);
      staterr = le32_to_cpu(rx_desc->wb.upper.status_error);

      bi = &rx_ring->rx_buffer_info[i];

      if(staterr & IXGBE_RXD_STAT_DD)
	full++;
      else if(staterr)
	other++;

      if(bi->dma == 0) null_dma++;
    }

    printk("[DNA] %s(): %s@%d [laps=%d][budget=%d][full=%d/other=%d][next_to_clean=%u][next_to_use=%d][#unused=%d][null_dma=%d]\n",
	   __FUNCTION__,
	   rx_ring->netdev->name, rx_ring->queue_index,
	   num_laps, budget, full, other,
	   rx_ring->next_to_clean, rx_ring->next_to_use,
	   ixgbe_desc_unused(rx_ring), null_dma);
  }

  return(budget);
}

