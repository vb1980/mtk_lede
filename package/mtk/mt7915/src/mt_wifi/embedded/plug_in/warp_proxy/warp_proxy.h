/*
 * Copyright (c) [2020], MediaTek Inc. All rights reserved.
 *
 * This software/firmware and related documentation ("MediaTek Software") are
 * protected under relevant copyright laws.
 * The information contained herein is confidential and proprietary to
 * MediaTek Inc. and/or its licensors.
 * Except as otherwise provided in the applicable licensing terms with
 * MediaTek Inc. and/or its licensors, any reproduction, modification, use or
 * disclosure of MediaTek Software, and information contained herein, in whole
 * or in part, shall be strictly prohibited.
*/
/*
 ***************************************************************************
 ***************************************************************************

	Module Name: wifi_offload
	warp_proxy.h
*/

#ifndef _WARP_PROXY_H_
#define _WARP_PROXY_H_

#include <rt_config.h>
#include <rtmp_comm.h>
#include <rt_os_util.h>
#include <rt_os_net.h>
#include <hdev/hdev_basic.h>
#include <os/rt_linux_txrx_hook.h>
#include <wifi_sys_notify.h>
#include <mcu/andes_core.h>
#include <mcu/mt_cmd.h>
#include <warp_wifi.h>

#ifdef ERR_RECOVERY
#define WIFI_MCU_INT_EVENT		WF_WFDMA_MCU_DMA1_PCI_BASE(WF_WFDMA_MCU_DMA1_HOST2MCU_SW_INT_SET_ADDR)
#define WIFI_TRIGGER_SER		MCU_INT_SER_TRIGGER_FROM_HOST
#endif

/* WIFI definition may move to wifi_profile */
#define WIFI_RING_OFFSET		0x10
#define WIFI_TX_RING_SIZE		2048
#define WIFI_PDMA_TXD_SIZE		TXD_SIZE
#define WIFI_PDMA_RXD_SIZE		RXD_SIZE
#define WIFI_TX_1ST_BUF_SIZE		128
#define WIFI_RX1_RING_SIZE		512
#define WIFI_TX_BUF_SIZE		1900
#define WIFI_RX_BUF_SIZE		1700

void client_config_atc(void *priv_data, bool enable);
void client_swap_irq(void *priv_data, u32 irq);
void client_txinfo_wrapper(u8 *tx_info, struct wlan_tx_info *info);
void client_txinfo_set_drop(u8 *tx_info);
bool client_hw_tx_allow(u8 *tx_info);
void client_tx_ring_info_dump(void *priv_data, u8 ring_id, u32 idx);
void client_warp_ver_notify(void *priv_data, u8 ver, u8 sub_ver, u8 branch, int hw_cap);
u32 client_token_rx_dmad_init(void *priv_data, void *pkt,
				unsigned long alloc_size, void *alloc_va,
				dma_addr_t alloc_pa);
int client_token_rx_dmad_lookup(void *priv_data, u32 tkn_rx_id,
				void **pkt,
				void **alloc_va, dma_addr_t *alloc_pa);
void client_rxinfo_wrapper(u8 *rx_info, struct wlan_rx_info *wlan_info);
void client_do_wifi_reset(void *priv_data);
void client_update_wo_rxcnt(void *priv_data, void *wo_rxcnt);

#endif
