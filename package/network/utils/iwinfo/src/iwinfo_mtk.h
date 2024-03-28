#ifndef __IWINFO_MTK_H_
#define __IWINFO_MTK_H_

#include <fcntl.h>

#include "iwinfo.h"
#include "iwinfo/utils.h"


#include "api/mtk.h"

int mtk_probe(const char *ifname);
int mtk_get_mode(const char *ifname, int *buf);
int mtk_get_ssid(const char *ifname, char *buf);
int mtk_get_bssid(const char *ifname, char *buf);
int mtk_get_country(const char *ifname, char *buf);
int mtk_get_channel(const char *ifname, int *buf);
int mtk_get_frequency(const char *ifname, int *buf);
int mtk_get_frequency_offset(const char *ifname, int *buf);
int mtk_get_txpower(const char *ifname, int *buf);
int mtk_get_txpower_offset(const char *ifname, int *buf);
int mtk_get_bitrate(const char *ifname, int *buf);
int mtk_get_signal(const char *ifname, int *buf);
int mtk_get_noise(const char *ifname, int *buf);
int mtk_get_quality(const char *ifname, int *buf);
int mtk_get_quality_max(const char *ifname, int *buf);
int mtk_get_enctype(const char *ifname, char *buf);
int mtk_get_encryption(const char *ifname, char *buf);
int mtk_get_phyname(const char *ifname, char *buf);
int mtk_get_assoclist(const char *ifname, char *buf, int *len);
int mtk_get_txpwrlist(const char *ifname, char *buf, int *len);
int mtk_get_scanlist(const char *ifname, char *buf, int *len);
int mtk_get_freqlist(const char *ifname, char *buf, int *len);
int mtk_get_countrylist(const char *ifname, char *buf, int *len);
int mtk_get_hwmodelist(const char *ifname, int *buf);
int mtk_get_htmodelist(const char *ifname, int *buf);
int mtk_get_mbssid_support(const char *ifname, int *buf);
int mtk_get_hardware_id(const char *ifname, char *buf);
int mtk_get_hardware_name(const char *ifname, char *buf);
void mtk_close(void);

const struct iwinfo_ops mtk_ops = {
	.name             = "mtk",
	.probe            = mtk_probe,
	.channel          = mtk_get_channel,
	.frequency        = mtk_get_frequency,
	.frequency_offset = mtk_get_frequency_offset,
	.txpower          = mtk_get_txpower,
	.txpower_offset   = mtk_get_txpower_offset,
	.bitrate          = mtk_get_bitrate,
	.signal           = mtk_get_signal,
	.noise            = mtk_get_noise,
	.quality          = mtk_get_quality,
	.quality_max      = mtk_get_quality_max,
	.mbssid_support   = mtk_get_mbssid_support,
	.hwmodelist       = mtk_get_hwmodelist,
	.htmodelist       = mtk_get_htmodelist,
	.mode             = mtk_get_mode,
	.ssid             = mtk_get_ssid,
	.bssid            = mtk_get_bssid,
	.country          = mtk_get_country,
	.hardware_id      = mtk_get_hardware_id,
	.hardware_name    = mtk_get_hardware_name,
	.encryption       = mtk_get_encryption,
	.phyname          = mtk_get_phyname,
	.assoclist        = mtk_get_assoclist,
	.txpwrlist        = mtk_get_txpwrlist,
	.scanlist         = mtk_get_scanlist,
	.freqlist         = mtk_get_freqlist,
	.countrylist      = mtk_get_countrylist,
	.close            = mtk_close
};

#endif
