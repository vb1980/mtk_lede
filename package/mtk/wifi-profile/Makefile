#
# Copyright (C) 2016 MediaTek
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/version.mk

PKG_NAME:=wifi-profile
PKG_RELEASE:=1
PKG_BUILD_DEPENDS:=
PKG_FILE_DEPENDS:=
PKG_LICENSE:=GPL-2.0

include $(INCLUDE_DIR)/package.mk

define Package/wifi-profile
  SECTION:=MTK Properties
  CATEGORY:=MTK Properties
  SUBMENU:=Drivers
  DEPENDS:=
  TITLE:=Build WiFi l1profile.data on demand & install wifi l2 profile.
  VERSION:=$(PKG_RELEASE)-$(REVISION)
  MENU:=1
endef

define Package/wifi-profile/description
  This package helps to build l1profile on demand & install wifi l2 profile.
endef

define Package/wifi-profile/config
	if PACKAGE_wifi-profile
	source "$(SOURCE)/l1profile.config.in"
	endif
endef

define Package/wifi-profile/conffiles
/etc/wireless/mediatek/
endef

CFG_PREFIX:=CONFIG_MTK_WLAN
define Build/Compile
endef

define Package/wifi-profile/install
	$(INSTALL_DIR) $(1)/lib/wifi/
	$(INSTALL_DIR) $(1)/etc/wireless/mediatek/
	$(INSTALL_DIR) $(1)/sbin/
	$(INSTALL_BIN) ./files/common/mtwifi.lua $(1)/lib/wifi/
	$(INSTALL_BIN) ./files/common/wifi_jedi $(1)/sbin/wifi
	echo $(PKG_VERSION) > $(1)/etc/wireless/mediatek/version

	if [ "$$(CONFIG_first_card_name)" = "MT7915" -o "$$(CONFIG_second_card_name)" = "MT7915" \
		-o "$$(CONFIG_third_card_name)" = "MT7915" ] ; then \
		$(INSTALL_BIN) ./files/mt7915/l1profile.dat $(1)/etc/wireless/l1profile.dat; \
		$(INSTALL_BIN) ./files/mt7915/mt7915.*.dat $(1)/etc/wireless/mediatek/; \
		$(INSTALL_BIN) ./files/mt7915/wifi_cert.*.dat $(1)/etc/wireless/mediatek/; \
	fi
endef

$(eval $(call BuildPackage,wifi-profile))
