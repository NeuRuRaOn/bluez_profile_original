/*
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2016-2017 Samsung Electronics Co. Ltd.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "lib/bluetooth.h"
#include "lib/uuid.h"
#include "src/plugin.h"

#include "gdbus/gdbus.h"

#include "src/adapter.h"
#include "src/device.h"
#include "src/profile.h"
#include "src/service.h"
#include "src/log.h"

#include "tds.h"

int tds_provider_adapter_probe(struct btd_profile *p,
					struct btd_adapter *adapter)
{
	DBG("+");
	tds_register_provider_interface(adapter);
	return 0;
}

void tds_provider_adapter_remove(struct btd_profile *p,
                                                struct btd_adapter *adapter)
{
	DBG("+");
	tds_unregister_provider_interface(adapter);
}

static int tds_device_probe(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	DBG("device path %s", device_get_path(device));
	btd_service_connecting_complete(service, 0);
	return 0;
}

static void tds_device_remove(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	DBG("device path %s", device_get_path(device));
	tds_seeker_disconnected(device_get_adapter(device), device);
	btd_service_disconnecting_complete(service, 0);
}

static int tds_device_accepted(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	DBG("device path %s", device_get_path(device));
	btd_service_connecting_complete(service, 0);
	return 0;
}

static int tds_device_disconnected(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	tds_seeker_disconnected(device_get_adapter(device), device);
	btd_service_disconnecting_complete(service, 0);
	return 0;
}

static struct btd_profile tds_provider = {
	.name           = "TDS Provider GATT Driver",
	.local_uuid    = TDS_UUID,
	.remote_uuid    = GATT_UUID,

	.adapter_probe  = tds_provider_adapter_probe,
	.adapter_remove = tds_provider_adapter_remove,

	.device_probe = tds_device_probe,
	.device_remove = tds_device_remove,

	.accept = tds_device_accepted,
	.disconnect = tds_device_disconnected,
};

static int tds_provider_init(void)
{
	return btd_profile_register(&tds_provider);
}

static void tds_provider_exit(void)
{
	btd_profile_unregister(&tds_provider);
}

BLUETOOTH_PLUGIN_DEFINE(tds, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
                        tds_provider_init, tds_provider_exit)
