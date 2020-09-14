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

#define TRANSPORT_DISCOVERY_SERVICE_UUID	0x1824
#define TDS_CONTROL_POINT_CHARACTERISTIC_UUID	0x2abc

#define TDS_USER_CHARACTERITIC_UUID		0x2af6
#define TDS_USER_CHARACTERITIC_DESCRIPTOR_UUID	0x2a56

#define TDS_SERVICE_PROVIDER_INTERFACE "org.bluez.TdsServiceProvider1"

void tds_register_provider_interface(struct btd_adapter *adapter);

void tds_unregister_provider_interface(struct btd_adapter *adapter);

void tds_seeker_disconnected(struct btd_adapter *adapter,
					struct btd_device *device);
