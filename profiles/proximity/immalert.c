/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012 Texas Instruments Corporation
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

#include <stdbool.h>

#include <glib.h>

#include <dbus/dbus.h>

#include "lib/bluetooth.h"
#include "lib/sdp.h"
#include "lib/uuid.h"

#include "gdbus/gdbus.h"

#include "src/log.h"
#include "src/adapter.h"
#include "attrib/gattrib.h"
#include "attrib/att.h"
#include "attrib/gatt.h"
#include "attrib/att-database.h"
#include "attrib/gatt-service.h"
#include "src/attrib-server.h"
#include "src/device.h"
#include "src/profile.h"
#include "src/attio.h"
#include "src/dbus-common.h"

#ifdef TIZEN_FEATURE_BLUEZ_MODIFY
#include "src/shared/queue.h"
#include "src/shared/gatt-db.h"
#include "src/shared/att.h"
 #include "btio/btio.h"
#include "src/gatt-database.h"
#endif

#include "reporter.h"
#include "immalert.h"

struct imm_alert_adapter {
	struct btd_adapter *adapter;
#ifdef TIZEN_FEATURE_BLUEZ_MODIFY
	struct gatt_db_attribute *imservice;
#endif
	GSList *connected_devices;
};

struct connected_device {
	struct btd_device *device;
	struct imm_alert_adapter *adapter;
	uint8_t alert_level;
	guint callback_id;
};

static GSList *imm_alert_adapters;

#ifdef TIZEN_FEATURE_BLUEZ_MODIFY
static bool get_dest_info(struct bt_att *att, bdaddr_t *dst, uint8_t *dst_type)
{
	GIOChannel *io = NULL;
	GError *gerr = NULL;
	int fd;

	fd = bt_att_get_fd(att);
	if (fd < 0) {
		error("failed to get fd");
		return false;
	}

	io = g_io_channel_unix_new(fd);
	if (!io)
		return false;

	bt_io_get(io, &gerr, BT_IO_OPT_DEST_BDADDR, dst,
					BT_IO_OPT_DEST_TYPE, dst_type,
					BT_IO_OPT_INVALID);

	if (gerr) {
		error("gatt: bt_io_get: %s", gerr->message);
		g_error_free(gerr);
		g_io_channel_unref(io);
		return false;
	}

	g_io_channel_unref(io);
	return true;
}
#endif

static int imdevice_cmp(gconstpointer a, gconstpointer b)
{
	const struct connected_device *condev = a;
	const struct btd_device *device = b;

	if (condev->device == device)
		return 0;

	return -1;
}

static struct connected_device *
find_connected_device(struct imm_alert_adapter *ia, struct btd_device *device)
{
	GSList *l = g_slist_find_custom(ia->connected_devices, device,
								imdevice_cmp);
	if (!l)
		return NULL;

	return l->data;
}

static int imadapter_cmp(gconstpointer a, gconstpointer b)
{
	const struct imm_alert_adapter *imadapter = a;
	const struct btd_adapter *adapter = b;

	if (imadapter->adapter == adapter)
		return 0;

	return -1;
}

static struct imm_alert_adapter *
find_imm_alert_adapter(struct btd_adapter *adapter)
{
	GSList *l = g_slist_find_custom(imm_alert_adapters, adapter,
								imadapter_cmp);
	if (!l)
		return NULL;

	return l->data;
}

const char *imm_alert_get_level(struct btd_device *device)
{
	struct imm_alert_adapter *imadapter;
	struct connected_device *condev;

	if (!device)
		return get_alert_level_string(NO_ALERT);

	imadapter = find_imm_alert_adapter(device_get_adapter(device));
	if (!imadapter)
		return get_alert_level_string(NO_ALERT);

	condev = find_connected_device(imadapter, device);
	if (!condev)
		return get_alert_level_string(NO_ALERT);

	return get_alert_level_string(condev->alert_level);
}

static void imm_alert_emit_alert_signal(struct connected_device *condev,
							uint8_t alert_level)
{
	const char *path, *alert_level_str;

	if (!condev)
		return;

	path = device_get_path(condev->device);
	alert_level_str = get_alert_level_string(alert_level);

	DBG("alert %s remote %s", alert_level_str, path);

	g_dbus_emit_property_changed(btd_get_dbus_connection(), path,
			PROXIMITY_REPORTER_INTERFACE, "ImmediateAlertLevel");
}

static void imm_alert_remove_condev(struct connected_device *condev)
{
	struct imm_alert_adapter *ia;

	if (!condev)
		return;

	ia = condev->adapter;

#ifndef TIZEN_FEATURE_BLUEZ_MODIFY
	if (condev->callback_id && condev->device)
		btd_device_remove_attio_callback(condev->device,
							condev->callback_id);
#endif

	if (condev->device)
		btd_device_unref(condev->device);

	ia->connected_devices = g_slist_remove(ia->connected_devices, condev);
	g_free(condev);
}

/* condev can be NULL */
static void imm_alert_disc_cb(gpointer user_data)
{
	struct connected_device *condev = user_data;

	if (!condev)
		return;

	DBG("immediate alert remove device %p", condev->device);

	imm_alert_emit_alert_signal(condev, NO_ALERT);
	imm_alert_remove_condev(condev);
}

#ifdef TIZEN_FEATURE_BLUEZ_MODIFY
static void imm_alert_alert_lvl_write(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct imm_alert_adapter *ia = user_data;
	struct connected_device *condev = NULL;
	uint8_t ecode = 0;
	bdaddr_t bdaddr;
	uint8_t bdaddr_type;
	struct btd_device *device = NULL;

	if (!value || len == 0) {
		ecode = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto done;
	}

	if (offset != 0) {
		ecode = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	if (!get_dest_info(att, &bdaddr, &bdaddr_type)) {
		ecode = BT_ATT_ERROR_UNLIKELY;
		goto done;
	}

	device = btd_adapter_get_device(ia->adapter, &bdaddr, bdaddr_type);
	if (!device) {
		ecode = BT_ATT_ERROR_UNLIKELY;
		goto done;
	}

	/* Write value should be anyone of 0x00, 0x01, 0x02 */
	if (value[0] > 0x02) {
		ecode = 0x80;
                goto done;
        }

	/* condev might remain NULL here if nothing is found */
	condev = find_connected_device(ia, device);

	/* Register a disconnect cb if the alert level is non-zero */
	if (value[0] != NO_ALERT && !condev) {
		condev = g_new0(struct connected_device, 1);
		condev->device = btd_device_ref(device);
		condev->adapter = ia;
		ia->connected_devices = g_slist_append(ia->connected_devices,
								condev);
		DBG("added connected dev %p", device);
	}

	if (condev) {
		if (value[0] != NO_ALERT) {
			condev->alert_level = value[0];
			imm_alert_emit_alert_signal(condev, value[0]);
		} else {
			imm_alert_emit_alert_signal(condev, value[0]);
			imm_alert_disc_cb(condev);
		}
	}

	DBG("alert level set to %d by device %p", value[0], device);
	gatt_db_attribute_write_result(attrib, id, ecode);
	return;

done:
	error("Set immediate alert level for dev %p", device);
	/* remove alerts by erroneous devices */
	imm_alert_disc_cb(condev);
	gatt_db_attribute_write_result(attrib, id, ecode);
}

void imm_alert_register(struct btd_adapter *adapter)
{
	bt_uuid_t uuid;
	struct imm_alert_adapter *imadapter;
	struct gatt_db_attribute *service, *charc;
	struct gatt_db *db;

	imadapter = g_new0(struct imm_alert_adapter, 1);
	imadapter->adapter = adapter;

	imm_alert_adapters = g_slist_append(imm_alert_adapters, imadapter);
	db = (struct gatt_db *) btd_gatt_database_get_db(btd_adapter_get_database(adapter));

	/* Immediate Alert Service */
	bt_uuid16_create(&uuid, IMMEDIATE_ALERT_SVC_UUID);
	service = gatt_db_add_service(db, &uuid, true, 3);
	if (!service)
		goto err;

	imadapter->imservice = service;

        /*
         * Alert Level characteristic.
         */
        bt_uuid16_create(&uuid, ALERT_LEVEL_CHR_UUID);
        charc = gatt_db_service_add_characteristic(service, &uuid, BT_ATT_PERM_WRITE,
						BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP,
						NULL,
						imm_alert_alert_lvl_write, imadapter);
	if (!charc)
		goto err;

	gatt_db_service_set_active(service, true);

	DBG("Immediate Alert service added");
	return;
err:
	DBG("Error adding Immediate Alert service");
	imm_alert_unregister(adapter);
}
#else
static uint8_t imm_alert_alert_lvl_write(struct attribute *a,
				struct btd_device *device, gpointer user_data)
{
	uint8_t value;
	struct imm_alert_adapter *ia = user_data;
	struct connected_device *condev = NULL;

	if (!device)
		goto set_error;

	condev = find_connected_device(ia, device);

	if (a->len == 0) {
		DBG("Illegal alert level length");
		goto set_error;
	}

	value = a->data[0];
	if (value != NO_ALERT && value != MILD_ALERT && value != HIGH_ALERT) {
		DBG("Illegal alert value");
		goto set_error;
	}

	/* Register a disconnect cb if the alert level is non-zero */
	if (value != NO_ALERT && !condev) {
		condev = g_new0(struct connected_device, 1);
		condev->device = btd_device_ref(device);
		condev->adapter = ia;
		condev->callback_id = btd_device_add_attio_callback(device,
					NULL, imm_alert_disc_cb, condev);
		ia->connected_devices = g_slist_append(ia->connected_devices,
								condev);
		DBG("added connected dev %p", device);
	}

	if (value != NO_ALERT) {
		condev->alert_level = value;
		imm_alert_emit_alert_signal(condev, value);
	}

	/*
	 * Emit NO_ALERT if the alert level was non-zero before. This is
	 * guaranteed when there's a condev.
	 */
	if (value == NO_ALERT && condev)
		imm_alert_disc_cb(condev);

	DBG("alert level set to %d by device %p", value, device);
	return 0;

set_error:
	error("Set immediate alert level for dev %p", device);
	/* remove alerts by erroneous devices */
	imm_alert_disc_cb(condev);
	return ATT_ECODE_IO;
}

void imm_alert_register(struct btd_adapter *adapter)
{
	gboolean svc_added;
	bt_uuid_t uuid;
	struct imm_alert_adapter *imadapter;

	bt_uuid16_create(&uuid, IMMEDIATE_ALERT_SVC_UUID);

	imadapter = g_new0(struct imm_alert_adapter, 1);
	imadapter->adapter = adapter;

	imm_alert_adapters = g_slist_append(imm_alert_adapters, imadapter);

	/* Immediate Alert Service */
	svc_added = gatt_service_add(adapter,
				GATT_PRIM_SVC_UUID, &uuid,
				/* Alert level characteristic */
				GATT_OPT_CHR_UUID16, ALERT_LEVEL_CHR_UUID,
				GATT_OPT_CHR_PROPS,
					GATT_CHR_PROP_WRITE_WITHOUT_RESP,
				GATT_OPT_CHR_VALUE_CB, ATTRIB_WRITE,
					imm_alert_alert_lvl_write, imadapter,
				GATT_OPT_INVALID);

	if (!svc_added) {
		imm_alert_unregister(adapter);
		return;
	}

	DBG("Immediate Alert service added");
}
#endif

static void remove_condev_list_item(gpointer data, gpointer user_data)
{
	struct connected_device *condev = data;

	imm_alert_remove_condev(condev);
}

void imm_alert_unregister(struct btd_adapter *adapter)
{
	struct imm_alert_adapter *imadapter;
#ifdef TIZEN_FEATURE_BLUEZ_MODIFY
	struct gatt_db *db;
#endif

	imadapter = find_imm_alert_adapter(adapter);
	if (!imadapter)
		return;

	g_slist_foreach(imadapter->connected_devices, remove_condev_list_item,
									NULL);
#ifdef TIZEN_FEATURE_BLUEZ_MODIFY
	/* Remove registered service */
	if (imadapter->imservice) {
		db = (struct gatt_db *) btd_gatt_database_get_db(btd_adapter_get_database(adapter));
		gatt_db_remove_service(db, imadapter->imservice);
	}
#endif

	imm_alert_adapters = g_slist_remove(imm_alert_adapters, imadapter);
	g_free(imadapter);
}
