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


#include <stdbool.h>

#include <glib.h>

#include <dbus/dbus.h>
#include <time.h>

#include "lib/bluetooth.h"
#include "lib/sdp.h"
#include "lib/uuid.h"
#include "src/plugin.h"

#include "gdbus/gdbus.h"

#include "src/error.h"
#include "src/log.h"
#include "src/adapter.h"

#include "attrib/gattrib.h"
#include "attrib/att.h"
#include "attrib/gatt.h"
#include "attrib/att-database.h"
#include "attrib/gatt-service.h"

#include "src/shared/gatt-server.h"
#include "src/attrib-server.h"
#include "src/device.h"
#include "src/profile.h"
#include "src/dbus-common.h"

#include "tds.h"

#ifdef TIZEN_FEATURE_BLUEZ_MODIFY
#include "src/shared/queue.h"
#include "src/shared/gatt-db.h"
#include "src/shared/att.h"
 #include "btio/btio.h"
#include "src/gatt-database.h"
#endif

#define TDS_USER_CHARACTERITIC_UUID		0x2af6
#define TDS_USER_CHARACTERITIC_DESCRIPTOR_UUID	0x2a56

/* TDS Block Data */
struct tds_block_data {
	uint8_t *val;
	unsigned int len;
};

/* pointer to User characteristic data */
static struct tds_block_data *ptr = NULL;

/* Adapter Instance for the provider */
struct tds_service_adapter {
	struct btd_adapter *adapter;
	struct gatt_db_attribute *service;
	GSList *connected_devices;
};

static GSList *tds_service_adapters;

struct connected_device {
        struct btd_device *device;
        struct tds_service_adapter *adapter;
        guint callback_id;
	uint16_t gatt_chr_handle;
	unsigned int timeout_id;
	bool tds_control_point_ccc_enabled;
};

static int tds_adapter_cmp(gconstpointer a, gconstpointer b)
{
	const struct tds_service_adapter *tdsadapter = a;
	const struct btd_adapter *adapter = b;

	if (tdsadapter->adapter == adapter)
		return 0;

	return -1;
}

static struct tds_service_adapter *
find_tds_service_adapter(struct btd_adapter *adapter)
{
	GSList *l = g_slist_find_custom(tds_service_adapters, adapter,
			tds_adapter_cmp);
	if (!l)
		return NULL;

	return l->data;
}

#if 0
static struct btd_device *tds_get_connected_device(struct connected_device *con_dev)
{
	return con_dev->device;
}
#endif

static int device_cmp(gconstpointer a, gconstpointer b)
{
	const struct connected_device *condev = a;
	const struct btd_device *device = b;

	if (condev->device == device)
		return 0;

	return -1;
}

static struct connected_device *
find_connected_device(struct tds_service_adapter *adapter, struct btd_device *device)
{
	GSList *l = g_slist_find_custom(adapter->connected_devices, device,
			device_cmp);
	if (!l)
		return NULL;

	return l->data;
}

static void indication_cfm_cb(void *user_data)
{
	struct connected_device *condev = user_data;
	DBG("Received confirmation of Indication Confirmation");
	g_dbus_emit_signal(btd_get_dbus_connection(), device_get_path(condev->device),
			TDS_SERVICE_PROVIDER_INTERFACE, "TdsActivationIndCnfm",
			DBUS_TYPE_INVALID);
}


static DBusMessage *tds_activation_response(DBusConnection *connection,
                                DBusMessage *msg, void *user_data)
{
	struct connected_device *condev = user_data;
	uint8_t *value;
	int32_t len = 0;
	uint8_t result = 0x04; /* Operation Failed */
	int k; /* Debug */
	uint8_t *pdu = NULL;

	DBG("+");
	if (condev->tds_control_point_ccc_enabled == false) {
		DBG("CCCD is disabled, can not send indication to remote device");
		return dbus_message_new_method_return(msg);
	}

	if (condev->timeout_id == 0) {
		DBG("Timer is not running: either no request pending or response came late!!");
		 return btd_error_failed(msg, "TDS Activation Request not pending");
	}

	/* Remove & reset Timer */
	g_source_remove(condev->timeout_id);
	condev->timeout_id =  0;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_BYTE, &result,
				DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &value, &len,
				DBUS_TYPE_INVALID))
		return btd_error_invalid_args(msg);

	DBG("Result [0x%x] data length [%d]", result, len);

	for(k=0; k < len ; k++)
		DBG("Data[%d] = [0x%x]", k, value[k]);

	switch(result) {
	case 0x00:
		DBG("Success");
		break;
	case 0x02:
		DBG("Invalid Parameter");
		break;
	case 0x03:
		DBG("Unsupported Organization ID");
		break;
	case 0x04:
		DBG("Operation Failed");
		break;
	default:
		return btd_error_invalid_args(msg);
	}

	pdu = g_malloc0(sizeof(uint8_t)* (2+ len));
	pdu[0] = 0x01; /* Opcode - TDS Control Point Activation Request */
	pdu[1] = result;

	if (len > 0) {
		memcpy(pdu+2, value, len);
	} else {
		DBG("TDS Response with no parameters");
	}

	DBG("Send Indication to device [%s], chr handle [%d]",  device_get_path(condev->device), condev->gatt_chr_handle);

	if (!bt_gatt_server_send_indication(btd_device_get_gatt_server(condev->device),
				condev->gatt_chr_handle,
				pdu, (2+len), indication_cfm_cb, condev, NULL))
		DBG("Sending Indication Failed!!");
	else
		DBG("Sending Indication Successful, wait for confirmation!!");

	g_free(pdu);
	DBG("-");
	return dbus_message_new_method_return(msg);
}

static void tds_client_remove_condev(struct connected_device *condev)
{
	struct tds_service_adapter *a;

	if (!condev)
		return;

	a = condev->adapter;
	if (condev->device)
		btd_device_unref(condev->device);

	a->connected_devices = g_slist_remove(a->connected_devices, condev);
	g_free(condev);
}

void tds_seeker_disconnected(struct btd_adapter *adapter,
					struct btd_device *device)
{
	struct tds_service_adapter *tsadapter;
	struct connected_device *condev;
	DBG("+");

	if (!device || !adapter)
		return;

	tsadapter = find_tds_service_adapter(adapter);
	if (!tsadapter)
		return;

	condev = find_connected_device(tsadapter, device);
	if (!condev)
		return;

	/* Unregister Interface */
	g_dbus_unregister_interface(btd_get_dbus_connection(),
			device_get_path(device),
			TDS_SERVICE_PROVIDER_INTERFACE);

	DBG("TDS Client remove device %p", device);
	tds_client_remove_condev(condev);
}

static const GDBusSignalTable tds_signals[] = {
        { GDBUS_SIGNAL("TdsActivationRequested",
                        GDBUS_ARGS({ "org_id", "y"},
                                        { "TdsDataBlock", "ay"})) },
	{ GDBUS_SIGNAL("TdsActivationIndCnfm", NULL) },
	{ }
};

static const GDBusMethodTable tds_methods[] = {
	{ GDBUS_ASYNC_METHOD("TdsActivationResponse",
			GDBUS_ARGS({ "result", "y" }, { "response_param", "ay" }), NULL,
			tds_activation_response) },
	{ }
};

static bool indication_wait_cb(gpointer user_data)
{
	struct connected_device *condev = (struct connected_device *)user_data;
	uint16_t len = 2;
	uint8_t pdu[2];
	DBG("Indication Timer Expired!!");
	condev->timeout_id =  0;

	if (!condev->tds_control_point_ccc_enabled) {
		DBG("CCCD is not Enabled!! No need to send indication");
		return false;
	} else {
		DBG("CCCD is Enabled!!..Send Indication with Operation Failed!");
	}

	pdu[0] = 0x01; /* Op Code: Activation Request */
	pdu[1] = 0x04; /* Result: Operation Failed*/

	DBG("Send Indication to device [%s], chr handle [%d]",  device_get_path(condev->device), condev->gatt_chr_handle);

	if (!bt_gatt_server_send_indication(btd_device_get_gatt_server(condev->device),
				condev->gatt_chr_handle,
				pdu, len, indication_cfm_cb, condev, NULL))
		DBG("Sending Indication Failed!!");
	else
		DBG("Sending Indication Successful, wait for confirmation!!");

	return false;
}

static void tds_control_point_char_write(struct gatt_db_attribute *attrib,
                                        unsigned int id, uint16_t offset,
                                        const uint8_t *value, size_t len,
                                        uint8_t opcode, struct bt_att *att,
                                        void *user_data)
{
	DBG("len [%d]", (int)len);
	DBG("Opcode [%d]", (int)opcode);
	DBG("TRansaction ID [%d]", (int)id);
	DBG("Offset [%d]", (int)offset);

	uint8_t ecode = 0;
	struct btd_device *device = NULL;
	struct tds_service_adapter *tsadapter = user_data;
	bdaddr_t bdaddr;
	uint8_t bdaddr_type;
	struct connected_device *condev = NULL;
	int k;
	const uint8_t *param = NULL;

	if (!value || len < 2) {
		ecode = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto done;
	}

	if (offset != 0) {
		ecode = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	if (!bt_att_get_remote_addr(att, &bdaddr, &bdaddr_type)) {
		ecode = BT_ATT_ERROR_UNLIKELY;
		goto done;
	}

	device = btd_adapter_get_device(tsadapter->adapter, &bdaddr, bdaddr_type);

	if (!device) {
		ecode = BT_ATT_ERROR_UNLIKELY;
		goto done;
	}
	DBG("Device path [%s]", device_get_path(device));

	/* Create Connected device and Register SIgnal Interface */
	condev = find_connected_device(tsadapter, device);

	if (!condev) {
		DBG("Device is NULL..create device");
		condev = g_new0(struct connected_device, 1);
		condev->device = btd_device_ref(device);
		condev->adapter = tsadapter;
		tsadapter->connected_devices = g_slist_append(tsadapter->connected_devices,
				condev);
		DBG("added connected dev %p", device);
		/* Register Signal on Device Interface */
		if (!g_dbus_register_interface(btd_get_dbus_connection(), device_get_path(device),
					TDS_SERVICE_PROVIDER_INTERFACE,
					tds_methods, tds_signals,
					NULL,
					condev, NULL)) {
			error("Unable to register TDS Activation Signal");
			tds_client_remove_condev(condev);
			goto done;
		}
	}

	if (condev->timeout_id) {
		DBG("Already one activation request is under progress from device [%s]", device_get_path(device));
		ecode = BT_ERROR_ALREADY_IN_PROGRESS;
		goto done;
	}

	condev->gatt_chr_handle = gatt_db_attribute_get_handle(attrib);
	DBG("Characteristic Attribute handle [0x%x]", condev->gatt_chr_handle);

	/* Write value should be anyone of 0x00, 0x01, 0x02 */
	switch(value[0]) {
	case 0x00: {
		DBG("Opcode reserved for future use");
		ecode = BT_ATT_ERROR_REQUEST_NOT_SUPPORTED;
		goto done;
	}
	case 0x01: {
		DBG("TDS Control Point Activation Request");
		break;
	}
	default: {
		DBG("Invalid Opcode [0x%x]", value[0]);
		ecode = 0x80;
		goto done;
	}
	}

	for(k=0; k < len; k++)
		DBG("@@TDS Control Point [%d] 0x%x", k, value[k]);

	/* Success case*/
	if (gatt_db_attribute_write_result(attrib, id, ecode)) {
		DBG("TDS Control Point Activation write resp sent successfully!!");
		/* Emit Signal */
		len = len -2;

		if (len > 0) {
			param = &value[2];
		}
		g_dbus_emit_signal(btd_get_dbus_connection(), device_get_path(device),
				TDS_SERVICE_PROVIDER_INTERFACE, "TdsActivationRequested",
				DBUS_TYPE_BYTE, &value[1],
				DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &param, len,
				DBUS_TYPE_INVALID);

		/* Start timer for max 10 seconds to wait for Indication from app */
		if (condev->tds_control_point_ccc_enabled) {
			DBG("Control point is enabled for device [%s] start the Indication Timer", device_get_path(device));
			if (condev->timeout_id)
				g_source_remove(condev->timeout_id);
			condev->timeout_id = g_timeout_add(10000, (GSourceFunc)indication_wait_cb, condev);
		} else {
			DBG("Control point is Not enabled for device [%s] Dont start the Indication Timer",device_get_path(device));
		}
	} else {
		DBG("TDS Control Point Activation write resp sending failed!!!");
	}

	return;
done:
	gatt_db_attribute_write_result(attrib, id, ecode);
}

static void tds_user_data_descriptor_read_cb(struct gatt_db_attribute *attrib,
                                        unsigned int id, uint16_t offset,
                                        uint8_t opcode, struct bt_att *att,
                                        void *user_data)
{
	DBG("TDS User Characteritsic descriptor Read requested..");

	if (!ptr) {
		DBG("TDS Block data still not set");
		gatt_db_attribute_read_result(attrib, id, 0, NULL, 0);
	} else {
		gatt_db_attribute_read_result(attrib, id, 0, ptr->val, ptr->len);
	}
}

static void tds_control_point_ccc_read_cb(struct gatt_db_attribute *attrib,
                                        unsigned int id, uint16_t offset,
                                        uint8_t opcode, struct bt_att *att,
                                        void *user_data)
{
	struct tds_service_adapter *adapter = user_data;
	struct btd_device *device = NULL;
	bdaddr_t bdaddr;
	uint8_t bdaddr_type;
	struct connected_device *condev = NULL;
	uint8_t ecode = 0;
	uint8_t value[2];
	DBG("TDS Control Point CCC Read requested..");

	if (!bt_att_get_remote_addr(att, &bdaddr, &bdaddr_type)) {
		ecode = BT_ATT_ERROR_UNLIKELY;
		goto done;
	}

	device = btd_adapter_get_device(adapter->adapter, &bdaddr, bdaddr_type);

	if (!device) {
		ecode = BT_ATT_ERROR_UNLIKELY;
		goto done;
	}
	DBG("Device path [%s]", device_get_path(device));

	/* Create Connected device and Register Signal Interface */
	condev = find_connected_device(adapter, device);
	if (!condev) {
		DBG("Device is not created yet, default CCCD value is Disabled");
		value[0] = 0x00;
	} else {
		DBG("CCCD is [%s] for device [%s]", condev->tds_control_point_ccc_enabled ? "Enabled" : "Disabled", device_get_path(device));
		value[0] = condev->tds_control_point_ccc_enabled;
	}

	value[1] = 0x00;

done:
	gatt_db_attribute_read_result(attrib, id, ecode, value, 2);
}


static void tds_user_char_read_cb(struct gatt_db_attribute *attrib,
                                        unsigned int id, uint16_t offset,
                                        uint8_t opcode, struct bt_att *att,
                                        void *user_data)
{
	uint8_t value[1];
	DBG("TDS user char Read requested..");
	value[0] = 0x01;
	gatt_db_attribute_read_result(attrib, id, 0, value, 1);
}

static void tds_control_point_ccc_write_cb(struct gatt_db_attribute *attrib,
                                        unsigned int id, uint16_t offset,
                                        const uint8_t *value, size_t len,
                                        uint8_t opcode, struct bt_att *att,
                                        void *user_data)
{
	struct tds_service_adapter *adapter = user_data;
	struct btd_device *device = NULL;
	bdaddr_t bdaddr;
	uint8_t bdaddr_type;
	struct connected_device *condev = NULL;
	uint8_t ecode = 0;
	DBG("TDS Control Point CCC Write requested..len [%d] val [0x%x] val [0x%x]",
			(int)len, value[0], value[1]);

	if (!value || len != 2) {
		ecode = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto done;
	}

	if (offset) {
		ecode = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	if (!bt_att_get_remote_addr(att, &bdaddr, &bdaddr_type)) {
		ecode = BT_ATT_ERROR_UNLIKELY;
		goto done;
	}

	device = btd_adapter_get_device(adapter->adapter, &bdaddr, bdaddr_type);

	if (!device) {
		ecode = BT_ATT_ERROR_UNLIKELY;
		goto done;
	}
	DBG("Device path [%s]", device_get_path(device));

	/* Create Connected device and Register Signal Interface */
	condev = find_connected_device(adapter, device);

	if (!condev) {
		DBG("Device is NULL..create device");
		condev = g_new0(struct connected_device, 1);
		condev->device = btd_device_ref(device);
		condev->adapter = adapter;
		adapter->connected_devices = g_slist_append(adapter->connected_devices,
				condev);
		DBG("added connected dev %p", device);

		/* Register Signal on Device Interface */
		if (!g_dbus_register_interface(btd_get_dbus_connection(), device_get_path(device),
					TDS_SERVICE_PROVIDER_INTERFACE,
					tds_methods, tds_signals,
					NULL,
					condev, NULL)) {
			error("Unable to register TDS Activation Signal");
			tds_client_remove_condev(condev);
			goto done;
		}
	}

	if (value[0] == 0x00) {
		DBG("CCCD is Disabled by Client [%s]", device_get_path(device));
		condev->tds_control_point_ccc_enabled = false;
	} else if (value[0] == 0x02) { /* Indication */
		if (condev->tds_control_point_ccc_enabled) {
			DBG("TDS Control point CCCD Already Enabled\n");
			goto done;
		}

		DBG("CCCD is Enabled by Client [%s]", device_get_path(device));
		condev->tds_control_point_ccc_enabled = true;
	} else
		ecode = 0x80;

	DBG("TDS Server: Control Point Enabled: [%s]\n",
			condev->tds_control_point_ccc_enabled ? "true" : "false");

done:
	gatt_db_attribute_write_result(attrib, id, ecode);
}

void tds_service_unregister(struct tds_service_adapter *tsadapter)
{
	DBG("TDS Service UnRegister..");
	struct gatt_db *db;

	/* Remove registered service */
	if (tsadapter->service) {
		db = (struct gatt_db *) btd_gatt_database_get_db(btd_adapter_get_database(tsadapter->adapter));
		gatt_db_remove_service(db, tsadapter->service);
	}

	if (ptr) {
		g_free(ptr->val);
		g_free(ptr);
		ptr = NULL;
	}
}

void tds_service_register(struct tds_service_adapter *tsadapter)
{
	DBG("TDS Service Register..");
	struct gatt_db_attribute *service, *char_tds_control, *char_user_char, *desc_tds_ccc, *desc_user;
	struct gatt_db *db;

	bt_uuid_t uuid;
	bt_uuid16_create(&uuid, TRANSPORT_DISCOVERY_SERVICE_UUID);

	db = (struct gatt_db *) btd_gatt_database_get_db(btd_adapter_get_database(tsadapter->adapter));

	/*
	 * TDS Primary Service
	 */
	service = gatt_db_add_service(db, &uuid, true, 7);
	if (!service)
		goto err;

	tsadapter->service = service;
	DBG("TDS Primary Service added");

	/*
	 * TDS Control Point characteristic.
	 */
	bt_uuid16_create(&uuid, TDS_CONTROL_POINT_CHARACTERISTIC_UUID);
	char_tds_control = gatt_db_service_add_characteristic(service, &uuid, BT_ATT_PERM_WRITE,
			BT_GATT_CHRC_PROP_WRITE | BT_GATT_CHRC_PROP_INDICATE,
			NULL, /* Non Readable */
			tds_control_point_char_write, tsadapter);

	if (!char_tds_control)
		goto err;
	DBG("TDS Control Point char added");


	bt_uuid16_create(&uuid, GATT_CLIENT_CHARAC_CFG_UUID);
	desc_tds_ccc =	gatt_db_service_add_descriptor(char_tds_control, &uuid,
			BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
			tds_control_point_ccc_read_cb,
			tds_control_point_ccc_write_cb, tsadapter);

	if (!desc_tds_ccc)
		goto err;
	DBG("TDS Control Point CCCD added");
	/*
	 * TDS User characteristic.
	 */
	bt_uuid16_create(&uuid, TDS_USER_CHARACTERITIC_UUID);
	char_user_char = gatt_db_service_add_characteristic(service, &uuid, BT_ATT_PERM_NONE,
			BT_ATT_PERM_READ,
			tds_user_char_read_cb,
			NULL, /* Non Writable */
			NULL);

	if (!char_user_char)
		goto err;

	DBG("TDS User Characteristic added");
	bt_uuid16_create(&uuid, TDS_USER_CHARACTERITIC_DESCRIPTOR_UUID);
	desc_user = gatt_db_service_add_descriptor(char_user_char, &uuid,
			BT_ATT_PERM_READ,
			tds_user_data_descriptor_read_cb,
			NULL, /* Non Writable */
			tsadapter);
	if (!desc_user)
		goto err;

	DBG("TDS User Char Descriptor added...");
	gatt_db_service_set_active(service, true);

	DBG("TDS Service activated");
	return;

err:
	error("Error adding TDS service");
	tds_service_unregister(tsadapter);
}

static DBusMessage *register_tds_proider(DBusConnection *conn, DBusMessage *msg,
                                                                void *user_data)
{
	DBG("TDS Provider Register");
	struct tds_service_adapter *tsadapter = user_data;

	if (tsadapter->adapter == NULL) {
		DBG("Adapter is NULL");
		return btd_error_invalid_args(msg);
	}

	tds_service_register(tsadapter);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *set_tds_block_data(DBusConnection *conn,
                                                DBusMessage *msg, void *data)
{
	uint8_t *value;
	int32_t len = 0;

	DBG("Set TDS Block data");

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &value, &len,
				DBUS_TYPE_INVALID))
		return btd_error_invalid_args(msg);

	/*TODO Max length to be checked*/
	if (len < 1)
		return btd_error_invalid_args(msg);

	if (ptr) {
		g_free(ptr->val);
		g_free(ptr);
	}
	ptr = g_malloc0(sizeof(struct tds_block_data));
	ptr->val = g_memdup(value, len);
	ptr->len = len;

	return dbus_message_new_method_return(msg);
}

static DBusMessage *unregister_tds_provider(DBusConnection *conn, DBusMessage *msg,
                                                                void *user_data)
{
	struct tds_service_adapter *tsadapter = user_data;

	if (tsadapter->adapter == NULL) {
		DBG("Adapter is NULL");
		return btd_error_invalid_args(msg);
	}

	tds_service_unregister(tsadapter);
	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable tds_provider_adapter_methods[] = {
	{ GDBUS_METHOD("RegisterTdsProvider", NULL, NULL,
			register_tds_proider) },
	{ GDBUS_METHOD("UnregisterTdsProvider", NULL, NULL,
			unregister_tds_provider) },
	{ GDBUS_METHOD("SetTdsBlockData",
			GDBUS_ARGS({ "value", "ay" }), NULL,
			set_tds_block_data) },
	{ }
};

void tds_unregister_provider_interface(struct btd_adapter *adapter)
{
	struct tds_service_adapter *tsadapter = find_tds_service_adapter(adapter);
	if (!tsadapter)
		return;
	DBG("+");
	tds_service_unregister(tsadapter);

	tds_service_adapters = g_slist_remove(tds_service_adapters, tsadapter);
	g_free(tsadapter);
}

void tds_register_provider_interface(struct btd_adapter *adapter)
{
	struct tds_service_adapter *tsadapter;
	const char *path = adapter_get_path(adapter);
	DBG("+");

	tsadapter = g_new0(struct tds_service_adapter, 1);
	tsadapter->adapter = adapter;

	g_dbus_register_interface(btd_get_dbus_connection(), path,
			TDS_SERVICE_PROVIDER_INTERFACE,
			tds_provider_adapter_methods,
			NULL, NULL, tsadapter, NULL);
	tds_service_adapters = g_slist_append(tds_service_adapters, tsadapter);
}
