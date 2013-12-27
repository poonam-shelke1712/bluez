/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#define BLUEZ_AUDIO_MTU 1024

static const char BLUEZ_AUDIO_SK_PATH[] = "\0bluez_audio_socket";

#define AUDIO_SERVICE_ID		0

#define AUDIO_STATUS_SUCCESS		0x00
#define AUDIO_STATUS_FAILED		0x01

#define AUDIO_OP_STATUS			0x00
struct audio_status {
	uint8_t code;
} __attribute__((packed));

#define AUDIO_OP_OPEN			0x01
struct audio_preset {
	uint8_t len;
	uint8_t data[0];
} __attribute__((packed));

struct audio_cmd_open {
	uint16_t uuid;
	uint8_t codec;
	uint8_t presets;
	uint8_t len;
	struct audio_preset preset[0];
} __attribute__((packed));

struct audio_rsp_open {
	uint8_t id;
} __attribute__((packed));

#define AUDIO_OP_CLOSE			0x02
struct audio_cmd_close {
	uint8_t id;
} __attribute__((packed));

#define AUDIO_OP_OPEN_STREAM		0x03
struct audio_cmd_open_stream {
	uint8_t id;
} __attribute__((packed));

struct audio_rsp_open_stream {
	uint8_t len;
	uint8_t data[0];
} __attribute__((packed));
