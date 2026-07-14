/*
Luanti
Copyright (C) 2024 proller <proler@gmail.com> and contributors.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation; either version 2.1 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#pragma once


#include <map>
#include <unordered_map>
#include <shared_mutex>
#include <string>
#include <atomic>
#include "irrTypes.h"
#include "json/json.h"
#include "threading/thread.h"
#include "network/address.h"

typedef struct service_t service_t;

class lan_adv_server : public Thread
{
public:
	void *run();

	lan_adv_server();
	void ask();

	void serve(Address addr, u16 proto_min, u16 proto_max);

	Json::Value server_data;
private:
	const char* get_host_name();
	int service_callback(const mdns_string_t* name, const mdns_record_type_t type,
		const mdns_record_class_t rclass, const uint32_t ttl,
		const void* data, const size_t size, const size_t record_offset,
		const size_t record_length, void* user_data
	);
	std::string address = "";
	unsigned short server_port = 0;
	int sockets[32];
	int open_sockets = 0;
	char sendbuffer[2048];
	std::unordered_map<std::string, Json::Value> servers = {};
	service_t service;
};

class lan_adv_client : public Thread
{
	public:
		lan_adv_client();
		~lan_adv_client();
		//void *run();

		std::map<std::string, Json::Value> collected;
		std::atomic_bool fresh;
	private:
		static int lan_adv_client::response_callback(
			int sock, const struct sockaddr* from, size_t addrlen, mdns_entry_type_t entry,
			uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void* data,
			size_t size, size_t name_offset, size_t name_length, size_t record_offset,
			size_t record_length, void* user_data
		);
		int sockets[32];
		int open_sockets = 0;
		char addrbuffer[64];
		char entrybuffer[256];
		char namebuffer[256];
		char txtbuffer[256];
		
}
