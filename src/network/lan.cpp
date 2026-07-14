/*
Luanti
Copyright (C) 2024 proller <proler@gmail.com> 2024-2026 DustyBagel

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

#include "network/lan.h"
#include "network/address.h"
#include "../lib/mdns/mdns.h"
#include "debug.h"
#include "settings.h"
#include "log.h"
#include <vector>


// Perhaps at least some of this should probably be moved to the mdns library.

// Note: get_host_name(), open_client_sockets(), and open_service_sockets()
// aswell as the ip_address_to_string() functions are copied from mdns.c
// which isn't included in this project since it just builds a command line
// tool so I should probably move them to mdns.h. That seems to make the
// most sense since that is where all the other mdns functions are.

// I wounder if if I were to switch to using Luanti's UDPSocket class
// instead of the direct socket calls if I can skip the winsock
// initialization and just run GetComputerNameA() on Windows without
// calling WSAStartup() first.
const char* service_name = "_luanti._udp.local";
const mdns_record_type_t record_type = MDNS_RECORDTYPE_PTR;

static bool dns_name_equals(const mdns_string_t& name, const char* service) {
    size_t len = strlen(service);
    if ((name.length == len) && (strncmp(name.str, service, len) == 0))
        return true;
    if ((name.length == len + 1) && (name.str[len] == '.') &&
        (strncmp(name.str, service, len) == 0))
        return true;
    return false;
}

static struct sockaddr_in service_address_ipv4;
static struct sockaddr_in6 service_address_ipv6;

// NOTE: According to the Luanti settings and my experiments, we do need to
// advertise the service on both IPv4 and IPv6 since Luanti supports joining
// on both addresses but only if ipv6_server is enabled, then we use only ipv4.
// Also, ipv6_server is ignored if a server bind address is specified. If a bind
// address is specified, then the server will only listen on that address and
// we should only advertise that address.

enum record_type {SRV, TXT, A, AAAA};
// Data for our service including the mDNS records
typedef struct {
    size_t record_count = 0;
    char* hostname_buffer = nullptr;
    char* instance_buffer = nullptr;
    char* local_hostname_buffer = nullptr;
    mdns_string_t service_instance;
	struct sockaddr_in address_ipv4;
	struct sockaddr_in6 address_ipv6;
	mdns_record_t record_ptr;
    std::vector<mdns_record_t> additional;
} service_t;

static mdns_string_t
ipv4_address_to_string(char* buffer, size_t capacity, const struct sockaddr_in* addr,
                       size_t addrlen) {
	char host[NI_MAXHOST] = {0};
	char service[NI_MAXSERV] = {0};
	int ret = getnameinfo((const struct sockaddr*)addr, (socklen_t)addrlen, host, NI_MAXHOST,
	                      service, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);
	int len = 0;
	if (ret == 0) {
		if (addr->sin_port != 0)
			len = snprintf(buffer, capacity, "%s:%s", host, service);
		else
			len = snprintf(buffer, capacity, "%s", host);
	}
	if (len >= (int)capacity)
		len = (int)capacity - 1;
	mdns_string_t str;
	str.str = buffer;
	str.length = len;
	return str;
}

static mdns_string_t
ipv6_address_to_string(char* buffer, size_t capacity, const struct sockaddr_in6* addr,
                       size_t addrlen) {
	char host[NI_MAXHOST] = {0};
	char service[NI_MAXSERV] = {0};
	int ret = getnameinfo((const struct sockaddr*)addr, (socklen_t)addrlen, host, NI_MAXHOST,
	                      service, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);
	int len = 0;
	if (ret == 0) {
		if (addr->sin6_port != 0)
			len = snprintf(buffer, capacity, "[%s]:%s", host, service);
		else
			len = snprintf(buffer, capacity, "%s", host);
	}
	if (len >= (int)capacity)
		len = (int)capacity - 1;
	mdns_string_t str;
	str.str = buffer;
	str.length = len;
	return str;
}

static mdns_string_t
ip_address_to_string(char* buffer, size_t capacity, const struct sockaddr* addr, size_t addrlen) {
	if (addr->sa_family == AF_INET6)
		return ipv6_address_to_string(buffer, capacity, (const struct sockaddr_in6*)addr, addrlen);
	return ipv4_address_to_string(buffer, capacity, (const struct sockaddr_in*)addr, addrlen);
}

// Open sockets for sending one-shot multicast queries from an ephemeral port
static int
open_client_sockets(int* sockets, int max_sockets, int port) {
	// When sending, each socket can only send to one network interface
	// Thus we need to open one socket for each interface and address family
	int num_sockets = 0;

#ifdef _WIN32

	IP_ADAPTER_ADDRESSES* adapter_address = 0;
	ULONG address_size = 8000;
	unsigned int ret;
	unsigned int num_retries = 4;
	do {
		adapter_address = (IP_ADAPTER_ADDRESSES*)malloc(address_size);
		ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, 0,
		                           adapter_address, &address_size);
		if (ret == ERROR_BUFFER_OVERFLOW) {
			free(adapter_address);
			adapter_address = 0;
			address_size *= 2;
		} else {
			break;
		}
	} while (num_retries-- > 0);

	if (!adapter_address || (ret != NO_ERROR)) {
		free(adapter_address);
		printf("Failed to get network adapter addresses\n");
		return num_sockets;
	}

	int first_ipv4 = 1;
	int first_ipv6 = 1;
	for (PIP_ADAPTER_ADDRESSES adapter = adapter_address; adapter; adapter = adapter->Next) {
		if (adapter->TunnelType == TUNNEL_TYPE_TEREDO)
			continue;
		if (adapter->OperStatus != IfOperStatusUp)
			continue;

		for (IP_ADAPTER_UNICAST_ADDRESS* unicast = adapter->FirstUnicastAddress; unicast;
		     unicast = unicast->Next) {
			if (unicast->Address.lpSockaddr->sa_family == AF_INET) {
				struct sockaddr_in* saddr = (struct sockaddr_in*)unicast->Address.lpSockaddr;
				if ((saddr->sin_addr.S_un.S_un_b.s_b1 != 127) ||
				    (saddr->sin_addr.S_un.S_un_b.s_b2 != 0) ||
				    (saddr->sin_addr.S_un.S_un_b.s_b3 != 0) ||
				    (saddr->sin_addr.S_un.S_un_b.s_b4 != 1)) {
					int log_addr = 0;
					if (first_ipv4) {
						service_address_ipv4 = *saddr;
						first_ipv4 = 0;
						log_addr = 1;
					}
					has_ipv4 = 1;
					if (num_sockets < max_sockets) {
						saddr->sin_port = htons((unsigned short)port);
						int sock = mdns_socket_open_ipv4(saddr);
						if (sock >= 0) {
							sockets[num_sockets++] = sock;
							log_addr = 1;
						} else {
							log_addr = 0;
						}
					}
					if (log_addr) {
						char buffer[128];
						mdns_string_t addr = ipv4_address_to_string(buffer, sizeof(buffer), saddr,
						                                            sizeof(struct sockaddr_in));
						printf("Local IPv4 address: %.*s\n", MDNS_STRING_FORMAT(addr));
					}
				}
			} else if (unicast->Address.lpSockaddr->sa_family == AF_INET6) {
				struct sockaddr_in6* saddr = (struct sockaddr_in6*)unicast->Address.lpSockaddr;
				// Ignore link-local addresses
				if (saddr->sin6_scope_id)
					continue;
				static const unsigned char localhost[] = {0, 0, 0, 0, 0, 0, 0, 0,
				                                          0, 0, 0, 0, 0, 0, 0, 1};
				static const unsigned char localhost_mapped[] = {0, 0, 0,    0,    0,    0, 0, 0,
				                                                 0, 0, 0xff, 0xff, 0x7f, 0, 0, 1};
				if ((unicast->DadState == NldsPreferred) &&
				    memcmp(saddr->sin6_addr.s6_addr, localhost, 16) &&
				    memcmp(saddr->sin6_addr.s6_addr, localhost_mapped, 16)) {
					int log_addr = 0;
					if (first_ipv6) {
						service_address_ipv6 = *saddr;
						first_ipv6 = 0;
						log_addr = 1;
					}
					has_ipv6 = 1;
					if (num_sockets < max_sockets) {
						saddr->sin6_port = htons((unsigned short)port);
						int sock = mdns_socket_open_ipv6(saddr);
						if (sock >= 0) {
							sockets[num_sockets++] = sock;
							log_addr = 1;
						} else {
							log_addr = 0;
						}
					}
					if (log_addr) {
						char buffer[128];
						mdns_string_t addr = ipv6_address_to_string(buffer, sizeof(buffer), saddr,
						                                            sizeof(struct sockaddr_in6));
						printf("Local IPv6 address: %.*s\n", MDNS_STRING_FORMAT(addr));
					}
				}
			}
		}
	}

	free(adapter_address);

#else

	struct ifaddrs* ifaddr = 0;
	struct ifaddrs* ifa = 0;

	if (getifaddrs(&ifaddr) < 0)
		printf("Unable to get interface addresses\n");

	int first_ipv4 = 1;
	int first_ipv6 = 1;
	for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr)
			continue;
		if (!(ifa->ifa_flags & IFF_UP) || !(ifa->ifa_flags & IFF_MULTICAST))
			continue;
		if ((ifa->ifa_flags & IFF_LOOPBACK) || (ifa->ifa_flags & IFF_POINTOPOINT))
			continue;

		if (ifa->ifa_addr->sa_family == AF_INET) {
			struct sockaddr_in* saddr = (struct sockaddr_in*)ifa->ifa_addr;
			if (saddr->sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
				int log_addr = 0;
				if (first_ipv4) {
					service_address_ipv4 = *saddr;
					first_ipv4 = 0;
					log_addr = 1;
				}
				has_ipv4 = 1;
				if (num_sockets < max_sockets) {
					saddr->sin_port = htons(port);
					int sock = mdns_socket_open_ipv4(saddr);
					if (sock >= 0) {
						sockets[num_sockets++] = sock;
						log_addr = 1;
					} else {
						log_addr = 0;
					}
				}
				if (log_addr) {
					char buffer[128];
					mdns_string_t addr = ipv4_address_to_string(buffer, sizeof(buffer), saddr,
					                                            sizeof(struct sockaddr_in));
					printf("Local IPv4 address: %.*s\n", MDNS_STRING_FORMAT(addr));
				}
			}
		} else if (ifa->ifa_addr->sa_family == AF_INET6) {
			struct sockaddr_in6* saddr = (struct sockaddr_in6*)ifa->ifa_addr;
			// Ignore link-local addresses
			if (saddr->sin6_scope_id)
				continue;
			static const unsigned char localhost[] = {0, 0, 0, 0, 0, 0, 0, 0,
			                                          0, 0, 0, 0, 0, 0, 0, 1};
			static const unsigned char localhost_mapped[] = {0, 0, 0,    0,    0,    0, 0, 0,
			                                                 0, 0, 0xff, 0xff, 0x7f, 0, 0, 1};
			if (memcmp(saddr->sin6_addr.s6_addr, localhost, 16) &&
			    memcmp(saddr->sin6_addr.s6_addr, localhost_mapped, 16)) {
				int log_addr = 0;
				if (first_ipv6) {
					service_address_ipv6 = *saddr;
					first_ipv6 = 0;
					log_addr = 1;
				}
				has_ipv6 = 1;
				if (num_sockets < max_sockets) {
					saddr->sin6_port = htons(port);
					int sock = mdns_socket_open_ipv6(saddr);
					if (sock >= 0) {
						sockets[num_sockets++] = sock;
						log_addr = 1;
					} else {
						log_addr = 0;
					}
				}
				if (log_addr) {
					char buffer[128];
					mdns_string_t addr = ipv6_address_to_string(buffer, sizeof(buffer), saddr,
					                                            sizeof(struct sockaddr_in6));
					printf("Local IPv6 address: %.*s\n", MDNS_STRING_FORMAT(addr));
				}
			}
		}
	}

	freeifaddrs(ifaddr);

#endif

	return num_sockets;
}

// Open sockets to listen to incoming mDNS queries on port 5353
static int
open_service_sockets(int* sockets, int max_sockets) {
	// When recieving, each socket can recieve data from all network interfaces
	// Thus we only need to open one socket for each address family
	int num_sockets = 0;

	// Call the client socket function to enumerate and get local addresses,
	// but not open the actual sockets
	open_client_sockets(0, 0, 0);

	if (num_sockets < max_sockets) {
		struct sockaddr_in sock_addr;
		memset(&sock_addr, 0, sizeof(struct sockaddr_in));
		sock_addr.sin_family = AF_INET;
#ifdef _WIN32
		sock_addr.sin_addr = in4addr_any;
#else
		sock_addr.sin_addr.s_addr = INADDR_ANY;
#endif
		sock_addr.sin_port = htons(MDNS_PORT);
#ifdef __APPLE__
		sock_addr.sin_len = sizeof(struct sockaddr_in);
#endif
		int sock = mdns_socket_open_ipv4(&sock_addr);
		if (sock >= 0)
			sockets[num_sockets++] = sock;
	}

	if (num_sockets < max_sockets) {
		struct sockaddr_in6 sock_addr;
		memset(&sock_addr, 0, sizeof(struct sockaddr_in6));
		sock_addr.sin6_family = AF_INET6;
		sock_addr.sin6_addr = in6addr_any;
		sock_addr.sin6_port = htons(MDNS_PORT);
#ifdef __APPLE__
		sock_addr.sin6_len = sizeof(struct sockaddr_in6);
#endif
		int sock = mdns_socket_open_ipv6(&sock_addr);
		if (sock >= 0)
			sockets[num_sockets++] = sock;
	}

	return num_sockets;
}

// Converts a C style string to a mdns_string_t.
mdns_string_t to_mdns_string(const char* __str) {
    mdns_string_t result;
    result.str = __str;
    result.length = strlen(__str);
    return result;
}

// Service
lan_adv_server::lan_adv_server(Address addr, u16 port) {
    int sockets[32];
    int num_sockets = open_service_sockets(sockets, sizeof(sockets) / sizeof(sockets[0]));
    if (num_sockets <= 0) {
        errorstream << "[LanServer] Failed to open any server sockets\n";
        return;
    }
    verbosestream << "[LanServer] Opened " << num_sockets << " socket" << (num_sockets > 1 ? "s" : "") << " for mDNS service\n";
    
	bool enable_ipv4 = true;
	bool enable_ipv6 = false;

	// It's safe to assume that if the bind_str isn't empty then
	// it's probably valid since main.cpp won't launch the server
	// unless it is and I don't see that behaivor changing for a
	// long time.
	std::string bind_str = g_settings->get("bind_address");
	bool addr_is_ipv6 = addr.isIPv6();

	if (bind_str.empty()) {
		enable_ipv4 = true
		enable_ipv6 = addr_is_ipv6;
	} else {
		enable_ipv4 = !addr_is_ipv6;
		enable_ipv6 = addr_is_ipv6;
	}
	
	service = build_service_record(enable_ipv4, enable_ipv6);
    start();
}

lan_adv_server::~lan_adv_server() {

}

// Gets the host name of the current machine. Returns a pointer to a buffer
// containing the host name, or nullptr if something went wrong. DO NOT CALL IT
// BEFORE CALLING lan_adv_server::build_service_record() since it allocates the
// uffer for the host name.
const char* lan_adv_server::get_host_name() {
    service.hostname_buffer = malloc(256);
#ifdef _WIN32

	WORD versionWanted = MAKEWORD(1, 1);
	WSADATA wsaData;
	if (WSAStartup(versionWanted, &wsaData)) {
		errorstream << "[Lan] Failed to initialize WinSock\n";
		return nullptr;
	}

	DWORD hostname_size = (DWORD)sizeof(*service.hostname_buffer);
	if (!GetComputerNameA(*service.hostname_buffer, &hostname_size)) {
        errorstream << "[Lan] Failed to get host name\n";
        return nullptr;
    }


#else
	size_t hostname_size = sizeof(*service.hostname_buffer);
	if (gethostname(*service.hostname_buffer, hostname_size) != 0) {
		errorstream << "[Lan] Failed to get host name\n";
        return nullptr;
    }
#endif
	return &service.hostname_buffer;
}

service_t lan_adv_server::build_service_record(bool allow_ipv4, bool allow_ipv6) {
    // We don't actually use some of these record types ourselves, but we need
    // them for compatablility with other mDNS applications.
    service_t service = {};

    if (!allow_ipv4 && !allow_ipv6) {
        errorstream << "[LanServer] No IP address families allowed for mDNS "
                    << "service.\n This should never happen and if it does, "
                    << "something is set up wrong.";
        return service;
    }

    const char* hostname = get_host_name();
    mdns_string_t hostname_str = to_mdns_string(hostname);

    int offset = hostname_str.length - 1;
    service.instance_buffer = malloc(
        sizeof(char) * (
            hostname_str.length + service_name.length
        )
    );
    memcpy(service.instance_buffer, hostname_str.str, offset);
    service.instance_buffer[offset] = '.';
    offset += 1;
    memcpy(service.instance_buffer + offset, service_name.str, service_name.length);

    mdns_string_t service_instance;
    service_instance.str = service.instance_buffer;
    service_instance.length = strlen(service.instance_buffer);

    const char* hn = get_host_name();
    mdns_string_t hostname;
    hostname.str = hn;
    hostname.length = strlen(hn);

    service.local_hostname_buffer = malloc(
        sizeof(char) * (hostname_str.length + 6)
    );
    offset = hostname_str.length - 1;
    memcpy(service.local_hostname_buffer, hostname_str.str, offset);
    memcpy(service.local_hostname_buffer + offset, ".local", 7);

    service.service_instance = service_instance;
    service.address_ipv4 = service_address_ipv4;
    service.address_ipv6 = service_address_ipv6;

    // Setup our mDNS records

    // PTR record reverse mapping "<_service-name>._tcp.local." to
    // "<hostname>.<_service-name>._tcp.local."
    service.record_ptr = mdns_record_t();
    service.record_ptr.name = service_name;
    service.record_ptr.type = MDNS_RECORDTYPE_PTR;
    service.record_ptr.data.ptr.name = service.service_instance;
    service.record_ptr.rclass = 0;
    service.record_ptr.ttl = 0;

    service.additional.resize(3);
    service.record_count = 3;

    // SRV record mapping "<hostname>.<_service-name>._tcp.local." to
    // "<hostname>.local." with port. Set weight & priority to 0.
    service.additional[SRV] = mdns_record_t();
    service.additional[SRV].name = service.service_instance;
    service.additional[SRV].type = MDNS_RECORDTYPE_SRV;
    service.additional[SRV].data.srv.name = service.hostname_qualified;
    service.additional[SRV].data.srv.port = service.port;
    service.additional[SRV].data.srv.priority = 0;
    service.additional[SRV].data.srv.weight = 0;
    service.additional[SRV].rclass = 0;
    service.additional[SRV].ttl = 0;


    // A/AAAA records mapping "<hostname>.local." to IPv4/IPv6 addresses
    if (allow_ipv4) {
        service.additional[A] = mdns_record_t();
        service.additional[A].name = service.hostname_qualified;
        service.additional[A].type = MDNS_RECORDTYPE_A;
        service.additional[A].data.a.addr = service.address_ipv4;
        service.additional[A].rclass = 0;
        service.additional[A].ttl = 0;
        service.record_count++;
        service.additional.resize(service.record_count);
    }
    
    if (allow_ipv6) {
        service.additional[service.record_index] = mdns_record_t();
        service.additional[service.record_index].name = service.hostname_qualified;
        service.additional[service.record_index].type = MDNS_RECORDTYPE_AAAA;
        service.additional[service.record_index].data.aaaa.addr = service.address_ipv6;
        service.additional[service.record_index].rclass = 0;
        service.additional[service.record_index].ttl = 0;
    }

    // Build the server data JSON string to be sent in the TXT record.
    /*Json::Value server = ServerList::getServerData(
        ServerList::AnnounceAction::ANNOUNCE_START,
        server_port,
        Server::getClientNames(),
        Server::getUptime(),
        Server::getGameTime(),
        Server::getLagEstimate(),
        g_settings->get("server_gameid"),
        g_settings->get("mg_name"),
        Server::getModSpecs(),
        Server::isDedicated()
    );*/
    server_data["name"] = g_settings->get("server_name");
    server_data["description"] = g_settings->get("server_description");
    server_data["version"] = g_version_string;
    server_data["url"] = g_settings->get("server_url");
    server_data["creative"] = g_settings->getBool("creative_mode");
    server_data["damage"] = g_settings->getBool("enable_damage");
    server_data["password"] = g_settings->getBool("disallow_empty_password");
    server_data["pvp"] = g_settings->getBool("enable_pvp");
    server_data["port"] = server_port;
    server_data["clients"] = clients_num.load();
    server_data["clients_max"] = g_settings->getU16("max_users");
    server_data["proto"] = "luanti";

    std::string server_data_str = fastWriteJson(server_data);

    mdns_string_t key;
    key.str = "server_data";
    key.length = strlen(key.str);
    mdns_string_t value;
    value.str = server_data_str.c_str();
    value.length = server_data_str.size();

    // The server data can go here.
    service.additional[TXT] = mdns_record_t();
    service.additional[TXT].name = service.service_instance;
    service.additional[TXT].type = MDNS_RECORDTYPE_TXT;
    service.additional[TXT].data.txt.key = key;
    service.additional[TXT].data.txt.value = value;
    service.additional[TXT].rclass = 0;
    service.additional[TXT].ttl = 0;

    return service;
}

static int service_callback(
    int sock, const struct sockaddr* from, size_t addrlen,
    mdns_entry_type_t entry, uint16_t query_id, uint16_t rtype,
    uint16_t rclass, uint32_t ttl, const void* data, size_t size,
    size_t name_offset, size_t name_length, size_t record_offset,
    size_t record_length, void* user_data
) {
    // Note: When responding to queries in which we are the ones advertising
    // a service for, it would make since that we are the authoritative source
    // for that information but I don't know if it's required in mDNS. From
    // what I've been told, it isn't strictly necessary but I NEED to do more
    // research on that. This is only needed for other things that use mDNS,
    // I don't currently believe that we need it for our service to work.
    char addrbuffer[64];
    char namebuffer[256];

	if (entry != MDNS_ENTRYTYPE_QUESTION)
		return 0;

	const char dns_sd[] = "_services._dns-sd._udp.local.";
	const service_t* service = (const service_t*)user_data;

	mdns_string_t fromaddrstr = ip_address_to_string(addrbuffer, sizeof(addrbuffer), from, addrlen);

	size_t offset = name_offset;
	mdns_string_t name = mdns_string_extract(data, size, &offset, namebuffer, sizeof(namebuffer));

	const char* record_name = 0;
	if (rtype == MDNS_RECORDTYPE_PTR)
		record_name = "PTR";
	else if (rtype == MDNS_RECORDTYPE_SRV)
		record_name = "SRV";
	else if (rtype == MDNS_RECORDTYPE_A)
		record_name = "A";
	else if (rtype == MDNS_RECORDTYPE_AAAA)
		record_name = "AAAA";
	else if (rtype == MDNS_RECORDTYPE_TXT)
		record_name = "TXT";
	else if (rtype == MDNS_RECORDTYPE_ANY)
		record_name = "ANY";
	else
		return 0;
	printf("Query %s %.*s\n", record_name, MDNS_STRING_FORMAT(name));

	if ((name.length == (sizeof(dns_sd) - 1)) &&
	    (strncmp(name.str, dns_sd, sizeof(dns_sd) - 1) == 0)) {
		if ((rtype == MDNS_RECORDTYPE_PTR) || (rtype == MDNS_RECORDTYPE_ANY)) {
			// The PTR query was for the DNS-SD domain, send answer with a PTR record for the
			// service name we advertise, typically on the "<_service-name>._tcp.local." format

			// Answer PTR record reverse mapping "<_service-name>._tcp.local." to
			// "<hostname>.<_service-name>._tcp.local."

			// Send the answer, unicast or multicast depending on flag in query
			uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
			printf("  --> answer %.*s (%s)\n", MDNS_STRING_FORMAT(service->record_ptr.data.ptr.name),
			       (unicast ? "unicast" : "multicast"));

			if (unicast) {
				mdns_query_answer_unicast(
                    sock, from, addrlen, sendbuffer, sizeof(sendbuffer),
				    query_id, rtype, name.str, name.length, service->record_ptr,
                    0, 0, 0, 0
                );
			} else {
				mdns_query_answer_multicast(
                    sock, sendbuffer, sizeof(sendbuffer), service->record_ptr,
                    0, 0, 0, 0
                );
			}
		}
	} else if ((name.length == service->service.length) &&
	           (strncmp(name.str, service->service.str, name.length) == 0)) {
		if ((rtype == MDNS_RECORDTYPE_PTR) || (rtype == MDNS_RECORDTYPE_ANY)) {
			// The PTR query was for our service (usually "<_service-name._tcp.local"), answer a PTR
			// record reverse mapping the queried service name to our service instance name
			// (typically on the "<hostname>.<_service-name>._tcp.local." format), and add
			// additional records containing the SRV record mapping the service instance name to our
			// qualified hostname (typically "<hostname>.local.") and port, as well as any IPv4/IPv6
			// address for the hostname as A/AAAA records, and two test TXT records

			// Answer PTR record reverse mapping "<_service-name>._tcp.local." to
			// "<hostname>.<_service-name>._tcp.local."

			// SRV record mapping "<hostname>.<_service-name>._tcp.local." to
			// "<hostname>.local." with port. Set weight & priority to 0.

			// A/AAAA records mapping "<hostname>.local." to IPv4/IPv6 addresses

			// Send the answer, unicast or multicast depending on flag in query
			uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
			printf("  --> answer %.*s (%s)\n",
			       MDNS_STRING_FORMAT(service->record_ptr.data.ptr.name),
			       (unicast ? "unicast" : "multicast"));

			if (unicast) {
				mdns_query_answer_unicast(
                    sock, from, addrlen, sendbuffer, sizeof(sendbuffer),
                    query_id, rtype, name.str, name.length,
                    service->record_ptr, 0, 0, service->additional[TXT], 1
                );
			} else {
				mdns_query_answer_multicast(
                    sock, sendbuffer, sizeof(sendbuffer), service->record_ptr, 0,
                    0, service->additional[TXT], 1
                );
			}
		}
	} else if ((name.length == service->service_instance.length) &&
	           (strncmp(name.str, service->service_instance.str, name.length) == 0)) {
		if ((rtype == MDNS_RECORDTYPE_SRV) || (rtype == MDNS_RECORDTYPE_ANY)) {
			// The SRV query was for our service instance (usually
			// "<hostname>.<_service-name._tcp.local"), answer a SRV record mapping the service
			// instance name to our qualified hostname (typically "<hostname>.local.") and port, as
			// well as any IPv4/IPv6 address for the hostname as A/AAAA records, and two test TXT
			// records

			// Answer PTR record reverse mapping "<_service-name>._tcp.local." to
			// "<hostname>.<_service-name>._tcp.local."

			// A/AAAA records mapping "<hostname>.local." to IPv4/IPv6 addresses

			// Send the answer, unicast or multicast depending on flag in query
			uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
			printf("  --> answer %.*s port %d (%s)\n",
			       MDNS_STRING_FORMAT(service->record_srv.data.srv.name), service->port,
			       (unicast ? "unicast" : "multicast"));

			if (unicast) {
				mdns_query_answer_unicast(
                    sock, from, addrlen, sendbuffer, sizeof(sendbuffer),
                    query_id, rtype, name.str, name.length,
                    service->additional[SRV], 0, 0, 0, 0
                );
			} else {
				mdns_query_answer_multicast(
                    sock, sendbuffer, sizeof(sendbuffer),
                    service->additional[SRV], 0, 0, 0, 0
                );
			}
        }
    // NOTE: I'm not sure how to handle A/AAAA records yet. Luanti allows you
    // you to connect on ipv4 and ipv6 but not in all circumstances. This
    // creates a difficult situation; do we advertise on both ipv4 and ipv6
    // regardless if the server is acutally available on both and if we do then
    // we can only respond with the record type for the available address to
    // connect to.
	} else if ((name.length == service->hostname_qualified.length) &&
	           (strncmp(name.str, service->hostname_qualified.str, name.length) == 0)) {
		if (((rtype == MDNS_RECORDTYPE_A) || (rtype == MDNS_RECORDTYPE_ANY)) &&
		    (service->address_ipv4.sin_family == AF_INET)) {
			// The A query was for our qualified hostname (typically "<hostname>.local.") and we
			// have an IPv4 address, answer with an A record mappiing the hostname to an IPv4
			// address, as well as any IPv6 address for the hostname, and two test TXT records

			// Answer A records mapping "<hostname>.local." to IPv4 address
			mdns_record_t answer = service->additional[A];

			// AAAA record mapping "<hostname>.local." to IPv6 addresses
			//if (service->address_ipv6.sin6_family == AF_INET6)
			//	additional[additional_count++] = service->record_aaaa;

			// Send the answer, unicast or multicast depending on flag in query
			uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
			mdns_string_t addrstr = ip_address_to_string(
			    addrbuffer, sizeof(addrbuffer), (struct sockaddr*)&service->record_a.data.a.addr,
			    sizeof(service->record_a.data.a.addr));
			printf("  --> answer %.*s IPv4 %.*s (%s)\n", MDNS_STRING_FORMAT(service->record_a.name),
			       MDNS_STRING_FORMAT(addrstr), (unicast ? "unicast" : "multicast"));

			if (unicast) {
				mdns_query_answer_unicast(
                    sock, from, addrlen, sendbuffer, sizeof(sendbuffer),
				    query_id, rtype, name.str, name.length, answer, 0, 0, 0, 0
                );
			} else {
				mdns_query_answer_multicast(
                    sock, sendbuffer, sizeof(sendbuffer), answer, 0, 0, 0, 0
                );
			}
		} else if (((rtype == MDNS_RECORDTYPE_AAAA) || (rtype == MDNS_RECORDTYPE_ANY)) &&
		           (service->address_ipv6.sin6_family == AF_INET6)) {
			// The AAAA query was for our qualified hostname (typically "<hostname>.local.") and we
			// have an IPv6 address, answer with an AAAA record mappiing the hostname to an IPv6
			// address, as well as any IPv4 address for the hostname, and two test TXT records

			// Answer AAAA records mapping "<hostname>.local." to IPv6 address
			mdns_record_t answer = service->additional[AAAA];

			// A record mapping "<hostname>.local." to IPv4 addresses
			//if (service->address_ipv4.sin_family == AF_INET)
			//	additional[additional_count++] = service->record_a;

			// Send the answer, unicast or multicast depending on flag in query
			uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
			mdns_string_t addrstr =
			    ip_address_to_string(addrbuffer, sizeof(addrbuffer),
			                         (struct sockaddr*)&service->record_aaaa.data.aaaa.addr,
			                         sizeof(service->record_aaaa.data.aaaa.addr));
			printf("  --> answer %.*s IPv6 %.*s (%s)\n",
			       MDNS_STRING_FORMAT(service->record_aaaa.name), MDNS_STRING_FORMAT(addrstr),
			       (unicast ? "unicast" : "multicast"));

			if (unicast) {
				mdns_query_answer_unicast(
                    sock, from, addrlen, sendbuffer, sizeof(sendbuffer),
				    query_id, rtype, name.str, name.length, answer, 0, 0, 0, 0
                );
			} else {
				mdns_query_answer_multicast(
                    sock, sendbuffer, sizeof(sendbuffer), answer, 0, 0, 0, 0
                );
			}
		} else if ((rtype == MDNS_RECORDTYPE_TXT) || (rtype == MDNS_RECORDTYPE_ANY)) {
   			// The A query was for our qualified hostname (typically "<hostname>.local."),
			// answer with an TXT record mappiing the hostname to the TXT record(s).
			mdns_record_t answer = service->additional[TXT];

			// A record mapping "<hostname>.local." to IPv4 addresses
			//if (service->address_ipv4.sin_family == AF_INET)
			//	additional[additional_count++] = service->record_a;

			// Send the answer, unicast or multicast depending on flag in query
			uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
			mdns_string_t addrstr =
			    ip_address_to_string(addrbuffer, sizeof(addrbuffer),
			                         (struct sockaddr*)&service->record_aaaa.data.aaaa.addr,
			                         sizeof(service->record_aaaa.data.aaaa.addr));
			printf("  --> answer %.*s IPv6 %.*s (%s)\n",
			       MDNS_STRING_FORMAT(service->record_aaaa.name), MDNS_STRING_FORMAT(addrstr),
			       (unicast ? "unicast" : "multicast"));

			if (unicast) {
				mdns_query_answer_unicast(
                    sock, from, addrlen, sendbuffer, sizeof(sendbuffer),
				    query_id, rtype, name.str, name.length, answer, 0, 0, 0, 0
                );
			} else {
				mdns_query_answer_multicast(
                    sock, sendbuffer, sizeof(sendbuffer), answer, 0, 0, 0, 0
                );
			}
        }
	}
	return 0;
}

void lan_adv_server::*run() {
    BEGIN_DEBUG_EXCEPTION_HANDLER;

    setName("lan_adv_server");

    const char* hostname = get_host_name();


    printf("Opened %d socket%s for mDNS service\n", num_sockets, num_sockets > 1 ? "s" : "");

    infostream << "[Lan] Service mDNS: " << service_name << ":" << server_port << std::endl;
    infostream << "[Lan] Hostname: " << hostname << std::endl;

    size_t capacity = 2048;
    void* buffer = malloc(capacity);

    actionstream << "[Lan] Sending Lan announce.\n";
    for (int isock = 0; isock < num_sockets; ++isock)
        mdns_announce_multicast(
            sockets[isock], buffer, capacity, service.record_ptr, 0, 0,
            service.additional.data(), service.additional.size()
        );

    // This is a crude implementation that checks for incoming queries
    while (isRunning() && !stopRequested()) {
        server_data["clients"] = clients_num.load();
        std::string server_data_str = fastWriteJson(server_data);
        service.additional[TXT].data.txt.value.str = server_data_str.c_str();
        service.additional[TXT].data.txt.value.length = server_data_str.size();

        int nfds = 0;
        fd_set readfs;
        FD_ZERO(&readfs);
        for (int isock = 0; isock < num_sockets; ++isock) {
            if (sockets[isock] >= nfds)
                nfds = sockets[isock] + 1;
            FD_SET(sockets[isock], &readfs);
        }

        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 100_000; // 100 ms

        if (select(nfds, &readfs, 0, 0, &timeout) >= 0) {
            for (int isock = 0; isock < num_sockets; ++isock) {
                if (FD_ISSET(sockets[isock], &readfs)) {
                    mdns_socket_listen(
                        sockets[isock], buffer, capacity, service_callback,
                        &service
                    );
                }
                FD_SET(sockets[isock], &readfs);
            }
        } else {
            errorstream << "[LanServer] select() failed: " << strerror(errno) << "\n";
        }
    }

    // Send a goodbye on end of service
    {
        actionstream << "[Lan] Sending server goodbye.\n";

        for (int isock = 0; isock < num_sockets; ++isock)
            mdns_goodbye_multicast(
                sockets[isock], buffer, capacity, service.record_ptr, 0, 0,
                service.additional.data(), service.additional.size()
            );
    }

    free(buffer);
    free(service.instance_buffer);
    free(service.local_hostname_buffer);
    free(service.hostname_buffer);

    for (int isock = 0; isock < num_sockets; ++isock)
        mdns_socket_close(sockets[isock]);
    verbosestream << "[Lan] Closed socket%s\n" << (num_sockets > 1 ? "s" : "") << "\n";

    END_DEBUG_EXCEPTION_HANDLER;

    return nullptr;
}

// Client
lan_adv_client::lan_adv_client() {
    int sockets[32];
    int num_sockets = open_clients_sockets(sockets, sizeof(sockets) / sizeof(sockets[0]));
    if (num_sockets <= 0) {
        errorstream << "[LanClient] Failed to open any server sockets\n";
        return;
    }
    verbosestream << "[LanClient] Opened " << num_sockets << " socket"
				  << (num_sockets > 1 ? "s" : "") << " for mDNS service discovery.\n";
}

lan_adv_client::~lan_adv_client() {
	free(addrbuffer);
	free(namebuffer);
	free(entrybuffer);
	free(txtbuffer);

	for (int isock = 0; isock < num_sockets; ++isock)
		mdns_socket_close(sockets[isock]);
	verbosestream << "[LanClient] Closed socket%s\n" << (num_sockets > 1 ? "s" : "")
				  << "\n";
}

static int lan_adv_client::response_callback(
	int sock, const struct sockaddr* from, size_t addrlen, mdns_entry_type_t entry,
    uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void* data,
    size_t size, size_t name_offset, size_t name_length, size_t record_offset,
    size_t record_length, void* user_data
) {
	(void)sizeof(sock);
	(void)sizeof(query_id);
	(void)sizeof(name_length);
	(void)sizeof(user_data);
	mdns_string_t fromaddrstr = ip_address_to_string(addrbuffer, sizeof(addrbuffer), from, addrlen);
	const char* entrytype = (entry == MDNS_ENTRYTYPE_ANSWER) ?
                                "answer" :
                                ((entry == MDNS_ENTRYTYPE_AUTHORITY) ? "authority" : "additional");
	mdns_string_t entrystr =
	    mdns_string_extract(data, size, &name_offset, entrybuffer, sizeof(entrybuffer));
	if (rtype == MDNS_RECORDTYPE_PTR) {
		mdns_string_t namestr = mdns_record_parse_ptr(data, size, record_offset, record_length,
		                                              namebuffer, sizeof(namebuffer));
		printf("%.*s : %s %.*s PTR %.*s rclass 0x%x ttl %u length %d\n",
		       MDNS_STRING_FORMAT(fromaddrstr), entrytype, MDNS_STRING_FORMAT(entrystr),
		       MDNS_STRING_FORMAT(namestr), rclass, ttl, (int)record_length);
	} else if (rtype == MDNS_RECORDTYPE_SRV) {
		mdns_record_srv_t srv = mdns_record_parse_srv(data, size, record_offset, record_length,
		                                              namebuffer, sizeof(namebuffer));
		printf("%.*s : %s %.*s SRV %.*s priority %d weight %d port %d\n",
		       MDNS_STRING_FORMAT(fromaddrstr), entrytype, MDNS_STRING_FORMAT(entrystr),
		       MDNS_STRING_FORMAT(srv.name), srv.priority, srv.weight, srv.port);
	} else if (rtype == MDNS_RECORDTYPE_A) {
		struct sockaddr_in addr;
		mdns_record_parse_a(data, size, record_offset, record_length, &addr);
		mdns_string_t addrstr =
		    ipv4_address_to_string(namebuffer, sizeof(namebuffer), &addr, sizeof(addr));
		printf("%.*s : %s %.*s A %.*s\n", MDNS_STRING_FORMAT(fromaddrstr), entrytype,
		       MDNS_STRING_FORMAT(entrystr), MDNS_STRING_FORMAT(addrstr));
	} else if (rtype == MDNS_RECORDTYPE_AAAA) {
		struct sockaddr_in6 addr;
		mdns_record_parse_aaaa(data, size, record_offset, record_length, &addr);
		mdns_string_t addrstr =
		    ipv6_address_to_string(namebuffer, sizeof(namebuffer), &addr, sizeof(addr));
		printf("%.*s : %s %.*s AAAA %.*s\n", MDNS_STRING_FORMAT(fromaddrstr), entrytype,
		       MDNS_STRING_FORMAT(entrystr), MDNS_STRING_FORMAT(addrstr));
	} else if (rtype == MDNS_RECORDTYPE_TXT) {
		size_t parsed = mdns_record_parse_txt(data, size, record_offset, record_length, txtbuffer,
		                                      sizeof(txtbuffer) / sizeof(mdns_record_txt_t));
		for (size_t itxt = 0; itxt < parsed; ++itxt) {
			if (txtbuffer[itxt].value.length) {
				printf("%.*s : %s %.*s TXT %.*s = %.*s\n", MDNS_STRING_FORMAT(fromaddrstr),
				       entrytype, MDNS_STRING_FORMAT(entrystr),
				       MDNS_STRING_FORMAT(txtbuffer[itxt].key),
				       MDNS_STRING_FORMAT(txtbuffer[itxt].value));
				if (strcmp(txtbuffer[itxt].key.str, "server_data") == 1) {
					return 0;
				}

				Json::Value server_data;
				Json::Reader reader;
				if (reader.parse(txtbuffer[itxt].value.str, server_data, false)) {
					std::string key = server_data["address"].asString() + ':' + server_data["port"].asString();
					collected.insert_or_assign(key, server_data);
					actionstream << "[Lan] A server has been placed in the server cache.\n";
				} else {
					errorstream << "[Lan] Failed to parse server data from TXT record: "
								<< reader.getFormattedErrorMessages() << "\n";
				}
				
				
			} else {
				printf("%.*s : %s %.*s TXT %.*s\n", MDNS_STRING_FORMAT(fromaddrstr), entrytype,
				       MDNS_STRING_FORMAT(entrystr), MDNS_STRING_FORMAT(txtbuffer[itxt].key));
			}
		}
	} else {
		printf("%.*s : %s %.*s type %u rclass 0x%x ttl %u length %d\n",
		       MDNS_STRING_FORMAT(fromaddrstr), entrytype, MDNS_STRING_FORMAT(entrystr), rtype,
		       rclass, ttl, (int)record_length);
	}
	return 0;
}

lan_adv_client::ask() {
	mdns_query_t query = {
		.name = service_name;
		.type = MDNS_RECORDTYPE_PTR;
		.length = strlen(service_name);
	};

	size_t capacity = 2048;
	void* buffer = malloc(capacity);

	printf("Sending mDNS query");

	for (int isock = 0; isock < num_sockets; ++isock) {
		if (mdns_multiquery_send(sockets[isock], &query, 1, buffer, capacity, 0))
			printf("Failed to send mDNS query: %s\n", strerror(errno));
	}

	// This is a simple implementation that loops for 5 seconds or as long as we get replies
	int res;
	printf("Reading mDNS query replies\n");
	int records = 0;
	do {
		struct timeval timeout;
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		int nfds = 0;
		fd_set readfs;
		FD_ZERO(&readfs);
		for (int isock = 0; isock < num_sockets; ++isock) {
			if (sockets[isock] >= nfds)
				nfds = sockets[isock] + 1;
			FD_SET(sockets[isock], &readfs);
		}

		res = select(nfds, &readfs, 0, 0, &timeout);
		if (res > 0) {
			for (int isock = 0; isock < num_sockets; ++isock) {
				if (FD_ISSET(sockets[isock], &readfs)) {
					size_t rec = mdns_query_recv(sockets[isock], buffer, capacity, query_callback,
					                             user_data, 0);
					if (rec > 0)
						records += rec;
				}
				FD_SET(sockets[isock], &readfs);
			}
		}
	} while (res > 0);

	printf("Read %d records\n", records);

	free(buffer);
}

