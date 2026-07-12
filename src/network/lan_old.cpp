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

#include "network/lan.h"

#include <cstdint>
#include <mutex>
#include <vector>

#include "../lib/mdns/mdns.h"

#include "convert_json.h"
#include "socket.h"
#include "log.h"
#include "settings.h"
#include "version.h"
#include "server/serverlist.h"
#include "debug.h"
#include "porting.h"
#include "network/address.h"
//#include "server.h"

//copypaste from ../socket.cpp
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
// Without this some of the network functions are not found on mingw
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#define LAST_SOCKET_ERR() WSAGetLastError()
typedef SOCKET socket_t;
typedef int socklen_t;
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
// This seems to be a linux internal header, I hope this doesn't cause issues on other platforms.
#if defined(__linux__)
#include <net/if.h>
#endif
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>

#ifndef __ANDROID__
#include <ifaddrs.h>
#define HAVE_IFADDRS 1
#endif

#define LAST_SOCKET_ERR() (errno)
typedef int socket_t;
#endif

const char* service_name = "_luanti._udp.local";
const mdns_record_type_t record_type = MDNS_RECORDTYPE_PTR;
static const char dns_sd_service_name[] = "_services._dns-sd._udp.local.";

static bool dns_name_equals(const mdns_string_t& name, const char* service) {
    size_t len = strlen(service);
    if ((name.length == len) && (strncmp(name.str, service, len) == 0))
        return true;
    if ((name.length == len + 1) && (name.str[len] == '.') &&
        (strncmp(name.str, service, len) == 0))
        return true;
    return false;
}

// Note to reviewers:
// I will be removing ipv6 support. This is to 
// simplify the code as it is really hard to
// work on this without having to juggle two
// ip versions. I can readd ipv6 later if it's
// required.
bool use_ipv6 = true;

const int keep_going = 0;
const int stop = 1;

std::vector<Json::Value> server_cache = {};
std::mutex query_cache_mutex;
struct query_item {
	std::string inst_name;
	mdns_query_t query;
};
std::vector<query_item> query_cache = {};

static char addrbuffer[64];
static char entrybuffer[256];
static char namebuffer[256];
static char sendbuffer[1024];
static mdns_record_txt_t txtbuffer[128];

static int has_ipv4;
static int has_ipv6;

static struct sockaddr_in service_address_ipv4;
static struct sockaddr_in6 service_address_ipv6;

// Data for our service including the mDNS records
typedef struct {
	mdns_string_t service;
	mdns_string_t hostname;
	mdns_string_t service_instance;
	mdns_string_t hostname_qualified;
	struct sockaddr_in address_ipv4;
	struct sockaddr_in6 address_ipv6;
	int port;
	mdns_record_t record_ptr;
	mdns_record_t record_srv;
	mdns_record_t record_a;
	mdns_record_t record_aaaa;
	mdns_record_t txt_record[1];
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

static int
query_callback(int sock, const struct sockaddr* from, size_t addrlen, mdns_entry_type_t entry,
               uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void* data,
               size_t size, size_t name_offset, size_t name_length, size_t record_offset,
               size_t record_length, void* user_data);

// Send a mDNS query
static int
send_mdns_query(mdns_query_t* query, size_t count) {
	int sockets[32];
	int query_id[32];
	int num_sockets = open_client_sockets(sockets, sizeof(sockets) / sizeof(sockets[0]), 0);
	if (num_sockets <= 0) {
		printf("Failed to open any client sockets\n");
		return -1;
	}
	printf("Opened %d socket%s for mDNS query\n", num_sockets, num_sockets > 1 ? "s" : "");

	size_t capacity = 2048;
	void* buffer = malloc(capacity);
	void* user_data = 0;

	printf("Sending mDNS query");
	for (size_t iq = 0; iq < count; ++iq) {
		const char* record_name = "PTR";
		if (query[iq].type == MDNS_RECORDTYPE_SRV)
			record_name = "SRV";
		else if (query[iq].type == MDNS_RECORDTYPE_A)
			record_name = "A";
		else if (query[iq].type == MDNS_RECORDTYPE_AAAA)
			record_name = "AAAA";
		else
			query[iq].type = MDNS_RECORDTYPE_PTR;
		printf(" : %s %s", query[iq].name, record_name);
	}
	printf("\n");
	for (int isock = 0; isock < num_sockets; ++isock) {
		query_id[isock] =
		    mdns_multiquery_send(sockets[isock], query, count, buffer, capacity, 0);
		if (query_id[isock] < 0)
			printf("Failed to send mDNS query: %s\n", strerror(errno));
	}

	// This is a simple implementation that loops for 5 seconds or as long as we get replies
	int res;
	printf("Reading mDNS query replies\n");
	int records = 0;
	do {
		struct timeval timeout;
		timeout.tv_sec = 10;
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
					                             user_data, query_id[isock]);
					if (rec > 0)
						records += rec;
				}
				FD_SET(sockets[isock], &readfs);
			}
		}
	} while (res > 0);

	printf("Read %d records\n", records);

	free(buffer);

	for (int isock = 0; isock < num_sockets; ++isock)
		mdns_socket_close(sockets[isock]);
	printf("Closed socket%s\n", num_sockets > 1 ? "s" : "");

	return 0;
}

// Callback handling questions incoming on service sockets
static int
service_callback(int sock, const struct sockaddr* from, size_t addrlen, mdns_entry_type_t entry,
                 uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void* data,
                 size_t size, size_t name_offset, size_t name_length, size_t record_offset,
                 size_t record_length, void* user_data) {
	(void)sizeof(ttl);
	if (entry != MDNS_ENTRYTYPE_QUESTION)
		return 0;

	const char dns_sd[] = "_services._dns-sd._udp.local.";
	const service_t* service = (const service_t*)user_data;

	// Why is this here if it isn't used?
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
			mdns_record_t answer;
			memset(&answer, 0, sizeof(answer));
			answer.name = name;
			answer.type = MDNS_RECORDTYPE_PTR;
			answer.data.ptr.name = service->service;

			// Send the answer, unicast or multicast depending on flag in query
			uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
			printf("  --> answer %.*s (%s)\n", MDNS_STRING_FORMAT(answer.data.ptr.name),
			       (unicast ? "unicast" : "multicast"));

			if (unicast) {
				int error = mdns_query_answer_unicast(sock, from, addrlen, sendbuffer, sizeof(sendbuffer),
				                          query_id, (mdns_record_type_t)rtype, name.str, name.length, answer, 0, 0, 0,
				                          0);
				if (error < 0) {
					errorstream << "[Lan] Failed to send mDNS unicast answer: " << strerror(errno) << "\n";
				}
			} else {
				int error = mdns_query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer), answer, 0, 0, 0,
				                            0);
				if (error < 0) {
					errorstream << "[Lan] Failed to send mDNS multicast answer: " << strerror(errno) << "\n";
				}
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
			mdns_record_t answer = service->record_ptr;

			// used to be 5 records.
			mdns_record_t additional[4] = {};
			size_t additional_count = 0;

			// SRV record mapping "<hostname>.<_service-name>._tcp.local." to
			// "<hostname>.local." with port. Set weight & priority to 0.
			additional[additional_count++] = service->record_srv;

			// A/AAAA records mapping "<hostname>.local." to IPv4/IPv6 addresses
			if (service->address_ipv4.sin_family == AF_INET)
				additional[additional_count++] = service->record_a;
			if (service->address_ipv6.sin6_family == AF_INET6)
				additional[additional_count++] = service->record_aaaa;

			// Add two test TXT records for our service instance name, will be coalesced into
			// one record with both key-value pair strings by the library
			additional[additional_count++] = service->txt_record[0];
			//additional[additional_count++] = service->txt_record[1];

			// Send the answer, unicast or multicast depending on flag in query
			uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
			printf("  --> answer %.*s (%s)\n",
			       MDNS_STRING_FORMAT(service->record_ptr.data.ptr.name),
			       (unicast ? "unicast" : "multicast"));

			if (unicast) {
				int error = mdns_query_answer_unicast(sock, from, addrlen, sendbuffer, sizeof(sendbuffer),
				                          query_id, (mdns_record_type_t)rtype, name.str, name.length, answer, 0, 0,
				                          additional, additional_count);
				if (error < 0) {
					errorstream << "[Lan] Failed to send mDNS unicast answer: " << strerror(errno) << " " << error << "\n";
				}
			} else {
				int error = mdns_query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer), answer, 0, 0,
				                            additional, additional_count);
				if (error < 0) {
					errorstream << "[Lan] Failed to send mDNS multicast answer: " << strerror(errno) << " " << error << "\n";
				}
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
			mdns_record_t answer = service->record_srv;

			// used to be 5 records.
			mdns_record_t additional[4] = {};
			size_t additional_count = 0;

			// A/AAAA records mapping "<hostname>.local." to IPv4/IPv6 addresses
			if (service->address_ipv4.sin_family == AF_INET)
				additional[additional_count++] = service->record_a;
			if (service->address_ipv6.sin6_family == AF_INET6)
				additional[additional_count++] = service->record_aaaa;

			// Add two test TXT records for our service instance name, will be coalesced into
			// one record with both key-value pair strings by the library
			additional[additional_count++] = service->txt_record[0];
			//additional[additional_count++] = service->txt_record[1];

			// Send the answer, unicast or multicast depending on flag in query
			uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
			printf("  --> answer %.*s port %d (%s)\n",
			       MDNS_STRING_FORMAT(service->record_srv.data.srv.name), service->port,
			       (unicast ? "unicast" : "multicast"));

			if (unicast) {
				mdns_query_answer_unicast(sock, from, addrlen, sendbuffer, sizeof(sendbuffer),
				                          query_id, (mdns_record_type_t)rtype, name.str, name.length, answer, 0, 0,
				                          additional, additional_count);
			} else {
				mdns_query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer), answer, 0, 0,
				                            additional, additional_count);
			}
		}
	} else if ((name.length == service->hostname_qualified.length) &&
	           (strncmp(name.str, service->hostname_qualified.str, name.length) == 0)) {
		if (((rtype == MDNS_RECORDTYPE_A) || (rtype == MDNS_RECORDTYPE_ANY)) &&
		    (service->address_ipv4.sin_family == AF_INET)) {
			// The A query was for our qualified hostname (typically "<hostname>.local.") and we
			// have an IPv4 address, answer with an A record mappiing the hostname to an IPv4
			// address, as well as any IPv6 address for the hostname, and two test TXT records

			// Answer A records mapping "<hostname>.local." to IPv4 address
			mdns_record_t answer = service->record_a;
			
			// used to be 5 records.
			mdns_record_t additional[4] = {};
			size_t additional_count = 0;

			// AAAA record mapping "<hostname>.local." to IPv6 addresses
			if (service->address_ipv6.sin6_family == AF_INET6)
				additional[additional_count++] = service->record_aaaa;

			// Add two test TXT records for our service instance name, will be coalesced into
			// one record with both key-value pair strings by the library
			additional[additional_count++] = service->txt_record[0];
			//additional[additional_count++] = service->txt_record[1];

			// Send the answer, unicast or multicast depending on flag in query
			uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
			mdns_string_t addrstr = ip_address_to_string(
			    addrbuffer, sizeof(addrbuffer), (struct sockaddr*)&service->record_a.data.a.addr,
			    sizeof(service->record_a.data.a.addr));
			printf("  --> answer %.*s IPv4 %.*s (%s)\n", MDNS_STRING_FORMAT(service->record_a.name),
			       MDNS_STRING_FORMAT(addrstr), (unicast ? "unicast" : "multicast"));

			if (unicast) {
				mdns_query_answer_unicast(sock, from, addrlen, sendbuffer, sizeof(sendbuffer),
				                          query_id, (mdns_record_type_t)rtype, name.str, name.length, answer, 0, 0,
				                          additional, additional_count);
			} else {
				mdns_query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer), answer, 0, 0,
				                            additional, additional_count);
			}
		} else if (((rtype == MDNS_RECORDTYPE_AAAA) || (rtype == MDNS_RECORDTYPE_ANY)) &&
		           (service->address_ipv6.sin6_family == AF_INET6)) {
			// The AAAA query was for our qualified hostname (typically "<hostname>.local.") and we
			// have an IPv6 address, answer with an AAAA record mappiing the hostname to an IPv6
			// address, as well as any IPv4 address for the hostname, and two test TXT records

			// Answer AAAA records mapping "<hostname>.local." to IPv6 address
			mdns_record_t answer = service->record_aaaa;

			// used to be 5 records.
			mdns_record_t additional[4] = {};
			size_t additional_count = 0;

			// A record mapping "<hostname>.local." to IPv4 addresses
			if (service->address_ipv4.sin_family == AF_INET)
				additional[additional_count++] = service->record_a;

			// Add two test TXT records for our service instance name, will be coalesced into
			// one record with both key-value pair strings by the library
			additional[additional_count++] = service->txt_record[0];
			//additional[additional_count++] = service->txt_record[1];

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
				int error = mdns_query_answer_unicast(
					sock, from, addrlen, sendbuffer, sizeof(sendbuffer),
				    query_id, (mdns_record_type_t)rtype, name.str,
					name.length, answer, 0, 0, additional,
					additional_count
				);
				if (error != 0) {
					errorstream << "[Lan] Failed to send mDNS unicast answer: " << strerror(errno) << "\n";
				}
			} else {
				int error = mdns_query_answer_multicast(
					sock, sendbuffer, sizeof(sendbuffer), answer,
					0, 0, additional, additional_count
				);
				if (error != 0) {
					errorstream << "[Lan] Failed to send mDNS multicast answer: " << strerror(errno) << "\n";
				}
			}
		}
	}
	return 0;
}

// Callback handling parsing answers to queries sent
static int
query_callback(int sock, const struct sockaddr* from, size_t addrlen, mdns_entry_type_t entry,
               uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void* data,
               size_t size, size_t name_offset, size_t name_length, size_t record_offset,
               size_t record_length, void* user_data) {
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

		// We found a ptr record that we actually want.
		// Store the address of the service instance name for later when we get
		// the SRV record that maps the service instance name to the hostname
		// and port.

		// Query for the service instance name to get the hostname and port, and add the PTR record
		// to the additional records for the query so we can match it when we get the

		query_item item = {};

		item.inst_name = std::string(namestr.str, namestr.length);
		
		item.query.name = item.inst_name.c_str();
		item.query.type = MDNS_RECORDTYPE_TXT;
		item.query.length = item.inst_name.length();
		
		std::lock_guard<std::mutex> lock(query_cache_mutex);
		query_cache.push_back(item);

		actionstream << "[Lan] Found '" << item.inst_name << "'.\n";

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
		// We have recived a TXT record, parse it into key-value pairs and print them out.
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
					std::lock_guard<std::mutex> lock(query_cache_mutex);
					server_cache.push_back(server_data);
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

// Send a DNS-SD query
static int
send_dns_sd(void) {
	int sockets[32];
	int num_sockets = open_client_sockets(sockets, sizeof(sockets) / sizeof(sockets[0]), 0);
	if (num_sockets <= 0) {
		errorstream << "[Lan] Failed to open any client sockets\n";
		return -1;
	}
	verbosestream << "[Lan] Opened %d socket%s for DNS-SD\n" << num_sockets
				  << (num_sockets > 1 ? "s" : "") << "\n";

	actionstream << "[Lan] Sending DNS-SD discovery\n";
	for (int isock = 0; isock < num_sockets; ++isock) {
		if (mdns_discovery_send(sockets[isock]))
			errorstream << "[Lan] Failed to send DNS-DS discovery: " << strerror(errno) << "\n";
	}

	size_t capacity = 2048;
	void* buffer = malloc(capacity);
	void* user_data = 0;
	size_t records;

	// This is a simple implementation that loops for 5 seconds or as long as we get replies
	int res;
	verbosestream << "[Lan] Reading DNS-SD replies\n";
	do {
		struct timeval timeout;
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;

		int nfds = 0;
		fd_set readfs;
		FD_ZERO(&readfs);
		for (int isock = 0; isock < num_sockets; ++isock) {
			if (sockets[isock] >= nfds)
				nfds = sockets[isock] + 1;
			FD_SET(sockets[isock], &readfs);
		}

		records = 0;
		res = select(nfds, &readfs, 0, 0, &timeout);
		if (res > 0) {
			for (int isock = 0; isock < num_sockets; ++isock) {
				if (FD_ISSET(sockets[isock], &readfs)) {
					records += mdns_discovery_recv(sockets[isock], buffer, capacity, query_callback,
					                               user_data);
				}
			}
		}
	} while (res > 0);

	free(buffer);

	for (int isock = 0; isock < num_sockets; ++isock)
		mdns_socket_close(sockets[isock]);
	verbosestream << "[Lan] Closed socket%s\n" << (num_sockets > 1 ? "s" : "") << "\n";

	return 0;
}

const char* get_host_name() {
	const char* hostname = "unknown";
#ifdef _WIN32

	WORD versionWanted = MAKEWORD(1, 1);
	WSADATA wsaData;
	if (WSAStartup(versionWanted, &wsaData)) {
		errorstream << "[Lan] Failed to initialize WinSock\n";
		return -1;
	}

	char hostname_buffer[256];
	DWORD hostname_size = (DWORD)sizeof(hostname_buffer);
	if (GetComputerNameA(hostname_buffer, &hostname_size))
		hostname = hostname_buffer;

	//SetConsoleCtrlHandler(console_handler, TRUE);
#else

	char hostname_buffer[256];
	size_t hostname_size = sizeof(hostname_buffer);
	if (gethostname(hostname_buffer, hostname_size) == 0)
		hostname = hostname_buffer;
	//signal(SIGINT, signal_handler);
#endif
	return hostname;
}
/*
static int mdns_parse_callback(
    int sock, const struct sockaddr* from, size_t addrlen,
    mdns_entry_type_t entry, uint16_t query_id, uint16_t rtype,
    uint16_t rclass, uint32_t ttl, const void* data, size_t size,
    size_t name_offset, size_t name_length, size_t record_offset,
    size_t record_length, void* user_data)
{
    alignas(4) char namebuf[256] = {};

    switch (rtype) {
        case MDNS_RECORDTYPE_PTR: {
			mdns_string_t instance = mdns_record_parse_ptr(data, size, record_offset, record_length, namebuf, sizeof(namebuf));
			
			// Only process if the service type matches "_luanti._udp.local"
			std::string service_name(instance.str, instance.length);
			actionstream << "Discovered service: " << service_name << std::endl;
			if (service_name.find(service_type) == std::string::npos) {
				// Not a Luanti service, ignore
				return keep_going;
			}
            break;
        }
        case MDNS_RECORDTYPE_SRV: {

            mdns_record_srv_t srv = mdns_record_parse_srv(data, size, record_offset, record_length, namebuf, sizeof(namebuf));
            // srv.name.str is the target host, srv.port is the port
			actionstream << "Service target: " << std::string(srv.name.str, srv.name.length)
						 << " Port: " << srv.port << std::endl;
            break;
        }
        case MDNS_RECORDTYPE_TXT: {
			mdns_record_txt_t txt[8];
			size_t count = mdns_record_parse_txt(
				data, size, record_offset, record_length, txt, 8
			);
			
			for (size_t i = 0; i < count; ++i) {
				lan_adv* lan_inst = static_cast<lan_adv*>(user_data);
				std::string instance_name(namebuf, name_length); // namebuf from callback args
				if (strcmp(txt[i].key.str, "json_data") != 0) {
					actionstream << "Ignoring TXT record with unrecognized key: " << txt[i].key.str << std::endl;
					return keep_going;
				}
				std::string value (txt[i].value.str, txt[i].value.length);

				Json::Reader reader;
				Json::Value server;
				bool got_data = reader.parse(value, server);
				if (!got_data) {
					errorstream << "[Lan] Failed to parse TXT record JSON data." << std::endl;
					return keep_going;
				} else {
					actionstream << "[Lan] Server Data: " << server.toStyledString() << std::endl;
					actionstream << "[Lan] Parsed TXT record for instance: " << instance_name << std::endl;
				}

				std::string address = server["address"].asString();
				std::string port_str = server["port"].asString();
				std::string server_id = address + ":" + port_str;
				
				std::unique_lock lock(lan_inst->mutex);
				
				if (ttl == 0) {
					lan_inst->collected.erase(server_id);
					lan_inst->fresh = true;
				} else {
					// Normal TXT record, add/update server info
					lan_inst->collected.insert_or_assign(server_id, server);
					lan_inst->fresh = true;
				}
				return stop;
			}

			// Not sure why this should be a loop, we only send one key
			// value pair.
			// for (size_t i = 0; i < count; ++i) {
				try {
					// WHAT IS GOING ON HERE???
					// I really don't understand pointers sometimes.
					lan_adv* lan_inst = static_cast<lan_adv*>(user_data);

					std::string instance_name(namebuf, name_length); // namebuf from callback args
					Json::Reader reader;
					Json::Value server;
					bool got_data = reader.parse(
						std::string(txt[i].value.str, txt[i].value.length),
						server
					);

					if (!got_data) {
						errorstream << "[Lan] Failed to parse TXT record JSON data.\n";
						continue;
					} else {
						actionstream << "[Lan] Parsed TXT record for instance: " << instance_name << std::endl;
					}

					usleep(5000000);

					std::string address = server["address"].asString();
					std::string port_str = server["port"].asString();
					std::string server_id = address + ":" + port_str;
					
					std::unique_lock lock(lan_inst->mutex);
					
					if (ttl == 0) {
						lan_inst->collected.erase(server_id);
						lan_inst->fresh = true;
					} else {
						// Normal TXT record, add/update server info
						lan_inst->collected.insert_or_assign(server_id, server);
						lan_inst->fresh = true;
					}
					return stop;
				} catch (const Json::Exception& e) {
					errorstream << "[Lan] JSON Exception while parsing TXT record: " << e.what() << std::endl;
					return keep_going;
				}
			}*
            break;
        }
        case MDNS_RECORDTYPE_A: {
            struct sockaddr_in addr;
            mdns_record_parse_a(data, size, record_offset, record_length, &addr);
            // addr.sin_addr contains the IPv4 address
			actionstream << "IPv4 Address: " << inet_ntoa(addr.sin_addr) << std::endl;
            break;
        }
        default:
            break;
    }
    return keep_going; // Return nonzero to stop parsing early
}
*/


lan_adv::lan_adv() : Thread("lan_adv")
{
}

void lan_adv::ask()
{
	actionstream << "[Lan] Looking for servers ...\n";
	server_cache.clear();
	
	std::unique_lock lock(query_cache_mutex);
	query_cache.clear();
	lock.unlock();
	
	// First, we send a DNS-SD query to discover the available services on the local network.

	int sockets[32];
	int num_sockets = open_client_sockets(sockets, sizeof(sockets) / sizeof(sockets[0]), 0);
	if (num_sockets <= 0) {
		errorstream << "[Lan] Failed to open any client sockets\n";
		return;
	}
	verbosestream << "[Lan] Opened %d socket%s for DNS-SD\n" << num_sockets
				  << (num_sockets > 1 ? "s" : "") << "\n";

	size_t capacity = 2048;
	void* buffer = malloc(capacity);
	void* user_data = 0;
	size_t records;

	// We already know what service to look for, so don't ask for
	// services, ask for instances of this service directly.

	for (int isock = 0; isock < num_sockets; ++isock) {
		uint16_t query_id = 0;
		int error = mdns_query_send(
			sockets[isock], MDNS_RECORDTYPE_PTR, service_name,
			strlen(service_name), buffer, capacity, query_id
		);
		if (error != query_id) {
			errorstream << "[Lan] Failed to send mDNS query: " << strerror(errno) << "\n";
			continue;
		}
	}

	// This is a simple implementation that loops for 5 seconds or as long as we get replies
	int res;
	verbosestream << "[Lan] Reading mDNS replies\n";
	do {
		struct timeval timeout;
		timeout.tv_sec = 0;
		timeout.tv_usec = 500000;

		int nfds = 0;
		fd_set readfs;
		FD_ZERO(&readfs);
		for (int isock = 0; isock < num_sockets; ++isock) {
			if (sockets[isock] >= nfds)
				nfds = sockets[isock] + 1;
			FD_SET(sockets[isock], &readfs);
		}

		records = 0;
		res = select(nfds, &readfs, 0, 0, &timeout);
		if (res > 0) {
			for (int isock = 0; isock < num_sockets; ++isock) {
				if (FD_ISSET(sockets[isock], &readfs)) {
					records += mdns_query_recv(
						sockets[isock], buffer, capacity, query_callback,
					    user_data, 0
					);
				}
			}
		}
	} while (res > 0);

	if (!query_cache.empty()) {
		for (int isock = 0; isock < num_sockets; ++isock) {
			for (size_t i = 0; i < query_cache.size(); i++) {
				query_item &item = query_cache[i];
				uint16_t query_id = 0;
				int error = mdns_query_send(
					sockets[isock], item.query.type,
					item.inst_name.c_str(), item.inst_name.length(),
					buffer, capacity, query_id
				);
				if (error != query_id) {
					errorstream << "[Lan] Failed to send mDNS query: " << strerror(errno) << "\n";
					continue;
				}
			}
		}
	} else {
		actionstream << "[Lan] No services found.\n";
		goto cleanup;
	}

	query_cache.clear();

	do {
		struct timeval timeout;
		timeout.tv_sec = 0;
		timeout.tv_usec = 500000;

		int nfds = 0;
		fd_set readfs;
		FD_ZERO(&readfs);
		for (int isock = 0; isock < num_sockets; ++isock) {
			if (sockets[isock] >= nfds)
				nfds = sockets[isock] + 1;
			FD_SET(sockets[isock], &readfs);
		}

		records = 0;
		res = select(nfds, &readfs, 0, 0, &timeout);
		if (res > 0) {
			for (int isock = 0; isock < num_sockets; ++isock) {
				if (FD_ISSET(sockets[isock], &readfs)) {
					records += mdns_query_recv(
						sockets[isock], buffer, capacity, query_callback,
					    user_data, 0
					);
				}
			}
		}
	} while (res > 0);

	cleanup:

	printf("Read %ld records\n", records);

	free(buffer);

	for (int isock = 0; isock < num_sockets; ++isock)
		mdns_socket_close(sockets[isock]);
	verbosestream << "[Lan] Closed socket%s\n" << (num_sockets > 1 ? "s" : "") << "\n";

	collected.clear();
	for (size_t i = 0; i < server_cache.size(); i++) {
		std::string key = server_cache[i]["address"].asString() + ":"
						+ server_cache[i]["port"].asString();
		collected.insert_or_assign(key, server_cache[i]);
	}
	fresh = true;
}

void lan_adv::serve(Address addr, u16 proto_min, u16 proto_max)
{
	// Switch from client to server mode.
	address = addr.serializeString();
	server_port = addr.getPort();
	stop();
	server_data["proto_min"] = proto_min;
	server_data["proto_max"] = proto_max;
	server_data["address"] = address;
	server_data["port"] = server_port;
	start();
}

void *lan_adv::run()
{
	if (server_port) {


		BEGIN_DEBUG_EXCEPTION_HANDLER;

		setName("lan_adv " + (server_port ? std::string("server") : std::string("client")));

		const char* hostname = get_host_name();

		int sockets[32];
		int num_sockets = open_service_sockets(sockets, sizeof(sockets) / sizeof(sockets[0]));
		if (num_sockets <= 0) {
			errorstream << "[Lan] Failed to open any server sockets\n";
			return nullptr;
		}
		printf("Opened %d socket%s for mDNS service\n", num_sockets, num_sockets > 1 ? "s" : "");

		size_t service_name_length = strlen(service_name);
		if (!service_name_length) {
			errorstream << "[Lan] Invalid service name\n";
			return nullptr;
		}

		char* service_name_buffer = (char*)malloc(service_name_length + 2);
		memcpy(service_name_buffer, service_name, service_name_length);
		if (service_name_buffer[service_name_length - 1] != '.')
			service_name_buffer[service_name_length++] = '.';
		service_name_buffer[service_name_length] = 0;
		service_name = service_name_buffer;

		infostream << "[Lan] Service mDNS: " << service_name << ":" << server_port << std::endl;
		infostream << "[Lan] Hostname: " << hostname << std::endl;

		size_t capacity = 2048;
		void* buffer = malloc(capacity);

		mdns_string_t service_string = (mdns_string_t){service_name, strlen(service_name)};
		mdns_string_t hostname_string = (mdns_string_t){hostname, strlen(hostname)};

		// Build the service instance "<hostname>.<_service-name>._tcp.local." string
		char service_instance_buffer[256] = {0};
		snprintf(service_instance_buffer, sizeof(service_instance_buffer) - 1, "%.*s.%.*s",
				MDNS_STRING_FORMAT(hostname_string), MDNS_STRING_FORMAT(service_string));
		mdns_string_t service_instance_string =
			(mdns_string_t){service_instance_buffer, strlen(service_instance_buffer)};

		// Build the "<hostname>.local." string
		char qualified_hostname_buffer[256] = {0};
		snprintf(qualified_hostname_buffer, sizeof(qualified_hostname_buffer) - 1, "%.*s.local.",
				MDNS_STRING_FORMAT(hostname_string));
		mdns_string_t hostname_qualified_string =
			(mdns_string_t){qualified_hostname_buffer, strlen(qualified_hostname_buffer)};

		service_t service = {};
		service.service = service_string;
		service.hostname = hostname_string;
		service.service_instance = service_instance_string;
		service.hostname_qualified = hostname_qualified_string;
		service.address_ipv4 = service_address_ipv4;
		service.address_ipv6 = service_address_ipv6;
		service.port = server_port;

		// Setup our mDNS records

		// PTR record reverse mapping "<_service-name>._tcp.local." to
		// "<hostname>.<_service-name>._tcp.local."
		service.record_ptr = mdns_record_t();
		service.record_ptr.name = service.service;
		service.record_ptr.type = MDNS_RECORDTYPE_PTR;
		service.record_ptr.data.ptr.name = service.service_instance;
		service.record_ptr.rclass = 0;
		service.record_ptr.ttl = 0;

		// SRV record mapping "<hostname>.<_service-name>._tcp.local." to
		// "<hostname>.local." with port. Set weight & priority to 0.
		service.record_srv = mdns_record_t();
		service.record_srv.name = service.service_instance;
		service.record_srv.type = MDNS_RECORDTYPE_SRV;
		service.record_srv.data.srv.name = service.hostname_qualified;
		service.record_srv.data.srv.port = service.port;
		service.record_srv.data.srv.priority = 0;
		service.record_srv.data.srv.weight = 0;
		service.record_srv.rclass = 0;
		service.record_srv.ttl = 0;

		// A/AAAA records mapping "<hostname>.local." to IPv4/IPv6 addresses
		service.record_a = mdns_record_t();
		service.record_a.name = service.hostname_qualified;
		service.record_a.type = MDNS_RECORDTYPE_A;
		service.record_a.data.a.addr = service.address_ipv4;
		service.record_a.rclass = 0;
		service.record_a.ttl = 0;

		service.record_aaaa = mdns_record_t();
		service.record_aaaa.name = service.hostname_qualified;
		service.record_aaaa.type = MDNS_RECORDTYPE_AAAA;
		service.record_aaaa.data.aaaa.addr = service.address_ipv6;
		service.record_aaaa.rclass = 0;
		service.record_aaaa.ttl = 0;
		
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

		// Add two test TXT records for our service instance name, will be coalesced into
		// one record with both key-value pair strings by the library

		// The server data can go here.
		service.txt_record[0] = mdns_record_t();
		service.txt_record[0].name = service.service_instance;
		service.txt_record[0].type = MDNS_RECORDTYPE_TXT;
		service.txt_record[0].data.txt.key = key;
		service.txt_record[0].data.txt.value = value;
		service.txt_record[0].rclass = 0;
		service.txt_record[0].ttl = 0;

		// Send an announcement on startup of service
		{
			actionstream << "[Lan] Sending Lan announce.\n";
			// used to be 5 records.
			mdns_record_t additional[4] = {};
			size_t additional_count = 0;
			additional[additional_count++] = service.record_srv;
			if (service.address_ipv4.sin_family == AF_INET)
				additional[additional_count++] = service.record_a;
			if (service.address_ipv6.sin6_family == AF_INET6)
				additional[additional_count++] = service.record_aaaa;
			additional[additional_count++] = service.txt_record[0];
			//additional[additional_count++] = service.txt_record[1];

			for (int isock = 0; isock < num_sockets; ++isock)
				mdns_announce_multicast(sockets[isock], buffer, capacity, service.record_ptr, 0, 0,
										additional, additional_count);
		}

		// This is a crude implementation that checks for incoming queries
		while (isRunning() && !stopRequested()) {
			server_data["clients"] = clients_num.load();
			std::string server_data_str = fastWriteJson(server_data);
			service.txt_record[0].data.txt.value.str = server_data_str.c_str();
			service.txt_record[0].data.txt.value.length = server_data_str.size();

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
			timeout.tv_usec = 100000;

			if (select(nfds, &readfs, 0, 0, &timeout) >= 0) {
				for (int isock = 0; isock < num_sockets; ++isock) {
					if (FD_ISSET(sockets[isock], &readfs)) {
						mdns_socket_listen(sockets[isock], buffer, capacity, service_callback,
										&service);
					}
					FD_SET(sockets[isock], &readfs);
				}
			} else {
				break;
			}
		}

		// Send a goodbye on end of service
		{
			actionstream << "[Lan] Sending server goodbye.\n";
			// used to be 5 records.
			mdns_record_t additional[4] = {};
			size_t additional_count = 0;
			additional[additional_count++] = service.record_srv;
			if (service.address_ipv4.sin_family == AF_INET)
				additional[additional_count++] = service.record_a;
			if (service.address_ipv6.sin6_family == AF_INET6)
				additional[additional_count++] = service.record_aaaa;
			additional[additional_count++] = service.txt_record[0];
			//additional[additional_count++] = service.txt_record[1];

			for (int isock = 0; isock < num_sockets; ++isock)
				mdns_goodbye_multicast(sockets[isock], buffer, capacity, service.record_ptr, 0, 0,
									additional, additional_count);
		}

		free(buffer);
		free(service_name_buffer);

		for (int isock = 0; isock < num_sockets; ++isock)
			mdns_socket_close(sockets[isock]);
		verbosestream << "[Lan] Closed socket%s\n" << (num_sockets > 1 ? "s" : "") << "\n";

		END_DEBUG_EXCEPTION_HANDLER;

		return nullptr;
	} else {
		// dummy loop.
		while (isRunning() && !stopRequested()) {
			sleep_ms(100);
		}
		return nullptr;
	}
}
