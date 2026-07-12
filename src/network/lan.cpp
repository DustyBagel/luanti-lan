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
#include "../lib/mdns/mdns.h"
#include "debug.h"


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
const char* get_host_name() {
	const char* hostname = nullptr;
#ifdef _WIN32

	WORD versionWanted = MAKEWORD(1, 1);
	WSADATA wsaData;
	if (WSAStartup(versionWanted, &wsaData)) {
		errorstream << "[Lan] Failed to initialize WinSock\n";
		return nullptr;
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
	mdns_record_t txt_record;
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



// Service
lan_adv_server::lan_adv_server() {
    int sockets[32];
    int num_sockets = open_service_sockets(sockets, sizeof(sockets) / sizeof(sockets[0]));
    if (num_sockets <= 0) {
        errorstream << "[LanServer] Failed to open any server sockets\n";
        return;
    }
    verbosestream << "[LanServer] Opened " << num_sockets << " socket" << (num_sockets > 1 ? "s" : "") << " for mDNS service\n";
    build_service_record();
    start();
}

lan_adv_server::~lan_adv_server() {

}

service_t lan_adv_server::build_service_record() {
    service_t service = {};
    
    mdns_string_t name;
    name.str = service_name;
    name.length = strlen(service_name);

    service.service = name;
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

    // The server data can go here.
    service.txt_record[0] = mdns_record_t();
    service.txt_record[0].name = service.service_instance;
    service.txt_record[0].type = MDNS_RECORDTYPE_TXT;
    service.txt_record[0].data.txt.key = key;
    service.txt_record[0].data.txt.value = value;
    service.txt_record[0].rclass = 0;
    service.txt_record[0].ttl = 0;

    return service;
}

void lan_adv_server::*run() {
    BEGIN_DEBUG_EXCEPTION_HANDLER;

    setName("lan_adv_server");

    const char* hostname = get_host_name();


    printf("Opened %d socket%s for mDNS service\n", num_sockets, num_sockets > 1 ? "s" : "");

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

 
    // Send an announcement on startup of service
    mdns_record_t additional[4] = {};
    size_t additional_count = 0;
    additional[additional_count++] = service.record_srv;
    if (service.address_ipv4.sin_family == AF_INET)
        additional[additional_count++] = service.record_a;
    if (service.address_ipv6.sin6_family == AF_INET6)
        additional[additional_count++] = service.record_aaaa;
    additional[additional_count++] = service.txt_record[0];

    actionstream << "[Lan] Sending Lan announce.\n";
    for (int isock = 0; isock < num_sockets; ++isock)
        mdns_announce_multicast(sockets[isock], buffer, capacity, service.record_ptr, 0, 0,
                                additional, additional_count);

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
}

// Client
lan_adv_client::lan_adv_client() {

}

