/*
 * Copyright 2013-2014 Intel Corporation - All Rights Reserved
 */

#include <syslinux/firmware.h>
#include <syslinux/pxe_api.h>
#include "efi.h"
#include "net.h"
#include "core_pxe.h"

const struct url_scheme url_schemes[] = {
    { "tftp", tftp_open, 0 },
    { "http", http_open, O_DIRECTORY },
    { "ftp",  ftp_open,  O_DIRECTORY },
    { NULL, NULL, 0 },
};

/**
 * Network stack-specific initialization
 */
void net_core_init(void)
{
    http_bake_cookies();
}

void pxe_init_isr(void) {}
void gpxe_init(void) {}

// It is kludgy to repurpose this existing hook for something different, fix later
void pxe_idle_init(void) {
    EFI_STATUS status;

    Print(L"Resetting EFI watchdog timer to 10 minutes\n");
    status = uefi_call_wrapper(BS->SetWatchdogTimer, 4, 600, 0x424242,
                   sizeof(L"SYSLINUX EFI PXE"), L"SYSLINUX EFI PXE");
    if (status != EFI_SUCCESS) {
        Print(L"Failed to change EFI watchdog timer\n");
    }
    return;
}

int reset_pxe(void)
{
    return 0;
}

// Yanked from dnsresolv.c, FIXME: avoid code duplication
/*
 * parse the ip_str and return the ip address with *res.
 * return true if the whole string was consumed and the result
 * was valid.
 *
 */
static bool parse_dotquad(const char *ip_str, uint32_t *res)
{
    const char *p = ip_str;
    uint8_t part = 0;
    uint32_t ip = 0;
    int i;

    for (i = 0; i < 4; i++) {
        while (is_digit(*p)) {
            part = part * 10 + *p - '0';
            p++;
        }
        if (i != 3 && *p != '.')
            return false;

        ip = (ip << 8) | part;
        part = 0;
        p++;
    }
    p--;

    *res = htonl(ip);
    return *p == '\0';
}

void hexDump (char *desc, void *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        Print(L"%a:\n", desc);

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %i\n",len);
        return;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                Print(L"  %a\n", buff);

            // Output the offset.
            Print(L"  %04x ", i);
        }

        // Now the hex code for the specific character.
        Print(L" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        Print(L"   ");
        i++;
    }

    // And print the final ASCII bit.
    Print(L"  %a\n", buff);
}

#define DNS_MAX_SERVERS 4		/* Max no of DNS servers */
uint32_t dns_server[DNS_MAX_SERVERS] = {0, };

uint32_t crude_dns_lookup(const char *name)
{
#define DNS_BUF_SIZE 2048
    struct pxe_pvt_inode socket;
    unsigned char buf[DNS_BUF_SIZE] = {
        // Header
        0x42, 0x42, // ID
        0x01, 0x00, // Flags & status, only set the RD flag to request recursion
        0x00, 0x01, // Question count
        0x00, 0x00, // Answer count
        0x00, 0x00, // Authority count
        0x00, 0x00, // Additional count
    };
    unsigned char *query, *nptr;
    uint16_t len = 12, n, err, hack;
    //uint32_t nsip = htonl(0x0A000001); // 10.0.0.1
    uint32_t nsip = dns_server[0];
    uint16_t nsport = 53;
    uint32_t src_ip;
    uint16_t src_port;
    uint32_t out, status;

    if (!nsip){
        Print(L"No DNS servers provided by DHCP, not attempting DNS resolution\n");
        return 0; // We could attempt a public nameserver instead like Google's 8.8.8.8 however that might introduce some security/privacy concerns?
    }

    /* convert hostname into suitable query format. */
    query = buf + len;
    do {
      nptr = query;
      ++query;
      for(n = 0; *name != '.' && *name != 0; ++name) {
        *query = *name;
        ++query;
        ++n;
      }
      *nptr = n;
    } while(*(name++) != 0);
    *query++ ='\0';

    *query++ = 0x00; *query++ = 0x01; // Q type: ask for 'A' record
    *query++ = 0x00; *query++ = 0x01; // Q class: IN internet class

    hack = len = query - buf;

    core_udp_open(&socket);
    Print(L"Test: socket open\n");
    hexDump("Sending",buf,len);
    core_udp_sendto(&socket, buf, len, nsip, nsport);
    Print(L"Test: packet sent\n");
    len = DNS_BUF_SIZE;
    err = core_udp_recv(&socket, buf, &len, &src_ip, &src_port);
    Print(L"Test: got response packet of length %d\n", len);
    hexDump("Received",buf,len);
    status = buf[3] & 0x0F;
    out = *(uint32_t *)(buf + hack + 12);
    Print(L"...status: %x  IP: %u.%u.%u.%u %d\n", buf[3] & 0x0F, buf[hack + 12] & 0x0F, buf[hack + 13] & 0x0F, buf[hack + 14] & 0x0F, buf[hack + 15] & 0x0F, ntohl(out));
    //core_udp_disconnect(socket);
    //core_udp_connect(socket, src_ip, src_port);
    //core_udp_send(socket, &err_buf, 4 + len + 1);
    core_udp_close(&socket);
    Print(L"Test: socket closed\n");

    if (status == 0){
      return out;
    } else {
      Print(L"Problem with DNS lookup, status: %d\n",status);
      return 0;
    }
}

uint32_t dump_avail_uefi_protocol_guid()
{
    EFI_HANDLE *handles;
    EFI_STATUS status;
    UINTN nr_handles, nr_protocols, hidx, pidx;
    EFI_GUID **protocol_guids;

    status = LibLocateHandle(AllHandles, NULL, NULL, &nr_handles, &handles);
    if (status != EFI_SUCCESS) {
	    Print(L"\nError listing UEFI Handles available\n");
    }else{
	    Print(L"\nFound %d UEFI Handles available\n", nr_handles);
        for (hidx=0; hidx < nr_handles; hidx++){
            status = uefi_call_wrapper(BS->ProtocolsPerHandle, 3, handles[hidx], &protocol_guids, &nr_protocols);
            Print(L"\nHandle %d supports %d protocols\n",hidx,nr_protocols);
            for (pidx=0; pidx < nr_protocols; pidx++){
                Print(L"GUID: %x %x %x %x",protocol_guids[pidx]->Data1,protocol_guids[pidx]->Data2,protocol_guids[pidx]->Data3,protocol_guids[pidx]->Data4[0]);
            }
        }
    }

    return 0;
}

__export uint32_t pxe_dns(const char *name)
{
    uint32_t i;
    uint32_t ip;

    /*
     * Return failure on an empty input... this can happen during
     * some types of URL parsing, and this is the easiest place to
     * check for it.
     */
    if (!name || !*name){
        Print(L"\nNo hostname in file URL therefore no DNS lookup needed\n");
        return 0;
    }

    /* If it is a valid dot quad, just return that value */
    if (parse_dotquad(name, &ip)){
        Print(L"\ndot-quad IPv4 address given in file URL so no DNS lookup is needed: %d\n",ip);
        return ip;
    }

    for (i=0; i<DNS_MAX_SERVERS; i++){
        Print(L"\nDNS server %d is %d\n",i,dns_server[i]);
    }

    Print(L"\nWARNING: file URLs needing DNS resolution not yet supported within UEFI boot\nExpect the PXE server IP to be attempted as a fallback\n");

    return crude_dns_lookup(name);
}

int pxe_init(bool quiet)
{
    EFI_HANDLE *handles;
    EFI_STATUS status;
    UINTN nr_handles;

    status = LibLocateHandle(ByProtocol, &PxeBaseCodeProtocol,
			     NULL, &nr_handles, &handles);
    if (status != EFI_SUCCESS) {
	if (!quiet)
	    Print(L"No PXE Base Code Protocol\n");
	return -1;
    }

    return 0;
}

#define EDHCP_BUF_LEN 8192

struct embedded_dhcp_options {
    uint32_t magic[4];
    uint32_t bdhcp_len;
    uint32_t adhcp_len;
    uint32_t buffer_size;
    uint32_t reserved;
    uint8_t  dhcp_data[EDHCP_BUF_LEN];
} __attribute__((aligned(16)));

struct embedded_dhcp_options embedded_dhcp_options =
{
    .magic[0] = 0x2a171ead,
    .magic[1] = 0x0600e65e,
    .magic[2] = 0x4025a4e4,
    .magic[3] = 0x42388fc8,
    .bdhcp_len = 0,
    .adhcp_len = 0,
    .buffer_size = EDHCP_BUF_LEN,
};

void net_parse_dhcp(void)
{
    EFI_PXE_BASE_CODE_MODE *mode;
    EFI_PXE_BASE_CODE *bc;
    unsigned int pkt_len = sizeof(EFI_PXE_BASE_CODE_PACKET);
    EFI_STATUS status;
    uint8_t hardlen;
    uint32_t ip;
    char dst[256];

    status = uefi_call_wrapper(BS->HandleProtocol, 3, image_device_handle,
			       &PxeBaseCodeProtocol, (void **)&bc);
    if (status != EFI_SUCCESS) {
	Print(L"Failed to lookup PxeBaseCodeProtocol\n");
	return;
    }

    mode = bc->Mode;

    /*
     * Parse any "before" hardcoded options
     */
    parse_dhcp_options(embedded_dhcp_options.dhcp_data,
		       embedded_dhcp_options.bdhcp_len, 0);

    /*
     * Get the DHCP client identifiers (BIOS/PXE query info 1)
     */
    Print(L"Getting cached packet ");
    parse_dhcp(&mode->DhcpDiscover.Dhcpv4, pkt_len, 1);
    /*
     * We don't use flags from the request packet, so
     * this is a good time to initialize DHCPMagic...
     * Initialize it to 1 meaning we will accept options found;
     * in earlier versions of PXELINUX bit 0 was used to indicate
     * we have found option 208 with the appropriate magic number;
     * we no longer require that, but MAY want to re-introduce
     * it in the future for vendor encapsulated options.
     */
    *(char *)&DHCPMagic = 1;

    /*
     * Get the BOOTP/DHCP packet that brought us file (and an IP
     * address). This lives in the DHCPACK packet (BIOS/PXE query info 2)
     */
    parse_dhcp(&mode->DhcpAck.Dhcpv4, pkt_len, 2);

    /*
     * Get the boot file and other info. This lives in the CACHED_REPLY
     * packet (BIOS/PXE query info 3)
     */
    EFI_PXE_BASE_CODE_DHCPV4_PACKET*     pkt_v4 = NULL;

    if (mode->PxeReplyReceived)
	pkt_v4 = &mode->PxeReply.Dhcpv4;
    else if (mode->ProxyOfferReceived)
	pkt_v4 = &mode->ProxyOffer.Dhcpv4;

    if (pkt_v4)
	parse_dhcp(pkt_v4, pkt_len, 3);

    /*
     * Save away MAC address (assume this is in query info 2. If this
     * turns out to be problematic it might be better getting it from
     * the query info 1 packet
     */
    hardlen = mode->DhcpAck.Dhcpv4.BootpHwAddrLen;
    MAC_len = hardlen > 16 ? 0 : hardlen;
    MAC_type = mode->DhcpAck.Dhcpv4.BootpHwType;
    memcpy(MAC, mode->DhcpAck.Dhcpv4.BootpHwAddr, MAC_len);

    Print(L"\n");

    /*
     * Parse any "after" hardcoded options
     */
    parse_dhcp_options(embedded_dhcp_options.dhcp_data +
		       embedded_dhcp_options.bdhcp_len,
		       embedded_dhcp_options.adhcp_len, 0);

    ip = IPInfo.myip;
    sprintf(dst, "%u.%u.%u.%u",
        ((const uint8_t *)&ip)[0],
        ((const uint8_t *)&ip)[1],
        ((const uint8_t *)&ip)[2],
        ((const uint8_t *)&ip)[3]);

    Print(L"My IP is %a\n", dst);
    if (!(ip_ok(ip))) {
	Print(L"  NO valid IP found.\n");
    }
}
