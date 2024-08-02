//SPDX-License-Identifier: BSD-3-Clause
/*
 * Trivial example program to exercise QEMU FMAPI Emulation over MCTP over I2C
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <linux/mctp.h>
#include <linux/types.h>
#include <linux/cxl_mem.h>

#define min(a, b) \
	({ __typeof__ (a) _a = (a); \
	__typeof__ (b) _b = (b); \
	_a < _b ? _a : _b; })

#define CXL_CCI_CMD_SET_INFO 0x0
#define  CXL_IDENTIFY 0x0
#define CXL_FM_API_CMD_SET_PHYSICAL_SWITCH 0x51
#define  CXL_IDENTIFY_SWITCH_DEVICE 0x00
#define  CXL_GET_PHYSICAL_PORT_STATE 0x01


/* Commands in the non device type specific range - use MCTP Type 3 binding */

/* CXL r3.0 Figure 7-19: CCI Message Format */
struct cci_msg {
#define CXL_MCTP_CATEGORY_REQ 0
#define CXL_MCTP_CATEGORY_RSP 1
	uint8_t category;
	uint8_t tag;
	uint8_t rsv1;
	uint8_t command;
	uint8_t command_set;
	uint8_t pl_length[3]; /* 20 bit little endian, BO bit at bit 23 */
	uint16_t return_code;
	uint16_t vendor_ext_status;
	uint8_t payload[];
} __attribute__ ((packed));

/* CXL r3.0 Section 8.2.9.1.1: Identify (Opcode 0001h) */
struct cci_infostat_identify_rsp {
	uint16_t vendor_id;
	uint16_t device_id;
	uint16_t subsys_vendor_id;
	uint16_t subsys_id;
	uint8_t serial_num[8];
	uint8_t max_msg;
	uint8_t component_type;
} __attribute__((packed));

/* CXL r3.0 Section 8.2.9.4.1: Get Timestamp (Opcode 0300h) */
struct cci_get_timestamp_rsp {
	uint64_t timestamp;
} __attribute__((packed));

/* CXL r3.0 Section 8.2.9.5.1: Get Supported Logs (Opcode 0400h) */
struct supported_log_entry {
	uint8_t uuid[0x10];
	uint32_t log_size;
} __attribute__((packed));

struct cci_get_supported_logs_rsp {
	uint16_t num_supported_log_entries;
	uint8_t reserved[6];
	struct supported_log_entry entries[];
} __attribute__((packed));

/*  CXL r3.0 Section 8.2.9.5.2: Get Log (Opcode 0401h) */
struct cci_get_log_req {
	uint8_t uuid[0x10];
	uint32_t offset;
	uint32_t length;
} __attribute__((packed));

struct cci_get_log_cel_rsp {
	uint16_t opcode;
	uint16_t commandeffect;
} __attribute__((packed));

/* cxl 3.1 8.2.9.9.1.1 Table 8-127 Opcode: 0x4000 */
struct cci_mem_dev_identify_rsp {
   char fw_revision[0x10];
    uint64_t total_capacity;
    uint64_t volatile_capacity;
    uint64_t persistent_capacity;
    uint64_t partition_align;
    uint16_t info_event_log_size;
    uint16_t warning_event_log_size;
    uint16_t failure_event_log_size;
    uint16_t fatal_event_log_size;
    uint32_t lsa_size;
    uint8_t poison_list_max_mer[3];
    uint16_t inject_poison_limit;
    uint8_t poison_caps;
    uint8_t qos_telemetry_caps;
    uint16_t dc_event_log_size;
} __attribute__((packed));

/* Commands using the MCTP FM-API binding */

/* CXL r3.0 Section 7.6.7.1.1: Identify Switch Device (Opcode 5100h) */
struct cxl_fmapi_ident_sw_dev_rsp {
	uint8_t ingres_port_id;
	uint8_t rsv1;
	uint8_t num_physical_ports;
	uint8_t num_vcs;
	uint8_t active_port_bitmask[32];
	uint8_t active_vcs_bitmask[32];
	uint16_t num_total_vppb;
	uint16_t num_active_vppb;
	uint8_t num_hdm_decoder_per_usp;
} __attribute__((packed));

/* CXL r3.0 Section 7.6.7.3.2: Tunnel Management Command (Opcode 5300h) */
struct cxl_fmapi_tunnel_command_req {
	uint8_t id; /* Port or LD ID as appropriate */
	uint8_t target_type;
#define TUNNEL_TARGET_TYPE_PORT_OR_LD  0
#define TUNNEL_TARGET_TYPE_LD_POOL_CCI 1
	uint16_t command_size;
	struct cci_msg message[];
} __attribute__((packed));

struct cxl_fmapi_tunnel_command_rsp {
	uint16_t length;
	uint16_t resv;
	struct cci_msg message[]; /* only one but lets closs over that */
} __attribute__((packed));

/* CXL r3.0 Section 7.6.7.1.2: Get Physical Port State (Opcode 5101h) */
struct cxl_fmapi_get_phys_port_state_req {
	uint8_t num_ports; /* CHECK. may get too large for MCTP message size */
	uint8_t ports[];
} __attribute__((packed));

struct cxl_fmapi_port_state_info_block {
	uint8_t port_id;
	uint8_t config_state;
	uint8_t conn_dev_cxl_ver;
	uint8_t rsv1;
	uint8_t conn_dev_type;
	uint8_t port_cxl_ver_bitmask;
	uint8_t max_link_width;
	uint8_t negotiated_link_width;
	uint8_t supported_link_speeds_vector;
	uint8_t max_link_speed;
	uint8_t current_link_speed;
	uint8_t ltssm_state;
	uint8_t first_lane_num;
	uint16_t link_state;
	uint8_t supported_ld_count;
} __attribute__((packed));

struct cxl_fmapi_get_phys_port_state_rsp {
	uint8_t num_ports;
	uint8_t rsv1[3];
	struct cxl_fmapi_port_state_info_block ports[];
} __attribute__((packed));

/* Local tracking of what we have */
enum cxl_type {
	cxl_switch,
	cxl_type3,
};

typedef int (*trans)(int sd, struct sockaddr_mctp *addr, int *tag,
		     int port, int ld,
		     struct cci_msg *req_msg, size_t req_msg_sz,
		     struct cci_msg *rsp_msg, size_t rsp_msg_sz,
		     size_t rsp_msg_sz_min);

int sanity_check_rsp(struct cci_msg *req, struct cci_msg *rsp,
		     size_t len, bool fixed_length,
		     size_t min_length)
{
	uint32_t pl_length;

	printf("command set: 0x%x, command: 0x%x\n", req->command_set, req->command);

	if (len < sizeof(rsp)) {
		printf("Too short to read error code\n");
		return -1;
	}

	if (rsp->category != CXL_MCTP_CATEGORY_RSP) {
		printf("Message not a response\n");
		return -1;
	}
	if (rsp->tag != req->tag) {
		printf("Reply has wrong tag %d %d\n", rsp->tag, req->tag);
		return -1;
	}
	if ((rsp->command != req->command) ||
		(rsp->command_set != req->command_set)) {
		printf("Response to wrong command\n");
		return -1;
	}

	if (rsp->return_code != 0) {
		printf("Error code in response %d\n", rsp->return_code);
		return -1;
	}

	if (fixed_length) {
		if (len != min_length) {
			printf("Not expected fixed length of response. %ld %ld\n",
			       len, min_length);
			return -1;
		}
	} else {
		if (len < min_length) {
			printf("Not expected minimum length of response\n");
			return -1;
		}
	}
	pl_length = rsp->pl_length[0] | (rsp->pl_length[1] << 8) |
		((rsp->pl_length[2] & 0xf) << 16);
	if (len - sizeof(*rsp) != pl_length) {
		printf("Payload length not matching expected part of full message %ld %d\n",
		       len - sizeof(*rsp), pl_length);
		return -1;
	}

	return 0;
}

static int parse_mem_dev_identify_rsp(struct cci_mem_dev_identify_rsp *pl,
       enum cxl_type type)
{
    if (type != cxl_type3) {
        printf("This command is only valid for type 3 device");
        return -1;
    }

    printf("memory device identify output payload information:\n");
    printf("\ttotal capacity: %llx\n", pl->total_capacity);
    printf("\tvolatile capacity: %llx\n", pl->volatile_capacity);
    printf("\tpersistent capacity: %llx\n", pl->persistent_capacity);
    printf("\tLSA size: %x\n", pl->lsa_size);
    printf("\tDynamic capacity event log size: %x\n", pl->dc_event_log_size);
}

static int parse_identify_rsp(struct cci_infostat_identify_rsp *pl,
			      enum cxl_type *type)
{
	enum cxl_type t;

	printf("Infostat Identify Response:\n");
	switch (pl->component_type) {
	case 0x00:
		printf("\tType: Switch\n");
		t = cxl_switch;
		/* PCIe Bridges don't have subsytem IDs, so ignore fields */
		printf("\tVID:%04x DID:%04x\n", pl->vendor_id, pl->device_id);
		break;
	case 0x03:
		printf("\tType: Type3\n");
		t = cxl_type3;
		printf("\tVID:%04x DID:%04x SubsysVID:%04x SubsysID:%04x\n",
		       pl->vendor_id, pl->device_id,
		       pl->subsys_vendor_id, pl->subsys_id);
		break;
	default:
		printf("\tType: Unknown\n");
		return -1;
	}
	printf("\tSerial number: 0x%lx\n", *(uint64_t *)pl->serial_num);
	if (type)
		*type = t;

	return 0;
}

static int query_cci_mem_dev_identify(int sd, struct sockaddr_mctp *addr, int *tag,
			      enum cxl_type type,
			      trans trans_func, int port, int id)
{
	int rc;
	struct cci_mem_dev_identify_rsp *pl;
	struct cci_msg *rsp;
	ssize_t rsp_sz;
	struct cci_msg req = {
		.category = CXL_MCTP_CATEGORY_REQ,
		.tag = *tag++,
		.command = 0,
		.command_set = 0x40,
		.vendor_ext_status = 0xabcd,
	};

    if (type != cxl_type3) {
        printf("Identify Memory Device command is only valid for memory device, skip\n");
        return 0;
    }

	printf("Information and Status: Identify Memory Device Request...\n");
	rsp_sz = sizeof(*rsp) + sizeof(*pl);
	rsp = malloc(rsp_sz);
	if (!rsp)
		return -1;

	rc = trans_func(sd, addr, tag, port, id, &req, sizeof(req), rsp, rsp_sz,
			rsp_sz);
	if (rc) {
		printf("trans fun failed\n");
		goto free_rsp;
	}

	if (rsp->return_code) {
		rc = rsp->return_code;
		goto free_rsp;
	}
	pl = (struct cci_mem_dev_identify_rsp *)rsp->payload;
	rc = parse_mem_dev_identify_rsp(pl, type);

free_rsp:
	free(rsp);
	return rc;
}

static int query_cci_identify(int sd, struct sockaddr_mctp *addr, int *tag,
			      enum cxl_type *type,
			      trans trans_func, int port, int id)
{
	int rc;
	struct cci_infostat_identify_rsp *pl;
	struct cci_msg *rsp;
	ssize_t rsp_sz;
	struct cci_msg req = {
		.category = CXL_MCTP_CATEGORY_REQ,
		.tag = *tag++,
		.command = 1,
		.command_set = 0,
		.vendor_ext_status = 0xabcd,
	};

	printf("Information and Status: Identify Request...\n");
	rsp_sz = sizeof(*rsp) + sizeof(*pl);
	rsp = malloc(rsp_sz);
	if (!rsp)
		return -1;

	rc = trans_func(sd, addr, tag, port, id, &req, sizeof(req), rsp, rsp_sz,
			rsp_sz);
	if (rc) {
		printf("trans fun failed\n");
		goto free_rsp;
	}

	if (rsp->return_code) {
		rc = rsp->return_code;
		goto free_rsp;
	}
	pl = (struct cci_infostat_identify_rsp *)rsp->payload;
	rc = parse_identify_rsp(pl, type);

free_rsp:
	free(rsp);
	return rc;
}

static int query_cci_timestamp(int sd, struct sockaddr_mctp *addr, int *tag,
			       trans trans_func, int port, int id)
{
	struct cci_get_timestamp_rsp *pl;
	struct cci_msg *rsp;
	int rc;
	ssize_t rsp_sz;
	struct cci_msg req = {
		.category = CXL_MCTP_CATEGORY_REQ,
		.tag = *tag++,
		.command = 0,
		.command_set = 3,
		.vendor_ext_status = 0xabcd,
	};

	printf("Timestamp: Get Request...\n");
	rsp_sz = sizeof(*rsp) + sizeof(*pl);
	rsp = malloc(rsp_sz);

	rc = trans_func(sd, addr, tag, port, id, &req, sizeof(req), rsp, rsp_sz,
			sizeof(*rsp) + sizeof(*pl));
	if (rc)
		goto free_rsp;

	pl = (struct cci_get_timestamp_rsp *)(rsp->payload);
	printf("Timestamp Get Response\n");
	printf("\tTimestamp: is %lu\n", pl->timestamp);

free_rsp:
	free(rsp);
	return rc;
}

static const uint8_t cel_uuid[0x10] = { 0x0d, 0xa9, 0xc0, 0xb5,
					0xbf, 0x41,
					0x4b, 0x78,
					0x8f, 0x79,
					0x96, 0xb1, 0x62, 0x3b, 0x3f, 0x17 };

static const uint8_t ven_dbg[0x10] = { 0x5e, 0x18, 0x19, 0xd9,
				       0x11, 0xa9,
				       0x40, 0x0c,
				       0x81, 0x1f,
				       0xd6, 0x07, 0x19, 0x40, 0x3d, 0x86 };

static const uint8_t c_s_dump[0x10] = { 0xb3, 0xfa, 0xb4, 0xcf,
					0x01, 0xb6,
					0x43, 0x32,
					0x94, 0x3e,
					0x5e, 0x99, 0x62, 0xf2, 0x35, 0x67 };
static const int maxlogs = 10; /* Only 3 in CXL r3.0 but let us leave room */

static int parse_supported_logs(struct cci_get_supported_logs_rsp *pl,
				size_t *cel_size)
{
	int i, j;

	*cel_size = 0;
	printf("Get Supported Logs Response %d\n",
	       min(maxlogs, pl->num_supported_log_entries));

	for (i = 0; i < min(maxlogs, pl->num_supported_log_entries); i++) {
		for (j = 0; j < sizeof(pl->entries[i].uuid); j++) {
			if (pl->entries[i].uuid[j] != cel_uuid[j])
				break;
		}
		if (j == 0x10) {
			*cel_size = pl->entries[i].log_size;
			printf("\tCommand Effects Log available\n");
		}
		for (j = 0; j < sizeof(pl->entries[i].uuid); j++) {
			if (pl->entries[i].uuid[j] != ven_dbg[j])
				break;
		}
		if (j == 0x10)
			printf("\tVendor Debug Log available\n");
		for (j = 0; j < sizeof(pl->entries[i].uuid); j++) {
			if (pl->entries[i].uuid[j] != c_s_dump[j])
				break;
		}
		if (j == 0x10)
			printf("\tComponent State Dump Log available\n");

	}
	if (cel_size == 0) {
		printf("\tNo Command Effects Log - so don't continue\n");
		return -1;
	}
	return 0;
}

static int get_supported_logs(int sd, struct sockaddr_mctp *addr, int *tag,
			      size_t *cel_size,
			      trans trans_func, int port, int id)
{
	struct cci_get_supported_logs_rsp *pl;
	struct cci_msg *rsp;
	int rc;
	ssize_t rsp_sz;
	struct cci_msg req = {
		.category = CXL_MCTP_CATEGORY_REQ,
		.tag = *tag++,
		.command = 0,
		.command_set = 4,
		.vendor_ext_status = 0xabcd,
	};

	printf("Supported Logs: Get Request...\n");
	rsp_sz = sizeof(*rsp) + sizeof(*pl) + maxlogs * sizeof(*pl->entries);

	rsp = malloc(rsp_sz);
	if (!rsp)
		return -1;

	rc = trans_func(sd, addr, tag, port, id, &req, sizeof(req), rsp, rsp_sz,
			sizeof(*rsp) + sizeof(*pl));
	if (rc)
		goto free_rsp;

	pl = (void *)(rsp->payload);
	rc = parse_supported_logs(pl, cel_size);

free_rsp:
	free(rsp);
	return rc;
}


int send_mctp_direct(int sd, struct sockaddr_mctp *addr, int *tag, int port, int ld,
		     struct cci_msg *req_msg, size_t req_msg_sz,
		     struct cci_msg *rsp_msg, size_t rsp_msg_sz,
		     size_t rsp_msg_sz_min)
{
	struct sockaddr_mctp addrrx;
	int len;
	socklen_t addrlen;

	len = sendto(sd, req_msg, req_msg_sz, 0,
		     (struct sockaddr *)addr, sizeof(*addr));

	len = recvfrom(sd, rsp_msg, rsp_msg_sz, 0,
		       (struct sockaddr *)&addrrx, &addrlen);

	return sanity_check_rsp(req_msg, rsp_msg, len,
				rsp_msg_sz == rsp_msg_sz_min, rsp_msg_sz_min);
}

static int get_cel(int sd, struct sockaddr_mctp *addr, int *tag,
		   size_t cel_size,
		   trans trans_func, int port, int id)
{
	struct cci_get_log_cel_rsp *pl;
	struct cci_get_log_req *req_pl;
	struct cci_msg *req, *rsp;
	size_t req_sz, rsp_sz;
	int rc = 0;
	int i;

	req_sz = sizeof(*req) + sizeof(*req_pl);
	req = malloc(req_sz);
	if (!req)
		return -1;

	*req = (struct cci_msg) {
		.category = CXL_MCTP_CATEGORY_REQ,
		.tag = *tag++,
		.command = 1,
		.command_set = 4,
		.vendor_ext_status = 0xabcd,
		.pl_length = {
			[0] = sizeof(*req_pl) & 0xff,
			[1] = (sizeof(*req_pl) >> 8) & 0xff,
			[2] = (sizeof(*req_pl) >> 16) & 0xff,
		},
	};
	req_pl = (struct cci_get_log_req *)req->payload;
	memcpy(req_pl->uuid, cel_uuid, sizeof(req_pl->uuid));
	req_pl->offset = 0;
	req_pl->length = cel_size;

	rsp_sz = sizeof(*rsp) + cel_size;
	rsp = malloc(rsp_sz);
	if (!rsp) {
		rc = -1;
		goto free_req;
	}

	printf("Command Effects Log Requested\n");

	rc = trans_func(sd, addr, tag, port, id, req, req_sz, rsp, rsp_sz,
			rsp_sz);
	if (rc)
		goto free_rsp;

	pl = (struct cci_get_log_cel_rsp *)rsp->payload;
	printf("Command Effects Log\n");
	for (i = 0; i < cel_size / sizeof(*pl); i++) {
		printf("\t[%04x] %s%s%s%s%s%s%s%s\n",
		       pl[i].opcode,
		       pl[i].commandeffect & 0x1 ? "ColdReset " : "",
		       pl[i].commandeffect & 0x2 ? "ImConf " : "",
		       pl[i].commandeffect & 0x4 ? "ImData " : "",
		       pl[i].commandeffect & 0x8 ? "ImPol " : "",
		       pl[i].commandeffect & 0x10 ? "ImLog " : "",
		       pl[i].commandeffect & 0x20 ? "ImSec" : "",
		       pl[i].commandeffect & 0x40 ? "BgOp" : "",
		       pl[i].commandeffect & 0x80 ? "SecSup" : "");
	}
 free_rsp:
	free(rsp);
 free_req:
	free(req);

	return rc;
}

static int parse_phys_sw_identify_swdev(struct cxl_fmapi_ident_sw_dev_rsp *pl,
					int *num_ports)
{
	uint8_t *b;

	printf("Physical Switch Identify Switch Device Response:\n");
	printf("\tNum tot vppb %d, Num Bound vPPB %d, Num HDM dec per USP %d\n",
	       pl->num_total_vppb, pl->num_active_vppb,
	       pl->num_hdm_decoder_per_usp);
	printf("\tPorts %d\n", pl->num_physical_ports);
	*num_ports = pl->num_physical_ports;
	b = pl->active_port_bitmask;
	printf("\tActivePortMask ");
	for (int i = 0; i < 32; i++)
		printf("%02x", b[i]);
	printf("\n");
	return 0;
}

/* Only directly accessed for now */
int query_physical_switch_info(int sd, struct sockaddr_mctp *addr, int *tag,
			       int *num_ports,
			       trans trans_func, int port, int id)
{
	int rc;
	ssize_t rsp_sz;
	struct cci_msg req = {
		.category = CXL_MCTP_CATEGORY_REQ,
		.tag = *tag++,
		.command = CXL_IDENTIFY_SWITCH_DEVICE,
		.command_set = CXL_FM_API_CMD_SET_PHYSICAL_SWITCH,
		.vendor_ext_status = 0xabcd,
	};
	struct cxl_fmapi_ident_sw_dev_rsp *pl;
	struct cci_msg *rsp;

	printf("Physical Switch: Identify Switch Device Request...\n");
	rsp_sz = sizeof(*rsp) + sizeof(*pl);
	rsp = malloc(rsp_sz);
	if (!rsp)
		return -1;

	rc = trans_func(sd, addr, tag, port, id, &req, sizeof(req), rsp, rsp_sz,
			rsp_sz);
	if (rc) {
		printf("trans fun failed\n");
		goto free_rsp;
	}

	pl = (struct cxl_fmapi_ident_sw_dev_rsp *)rsp->payload;
	rc = parse_phys_sw_identify_swdev(pl, num_ports);

free_rsp:
	free(rsp);
	return rc;
}

int parse_phys_port_state_rsp(struct cxl_fmapi_get_phys_port_state_rsp *pl,
			      struct cxl_fmapi_get_phys_port_state_req *reqpl,
			      int *ds_dev_types)
{
	printf("Physical Switch Port State Response - num ports %d:\n", pl->num_ports);
	for (int i = 0; i < pl->num_ports; i++) {
		struct cxl_fmapi_port_state_info_block *port = &pl->ports[i];
		const char *port_states[] = {
			[0x0] = "Disabled",
			[0x1] = "Bind in progress",
			[0x2] = "Unbind in progress",
			[0x3] = "DSP",
			[0x4] = "USP",
			[0x5] = "Reserved",
			//other values not present.
			[0xf] = "Invalid Port ID"
		  };
		const char *conn_dev_modes[] = {
			[0] = "Not CXL / connected",
			[1] = "CXL 1.1",
			[2] = "CXL 2.0",
		};
		const char *conn_dev_type[] = {
			[0] = "No device detected",
			[1] = "PCIe device",
			[2] = "CXL type 1 device",
			[3] = "CXL type 2 device",
			[4] = "CXL type 3 device",
			[5] = "CXL type 3 pooled device",
			[6] = "Reserved",
		};
		const char *ltssm_states[] = {
			[0] = "Detect",
			[1] = "Polling",
			[2] = "Configuration",
			[3] = "Recovery",
			[4] = "L0",
			[5] = "L0s",
			[6] = "L1",
			[7] = "L2",
			[8] = "Disabled",
			[9] = "Loop Back",
			[10] = "Hot Reset",
		};

		if (port->port_id != reqpl->ports[i]) {
			printf("port id wrong %d %d\n",
			       port->port_id, reqpl->ports[i]);
			return -1;
		}
		printf("Port%02d:\n ", port->port_id);
		printf("\tPort state: ");
		if (port_states[port->config_state & 0xf])
			printf("%s\n", port_states[port->config_state]);
		else
			printf("Unknown state\n");

		/* DSP so device could be there */
		if (port->config_state == 3) {
			printf("\tConnected Device CXL Version: ");
			if (port->conn_dev_cxl_ver > 2)
				printf("Unknown CXL Version\n");
			else
				printf("%s\n",
				       conn_dev_modes[port->conn_dev_cxl_ver]);

			printf("\tConnected Device Type: ");
			ds_dev_types[i] = port->conn_dev_type;
			if (port->conn_dev_type > 7)
				printf("Unknown\n");
			else
				printf("%s\n",
				       conn_dev_type[port->conn_dev_type]);
		}

		printf("\tSupported CXL Modes:");
		if (port->port_cxl_ver_bitmask & 0x1)
			printf(" 1.1");
		if (port->port_cxl_ver_bitmask & 0x2)
			printf(" 2.0");
		printf("\n");

		printf("\tMaximum Link Width: %d Negotiated Width %d\n",
			   port->max_link_width,
			   port->negotiated_link_width);
		printf("\tSupported Speeds: ");
		if (port->supported_link_speeds_vector & 0x1)
			printf(" 2.5 GT/s");
		if (port->supported_link_speeds_vector & 0x2)
			printf(" 5.0 GT/s");
		if (port->supported_link_speeds_vector & 0x4)
			printf(" 8.0 GT/s");
		if (port->supported_link_speeds_vector & 0x8)
			printf(" 16.0 GT/s");
		if (port->supported_link_speeds_vector & 0x10)
			printf(" 32.0 GT/s");
		if (port->supported_link_speeds_vector & 0x20)
			printf(" 64.0 GT/s");
		printf("\n");

		printf("\tLTSSM: ");
		if (port->ltssm_state >= sizeof(ltssm_states))
			printf("Unkown\n");
		else
			printf("%s\n", ltssm_states[port->ltssm_state]);
	}
	return 0;
}

/* So far this is only used for direct connected CCIs */
int query_ports(int sd, struct sockaddr_mctp *addr, int *tag,
		int num_ports, int *ds_dev_types,
		trans trans_func, int port, int id)
{
	int rc, i;
	uint8_t *port_list;
	struct cci_msg *req, *rsp;
	struct cxl_fmapi_get_phys_port_state_req *reqpl;
	struct cxl_fmapi_get_phys_port_state_rsp *rsppl;

	size_t req_sz = sizeof(*reqpl) + num_ports + sizeof(*req);
	size_t rsp_sz = sizeof(*rsp) + sizeof(*rsppl) +
		num_ports * sizeof(*rsppl->ports);

	port_list = malloc(sizeof(*port_list) * num_ports);
	if (!port_list)
		return -1;

	for (i = 0; i < num_ports; i++) {
		/* Done like this to allow easy testing of nonsequential lists */
		port_list[i] = i;
	}

	req = malloc(req_sz);
	if (!req) {
		rc = -1;
		goto free_port_list;
	}
	rsp = malloc(rsp_sz);
	if (!rsp) {
		rc = -1;
		goto free_req;
	}

	*req = (struct cci_msg) {
		.category = CXL_MCTP_CATEGORY_REQ,
		.tag = *tag++,
		.command = CXL_GET_PHYSICAL_PORT_STATE,
		.command_set = CXL_FM_API_CMD_SET_PHYSICAL_SWITCH,
		.pl_length = {
			req_sz & 0xff,
			(req_sz >> 8) & 0xff,
			(req_sz >> 16) & 0xff },
		.vendor_ext_status = 0x1234,
	};
	reqpl = (void *)req->payload;
	*reqpl = (struct cxl_fmapi_get_phys_port_state_req) {
		.num_ports = num_ports,
	};
	for (int j = 0; j < num_ports; j++)
		reqpl->ports[j] = port_list[j];

	printf("Physical Switch Port State Requested\n");
	rc = trans_func(sd, addr, tag, port, id, req, req_sz, rsp, rsp_sz,
			rsp_sz);
	if (rc)
		goto free_rsp;

	rsppl = (struct cxl_fmapi_get_phys_port_state_rsp *)rsp->payload;

	/* Move to standard check */
	rc = parse_phys_port_state_rsp(rsppl, reqpl, ds_dev_types);
free_port_list:
	free(port_list);
free_rsp:
	free(rsp);
free_req:
	free(req);

	return rc;
}

void extract_rsp_msg_from_tunnel(struct cci_msg *tunnel_msg,
				 struct cci_msg *extracted_msg,
				 size_t extracted_msg_size)
{
	struct cxl_fmapi_tunnel_command_rsp *rsp =
		(struct cxl_fmapi_tunnel_command_rsp *)tunnel_msg->payload;

	memcpy(extracted_msg, &rsp->message, extracted_msg_size);
}

int build_tunnel_req(int *tag, int port_or_ld,
		     struct cci_msg *payload_in, size_t payload_in_sz,
		     struct cci_msg **payload_out, size_t *payload_out_sz)
{
	struct cxl_fmapi_tunnel_command_req *t_req;
	struct cci_msg *req;
	size_t t_req_sz = sizeof(*t_req) + payload_in_sz;
	size_t req_sz = sizeof(*req) + t_req_sz;

	req = malloc(req_sz);
	if (!req)
		return -1;

	*req = (struct cci_msg) {
		.category = CXL_MCTP_CATEGORY_REQ,
		.tag = *tag++,
		.command = 0,
		.command_set = 0x53,
		.vendor_ext_status = 0xabcd,
		.pl_length = {
			t_req_sz & 0xff,
			(t_req_sz >> 8) & 0xff,
			(t_req_sz >> 16) & 0xff,
		}
	};
	t_req = (struct cxl_fmapi_tunnel_command_req *)req->payload;
	*t_req = (struct cxl_fmapi_tunnel_command_req) {
		.target_type = TUNNEL_TARGET_TYPE_PORT_OR_LD,
		.id = port_or_ld,
		.command_size = payload_in_sz,
	};
	if (payload_in_sz)
		memcpy(t_req->message, payload_in, payload_in_sz);
	*payload_out = req;
	*payload_out_sz = req_sz;

	return 0;
}

int send_mctp_tunnel1(int sd, struct sockaddr_mctp *addr, int *tag, int port,
		      int ld,
		      struct cci_msg *req_msg, size_t req_msg_sz,
		      struct cci_msg *rsp_msg, size_t rsp_msg_sz,
		      size_t rsp_msg_sz_min)
{
	struct cxl_fmapi_tunnel_command_req *t_req;
	struct cxl_fmapi_tunnel_command_rsp *t_rsp;
	struct cci_msg *t_req_msg, *t_rsp_msg;
	struct sockaddr_mctp addrrx;
	size_t t_req_msg_sz, t_rsp_msg_sz, rsp_sz_min, len_max, len_min;
	int len, rc;
	socklen_t addrlen;

	build_tunnel_req(tag, port, req_msg, req_msg_sz, &t_req_msg,
			 &t_req_msg_sz);

	/* Outer CCI message + tunnel header + inner message */
	t_rsp_msg_sz = sizeof(*t_rsp_msg) + sizeof(*t_rsp) + rsp_msg_sz;
	/* These length will be update as tunnel unwound */
	len_min = sizeof(*t_rsp_msg) + sizeof(*t_rsp) + rsp_msg_sz_min;
	len_max = sizeof(*t_rsp_msg) + sizeof(*t_rsp) + rsp_msg_sz;
	t_rsp_msg = malloc(t_rsp_msg_sz);
	if (!t_rsp_msg) {
		rc = -1;
		goto free_req;
	}
	len = sendto(sd, t_req_msg, t_req_msg_sz, 0,
		     (struct sockaddr *)addr, sizeof(*addr));
	if (len != t_req_msg_sz) {
		printf("Failed to send whole request\n");
		rc = -1;
		goto free_rsp;
	}

	len = recvfrom(sd, t_rsp_msg, t_rsp_msg_sz, 0,
		       (struct sockaddr *)&addrrx, &addrlen);
	rc = sanity_check_rsp(t_req_msg, t_rsp_msg, len, len_min == len_max, len_min);
	if (rc)
		goto free_rsp;

	/* Update lengths to unwind the outer tunnel */
	len -= sizeof(*t_rsp_msg) + sizeof(*t_rsp);
	len_max -= sizeof(*t_rsp_msg) + sizeof(*t_rsp);
	len_min -= sizeof(*t_rsp_msg) + sizeof(*t_rsp);

	/* Unwind one level of tunnel */
	t_req = (struct cxl_fmapi_tunnel_command_req *)t_req_msg->payload;
	t_rsp = (struct cxl_fmapi_tunnel_command_rsp *)t_rsp_msg->payload;

	if (t_rsp->length != len) {
		printf("Tunnel length is not consistent with received length\n");
		rc = -1;
		goto free_rsp;
	}

	/* Need to exclude the tunneled command header from sizes as used for PL check */
	rc = sanity_check_rsp(t_req->message, t_rsp->message, len,
			      len_min == len_max, len_min);
	if (rc)
		goto free_rsp;
	extract_rsp_msg_from_tunnel(t_rsp_msg, rsp_msg, rsp_msg_sz);

 free_rsp:
	free(t_rsp_msg);
 free_req:
	free(t_req_msg);
	return rc;
}

int send_mctp_tunnel2(int sd, struct sockaddr_mctp *addr, int *tag,
		      int port, int ld,
		      struct cci_msg *req_msg, size_t req_msg_sz,
		      struct cci_msg *rsp_msg, size_t rsp_msg_sz,
		      size_t rsp_msg_sz_min)
{
	struct cci_msg *inner_req, *outer_req, *inner_rsp, *outer_rsp;
	size_t inner_req_sz, outer_req_sz, outer_rsp_sz, len_min, len_max;
	struct cxl_fmapi_tunnel_command_req *inner_t_req, *outer_t_req;
	struct cxl_fmapi_tunnel_command_rsp *inner_t_rsp, *outer_t_rsp;
	struct sockaddr_mctp addrrx;
	int len, rc;
	socklen_t addrlen;

	printf("2 Level tunnel of opcode %02x%02x\n",
	       req_msg->command_set, req_msg->command);

	rc = build_tunnel_req(tag, ld, req_msg, req_msg_sz,
			      &inner_req, &inner_req_sz);
	if (rc)
		return rc;

	rc = build_tunnel_req(tag, port, inner_req, inner_req_sz,
			      &outer_req, &outer_req_sz);

	if (rc)
		goto free_inner_req;

	/*
	 * Outer tunnel message + outer tunnel header +
	 * inner tunnel message + inner tunnel header +
	 * inner message
	 */
	outer_rsp_sz = sizeof(*outer_rsp) + sizeof(*outer_t_rsp) +
		sizeof(*inner_rsp) + sizeof(*inner_t_rsp) + rsp_msg_sz;
	len_min = sizeof(*outer_rsp) + sizeof(*outer_t_rsp) +
		sizeof(*inner_rsp) + sizeof(*inner_t_rsp) + rsp_msg_sz_min;
	len_max = outer_rsp_sz;
	outer_rsp = malloc(outer_rsp_sz);
	if (!outer_rsp) {
		rc = -1;
		goto free_outer_req;
	}

	len = sendto(sd, outer_req, outer_req_sz, 0,
		     (struct sockaddr *)addr, sizeof(*addr));
	if (len != outer_req_sz) {
		printf("Failed to send whole request\n");
		rc = -1;
		goto free_outer_rsp;
	}

	len = recvfrom(sd, outer_rsp, outer_rsp_sz, 0,
		       (struct sockaddr *)&addrrx, &addrlen);
	if (len < len_min) {
		printf("Not enough data in reply\n");
		rc = -1 ;
		goto free_outer_rsp;
	}

	rc = sanity_check_rsp(outer_req, outer_rsp, len, len_min == len_max,
			      len_min);
	if (rc)
		goto free_outer_rsp;

	len -= sizeof(*outer_rsp) + sizeof(*outer_t_rsp);
	len_min -= sizeof(*outer_rsp) + sizeof(*outer_t_rsp);
	len_max -= sizeof(*outer_rsp) + sizeof(*outer_t_rsp);

	outer_t_req = (struct cxl_fmapi_tunnel_command_req *)outer_req->payload;
	outer_t_rsp = (struct cxl_fmapi_tunnel_command_rsp *)outer_rsp->payload;

	if (outer_t_rsp->length != len) {
		printf("Tunnel length not consistent with received length\n");
		rc = -1;
		goto free_outer_rsp;
	}

	rc = sanity_check_rsp(outer_t_req->message, outer_t_rsp->message, len,
			      len_min == len_max, len_min);
	if (rc)
		goto free_outer_rsp;

	/*
	 * TODO: Consider doing the extra copies so that
	 * extract_rsp_msg_from_tunnel() could be used
	 */
	inner_rsp = outer_t_rsp->message;
	inner_t_req = (struct cxl_fmapi_tunnel_command_req *)inner_req->payload;
	inner_t_rsp = (struct cxl_fmapi_tunnel_command_rsp *)inner_rsp->payload;

	len -= sizeof(*inner_rsp) + sizeof(*inner_t_rsp);
	len_min -= sizeof(*inner_rsp) + sizeof(*inner_t_rsp);
	len_max -= sizeof(*inner_rsp) + sizeof(*inner_t_rsp);

	if (inner_t_rsp->length != len) {
		printf("Tunnel lenght not consistent with received length\n");
		rc = -1;
		goto free_outer_rsp;
	}
	rc = sanity_check_rsp(inner_t_req->message, inner_t_rsp->message, len,
			      len_min == len_max, len_min);
	if (rc)
		goto free_outer_rsp;

	extract_rsp_msg_from_tunnel(inner_rsp, rsp_msg, rsp_msg_sz);

 free_outer_rsp:
	free(outer_rsp);
 free_outer_req:
	free(outer_req);
 free_inner_req:
	free(inner_req);

	return rc;
}

/*
 * Whilst we don't send a cci_msg directly over the IOCTL, that has all the
 * information need - so transltate it to a struct cxl_send_command
 */
int send_ioctl(int fd, struct sockaddr_mctp *addr, int *tag, int port, int ld,
	       struct cci_msg *req_msg, size_t req_msg_sz,
	       struct cci_msg *rsp_msg, size_t rsp_msg_sz,
	       size_t rsp_msg_sz_min)
{
	int rc;
	/* Mapping to specific IOCTL is a pain - so use raw for now */
	struct cxl_send_command cmd = {
		.id = CXL_MEM_COMMAND_ID_RAW,
		.raw.opcode = req_msg->command | (req_msg->command_set << 8),
		/* The payload is the same, but take off the CCI message header */
		.in.size = req_msg_sz - sizeof(*req_msg),
		.in.payload = (__u64)req_msg->payload,
		.out.size = rsp_msg_sz - sizeof(*rsp_msg),
		.out.payload = (__u64)rsp_msg->payload,
	};

	rc = ioctl(fd, CXL_MEM_SEND_COMMAND, &cmd);
	if (rc < 0) {
		printf("IOCTL failed %d\n", rc);
		return rc;
	}

	if (cmd.retval != 0) {
		printf("IOCTL returned non zero retval %d\n", cmd.retval);
		return -1;
	}
	if (cmd.out.size < rsp_msg_sz_min - sizeof(*rsp_msg)) {
		printf("IOCTL returned too little data\n");
		return -1;
	}

	return 0;
}

int send_ioctl_tunnel1(int fd, struct sockaddr_mctp *addr, int *tag, int port, int ld,
		       struct cci_msg *req_msg, size_t req_msg_sz,
		       struct cci_msg *rsp_msg, size_t rsp_msg_sz,
		       size_t rsp_msg_sz_min)
{
	struct cxl_fmapi_tunnel_command_req *t_req;
	struct cxl_fmapi_tunnel_command_rsp *t_rsp;
	size_t t_req_sz, t_rsp_sz, len_min, len_max;
	struct cxl_send_command cmd;
	int rc, len;

	printf("Tunneling over switch CCI mailbox by IOCTL\n");

	/*
	 * Step 1. Wrap the CCI message in a tunnel command
	 * that we will send via ioctl.
	 */
	t_req_sz = sizeof(*t_req) + req_msg_sz;
	t_req = malloc(t_req_sz);
	if (!t_req)
		return -1;

	*t_req = (struct cxl_fmapi_tunnel_command_req) {
		.target_type = TUNNEL_TARGET_TYPE_PORT_OR_LD,
		.id = port,
		.command_size = req_msg_sz,
	};
	memcpy(t_req->message, req_msg, req_msg_sz);
	/* These will be updated to reflect current parsing state */
	len_min = sizeof(*t_req) + rsp_msg_sz_min;
	len_max = sizeof(*t_req) + rsp_msg_sz;

	t_rsp_sz = sizeof(*t_rsp) + rsp_msg_sz;
	t_rsp = calloc(t_rsp_sz, 1);
	if (!t_rsp) {
		rc = -1;
		goto free_tunnel_req;
	}

	cmd = (struct cxl_send_command) {
		.id = CXL_MEM_COMMAND_ID_RAW,
		.raw.opcode = 0 | (0x53 << 8),
		.in.payload = (__u64)t_req,
		.in.size = t_req_sz,
		.out.payload = (__u64)t_rsp,
		.out.size = t_rsp_sz,
	};
	rc = ioctl(fd, CXL_MEM_SEND_COMMAND, &cmd);
	if (rc < 0)
		goto free_tunnel_rsp;

	if (cmd.retval) {
		printf("bad return value\n");
		rc = -cmd.retval;
		goto free_tunnel_rsp;
	}
	len = cmd.out.size;

	if (len < len_min) {
		printf("IOCTL output too small %d < %d\n", len, len_min);
		rc = -1;
		goto free_tunnel_rsp;
	}

	len -= sizeof(*t_rsp);
	len_min -= sizeof(*t_rsp);
	len_max -= sizeof(*t_rsp);
	if (t_rsp->length != len) {
		printf("Tunnel length not consistent with ioctl data returned\n");
		rc = -1;
		goto free_tunnel_rsp;
	}
	if (t_rsp->length < len_min) {
		printf("Got back too liggle dat ain the tunnel\n");
		rc = -1;
		goto free_tunnel_rsp;
	};
	rc = sanity_check_rsp(t_req->message, t_rsp->message, len,
			      len_max == len_min, len_min);
	if (rc) {
		printf("Inner tunnel repsonse failed\n");
		goto free_tunnel_rsp;
	}

	memcpy(rsp_msg, t_rsp->message, rsp_msg_sz);

	if (rsp_msg->return_code) {
		rc = -rsp_msg->return_code;
		printf("ret code \n");
		goto free_tunnel_rsp;
	}

 free_tunnel_rsp:
	free(t_rsp);

 free_tunnel_req:
	free(t_req);
	return rc;
}


/*
 * 2 level tunnel - so there are two tunnel_command_req, tunnel_comamnd_rsp
 * burried in an ioctl message
 */
int send_ioctl_tunnel2(int fd, struct sockaddr_mctp *addr, int *tag, int port, int ld,
		      struct cci_msg *req_msg, size_t req_msg_sz,
		      struct cci_msg *rsp_msg, size_t rsp_msg_sz,
		      size_t rsp_msg_sz_min)
{
	struct cci_msg  *inner_req, *inner_rsp;
	size_t inner_req_sz;
	struct cxl_fmapi_tunnel_command_req *outer_t_req, *inner_t_req;
	struct cxl_fmapi_tunnel_command_rsp *outer_t_rsp, *inner_t_rsp;
	size_t outer_t_req_sz, outer_t_rsp_sz, len_min, len_max;
	struct cxl_send_command cmd;
	int rc, len;

	printf("Tunneling 2 levels over switch CCI mailbox by IOCTL\n");
	/*
	 * Step 1. Wrap to be the tunneled CCI message including payload in a
	 * CCI message that is a Tunnelled request.
	 *      12             4            req_msg_sz
	 * | CCIMessage | TunnelHdr | req_msg (CCIMessage +PL) |
	 */
	rc = build_tunnel_req(tag, ld, req_msg, req_msg_sz, &inner_req,
			      &inner_req_sz);
	if (rc)
		return rc;

	/*
	 * Step 2. Wrap the now already inner wrapped CCI message in
	 * tunnel command that we will send via ioctl.
	 * |      4        12 + 4 + req_msg_sz
	 * | Tunnel Hdr | Inner Req as above   |
	 */
	outer_t_req_sz = sizeof(*outer_t_req) + inner_req_sz;
	outer_t_req = malloc(outer_t_req_sz);
	if (!outer_t_req) {
		rc = -1;
		goto free_inner_req;
	}
	*outer_t_req = (struct cxl_fmapi_tunnel_command_req) {
		.target_type = TUNNEL_TARGET_TYPE_PORT_OR_LD,
		.id = port,
		.command_size = inner_req_sz,
	};
	memcpy(outer_t_req->message, inner_req, inner_req_sz);

	/*
	 * Allocate the whole response in one go
	 *       4           12           4             resp_msg_sz
	 * | TunnelHdr | CCIMessage | TunnelHdr | rsp_msg (CCIMessage + PL) |
	 */
	outer_t_rsp_sz = sizeof(*outer_t_rsp) + sizeof(*outer_t_rsp->message) +
		sizeof(*inner_t_rsp) + rsp_msg_sz;
	/*
	 * Also compute the max/min good response size - this will be updated as
	 * the tunnelling is unwound.
	 */
	len_min = sizeof(*outer_t_rsp) + sizeof(*outer_t_rsp->message) +
		sizeof(*inner_t_rsp) + rsp_msg_sz_min;
	len_max = outer_t_rsp_sz;

	outer_t_rsp = calloc(outer_t_rsp_sz, 1);
	if (!outer_t_rsp) {
		rc = -1;
		goto free_tunnel_req;
	}

	cmd = (struct cxl_send_command) {
		.id = CXL_MEM_COMMAND_ID_RAW,
		.raw.opcode = 0 | (0x53 << 8),
		.in.payload = (__u64)outer_t_req,
		.in.size = outer_t_req_sz,
		.out.payload = (__u64)outer_t_rsp,
		.out.size = outer_t_rsp_sz,
	};
	rc = ioctl(fd, CXL_MEM_SEND_COMMAND, &cmd);
	if (rc < 0)
		goto free_tunnel_rsp;

	if (cmd.retval) {
		printf("Bad return value\n");
		rc = -cmd.retval;
		goto free_tunnel_rsp;
	}
	len = cmd.out.size;

	/* Check overal message size */
	if (len < len_min) {
		printf("IOCTL output too small %d < %d\n", len, len_min);
		rc = -1;
		goto free_tunnel_rsp;
	}

	/* Check the length in the tunnel header */
	len -= sizeof(*outer_t_rsp);
	len_min -= sizeof(*outer_t_rsp);
	len_max -= sizeof(*outer_t_rsp);

	if (outer_t_rsp->length != len) {
		printf("Tunnel length not consistent with ioctl data returned\n");
		rc = -1;
		goto free_tunnel_rsp;
	}
	if (outer_t_rsp->length < len_min) {
		printf("Got back to little data in the tunnel overall %d %d %d\n",
		       outer_t_rsp->length, len_min, cmd.out.size);
		rc = -1;
		goto free_tunnel_rsp;
	}

	/* Check the outer tunnel */
	rc = sanity_check_rsp(outer_t_req->message, outer_t_rsp->message, len,
			      len_max == len_min, len_min);
	if (rc) {
		printf("Outer tunnel response failed\n");
		goto free_tunnel_rsp;
	}

	len -= sizeof(*inner_t_rsp) + sizeof(*inner_t_rsp->message);
	len_min -= sizeof(*inner_t_rsp) + sizeof(*inner_t_rsp->message);
	len_max -= sizeof(*inner_t_rsp) + sizeof(*inner_t_rsp->message);

	inner_t_req = (struct cxl_fmapi_tunnel_command_req *)inner_req->payload;
	inner_rsp = outer_t_rsp->message;
	inner_t_rsp = (struct cxl_fmapi_tunnel_command_rsp *)inner_rsp->payload;
	if (inner_t_rsp->length != len) {
		printf("Tunnel length not consistent with ioctl data returned\n");
		rc = -1;
		goto free_tunnel_rsp;
	}
	rc = sanity_check_rsp(inner_t_req->message, inner_t_rsp->message, len,
			      len_max == len_min, len_min);
	if (rc) {
		printf("Inner tunnel repsonse failed\n");
		goto free_tunnel_rsp;
	}
	extract_rsp_msg_from_tunnel(inner_rsp, rsp_msg, rsp_msg_sz);
 free_tunnel_rsp:
	free(outer_t_rsp);

 free_tunnel_req:
	free(outer_t_req);

 free_inner_req:
	free(inner_req);
	return rc;
}

/* A series of queries that only make sense if first hop hits a switch */
int poke_switch(int dev_addr, bool mctp, int fd, trans direct, trans tunnel1, trans tunnel2)
{
	struct sockaddr_mctp fmapi_addr = {
		.smctp_family = AF_MCTP,
		.smctp_network = 11,
		.smctp_addr.s_addr = dev_addr,
		.smctp_type = 0x7, /* CXL FMAPI */
		.smctp_tag = MCTP_TAG_OWNER,
	};
	int fmapi_sd, num_ports, i, rc;
	int *ds_dev_types;
	int tag = 42; /* can start anywhere */
	if (mctp) {
		fmapi_sd = socket(AF_MCTP, SOCK_DGRAM, 0);
		rc = bind(fmapi_sd, (struct sockaddr *)&fmapi_addr, sizeof(fmapi_addr));
		if (rc) {
			return -1;
		}
	} else {
		fmapi_sd = fd; /* For Switch CCI no difference */
	}

	rc = query_physical_switch_info(fmapi_sd, &fmapi_addr, &tag, &num_ports,
					direct, 0, 0);
	if (rc)
		goto err_close_fd;

	ds_dev_types = malloc(sizeof(*ds_dev_types) * num_ports);
	if (!ds_dev_types) {
		rc = -1;
		goto err_close_fd;
	}

	/* Next query some of the ports */
	rc = query_ports(fmapi_sd, &fmapi_addr, &tag, num_ports, ds_dev_types,
			 direct, 0, 0);
	if (rc)
		goto err_free_ds_dev_types;

	for (i = 0; i < num_ports; i++) {
		switch (ds_dev_types[i]) {
		case 5: /* MLD */ {
			size_t cel_size = 0;
			enum cxl_type target_type;
			printf("Query the FM-Owned LD.....\n");
			rc = query_cci_identify(fmapi_sd, &fmapi_addr, &tag,
						&target_type,
						tunnel1, i, 0);
			if (rc)
				goto err_free_ds_dev_types;

			rc = get_supported_logs(fmapi_sd, &fmapi_addr, &tag,
						&cel_size, tunnel1, i, 0);
			if (rc)
				goto err_free_ds_dev_types;

			rc = get_cel(fmapi_sd, &fmapi_addr, &tag,
				     cel_size, tunnel1, i, 0);
			if (rc)
				goto err_free_ds_dev_types;
			printf("Query LD%d.......\n", 0);

			rc = query_cci_identify(fmapi_sd, &fmapi_addr, &tag,
						&target_type,
						tunnel2, i, 0);
			if (rc)
				goto err_free_ds_dev_types;
			rc = get_supported_logs(fmapi_sd, &fmapi_addr, &tag,
						&cel_size, tunnel2, i, 0);
			if (rc)
				goto err_free_ds_dev_types;

			rc = get_cel(fmapi_sd, &fmapi_addr, &tag,
				     cel_size, tunnel2, i, 0);
			if (rc)
				goto err_free_ds_dev_types;

			break;
		}
		default:
			/* Ignoring other types for now */
			break;
		}
	}
err_free_ds_dev_types:
	free(ds_dev_types);
err_close_fd:
	close(fmapi_sd);

	return rc;
}

int poke_direct_mld(struct sockaddr_mctp *cci_addr, int cci_sd, int dev_addr)
{
	struct sockaddr_mctp fmapi_addr = {
		.smctp_family = AF_MCTP,
		.smctp_network = 11,
		.smctp_addr.s_addr = dev_addr,
		.smctp_type = 0x7, /* CXL FMAPI */
		.smctp_tag = MCTP_TAG_OWNER,
	};
	int fmapi_sd = socket(AF_MCTP, SOCK_DGRAM, 0);
	int tag = 0x42;
	int rc;
	size_t cel_size;

	rc = bind(fmapi_sd, (struct sockaddr *)&fmapi_addr, sizeof(fmapi_addr));
	if (rc)
		return -1;

	printf("1 level tunneled Querying supported logs\n");
	rc = get_supported_logs(fmapi_sd, &fmapi_addr, &tag, &cel_size,
				send_mctp_tunnel1, 0, 0);
	if (rc)
		goto err_close_fd;
	printf("Querying supported logs on LD done\n");

	printf("1 Level tunneled Identify Device Request\n");
	rc = query_cci_identify(fmapi_sd, &fmapi_addr, &tag, NULL,
				send_mctp_tunnel1, 0, 0);
	if (rc)
		goto err_close_fd;
	printf("1 Level tunneled Identify Device Response:\n");

	rc = get_cel(fmapi_sd, &fmapi_addr, &tag, cel_size,
		     send_mctp_tunnel1, 0, 0);

 err_close_fd:
	close(fmapi_sd);

	return rc;
}

int main(int argv, char **argc)
{
	int rc, cci_sd;
	int tag = 0; /* will increment on each use */
	int dev_addr;
	bool mctp;
	trans direct;
	trans tunnel1_level;
	trans tunnel2_level;
	/*
	 * CXL r3.0 + DMTF binding specs are not clear on what Message type
	 * is used for the non type specific commands such as Information and
	 * Status / Identify which may return that it is a switch or a type 3
	 * device and hence can be issued to either. The assumption here, is
	 & that for those command either smctp_type is fine. Likely though
	 * that a switch will not implement the Type 3 binding and an SLD
	 * won't implement FM-API binding (though it might be necessary for
	 * supporting tunneled commands via a switch) so in reality so it
	 * is probably a case of trial an error for any code trying to walk
	 * the devices it can see.
	 */
	struct sockaddr_mctp cci_addr = {
		.smctp_family = AF_MCTP,
		.smctp_network = 11,
		/*		.smctp_addr.s_addr = dev_addr, */
		.smctp_type = 0x8, /* CXL CCI */
		.smctp_tag = MCTP_TAG_OWNER,
	};

	enum cxl_type type;
	size_t cel_size;

	if (argv < 2) {
		printf("Please provide an MCTP address\n");
		return -1;
	}
	dev_addr = atoi(argc[1]);
	if (argv == 3) {
		char filename[40];

		snprintf(filename, sizeof(filename), "/dev/cxl/switch%d", dev_addr);
		mctp = false;

		cci_sd = open(filename, O_RDWR);
		if (cci_sd < 0)
			return -1;
		direct = &send_ioctl;
		tunnel1_level = &send_ioctl_tunnel1;
		tunnel2_level = &send_ioctl_tunnel2;
	} else {
		mctp = true;
		cci_addr.smctp_addr.s_addr = dev_addr;
		cci_sd = socket(AF_MCTP, SOCK_DGRAM, 0);
		rc = bind(cci_sd, (struct sockaddr *)&cci_addr, sizeof(cci_addr));
		if (rc)
			return -1;
		direct = &send_mctp_direct;
		tunnel1_level = &send_mctp_tunnel1;
		tunnel2_level = &send_mctp_tunnel2;
	}
	rc = query_cci_identify(cci_sd, &cci_addr, &tag, &type,
				direct, 0, 0);
	if (rc)
		goto close_cci_sd;

    rc = query_cci_mem_dev_identify(cci_sd, &cci_addr, &tag,
            type, direct, 0, 0);
    if (rc)
        goto close_cci_sd;

	rc = get_supported_logs(cci_sd, &cci_addr, &tag, &cel_size,
				direct, 0, 0);
	if (rc)
		goto close_cci_sd;

	rc = get_cel(cci_sd, &cci_addr, &tag, cel_size, direct, 0, 0);
	if (rc)
		goto close_cci_sd;

	if (type == cxl_switch) {
		int num_ports;

		if (mctp) { /* This test only meaninful for MCTP connections */
			/* Deliberately wrong message type */
			printf("NB: Next query is expected to fail due to wrong MCTP message type\n");
			rc = query_physical_switch_info(cci_sd, &cci_addr, &tag, &num_ports,
							direct, 0, 0);
			if (rc == 0) {
				printf("Should have failed to query switch info, but succeeded\n");
				goto close_cci_sd;
			}
		}
		rc = poke_switch(dev_addr, mctp, cci_sd, direct, tunnel1_level, tunnel2_level);
		if (rc)
			goto close_cci_sd;
	} else { /* FM Owned LD on a type 3 MLD directly connected */
		rc = query_cci_timestamp(cci_sd, &cci_addr, &tag,
					 direct, 0, 0);
		if (rc)
			goto close_cci_sd;

		rc = poke_direct_mld(&cci_addr, cci_sd, dev_addr);
		if (rc)
			goto close_cci_sd;
	}

close_cci_sd:
	close(cci_sd);
	return 0;
}
