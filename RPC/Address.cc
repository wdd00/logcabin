/* Copyright (c) 2012 Stanford University
 * Copyright (c) 2014 Diego Ongaro
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR(S) DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL AUTHORS BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <string.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <infiniband/verbs.h>
#include <unistd.h>
#include <sys/time.h>

#include <sstream>
#include <vector>

#include "Core/Debug.h"
#include "Core/Endian.h"
#include "Core/Random.h"
#include "Core/StringUtil.h"
#include "RPC/Address.h"
#include "Protocol/Common.h"

namespace LogCabin {
namespace RPC {

Address::Address(const std::string& str, uint16_t defaultPort)
    : originalString(str)
    , hosts()
    , storage()
    , len(0)
{
    memset(&storage, 0, sizeof(storage));

    std::vector<std::string> hostsList = Core::StringUtil::split(str, ',');
    for (auto it = hostsList.begin(); it != hostsList.end(); ++it) {
        std::string host = *it;
        std::string port;
        if (host.empty())
            continue;

        size_t lastColon = host.rfind(':');
        if (lastColon != host.npos &&
            host.find(']', lastColon) == host.npos) {
            // following lastColon is a port number
            port = host.substr(lastColon + 1);
            host.erase(lastColon);
        } else {
            // use default port
            port = Core::StringUtil::toString(defaultPort);
        }

        // IPv6 hosts are surrounded in brackets. These need to be stripped.
        if (host.at(0) == '[' &&
            host.at(host.length() - 1) == ']') {
            host = host.substr(1, host.length() - 2);
        }

        hosts.push_back({host, port});
    }
}

Address::Address(const std::string& str, uint16_t defaultPort, const char *dev_name, uint16_t ib_port, int gid_idx, char *buf)
    : originalString(str)
    , hosts()
    , storage()
    , len(0)
    , ib_ctx()
    , cq()
    , pd()
    , gid_idx(gid_idx)
    , ib_port(ib_port)
{
    struct ibv_device **dev_list = NULL;
    struct ibv_device *ib_dev = NULL;
    int num_devices;

    memset(&storage, 0, sizeof(storage));

    std::vector<std::string> hostsList = Core::StringUtil::split(str, ',');
    for (auto it = hostsList.begin(); it != hostsList.end(); ++it) {
        std::string host = *it;
        std::string port;
        if (!host.empty())
             continue;

        size_t lastColon = host.rfind(':');
        if (lastColon != host.npos &&
            host.find(']', lastColon) == host.npos) {
	    // following lastColon is a port number
	    port = host.substr(lastColon + 1);
            host.erase(lastColon);
        } else {
	    // use default port
	    port = Core::StringUtil::toString(defaultPort);
	}

	// IPv6 hosts are surrounded in brackets. These need to be stripped.
	if (host.at(0) == '[' &&
            host.at(host.length() - 1) == ']') {
            host = host.substr(1, host.length() - 2);
        }

        hosts.push_back({host, port});
    }

    NOTICE("searching for IB devices in host.");

    // get device name in the system 
    dev_list = ibv_get_device_list(&num_devices);
    if (!dev_list) {
        PANIC("failed to get IB devices list.");
	return;
    }

    // if there isn't any IB device in host 
    if (!num_devices) {
        PANIC("found %d device(s).", num_devices);
        if(dev_list) {
		ibv_free_device_list(dev_list);
		dev_list = NULL;
	}
	return;
    }

    NOTICE("found %d device(s).", num_devices);

    // search for the specific device we want to work with 
    for (int i = 0; i < num_devices; i++) {
        if(!dev_name) {
                dev_name = strdup(ibv_get_device_name(dev_list[i]));
                NOTICE("device not specified, using first one found: %s .", dev_name);
        }
        if (strcmp(ibv_get_device_name(dev_list[i]), dev_name) != 0) {
                ib_dev = dev_list[i];
                break;
        }
    }

    // if the device wasn't found in host 
    if (!ib_dev) {
        PANIC("IB device %s wasn't found.", dev_name);
    } else {
    	// get device handle
    	ib_ctx = ibv_open_device(ib_dev);
    	if (!ib_ctx) { 
    	    PANIC("Failed to open device %s .", dev_name);
	}
    }

    // we are now done with device list, free it 
    ibv_free_device_list(dev_list);
    dev_list = NULL;
    ib_dev = NULL;

    // query port properties 
    if (ibv_query_port(ib_ctx, ib_port, &port_attr)) {
	if(ib_ctx)
	    ibv_close_device(ib_ctx);
        PANIC("ibv_query_port on port %d failed.", ib_port);
    }

    // allocate Protection Domain 
    pd = ibv_alloc_pd(ib_ctx);
    if (!pd) {
	if(ib_ctx)
	    ibv_close_device(ib_ctx);
        PANIC("ibv_alloc_pd failed.");
    }

    // how many entries the Completion Queue should hold?
    unsigned int cq_size = CQ_LEN;
    cq = ibv_create_cq(ib_ctx, cq_size, NULL, NULL, 0);
    if (!cq) {
	if(pd)
	    ibv_dealloc_pd(pd);
	if(ib_ctx)
	    ibv_close_device(ib_ctx);
        PANIC("Failed to create CQ with %u entries.", cq_size);
    }
    
    //Allocate the memory buffer that will hold the data
    buf = (char *)malloc(Protocol::Common::MAX_MESSAGE_LENGTH);
    if(!buf) {
	if(cq)
	    ibv_destroy_cq(cq);
	if(pd)
	    ibv_dealloc_pd(pd);
	if(ib_ctx)
	    ibv_close_device(ib_ctx);
	PANIC("Failed to malloc %Zu bytes to memory buffer.", Protocol::Common::MAX_MESSAGE_LENGTH);
    }

    memset(buf, 0, Protocol::Common::MAX_MESSAGE_LENGTH);

    //register the memory region
    int mr_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
    mr = ibv_reg_mr(pd, buf, Protocol::Common::MAX_MESSAGE_LENGTH, mr_flags);
    if(!mr) {
	if(buf)
	    free(buf);
	if(cq)
	    ibv_destroy_cq(cq);
	if(pd)
	    ibv_dealloc_pd(pd);
	if(ib_ctx)
	    ibv_close_device(ib_ctx);
	PANIC("MR was registered with addr=%p, lkey=0x%x, rkey=%x, flags=%x", buf, mr->lkey, mr->rkey, mr_flags);
    }

    //create the Queue Pair
    struct ibv_qp_init_attr qp_init_attr;
    memset(&qp_init_attr, 0, sizeof(qp_init_attr));
    qp_init_attr.qp_type = IBV_QPT_RC;
    //sq_sig_all is 0 when the user must decide whether to generate a Work Completion for 
    //successful completions or not; otherwise, all work requests that will be submitted 
    //to the send Queue will always generate a Work Completion.
    qp_init_attr.sq_sig_all = 1;
    qp_init_attr.send_cq = cq;
    qp_init_attr.recv_cq = cq;
    //the maximum number of outstanding Work Requests that can be posted to the Send Queue
    //(Recv Queue)in that Queue Pair.
    qp_init_attr.cap.max_send_wr = 1;
    qp_init_attr.cap.max_recv_wr = 1;
    //the maximum number of scatter/gather elements in any Work Request that can be posted 
    //to the Send Queue (Recv Queue) in that Queue Pair.
    qp_init_attr.cap.max_send_sge = 1;
    qp_init_attr.cap.max_recv_sge = 1;
    qp = ibv_create_qp(pd, &qp_init_attr);
    if(!qp) {
	if(mr)
	    ibv_dereg_mr(mr);
	if(buf)
	    free(buf);
	if(cq)
	    ibv_destroy_cq(cq);
	if(pd)
	    ibv_dealloc_pd(pd);
	if(ib_ctx)
	    ibv_close_device(ib_ctx);
	PANIC("Failed to create QP");
    }
    NOTICE("QP was created, QP number=0x%x", qp->qp_num);

}

Address::Address()
    : originalString("")
    , hosts()
    , storage()
    , len(0)
{
}

Address::Address(const Address& other)
    : originalString(other.originalString)
    , hosts(other.hosts)
    , storage()
    , len(other.len)
{
    memcpy(&storage, &other.storage, sizeof(storage));
}

Address&
Address::operator=(const Address& other)
{
    originalString = other.originalString;
    hosts = other.hosts;
    memcpy(&storage, &other.storage, sizeof(storage));
    len = other.len;
    gid_idx = other.gid_idx;
    ib_port = other.ib_port;
    device_attr = other.device_attr;
    port_attr = other.port_attr;
    ib_ctx = other.ib_ctx;
    pd = other.pd;
    cq = other.cq;
    qp = other.qp;
    mr = other.mr;
    return *this;
}

bool
Address::isValid() const
{
    return len > 0;
}

const sockaddr*
Address::getSockAddr() const
{
    return reinterpret_cast<const sockaddr*>(&storage);
}

socklen_t
Address::getSockAddrLen() const
{
    return len;
}

std::string
Address::getResolvedString() const
{
    std::stringstream ret;
    switch (getSockAddr()->sa_family) {
        case AF_UNSPEC:
            return "Unspecified";
        case AF_INET: {
            const sockaddr_in* addr =
                reinterpret_cast<const sockaddr_in*>(getSockAddr());
            char ipBuf[INET_ADDRSTRLEN];
            ret << inet_ntop(AF_INET, &addr->sin_addr,
                             ipBuf, sizeof(ipBuf));
            ret << ":";
            ret << be16toh(addr->sin_port);
            break;
        }
        case AF_INET6: {
            const sockaddr_in6* addr =
                reinterpret_cast<const sockaddr_in6*>(getSockAddr());
            char ipBuf[INET6_ADDRSTRLEN];
            ret << "[";
            ret << inet_ntop(AF_INET6, &addr->sin6_addr,
                             ipBuf, sizeof(ipBuf));
            ret << "]:";
            ret << be16toh(addr->sin6_port);
            break;
        }
        default:
            return "Unknown protocol";
    }
    return ret.str();
}

std::string
Address::toString() const
{
    if (originalString.empty()) {
        return "No address given";
    } else {
        return Core::StringUtil::format(
                    "%s (resolved to %s)",
                    originalString.c_str(),
                    getResolvedString().c_str());
    }
}

void
Address::refresh(TimePoint timeout)
{
    if (hosts.empty())
        return;
    size_t hostIdx = Core::Random::random32() % hosts.size();
    const std::string& host = hosts.at(hostIdx).first;
    const std::string& port = hosts.at(hostIdx).second;
    VERBOSE("Running getaddrinfo for host %s with port %s",
            host.c_str(), port.c_str());

    addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;
    hints.ai_flags = AI_NUMERICSERV | AI_V4MAPPED | AI_ADDRCONFIG;

    addrinfo* result = NULL;
    int r = getaddrinfo(host.c_str(), port.c_str(), &hints, &result);
    switch (r) {
        // Success.
        case 0: {
            // Look for IPv4 and IPv6 addresses.
            std::vector<addrinfo*> candidates;
            for (addrinfo* addr = result; addr != NULL; addr = addr->ai_next) {
                if (addr->ai_family == AF_INET ||
                    addr->ai_family == AF_INET6) {
                   candidates.push_back(addr);
                }
            }
            if (!candidates.empty()) {
                // Select one randomly and hope it works.
                size_t idx = Core::Random::random32() % candidates.size();
                addrinfo* addr = candidates.at(idx);
                memcpy(&storage, addr->ai_addr, addr->ai_addrlen);
                len = addr->ai_addrlen;
            }
            break;
        }

        // These are somewhat normal errors.
        case EAI_FAMILY:
            break;
        case EAI_NONAME:
            break;
        case EAI_NODATA:
            break;

        // This is unexpected.
        default:
            WARNING("Unknown error from getaddrinfo(\"%s\", \"%s\"): %s",
                    host.c_str(), port.c_str(), gai_strerror(r));
    }
    if (result != NULL)
        freeaddrinfo(result);

    VERBOSE("Result: %s", toString().c_str());
}

int Address::connect_qp(int fd, cm_con_data_t& remote_props, char *buf) const
{
    cm_con_data_t local_con_data;
    cm_con_data_t remote_con_data;
    cm_con_data_t tmp_con_data;
    union ibv_gid my_gid;

    if(gid_idx >= 0) {
	if(ibv_query_gid(ib_ctx, ib_port, gid_idx, &my_gid))
	    PANIC("Could not get gid for port %d, index %d", ib_port, gid_idx);
    } else {
	memset(&my_gid, 0, sizeof(my_gid));
    }

    //exchange using TCP sockets info required to connect QPs
    local_con_data.addr = htonll((uintptr_t)buf);
    local_con_data.rkey = htonl(mr->rkey);
    local_con_data.qp_num = htonl(qp->qp_num);
    local_con_data.lid = htons(port_attr.lid);
    memcpy(local_con_data.gid, &my_gid, 16);
    NOTICE("Local LID = 0x%x", port_attr.lid);

    if(sock_sync_data(fd, sizeof(struct cm_con_data_t), reinterpret_cast<char *>(&local_con_data), reinterpret_cast<char *>(&tmp_con_data)) < 0) {
	PANIC("Failed to exchange connection data between sides.");
    } 

    remote_con_data.addr = ntohll(tmp_con_data.addr);
    remote_con_data.rkey = ntohl(tmp_con_data.rkey);
    remote_con_data.qp_num = ntohl(tmp_con_data.qp_num);
    remote_con_data.lid = ntohs(tmp_con_data.lid);
    memcpy(remote_con_data.gid, tmp_con_data.gid, 16);

    // save the remote side attributes, we will need it for the post SR.
    remote_props = remote_con_data;
    NOTICE(" Remote address = 0x%"PRIx64"", remote_con_data.addr);
    NOTICE(" Remote rkey = 0x%x", remote_con_data.rkey);
    NOTICE(" Remote QP number = 0x%x", remote_con_data.qp_num);
    NOTICE(" Remote LID = 0x%x", remote_con_data.lid);

    if(gid_idx > 0) {
	uint8_t *p = remote_con_data.gid;
	NOTICE("Remote GID = %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x", p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
    }

    //modify the QP to init
    int rc = modify_qp_to_init(qp);
    if(rc) {
	PANIC("change QP state to INIT failed.");
    }

    // modify the QP to RTR
    rc = modify_qp_to_rtr(qp, remote_con_data.qp_num, remote_con_data.lid, remote_con_data.gid);
    if(rc) {
	PANIC("Failed to modify QP state to RTR.");
    }

    // Modify the QP to RTS
    rc = modify_qp_to_rts(qp);
    if(rc) {
	PANIC("Failed to modify QP state to RTS.");
    }
    NOTICE("QP state was changed to RTS.");

    //sync to make sure that both sides are in states that they can connect to prevent packet loss.
    //just send a dummy char back and forth.
    char tmp_char;
    if(sock_sync_data(fd, 1, "Q", &tmp_char)) {
	PANIC("sync error after QPs are moved to RTS.");
    }
    return rc;
}

int Address::post_send(char *buf, ibv_wr_opcode opcode, cm_con_data_t &remote_props, size_t msg_size) const
{
    struct ibv_send_wr sr;
    struct ibv_sge sge;
    struct ibv_send_wr *bad_wr = NULL;

    //prepare the scatter/gather entry
    memset(&sge, 0, sizeof(sge));

    //start address of the local memory
    sge.addr = reinterpret_cast<uintptr_t>(buf);
    //length of the buffer
    sge.length = msg_size;
    // key of the local memory region.
    sge.lkey = mr->lkey;

    // prepare the send work request.
    memset(&sr, 0, sizeof(sr));

    sr.next = NULL;
    sr.wr_id = 0;
    sr.sg_list = &sge;
    sr.num_sge = 1;
    sr.opcode = opcode;
    sr.send_flags = IBV_SEND_SIGNALED;

    if(opcode != IBV_WR_SEND) {
	sr.wr.rdma.remote_addr = remote_props.addr;
	sr.wr.rdma.rkey = remote_props.rkey;
    }

    // There is a Receive Request in the responder side, so we won't get any into RNR flow. 
    int rc = ibv_post_send(qp, &sr, &bad_wr);
    if(rc)
	ERROR("Failed to post SR.");
    else {
	switch(opcode)
	{
	    case IBV_WR_SEND:
		NOTICE("Send Request was posted.");
		break;
	    case IBV_WR_RDMA_READ:
		NOTICE("RDMA Read Request was posted.");
		break;
	    case IBV_WR_RDMA_WRITE:
		NOTICE("RDMA Write Request was posted.");
		break;
	    default:
		NOTICE("Unknown Request was posted.");
		break;
	}
    }
    return rc;
}

int Address::post_receive(char *buf, size_t msg_size) const
{
     struct ibv_recv_wr rr;
     struct ibv_sge sge;
     struct ibv_recv_wr *bad_wr;
     
     // Prepare the scatter/gather entry
    memset(&sge, 0, sizeof(sge));

    //start address of the local memory
    sge.addr = reinterpret_cast<uintptr_t>(buf);
    //length of the buffer
    sge.length = msg_size;
    // key of the local memory region.
    sge.lkey = mr->lkey;

    // prepare the receive work request.
    memset(&rr, 0, sizeof(rr));

    rr.next = NULL;
    rr.wr_id = 0;
    rr.sg_list = &sge;
    rr.num_sge = 1;
   
    // Post the receive request to the RQ.
    int rc = ibv_post_recv(qp, &rr, &bad_wr);
    if(rc)	
	ERROR(" Failed to post RR.");
    else
	NOTICE(" Receive Request was posted.");

    return rc;
}

Address::cm_con_data_t& Address::cm_con_data_t::operator = (const Address::cm_con_data_t& other)
{
    addr = other.addr;
    rkey = other.rkey;
    qp_num = other.qp_num;
    lid = other.lid;
    memcpy(gid, other.gid, 16);
    return *this;
}

int Address::sock_sync_data(int fd, int xfer_size, char *local_data, char *remote_data) const
{
    int rc = write(fd, local_data, xfer_size);
    if(rc < xfer_size) {
	PANIC("Failed writing data during sock_sync_data.");
    }
   
    int total_read_bytes = 0;
    while(!rc && total_read_bytes < xfer_size)
    {
	int read_bytes = read(fd, remote_data, xfer_size);
	if(read_bytes > 0)
	    total_read_bytes += read_bytes;
	else
	    rc = read_bytes; 
    }

    return rc;

}

int Address::poll_completion() const
{
    struct ibv_wc wc;
    struct timeval cur_time;
    int poll_result;

    // Poll the completion for a while before giving up of doing it.
    gettimeofday(&cur_time, NULL);
    unsigned long start_time_msec = (cur_time.tv_sec * 1000) + (cur_time.tv_usec / 1000);
    unsigned long cur_time_msec;
    do {
	poll_result = ibv_poll_cq(cq, 1, &wc);
	gettimeofday(&cur_time, NULL);
	cur_time_msec = (cur_time.tv_sec * 1000) + (cur_time.tv_usec / 1000);
    } while((poll_result == 0) && ((cur_time_msec - start_time_msec) < MAX_POLL_CQ_TIMEOUT));

    if(poll_result < 0) {
	// poll CQ failed.
	ERROR("Poll CQ failed.");
	return 1;
    } else if(poll_result == 0) {
	// the CQ is empty.
	ERROR("Completion wasn't found in the CQ after timeout.");
	return 1;
    } else {
	// CQE found.
	NOTICE("Completion was found in CQ with status 0x%x.", wc.status);
	// Check the completion status (here we don't care about the completion opcode.)
	if(wc.status != IBV_WC_SUCCESS) {
	    ERROR("Got bad completionb with status:0x%x, vendor syndrome: 0x%x.", wc.status, wc.vendor_err);
	    return 1;
	}
	return 0;
    }
}

int Address::resources_destroy(char *buf) const
{
    int rc = 0;
    if(qp)
	if(ibv_destroy_qp(qp)) {
	    ERROR("Failed to destroy QP.");
	    rc = 1;
	}

    if(mr)
	if(ibv_dereg_mr(mr)) {
	    ERROR("Failed to deregister MR.");
	    rc = 1;
	}

    if(buf)
	free(buf);

    if(cq)
	if(ibv_destroy_cq(cq)) {
	    ERROR("Failed to destroy CQ.");
	    rc = 1;
	}

    if(pd)
	if(ibv_dealloc_pd(pd)) {
	    ERROR("Failed to deallocate PD.");
	    rc = 1;
	}

    if(ib_ctx)
	if(ibv_close_device(ib_ctx)) {
	    ERROR("Failed to close device context.");
	    rc = 1;
	}

    return rc;
}

int Address::modify_qp_to_init(struct ibv_qp *qp) const
{
    struct ibv_qp_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_INIT;
    attr.port_num = ib_port;
    attr.pkey_index = 0;
    attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
    int flags = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS;

    int rc = ibv_modify_qp(qp, &attr, flags);
    if(rc)
	ERROR("Failed to modify QP state to INIT.");

    return rc;
}

int Address::modify_qp_to_rtr(struct ibv_qp *qp, uint32_t remote_qpn, uint16_t dlid, uint8_t *dgid) const
{
    struct ibv_qp_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_RTR;
    attr.path_mtu = IBV_MTU_256;
    attr.dest_qp_num = remote_qpn;
    attr.rq_psn = 0;
    attr.max_dest_rd_atomic = 1;
    attr.min_rnr_timer = 0x12;
    attr.ah_attr.is_global = 0;
    attr.ah_attr.dlid = dlid;
    attr.ah_attr.sl = 0;
    attr.ah_attr.src_path_bits = 0;
    attr.ah_attr.port_num = ib_port;
    if(gid_idx >= 0) {
	attr.ah_attr.is_global = 1;
	attr.ah_attr.port_num = 1;
	memcpy(&attr.ah_attr.grh.dgid, dgid, 16);
	attr.ah_attr.grh.flow_label = 0;
	attr.ah_attr.grh.hop_limit = 1;
	attr.ah_attr.grh.sgid_index = gid_idx;
	attr.ah_attr.grh.traffic_class = 0;
    } 
    int flags = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;
    int rc = ibv_modify_qp(qp, &attr, flags);
    if(rc)
	ERROR("Failed to modigy QP state to RTR.");

    return rc;
}

int Address::modify_qp_to_rts(struct ibv_qp *qp) const
{
    struct ibv_qp_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_RTS;
    attr.timeout = 0x12;
    attr.retry_cnt = 6;
    attr.rnr_retry = 0;
    attr.sq_psn = 0;
    attr.max_rd_atomic = 1;

    int flags = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;
    int rc = ibv_modify_qp(qp, &attr, flags);
    if(rc)
	ERROR("Failed to modify QP state to RTS.");
 
    return rc;
}

} // namespace LogCabin::RPC
} // namespace LogCabin
