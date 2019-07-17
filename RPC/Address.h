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

#ifndef LOGCABIN_RPC_ADDRESS_H
#define LOGCABIN_RPC_ADDRESS_H

#include <sys/socket.h>
#include <string>
#include <vector>
#include <infiniband/verbs.h>
#include <byteswap.h>

#include "Core/Time.h"

//set the default size of completion queue is 1
#define CQ_LEN 1
// poll CQ timeout in millisec (2 seconds)
#define MAX_POLL_CQ_TIMEOUT 2000

namespace LogCabin {
namespace RPC {

/**
 * This class resolves user-friendly addresses for services into socket-level
 * addresses. It supports DNS lookups for addressing hosts by name, and it
 * supports multiple (alternative) addresses.
 */
class Address {
  public:
    /// Clock used for timeouts.
    typedef Core::Time::SteadyClock Clock;
    /// Type for absolute time values used for timeouts.
    typedef Clock::time_point TimePoint;

    /**
     * Constructor. You will usually need to call #refresh() before using this
     * class.
     * \param str
     *      A string representation of the host and, optionally, a port number.
     *          - hostname:port
     *          - hostname
     *          - IPv4Address:port
     *          - IPv4Address
     *          - [IPv6Address]:port
     *          - [IPv6Address]
     *      Or a comma-delimited list of these to represent multiple hosts.
     * \param defaultPort
     *      The port number to use if none is specified in str.
     */
    Address(const std::string& str, uint16_t defaultPort);

    /**
     * Constructor. you will usually need to call #refresh() before using this class.
     * \param str
     *      A string representation of the host and, optionally, a port number.
     *          - hostname:port
     *          - hostname
     *          - IPv4Address:port
     *          - IPv4Address
     *          - [IPv6Address]:port
     *          - [IPv6Address]
     *      Or a comma-delimited list of these to represent multiple hosts. 
     * \param defaultPort
     *      The port number to use if none is specified in str.
     * \param dev_name
     *      The name of infiniband device.
     * \param ib_port
     *      The port number of infiniband device to use.            
     * \param rc
     * 	The value to judge whether the IB connection is available, 0 for success; 1 for error.
     */
    Address(const std::string& str, uint16_t defaultPort, const char *dev_name, uint16_t ib_port, int gid_idx, char *buf);

    /// Default constructor.
    Address();

    /// Copy constructor.
    Address(const Address& other);

    /// Assignment.
    Address& operator=(const Address& other);

    /**
     * Structure to exchange data which is needed to connect the QPs 
     */
    struct cm_con_data_t {
        uint64_t addr; /* Buffer address */
        uint32_t rkey; /* Remote key */
        uint32_t qp_num; /* QP number */
        uint16_t lid; /* LID of the IB port */
        uint8_t gid[16]; /* gid */
        cm_con_data_t& operator = (const cm_con_data_t& other);
    }__attribute__ ((packed));

    /**
     * Return true if the sockaddr returned by getSockAddr() is valid.
     * \return
     *      True if refresh() has ever succeeded for this host and port.
     *      False otherwise.
     */
    bool isValid() const;

    /**
     * Return a sockaddr that may be used to connect a socket to this Address.
     * \return
     *      The returned value will never be NULL and it is always safe to read
     *      the protocol field from it, even if getSockAddrLen() returns 0.
     */
    const sockaddr* getSockAddr() const;

    /**
     * Return the length in bytes of the sockaddr in getSockAddr().
     * This is the value you'll want to pass in to connect() or bind().
     */
    socklen_t getSockAddrLen() const;

    /**
     * Return a string describing the sockaddr within this Address.
     * This string will reflect the numeric address produced by the latest
     * successful call to refresh(), or "Unspecified".
     */
    std::string getResolvedString() const;

    /**
     * Return a string describing this Address.
     * This will contain both the user-provided string passed into the
     * constructor and the numeric address produced by the latest successful
     * call to refresh(). It's the best representation to use in error messages
     * for the user.
     */
    std::string toString() const;

    /**
     * Convert (a random one of) the host(s) and port(s) to a sockaddr.
     * If the host is a name instead of numeric, this will run a DNS query and
     * select a random result. If this query fails, any previous sockaddr will
     * be left intact.
     * \param timeout
     *      Not yet implemented.
     * \warning
     *      Timeouts have not been implemented.
     *      See https://github.com/logcabin/logcabin/issues/75
     */
    void refresh(TimePoint timeout);

    /**
     * Connect the QP. Transition sender side to RTS.
     * \Returns
     * 	    0 on success, error code on failure.
     */
    int connect_qp(int fd, cm_con_data_t& remote_props, char *buf) const; 

    /**
     * Sync data across a socket. The indicated local data will be sent to the 
     * remote. It will then wait for the remote to send its data back. It is 
     * assumed that the two sides are in sync and call this function in the 
     * proper order. Chaos will ensue if they are not.
     * Also note this is a blocking function and will wait for the full data 
     * to be received from the remote.
     * \param fd
     *     socket to transfer data on.
     * \param xfer_size
     *     the size of data to transfer.
     * \param local_data
     *     pointer to data to be sent to remote.
     * \param remote_data
     *     pointer to buffer to receive remote data.
     */
    int sock_sync_data(int fd, int xfer_size, char *local_data, char *remote_data) const;

    /**
     * This function will create and post a send work request.
     * \param buf
     * 	   the buffer related with the registered memory region and store the message to be sent.
     * \param opcode
     * 	   IBV_WR_SEND, IBV_WR_RDMA_READ or IBV_WR_RDMA_WRITE
     * \param remote_props
     *     values to connecto to remote side
     * \param msg_size
     *     the total size of header and contents to be sent.
     */
    int post_send(char *buf, ibv_wr_opcode opcode, cm_con_data_t& remote_props, size_t msg_size) const; 

    /**
     * This function will block and post a receive work request.
     * \param buf
     *     the buffer related with the registered memory region and store the message to be received.
     * \param msg_size
     *     the size of message to be sent.
     */
    int post_receive(char *buf, size_t msg_size) const;	 

    /**
     * Poll the compltion queue for a single event. This function will continue to poll the queue until MAX_POLL_CQ_TIMEOUT milliseconds have passed.
     * Returns 
     *     0 on succuss, 1 on failure.
     */
    int poll_completion() const;  

    /**
     * Cleanup and deallocate all resources used.
     * \param buf
     *     the buffer related with the registered memory region.
     * Returns 
     *     0 on success, 1 on failure.
     */
    int resources_destroy(char *buf) const; 

  private:

     /**
      * The host name(s) or numeric address(es) as passed into the constructor.
      */
    std::string originalString;

    /**
     * A list of (host, port) pairs as parsed from originalString.
     * - First component: the host name or numeric address as parsed from the
     *   string passed into the constructor. This has brackets stripped out of
     *   IPv6 addresses and is in the form needed by getaddrinfo().
     * - Second component: an ASCII representation of the port number to use.
     *   It is stored in string form because that's sometimes how it comes into
     *   the constructor and always what refresh() needs to call getaddrinfo().
     */
    std::vector<std::pair<std::string, std::string>> hosts;

    /**
     * Storage for the sockaddr returned by getSockAddr.
     * This is always zeroed out from len to the end.
     */
    sockaddr_storage storage;

    /**
     * The length in bytes of storage that are in use.
     * The remaining bytes of storage are always zeroed out.
     */
    socklen_t len;

    /**
     * the gid of the infiniband device.
     */
    int gid_idx;

    int ib_port;

    /**
     * The parameters of RDMA.
     */
    struct ibv_device_attr device_attr; /* device attributes */
    struct ibv_port_attr port_attr; /* IB port attributes */
    struct ibv_context *ib_ctx; /* device handle */
    struct ibv_pd *pd; /* pd handle */
    struct ibv_cq *cq;
    struct ibv_qp *qp;
    struct ibv_mr *mr;

    #if __BYTE_ORDER == __LITTLE_ENDIAN
    static inline uint64_t htonll(uint64_t x) { return bswap_64(x);}
    static inline uint64_t ntohll(uint64_t x) { return bswap_64(x);}
    #elif __BYTE_ORDER == __BIG_ENDIAN
    static inline uint64_t htonll(uint64_t x) { return x;}
    static inline uint64_t ntohll(uint64_t x) { return x;}
    #else
    #error __BYTE_ORDER is neither __LITTLE_ENDIAN nor __BIG_ENDIAN
    #endif

    /**
     * Transition a QP from RESET to INIT state.
     */
    int modify_qp_to_init(struct ibv_qp *qp) const;

    /**
     * Transition a QP from INIT to RTR state, using the specified QP number.
     */
    int modify_qp_to_rtr(struct ibv_qp *qp, uint32_t remote_qpn, uint16_t dlid, uint8_t *dgid) const;

    /**
     * Transition a QP from the RTR yo RTS state,
     */
    int modify_qp_to_rts(struct ibv_qp *qp) const;   
};

} // namespace LogCabin::RPC
} // namespace LogCabin

#endif /* LOGCABIN_RPC_ADDRESS_H */
