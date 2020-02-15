#include "connstat.h"

#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/msg.h>
#include <netlink/route/link.h>
#include <net/if.h>

namespace dht {
namespace net {

ConnectivityStatus::ConnectivityStatus()
    : logger_(new dht::Logger)
    , bye(nlmsg_alloc_simple(NLMSG_NOOP, NLM_F_ECHO), &nlmsg_free)
    , nlsk(nlsk_init())
{
    nlsk_setup(nlsk.get());

    thrd_ = std::thread([this] () { nl_event_loop_thrd(nlsk.get()); });
}

ConnectivityStatus::~ConnectivityStatus()
{
    stop = true;

    nl_send_auto(nlsk.get(), bye.get());

    if (thrd_.joinable())
        thrd_.join();

}

void
ConnectivityStatus::setEventListener(ConnectionEventCb ucb, Event event)
{
    std::lock_guard<std::mutex> lck(mtx_);
    switch (event) {
    case Event::NEWADDR:
    case Event::DELADDR:
    case Event::ADDR:
        nl_socket_add_memberships(nlsk.get(), RTNLGRP_IPV6_IFADDR, RTNLGRP_NONE);
        nl_socket_add_memberships(nlsk.get(), RTNLGRP_IPV4_IFADDR, RTNLGRP_NONE);
        break;
    default:
        break;
    }
    event_cbs[event] = ucb;
}

void
ConnectivityStatus::removeEventListener(Event event)
{
    std::lock_guard<std::mutex> lck(mtx_);
    event_cbs.erase(event);
    switch (event) {
    case Event::NEWADDR:
    case Event::DELADDR:
    case Event::ADDR:
        nl_socket_drop_memberships(nlsk.get(), RTNLGRP_IPV6_IFADDR, RTNLGRP_NONE);
        nl_socket_drop_memberships(nlsk.get(), RTNLGRP_IPV4_IFADDR, RTNLGRP_NONE);
        break;
    default:
        break;
    }
}

void
ConnectivityStatus::executer(Event event)
{
    auto cb = event_cbs.find(event);
    if (cb != event_cbs.end() && cb->second)
        (cb->second)(event);
}


void
ConnectivityStatus::nlsk_setup(nl_sock* nlsk)
{
    nl_socket_disable_seq_check(nlsk);
    nl_socket_set_nonblocking(nlsk);

    nl_socket_modify_cb(nlsk, NL_CB_MSG_IN, NL_CB_CUSTOM, [](nl_msg* msg, void* data) -> int {
            return ((ConnectivityStatus*)data)->nl_event_cb(msg);
    }, (void*)this);

    nl_connect(nlsk, NETLINK_ROUTE);
}

ConnectivityStatus::NlPtr
ConnectivityStatus::nlsk_init(void)
{
    NlPtr ret(nl_socket_alloc(), &nl_socket_free);
    if (not ret.get())
        throw std::runtime_error("couldn't allocate netlink socket!\n");
    else
        return ret;
}

void
ConnectivityStatus::get_neigh_state(struct nl_msg* msg)
{
    struct nlmsghdr *h = nlmsg_hdr(msg);
    struct ndmsg *r = (struct ndmsg*)nlmsg_data(h);

    switch (r->ndm_state) {
    case NUD_REACHABLE:
        executer(Event::NEWNEIGH);
        break;
    default:
        break;
    }
}

int
ConnectivityStatus::nl_event_cb(struct nl_msg* msg)
{
    std::lock_guard<std::mutex> lck(mtx_);
    fprintf(stderr, "MSG_IN\n");
    if (stop)
        return NL_OK-1;

    struct nlmsghdr *h = nlmsg_hdr(msg);

    int status = NL_SKIP;
    /* this will goto out: */
    switch (h->nlmsg_type) {
    case RTM_NEWADDR:
        executer(Event::ADDR);
        executer(Event::NEWADDR);
        break;
    case RTM_DELADDR:
        executer(Event::ADDR);
        executer(Event::DELADDR);
        break;
    case RTM_NEWNEIGH:
    case RTM_DELNEIGH:
    case RTM_NEWNEIGHTBL:
        get_neigh_state(msg);
        break;
    default:
        break;
    }

    return status;

}

void
ConnectivityStatus::nl_event_loop_thrd(nl_sock *nlsk)
{
    while (!stop && nl_recvmsgs_report(nlsk, nl_socket_get_cb(nlsk)) >= NL_OK)
        ;
}

} /* namespace net */
} /* namespace dht */

