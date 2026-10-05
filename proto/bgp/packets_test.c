/*
 * BIRD -- BGP Packet Tests
 *
 * Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "test/bt-utils.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "lib/event.h"
#include "lib/unaligned.h"
#include "proto/bgp/bgp.h"

struct fixture {
  struct rtable_config igp_cf, evpn_cf;
  struct bgp_channel_config cf;
  struct bgp_proto p;
  struct bgp_channel c;
  struct channel igp;
  struct iface iface;
  struct rte_src *src;
  net_addr_ip4 underlay;
};

static void
init_fixture(struct fixture *f)
{
  f->igp_cf = (struct rtable_config) {
    .name = "igp", .addr_type = NET_IP4,
    .gc_threshold = 1000, .gc_period = 1 S,
  };
  f->evpn_cf = (struct rtable_config) {
    .name = "evpn", .addr_type = NET_EVPN,
    .gc_threshold = 1000, .gc_period = 1 S,
  };
  f->p.p.name = "test_bgp";
  f->p.p.proto = &proto_bgp;
  f->cf.gw_mode = GW_RECURSIVE;
  f->c = (struct bgp_channel) {
    .c = { .proto = &f->p.p, .channel_state = CS_UP,
           .table = rt_setup(&root_pool, &f->evpn_cf) },
    .cf = &f->cf, .afi = BGP_AF_EVPN,
    .desc = bgp_get_af_desc(BGP_AF_EVPN),
    .igp_table_ip4 = rt_setup(&root_pool, &f->igp_cf),
  };
  f->igp = (struct channel) { .proto = &f->p.p, .channel_state = CS_UP,
                             .table = f->c.igp_table_ip4 };
  f->src = rt_get_source(&f->p.p, 0);
  rt_lock_source(f->src);
  f->underlay = NET_ADDR_IP4(ip4_build(192, 0, 2, 1), 32);
  strcpy(f->iface.name, "test_iface");
}

static void
set_underlay(struct fixture *f, int reachable)
{
  rta a = { .source = RTS_STATIC, .scope = SCOPE_UNIVERSE,
            .dest = RTD_UNICAST, .pref = 200, .igp_metric = 42,
            .nh = { .gw = ipa_from_ip4(ip4_build(192, 0, 2, 254)),
                    .iface = &f->iface } };
  ea_set_attr_u32(&a.eattrs, tmp_linpool, EA_GEN_IGP_METRIC, 0, EAF_TYPE_INT, 42);
  rte_update2(&f->igp, (net_addr *) &f->underlay,
              reachable ? rte_get_temp(&a, f->src) : NULL, f->src);
}

static void
drain_events(void)
{
  /* Hostcache updates and dependent-table nexthop updates are asynchronous. */
  for (uint i = 0; i < 100; i++)
  {
    ev_run_list(&global_event_list);
    ev_run_list(&global_work_list);
    if (EMPTY_LIST(global_event_list) && EMPTY_LIST(global_work_list))
      return;
  }
  bt_abort_msg("Routing events did not settle");
}

static uint
encode_nlri(byte *buf, uint type)
{
  byte *p = buf;
  *p++ = type;
  *p++ = (type == NET_EVPN_MAC) ? 33 : (type == NET_EVPN_IMET) ? 17 : 23;
  memset(p, 0, 8); p += 8; /* RD */
  if ((type == NET_EVPN_MAC) || (type == NET_EVPN_ES))
  { memset(p, 0, 10); p += 10; } /* ESI */
  if ((type == NET_EVPN_MAC) || (type == NET_EVPN_IMET))
  { put_u32(p, 0); p += 4; } /* Ethernet tag */
  if (type == NET_EVPN_MAC)
  {
    *p++ = 48;
    memset(p, 0, 6); p[5] = 1; p += 6;
    *p++ = 0; /* No IP */
    put_u24(p, 100); p += 3;
  }
  else
  {
    *p++ = 32;
    put_u32(p, 0xc0000201); p += 4;
  }
  return p - buf;
}

static void
decode(struct fixture *f, uint first, uint second)
{
  byte nlri[100], nh[4];
  uint len = encode_nlri(nlri, first);
  if (second)
    len += encode_nlri(nlri + len, second);
  put_u32(nh, 0xc0000201);
  struct bgp_parse_state s = {
    .proto = &f->p, .channel = &f->c, .pool = tmp_linpool,
    .mpls = f->c.desc->mpls, .last_src = f->src,
  };
  rta *a = lp_allocz(tmp_linpool, RTA_MAX_SIZE);
  a->source = RTS_BGP;
  a->scope = SCOPE_UNIVERSE;
  a->pref = 100;
  if (setjmp(s.err_jmpbuf))
    bt_abort_msg("Unexpected EVPN parse error %u", s.err_subcode);
  f->c.desc->decode_next_hop(&s, nh, sizeof(nh), a);
  bt_assert(!s.err_withdraw && s.hostentry);
  f->c.desc->decode_nlri(&s, nlri, len, a);
}

static rte *
find_route(struct fixture *f, uint type)
{
  /* Construct the same key without using the decoder under test. */
  net_addr_evpn key;
  ip_addr router = ipa_from_ip4(ip4_build(192, 0, 2, 1));
  if (type == NET_EVPN_IMET)
    net_fill_evpn_imet((net_addr *) &key, RD_NONE, 0, router);
  else if (type == NET_EVPN_ES)
    net_fill_evpn_es((net_addr *) &key, RD_NONE, EVPN_ESI_NONE, router);
  else
  {
    mac_addr mac = MAC_NONE;
    mac.addr[5] = 1;
    net_fill_evpn_mac((net_addr *) &key, RD_NONE, 0, mac);
  }
  net *n = net_find(f->c.c.table, (net_addr *) &key);
  return n ? n->routes : NULL;
}

static void
check_route(struct fixture *f, uint type, int reachable)
{
  rte *r = find_route(f, type);
  bt_assert(r && r->attrs->hostentry);
  if (!r || !r->attrs->hostentry)
    return;
  bt_assert(r->attrs->hostentry->tab == f->c.c.table);
  bt_assert(r->attrs->dest == (reachable ? RTD_UNICAST : RTD_UNREACHABLE));
  bt_assert(rte_resolvable(r) == reachable);
  bt_assert(r->attrs->nh.labels == (type == NET_EVPN_MAC ? 1 : 0));
  if (reachable)
  {
    bt_assert(r->attrs->igp_metric == 42);
    bt_assert(r->attrs->nh.iface == &f->iface);
    bt_assert(ipa_equal(r->attrs->nh.gw, ipa_from_ip4(ip4_build(192, 0, 2, 254))));
  }
}

static int
t_unlabeled(void)
{
  static struct fixture f;
  init_fixture(&f);
  /* Both unlabeled types must resolve even without preceding labeled NLRI. */
  decode(&f, NET_EVPN_IMET, NET_EVPN_ES);
  check_route(&f, NET_EVPN_IMET, 0);
  check_route(&f, NET_EVPN_ES, 0);
  set_underlay(&f, 1);
  drain_events();
  check_route(&f, NET_EVPN_IMET, 1);
  check_route(&f, NET_EVPN_ES, 1);
  set_underlay(&f, 0);
  drain_events();
  check_route(&f, NET_EVPN_IMET, 0);
  check_route(&f, NET_EVPN_ES, 0);
  set_underlay(&f, 1);
  drain_events();
  check_route(&f, NET_EVPN_IMET, 1);
  check_route(&f, NET_EVPN_ES, 1);
  return 1;
}

static int
t_mixed(void)
{
  static struct fixture f;
  init_fixture(&f);
  set_underlay(&f, 1);
  for (uint type = NET_EVPN_IMET; type <= NET_EVPN_ES; type++)
  {
    decode(&f, NET_EVPN_MAC, type);
    check_route(&f, NET_EVPN_MAC, 1);
    check_route(&f, type, 1);
    decode(&f, type, NET_EVPN_MAC);
    check_route(&f, type, 1);
    check_route(&f, NET_EVPN_MAC, 1);
  }
  return 1;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);
  bt_bird_init();
  bt_config_parse("hostname \"test\"; " BT_CONFIG_SIMPLE);
  bt_test_suite(t_unlabeled, "Recursive unlabeled EVPN routes track underlay reachability");
  bt_test_suite(t_mixed, "Mixed labeled and unlabeled EVPN NLRI resolve independently");
  return bt_exit_value();
}
