/*
 * BIRD -- Extended Attribute Tests
 *
 * Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "lib/evpn.h"

static int
t_get_val(void)
{
  struct ea_one_attr_list attrs = {
    .l.count = 1,
    .a.id = EA_EVPN_ESI,
    .a.type = EAF_TYPE_INT,
    .a.u.data = 0xf,
  };
  struct {
    adata a;
    evpn_esi esi;
  } data = { .a.length = sizeof(evpn_esi), .esi = { .type = 1 } };
  evpn_esi esi;

  /* Embedded values must never be interpreted as adata pointers. */
  esi = ea_get_val(&attrs.l, EA_EVPN_ESI, evpn_esi, EVPN_ESI_NONE);
  bt_assert(evpn_esi_zero(esi));

  attrs.a.type = EAF_TYPE_OPAQUE;
  attrs.a.u.ptr = NULL;
  esi = ea_get_val(&attrs.l, EA_EVPN_ESI, evpn_esi, EVPN_ESI_NONE);
  bt_assert(evpn_esi_zero(esi));

  attrs.a.u.ptr = &data.a;
  esi = ea_get_val(&attrs.l, EA_EVPN_ESI, evpn_esi, EVPN_ESI_NONE);
  bt_assert(evpn_esi_equal(esi, data.esi));

  data.a.length--;
  esi = ea_get_val(&attrs.l, EA_EVPN_ESI, evpn_esi, EVPN_ESI_NONE);
  bt_assert(evpn_esi_zero(esi));

  attrs.a.undef = 1;
  esi = ea_get_val(&attrs.l, EA_EVPN_ESI, evpn_esi, EVPN_ESI_NONE);
  bt_assert(evpn_esi_zero(esi));

  esi = ea_get_val(NULL, EA_EVPN_ESI, evpn_esi, EVPN_ESI_NONE);
  bt_assert(evpn_esi_zero(esi));
  return 1;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);
  bt_test_suite(t_get_val, "Reading data attributes safely");
  return bt_exit_value();
}
