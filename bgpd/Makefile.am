## Process this file with automake to produce Makefile.in.

AM_CPPFLAGS = -I.. -I$(top_srcdir) -I$(top_srcdir)/lib -I$(top_builddir)/lib -DBOOST_LOG_DYN_LINK
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
INSTALL_SDATA=@INSTALL@ -m 600

AM_CFLAGS = $(WERROR)

noinst_LIBRARIES = libbgp.a
sbin_PROGRAMS = bgpd
bin_PROGRAMS = bgp_btoa

libbgp_a_SOURCES = \
	bgpd.c bgp_fsm.c bgp_aspath.c bgp_community.c bgp_attr.c \
	bgp_debug.c bgp_route.c bgp_zebra.c bgp_open.c bgp_routemap.c \
	bgp_packet.c bgp_network.c bgp_filter.c bgp_regex.c bgp_clist.c \
	bgp_dump.c bgp_snmp.c bgp_ecommunity.c bgp_lcommunity.c \
	bgp_mplsvpn.c bgp_nexthop.c \
	bgp_damp.c bgp_table.c bgp_advertise.c bgp_vty.c bgp_mpath.c \
	bgp_encap.c bgp_encap_tlv.c bgp_nht.c \
    dcn_master.c dcn_conf_parameter.c dcn_conf_file.c dcn_common.c \
    seq_mgr.c 

noinst_HEADERS = \
	bgp_aspath.h bgp_attr.h bgp_community.h bgp_debug.h bgp_fsm.h \
	bgp_network.h bgp_open.h bgp_packet.h bgp_regex.h bgp_route.h \
	bgpd.h bgp_filter.h bgp_clist.h bgp_dump.h bgp_zebra.h \
	bgp_ecommunity.h bgp_lcommunity.h \
	bgp_mplsvpn.h bgp_nexthop.h bgp_damp.h bgp_table.h \
	bgp_advertise.h bgp_snmp.h bgp_vty.h bgp_mpath.h \
	bgp_encap.h bgp_encap_tlv.h bgp_encap_types.h bgp_nht.h \
    dcn_master.hpp dcn_conf_parameter.hpp dcn_conf_file.hpp dcn_common.hpp \
    seq_mgr.hpp 

bgpd_SOURCES = bgp_main.c
bgpd_LDADD = libbgp.a ../lib/libzebra.la @LIBCAP@ @LIBM@ @LIBNDN@

bgp_btoa_SOURCES = bgp_btoa.c
bgp_btoa_LDADD = libbgp.a ../lib/libzebra.la @LIBCAP@ @LIBM@ @LIBNDN@

examplesdir = $(exampledir)
dist_examples_DATA = dbgpd.conf.sample dbgpd.conf.sample2 dbgpd-static.conf.sample

EXTRA_DIST = BGP4-MIB.txt

