## Process this file with automake to produce Makefile.in.

SUBDIRS = lib @BGPD@

DIST_SUBDIRS = lib bgpd

EXTRA_DIST = aclocal.m4 SERVICES TODO REPORTING-BUGS INSTALL.quagga.txt \
	update-autotools 
#	vtysh/Makefile.in vtysh/Makefile.am \
#	tools/zebra.el tools/multiple-bgpd.sh

if HAVE_PANDOC

HACKING.pdf: HACKING.md
	pandoc -o $@ $<

clean-local:
	-$(LATEXMK) -C HACKING.tex

endif

ACLOCAL_AMFLAGS = -I m4
