####### kdevelop will overwrite this part!!! (begin)##########


EXTRA_DIST = networkprotocoldb.xml protocoldb.dtd xmlcatalog dbvalid

install-data-local:
	$(mkinstalldirs) $(kde_datadir)/guarddog/
	$(INSTALL_DATA) $(srcdir)/networkprotocoldb.xml $(kde_datadir)/guarddog/networkprotocoldb.xml
	$(mkinstalldirs) $(datadir)/sgml/protocoldb/1.0/
	$(INSTALL_DATA) $(srcdir)/protocoldb.dtd $(datadir)/sgml/protocoldb/1.0/protocoldb.dtd
	$(mkinstalldirs) $(datadir)/sgml/protocoldb/
	$(INSTALL_DATA) $(srcdir)/xmlcatalog $(datadir)/sgml/protocoldb/xmlcatalog

uninstall-local:
	-rm -f $(kde_datadir)/guarddog/networkprotocoldb.xml
	-rm -f $(datadir)/sgml/protocoldb/1.0/protocoldb.dtd
	-rm -f $(datadir)/sgml/protocoldb/xmlcatalog

####### kdevelop will overwrite this part!!! (end)############

MOSTLYCLEANFILES = dbvalid

rootcatalog = /etc/xml/catalog
XMLCATALOG = /usr/bin/xmlcatalog
XMLLINT = /usr/bin/xmllint

# "Compiling" the protocol database means checking it against the DTD.  dbvalid is just
# a flag to prevent unnecessary validations.
all-local: dbvalid
dbvalid: networkprotocoldb.xml protocoldb.dtd
	touch $@
	
#export SGML_CATALOG_FILES=xmlcatalog ; $(XMLLINT) --catalogs --noout --valid --dtdvalid protocoldb.dtd $<
	

# Modify libxml2's root catalog to delegate Guarddog references to the Guarddog catalog.
#install-data-hook:
#	$(XMLCATALOG) --noout --add "delegatePublic" "-//Simonzone//DTD protocoldb" "file://$(datadir)/sgml/protocoldb/xmlcatalog" $(rootcatalog)
#	$(XMLCATALOG) --noout --add "delegateSystem" "http://www.simonzone.com/software/protocoldb" "file://$(datadir)/sgml/protocoldb/xmlcatalog" $(rootcatalog)
#	$(XMLCATALOG) --noout --add "delegateURI"    "http://www.simonzone.com/software/protocoldb" "file://$(datadir)/sgml/protocoldb/xmlcatalog" $(rootcatalog)

# Remove our modifications to the root catalog.    
#uninstall-hook:
#	$(XMLCATALOG) --noout --del "-//Simonzone//DTD protocoldb" $(rootcatalog)
#	$(XMLCATALOG) --noout --del "http://www.simonzone.com/software/guarddog" $(rootcatalog)
