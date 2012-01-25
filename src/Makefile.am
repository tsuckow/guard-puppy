## Makefile.am for guarddog

# this is the program that gets installed.  it's name is used for all
# of the other Makefile.am variables
bin_PROGRAMS = guarddog

# set the include path for X, qt and KDE
INCLUDES         = $(all_includes)

# the library search path. 
guarddog_LDFLAGS = $(KDE_RPATH) $(all_libraries)

# the libraries to link against.
guarddog_LDADD   = $(LIB_KFILE) $(LIB_KDEPRINT)

# which sources should be compiled for guarddog
guarddog_SOURCES = main.cpp guarddog.cpp checktablelistitem.cpp commandrunner.cpp guarddogdoc.cpp iprange.cpp protocoldb.cpp simelineedit.cpp userdefinedprotocol.cpp

# these are the headers for your project
noinst_HEADERS = guarddog.h

# client stuff


# let automoc handle all of the meta source files (moc)
METASOURCES = AUTO

messages: rc.cpp
	$(XGETTEXT) *.cpp -o $(podir)/guarddog.pot

KDE_ICON = guarddog

# this is where the kdelnk file will go 
kdelnkdir   = $(kde_appsdir)/Utilities


# this is where the XML-GUI resource file goes
rcdir = $(kde_datadir)/guarddog


dist-hook:
	-cd $(top_distdir) && rm src/guarddog
