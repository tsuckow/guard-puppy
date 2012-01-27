/***************************************************************************
                          guarddogdoc.h  -  description
                             -------------------
    begin                : Thu Feb 10 20:57:36 EST 2000
    copyright            : (C) 2000-2006 by Simon Edwards
    email                : simon@simonzone.com
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#ifndef GUARDDOGDOC_H
#define GUARDDOGDOC_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

// include files for QT
#ifndef QT_LITE
//#include <qstring.h>
//#include <qptrlist.h>
//#include <qptrdict.h>
//#include <qstringlist.h>
//#include <qtextstream.h>
#else
//#include "qstring.h"
//#include "qptrlist.h"
//#include "qptrdict.h"
//#include "qstringlist.h"
//#include "qtextstream.h"
//#include "dummylocale.h"
#endif

#include <map>
#include <boost/foreach.hpp>

#include "protocoldb.h"
#include "userdefinedprotocol.h"
#include "iprange.h"

class GuarddogDoc {

};

#endif // GUARDDOGDOC_H
