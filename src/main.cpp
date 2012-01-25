
/***************************************************************************
                          main.cpp  -  description
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

#include <kaboutdata.h>
#include <kcmdlineargs.h>
#include <klocale.h>
#include <kmessagebox.h>
#include <kglobal.h>
#include <unistd.h>
#include "guarddog.h"

int main(int argc, char *argv[]) {

    KAboutData aboutData("guarddog",I18N_NOOP("Guarddog"),VERSION,
        I18N_NOOP("Firewall utility"),KAboutData::License_GPL,
        "(c) 2000-2007, Simon Edwards",
        I18N_NOOP("Utility for easily creating and configuring a firewall."),
        "http://www.simonzone.com/software/guarddog/");

    aboutData.addAuthor("Simon Edwards",I18N_NOOP("Developer"),"simon@simonzone.com","http://www.simonzone.com/");
    aboutData.addCredit("J F Gratton",I18N_NOOP("Help with a little bit of network code."));
    aboutData.addCredit("Joerg Buchland",I18N_NOOP("Help with sorting out what /dev interface ISDN uses."));
    aboutData.addCredit("Ludovic Lange",I18N_NOOP("Bug fixes, DHCP help."));
    aboutData.addCredit("Jason L. Buberel",I18N_NOOP("Feedback, protocol info."));
    aboutData.addCredit("Carsten Pfeiffer",I18N_NOOP("Feedback, help with KDE3"));
    aboutData.addCredit("Gunner Poulsen", I18N_NOOP("Danish translation"));
    aboutData.addCredit("Daniele Medri", I18N_NOOP("Italian translation"));
    aboutData.addCredit("Stephan Johach", I18N_NOOP("German translation"));
    aboutData.addCredit("Pascal Billery Schneider", I18N_NOOP("French translation"));
    aboutData.addCredit("Ceoldo Costantino", I18N_NOOP("Italian translation"));
    aboutData.addCredit("Per Agerb�", I18N_NOOP("Code Contribution"));
    aboutData.addCredit("Antonio Diaz", I18N_NOOP("Spanish translation"));
    aboutData.addCredit("Tomas N?mec", I18N_NOOP("Czech translation"));
    aboutData.addCredit("Ray Lambert", I18N_NOOP("Port reference tab"));

    KCmdLineArgs::init(argc,argv,&aboutData);
    KApplication app;

    GuarddogApp *guarddog = new GuarddogApp("Firewall Configuration");
    if(guarddog->initialise(getuid()==0)) {
            // Are we running as a mortal?
        if(getuid()!=0) {
            KMessageBox::information(0,i18n(
                "Since you do not have superuser privileges, Guarddog is running with\n"
                "reduced functionality. Firewall scripts may be Imported/Exported, but\n"
                "the system's firewall settings may not be changed.\n"),QString::null,QString("MORTALMODEWARNING"));
        }
        guarddog->exec();
    }
    delete guarddog;
}
