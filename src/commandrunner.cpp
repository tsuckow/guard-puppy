/***************************************************************************
                          commandrunner.cpp  -  description
                             -------------------
    begin                : Sat Jul 14 2001
    copyright            : (C) 2001 by Simon Edwards
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

#include "commandrunner.h"
#include <klocale.h>
#include <kiconloader.h>
#include <qvbox.h>
#include <qlayout.h>
#include <kdebug.h>

///////////////////////////////////////////////////////////////////////////
CommandRunner::CommandRunner(QWidget *parent,const char *name) : KDialogBase(parent,name,true, QString::null, Ok ) {
    QWidget *vbox;
    QHBox *hbox;
    QLabel *tmplabel;

    running = false;

    vbox =  makeVBoxMainWidget();
    hbox = new QHBox(vbox);
    hbox->setSpacing(spacingHint());

    tmplabel = new QLabel(hbox);
    tmplabel->setPixmap(UserIcon("laserwarn"));
    hbox->setStretchFactor(tmplabel,0);

    headinglabel = new QLabel(hbox);
    hbox->setStretchFactor(headinglabel,1);

    outputview = new QTextView(vbox);
    outputview->setTextFormat(PlainText);

    connect(this,SIGNAL(okClicked()),this,SLOT(slotOkClicked()));

    kid = new KShellProcess("/bin/bash");
    connect(kid,SIGNAL(processExited(KProcess *)),this,SLOT(slotKidExited(KProcess *)));
    connect(kid,SIGNAL(receivedStdout(KProcess *,char *,int)),this,SLOT(slotReceivedStdout(KProcess *,char *,int)));
    connect(kid,SIGNAL(receivedStderr(KProcess *,char *,int)),this,SLOT(slotReceivedStderr(KProcess *,char *,int)));
}

///////////////////////////////////////////////////////////////////////////
CommandRunner::~CommandRunner() {
    delete kid;
}

///////////////////////////////////////////////////////////////////////////
void CommandRunner::setHeading(const QString &heading) {
    headinglabel->setText(heading);
}

///////////////////////////////////////////////////////////////////////////
void CommandRunner::run(QString cmd) {
    command = cmd;
    kid->setExecutable(command);
    output.truncate(0);
    outputview->setText(output);
    bootstrapid = startTimer(0);
    running = true;
    enableButtonOK( false );
    exec();
}

///////////////////////////////////////////////////////////////////////////
void CommandRunner::timerEvent(QTimerEvent *) {
    killTimer(bootstrapid);

        // Lets start up the command.
    kid->start(KProcess::NotifyOnExit,KProcess::AllOutput);
}

///////////////////////////////////////////////////////////////////////////
void CommandRunner::slotKidExited(KProcess *) {
    running = false;
    enableButtonOK( true );
}

///////////////////////////////////////////////////////////////////////////
void CommandRunner::slotReceivedStdout(KProcess *, char *buffer,int buflen) {
    int i;
    for(i=0; i<buflen; i++) {
        output.append(buffer[i]);
    }
    outputview->setText(output);
    outputview->ensureVisible(0,outputview->contentsHeight());
}

///////////////////////////////////////////////////////////////////////////
void CommandRunner::slotReceivedStderr(KProcess *,char *buffer,int buflen) {
    int i;
    for(i=0; i<buflen; i++) {
        output.append(buffer[i]);
    }
    outputview->setText(output);
    outputview->ensureVisible(0,outputview->contentsHeight());
}

///////////////////////////////////////////////////////////////////////////
void CommandRunner::slotOkClicked() {
    done(0);
}
