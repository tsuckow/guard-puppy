/***************************************************************************
                          commandrunner.h  -  description
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

#ifndef COMMANDRUNNER_H
#define COMMANDRUNNER_H

#include <kdialogbase.h>
#include <qlabel.h>
#include <qtextview.h>
#include <kprocess.h>

/**
  *@author Simon Edwards
  */

class CommandRunner : public KDialogBase  {
    Q_OBJECT
public:
	CommandRunner(QWidget *parent=0,const char *name=0);
	~CommandRunner();
    void run(QString cmd);
    void setHeading(const QString &heading);

protected:
    void timerEvent(QTimerEvent *qte);

private slots:
    void slotKidExited(KProcess *endkid);
    void slotReceivedStdout(KProcess *kid,char *buffer,int buflen);
    void slotReceivedStderr(KProcess *kid,char *buffer,int buflen);
    void slotOkClicked();

private:
    QLabel *headinglabel;
    QTextView *outputview;
    int bootstrapid;
    KShellProcess *kid;
    QString command;
    QString output;
    bool running;
};

#endif
