#pragma once

#include <QDialog>
#include <QMessageBox>
#include "ui_aboutDialog.h"

class GuardDogAboutDialog_w : public QDialog, Ui::GuardDogAboutDialog
{
    Q_OBJECT
public:
    GuardDogAboutDialog_w()
    {
        setupUi( this );
        connect( closePushButton, SIGNAL( clicked() ), this, SLOT(accept() ) );
    }
};


