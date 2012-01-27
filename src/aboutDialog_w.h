#pragma once

#include <QDialog>
#include <QMessageBox>
#include "ui_aboutDialog.h"

class GuardPuppyAboutDialog_w : public QDialog, Ui::GuardPuppyAboutDialog
{
    Q_OBJECT
public:
    GuardPuppyAboutDialog_w()
    {
        setupUi( this );
        connect( closePushButton, SIGNAL( clicked() ), this, SLOT(accept() ) );
    }
};


