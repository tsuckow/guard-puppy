/***************************************************************************
                          checktablelistitem.h  -  description
                             -------------------
    begin                : Thu Feb 10 20:57:36 EST 2000
    copyright            : (C) 2000-2001 by Simon Edwards
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

#ifndef CHECKTABLELISTITEM_H
#define CHECKTABLELISTITEM_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <qlistview.h>

class CheckTableListItem : public QListViewItem {

public:
    CheckTableListItem(QListView *parent);
    CheckTableListItem(QListView *parent,QListViewItem *after);
    CheckTableListItem(QListViewItem *parent);
    CheckTableListItem(QListViewItem *parent,QListViewItem *after);
    ~CheckTableListItem();
    
    enum State {CLEAR, CHECKED, CROSSED };
    void setState(int column, State s);
    State getState(int column) const;
    
    virtual int width( const QFontMetrics& fm, const QListView* lv, int column) const;
    virtual void paintCell(QPainter * p, const QColorGroup & cg, int column, int width, int align);
    
private:
    void init();    

    class Column {
    public:
        Column();
        ~Column();
        bool booleancol;
        QString text;
        State state;
    };
    Column *columns;
    
};


#endif

