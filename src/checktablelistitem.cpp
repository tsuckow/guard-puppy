/***************************************************************************
                          checktablelistitem.cpp  -  description
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

#include "checktablelistitem.h"
#include <qpainter.h>
#include <qpointarray.h>

#define BOXSIZE 16

///////////////////////////////////////////////////////////////////////////
CheckTableListItem::CheckTableListItem(QListView *parent) : QListViewItem(parent) {
    init();
}

///////////////////////////////////////////////////////////////////////////
CheckTableListItem::CheckTableListItem(QListView *parent,QListViewItem *after) : QListViewItem(parent,after){
    init();
}

///////////////////////////////////////////////////////////////////////////
CheckTableListItem::CheckTableListItem(QListViewItem *parent) : QListViewItem(parent){
    init();
}

///////////////////////////////////////////////////////////////////////////
CheckTableListItem::CheckTableListItem(QListViewItem *parent,QListViewItem *after) : QListViewItem(parent,after){
    init();
}

///////////////////////////////////////////////////////////////////////////
void CheckTableListItem::init() {
    columns = new Column[listView()->columns()];
}

///////////////////////////////////////////////////////////////////////////
CheckTableListItem::~CheckTableListItem() {
    delete[] columns;
}

///////////////////////////////////////////////////////////////////////////
CheckTableListItem::Column::Column() {
    text = QString::null;
    booleancol = false;
    state = CLEAR;
}

///////////////////////////////////////////////////////////////////////////
CheckTableListItem::Column::~Column() {

}

///////////////////////////////////////////////////////////////////////////
void CheckTableListItem::setState(int column, CheckTableListItem::State s) {
    columns[column].booleancol = true;
    columns[column].state = s;
    repaint();
}

///////////////////////////////////////////////////////////////////////////
CheckTableListItem::State CheckTableListItem::getState(int column) const {
    return columns[column].state;
}

///////////////////////////////////////////////////////////////////////////
int CheckTableListItem::width( const QFontMetrics& fm, const QListView* lv, int column) const {
    if(columns[column].booleancol) {
        return lv->itemMargin() + BOXSIZE + 4;
    } else {
        return QListViewItem::width(fm,lv,column);
    }
}

///////////////////////////////////////////////////////////////////////////
void CheckTableListItem::paintCell(QPainter * p, const QColorGroup & cg, int column, int width, int align) {
    QListView *lv;
    int marg;
    int x;
    int y;
  	int i, xx, yy;
  	QPointArray a(7*2);
    QPointArray cross(2*2);
    
    if(p==0) {
        return;
    }

    p->fillRect( 0, 0, width, height(), cg.brush(QColorGroup::Base) );
    
    if(columns[column].booleancol) {
        lv = listView();
        if(lv==0) {
        	return;
        }
    
        marg = lv->itemMargin();
      	x = 0; //(width - BOXSIZE - marg) / 2;
    	y = (height() - BOXSIZE) / 2;

//        if(isEnabled()) {
	    	p->setPen( QPen( cg.text(), 2 ) );
//	    } else {
//		    p->setPen( QPen( listView()->palette().color( QPalette::Disabled, QColorGroup::Text ), 2 ) );
//		}
        p->drawRect(x+marg, y+2, BOXSIZE-4, BOXSIZE-4);
	    x++;
        y++;
            // Sorry, the whole image drawing is a bit of a mess.
	    switch(columns[column].state) {
	        case CHECKED:
	            xx = x+1+marg;
    	        yy = y+5;
	            for(i=0; i<3; i++) {
    	    	    a.setPoint(2*i, xx, yy );
	                a.setPoint( 2*i+1, xx, yy+2 );
    	            xx++; yy++;
	            }
	            yy -= 2;
	            for(i=3; i<7; i++) {
        		    a.setPoint( 2*i,   xx, yy );
	                a.setPoint( 2*i+1, xx, yy+2 );
    	    	    xx++; yy--;
	            }
        		p->drawLineSegments( a );
                break;

            case CROSSED:
                xx = x + marg;
                yy = y + 2;
                cross.setPoint(0, xx+1, yy+1);
                cross.setPoint(1, xx+BOXSIZE-9, yy+BOXSIZE-9);
                cross.setPoint(2, xx+1, yy+BOXSIZE-9);
                cross.setPoint(3, xx+BOXSIZE-9, yy+1);
                p->drawPoint(xx+BOXSIZE-9, yy+BOXSIZE-9);
                p->drawPoint(xx+BOXSIZE-9, yy+1);
        		p->drawLineSegments(cross);
                break;
            
            default:
                break;
        }
    
    } else {
        QListViewItem::paintCell(p, cg, column, width, align);
    }
}

