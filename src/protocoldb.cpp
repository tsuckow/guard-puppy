/***************************************************************************
                          forensicdb.cpp  -
                             -------------------
    begin                : Thu Nov 23 09:00:22 CET 2000
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

#ifndef QT_LITE
#include <kapp.h>
#include <klocale.h>
#endif
#include "protocoldb.h"
#include <stdio.h>

///////////////////////////////////////////////////////////////////////////
ProtocolDB::PortRangeInfo::PortRangeInfo() {
    dynamicStart = 1024;
    dynamicEnd = 65535;
}

///////////////////////////////////////////////////////////////////////////
ProtocolDB::PortRangeInfo::~PortRangeInfo() {
}

///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
ProtocolDB::ProtocolNetUseDetail::ProtocolNetUseDetail() {
    alternate = false;
    rangetype = PORTRANGE_RANGE;
    start = 0;
    end = 0;
}

///////////////////////////////////////////////////////////////////////////
ProtocolDB::ProtocolNetUseDetail::~ProtocolNetUseDetail() {

}

///////////////////////////////////////////////////////////////////////////
uint ProtocolDB::ProtocolNetUseDetail::getStart(const PortRangeInfo *ri) {
    switch(rangetype) {
        case PORTRANGE_RANGE:
            return start;
        case PORTRANGE_ANY:
            return 0;
        case PORTRANGE_PRIVILEGED:
            return 0;
        case PORTRANGE_NONPRIVILEGED:
            return 1024;
        case PORTRANGE_DYNAMIC:
        default:
            return ri==0 ? 1024 : ri->dynamicStart;
    }
}

///////////////////////////////////////////////////////////////////////////
uint ProtocolDB::ProtocolNetUseDetail::getEnd(const PortRangeInfo *ri) {
    switch(rangetype) {
        case PORTRANGE_RANGE:
            return end;
        case PORTRANGE_ANY:
            return 65535;
        case PORTRANGE_PRIVILEGED:
            return 1023;
        case PORTRANGE_NONPRIVILEGED:
            return 65535;
        case PORTRANGE_DYNAMIC:
        default:
            return ri==0 ? 65535 : ri->dynamicEnd;
    }
}

///////////////////////////////////////////////////////////////////////////
void ProtocolDB::ProtocolNetUseDetail::print() {
    fprintf(stderr,"[ Alternate: %d Start: %u End: %u ]",
        (int)alternate,start,end);
}

///////////////////////////////////////////////////////////////////////////
ProtocolDB::ProtocolNetUse::ProtocolNetUse() {
    sourcedetaillist.setAutoDelete(true);
    destdetaillist.setAutoDelete(true);
	source = ENTITY_CLIENT;
	dest = ENTITY_SERVER;
	bidirectional = false;
}

///////////////////////////////////////////////////////////////////////////
ProtocolDB::ProtocolNetUse::~ProtocolNetUse() {

}

///////////////////////////////////////////////////////////////////////////
void ProtocolDB::ProtocolNetUse::print() {
    ProtocolNetUseDetail *x;

    fprintf(stderr,"[Description: %s ",(const char *)description);
    switch(type) {
        case IPPROTO_TCP:
            fprintf(stderr," Type: tcp ");
            break;

        case IPPROTO_UDP:
            fprintf(stderr," Type: udp ");
            break;

        case IPPROTO_ICMP:
            fprintf(stderr," Type: icmp ");
            break;
            
        default:
            fprintf(stderr," Type: %d ",(int)type);
            break;
    }
	fprintf(stderr," Source: ");
    for(x=sourcedetaillist.first(); x!=0; x=sourcedetaillist.next()) {
        x->print();
    }
	fprintf(stderr," Dest: ");
    for(x=destdetaillist.first(); x!=0; x=destdetaillist.next()) {
        x->print();
    }
    fprintf(stderr,"]");
}
///////////////////////////////////////////////////////////////////////////
bool ProtocolDB::ProtocolNetUse::sourcePortEquals(uint port) {
	ProtocolNetUseDetail *p;
	
	p=sourcedetaillist.first();
	if(p==0) {
		return true;	//An empty list matches anything.
	}
	for(; p!=0; p=sourcedetaillist.next()) {
		if(port>=p->start && port<=p->end) {	// It must be in range.
			return true;
		}
	}
    return false;
}
///////////////////////////////////////////////////////////////////////////
bool ProtocolDB::ProtocolNetUse::destPortEquals(uint port) {
	ProtocolNetUseDetail *p;
	
	p=destdetaillist.first();
	if(p==0) {
		return true;	// An empty list matches anything.
	}
	for(; p!=0; p=destdetaillist.next()) {
		if(port>=p->start && port<=p->end) {
			return true;
		}
	}
    return false;
}
///////////////////////////////////////////////////////////////////////////
bool ProtocolDB::ProtocolNetUse::icmpTypeCodeEquals(uint type, int code) {
	ProtocolNetUseDetail *p;
	
	for(p=sourcedetaillist.first(); p!=0; p=sourcedetaillist.next()) {
		if(type==p->type) {
			if(p->code==-1) {	// -1 is the wild card.
				return true;
			} else {
				if(p->code==code) {
					return true;
				}
			}
		}
	}
    return false;
}

///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
ProtocolDB::ProtocolEntry::ProtocolEntry() {
    networkuse.setAutoDelete(true);
    threat = SCORE_UNKNOWN;
    falsepos = SCORE_UNKNOWN;
    classification = CLASS_UNKNOWN;
}

///////////////////////////////////////////////////////////////////////////
ProtocolDB::ProtocolEntry::~ProtocolEntry() {

}
///////////////////////////////////////////////////////////////////////////
void ProtocolDB::ProtocolEntry::print() {
    ProtocolNetUse *x;

    fprintf(stderr,"[ Name: %s Longname: %s Threat: ",(const char *)name,(const char *)longname);
    switch(threat) {
        case SCORE_LOW:
            fprintf(stderr,"low");
            break;
        case SCORE_MEDIUM:
            fprintf(stderr,"medium");
            break;
        case SCORE_HIGH:
            fprintf(stderr,"high");
            break;
        default:
            fprintf(stderr,"unknown");
            break;
    }
    fprintf(stderr," Classification: ");
    switch(classification) {
        case CLASS_UNKNOWN:
            fprintf(stderr,"unknown");
            break;
            
        case CLASS_MAIL:
            fprintf(stderr,"mail");
            break;
            
        case CLASS_CHAT:
            fprintf(stderr,"chat");
            break;
            
        case CLASS_FILE:
            fprintf(stderr,"file");
            break;
            
        case CLASS_GAME:
            fprintf(stderr,"game");
            break;
            
        case CLASS_SESSION:
            fprintf(stderr,"session");
            break;
            
        case CLASS_DATA:
            fprintf(stderr,"data");
            break;
            
        case CLASS_MEDIA:
            fprintf(stderr,"media");
            break;
            
        case CLASS_NET:
            fprintf(stderr,"net");
            break;
            
        default:
            break;
    }
    
    for(x=networkuse.first(); x!=0; x=networkuse.next()) {
        x->print();
    }
    fprintf(stderr,"]");
}

///////////////////////////////////////////////////////////////////////////
ProtocolDB::ProtocolDB() :  protocolnamespace(""),
                            linesattr("lines"),
                            nameattr("name"),
                            portnumattr("portnum"),
                            portstartattr("start"),
                            portendattr("end"),
                            threatattr("threat"),
                            falseposattr("falsepos"),
                            sourceattr("source"),
                            destattr("dest"),
                            directionattr("direction"),
                            valueattr("value"),
                            codeattr("code"),
                            classattr("class"),
                            langattr("lang"),
                            protocolattr("protocol"),
                            porthash(6007) {
    xmlfile = 0;
    xmllocator = 0;
    currententry = 0;
    currentnetuse = 0;
    currentnetusedetail = 0;

#ifndef QT_LITE
    progressdialog = 0;    
#endif
    db.setAutoDelete(true);
    porthash.setAutoDelete(true);
}

///////////////////////////////////////////////////////////////////////////
ProtocolDB::~ProtocolDB() {
    delete currententry;    // Just a litte bit of clean up.
    delete currentnetuse;
    delete currentnetusedetail;
    delete xmlfile;
}

///////////////////////////////////////////////////////////////////////////
bool ProtocolDB::loadDB(const QString &filename,const QStringList &languages) {
    bool rc;
    currententry = 0;
    parsestate = PROTOCOL_STATE_OUTSIDE;
	errorstate = PROTOCOL_ERROR_NOERROR;
    unknowndepth = 0;
    
    // Copy the list of permitted languages one by one. Convert things
    // like 'en_GB' to just 'en'.
    for(QStringList::ConstIterator lang = languages.begin(); lang != languages.end(); ++lang) {
        languagelist.append((*lang).left(2));
    }
        
    xmlfile = new QFile(filename);
    if(!xmlfile->open(IO_ReadOnly)) {
        errorstate = PROTOCOL_ERROR_OPEN_ERROR;
        delete xmlfile;
        xmlfile = 0;
        return false;
    }
    xmlfile->close();
#ifndef QT_LITE    
    progressdialog = new QProgressDialog(0,0,true);
    progressdialog->setLabelText(i18n("Reading network protocol database"));
#endif    
    QXmlInputSource source(*xmlfile);
    QXmlSimpleReader reader;
    reader.setContentHandler(this);
    reader.setErrorHandler(this);
    parseerror.truncate(0);
    if(reader.parse(source)) {
        buildPortHash();
        rc = true;
        goto cleanup;
    } else {
        rc = false;
        goto cleanup;
    }
    
cleanup:
    xmlfile->close();
#ifndef QT_LITE    
    delete progressdialog;
    progressdialog = 0;
#endif    
    delete xmlfile;
    xmlfile = 0;
    xmllocator = 0;
    return rc;
}

///////////////////////////////////////////////////////////////////////////
bool ProtocolDB::startElement(const QString &/*namespaceURI*/, const QString &localName,
        const QString &/*qName*/, const QXmlAttributes &atts) {
    int i,j;
    QString protocolname;
    QString tmp;
    bool ok;
    int x;
    
    if(unknowndepth==0) {
        switch(parsestate) {
            case PROTOCOL_STATE_OUTSIDE:
                if(localName=="protocoldb") {
                    parsestate = PROTOCOL_STATE_PROTOCOLDB;
                    i = atts.index(protocolnamespace,linesattr);
                    if(i!=-1) {
                        numberoflines = atts.value(i).toInt(&ok);
                        if(ok==false) {
                            numberoflines = 1;
                        } else {
#ifndef QT_LITE                                
                                // Set the number of steps for the progress dialog.
                            progressdialog->setTotalSteps(numberoflines/100);
#endif                        
                        }
                    }
                    return true;
                }
                break;

            case PROTOCOL_STATE_PROTOCOLDB:
                if(localName=="protocol") {
                    if(xmllocator!=0) {
                        if(xmllocator->lineNumber()%100==0) {
#ifndef QT_LITE
                            progressdialog->setProgress(xmllocator->lineNumber()/100);
                            kapp->processEvents();
#endif
                        }
                    }
                    currententry = new ProtocolEntry();
                        // Fetch the name attribute.
                    i = atts.index(protocolnamespace,nameattr);
                    if(i==-1) {
                    	errorstate = PROTOCOL_ERROR_ENTRY_NAME_ATTR_NOT_FOUND;
                        return false;
                    }
                    currententry->name = atts.value(i);
                    parsestate = PROTOCOL_STATE_ENTRY;
                    return true;
                }
                break;

            case PROTOCOL_STATE_ENTRY:
                if(localName=="longname") {
                    loadlongname = false;
                    i = atts.index(protocolnamespace,langattr);
                    if(i!=-1) {
                        tmp = atts.value(i);
                    } else {
                        tmp = "en";
                    }
                    if(currententry->longnamelanguage.isNull()) {
                        loadlongname = true;
                        currententry->longnamelanguage = tmp;
                    } else {
                            // Which language is more important?
                            // (Which appears first in the list of acceptable
                            // languages.)
                        i = languagelist.findIndex(currententry->longnamelanguage);
                        i = i==-1 ? 10000 : i;
                        j = languagelist.findIndex(tmp);
                        j = j==-1 ? 10000 : j;
                        if(j<i) {
                            loadlongname = true;
                            currententry->longnamelanguage = tmp;
                        }
                    }
                
                    parsestate = PROTOCOL_STATE_LONGNAME;
                    return true;
                }
                if(localName=="description") {
                    loaddescription = false;
                    i = atts.index(protocolnamespace,langattr);
                    if(i!=-1) {
                        tmp = atts.value(i);
                    } else {
                        tmp = "en";
                    }
                    if(currententry->descriptionlanguage.isNull()) {
                        loaddescription = true;
                        currententry->descriptionlanguage = tmp;
                    } else {
                            // Which language is more important?
                            // (Which appears first in the list of acceptable
                            // languages.)
                        i = languagelist.findIndex(currententry->descriptionlanguage);
                        i = i==-1 ? 10000 : i;
                        j = languagelist.findIndex(tmp);
                        j = j==-1 ? 10000 : j;
                        if(j<i) {
                            loaddescription = true;
                            currententry->descriptionlanguage = tmp;
                        }
                    }
                    parsestate = PROTOCOL_STATE_DESCRIPTION;
                    return true;
                }
                if(localName=="classification") {
                    i = atts.index(protocolnamespace,classattr);
                    if(i!=-1) {
                        tmp = atts.value(i);
                        if(tmp=="unknown") {
                            currententry->classification = CLASS_UNKNOWN;
                        } else if(tmp=="mail") {
                            currententry->classification = CLASS_MAIL;
                        } else if(tmp=="chat") {
                            currententry->classification = CLASS_CHAT;
                        } else if(tmp=="file") {
                            currententry->classification = CLASS_FILE;
                        } else if(tmp=="game") {
                            currententry->classification = CLASS_GAME;
                        } else if(tmp=="session") {
                            currententry->classification = CLASS_SESSION;
                        } else if(tmp=="data") {
                            currententry->classification = CLASS_DATA;
                        } else if(tmp=="media") {
                            currententry->classification = CLASS_MEDIA;
                        } else if(tmp=="net") {
                            currententry->classification = CLASS_NET;
                        } else {
                            errorstate = PROTOCOL_ERROR_CLASSIFICATION_CLASS_UNKNOWN;
                            return false;
                        }
                    }
                    parsestate = PROTOCOL_STATE_CLASSIFICATION;
                    return true;
                }
                if(localName=="network") {
                	parsestate = PROTOCOL_STATE_NETWORK;
                	return true;
                }
				if(localName=="security") {
                        // Grab the threat info
                    i = atts.index(protocolnamespace,threatattr);
                    if(i!=-1) {
                        tmp = atts.value(i);
                        if(tmp=="unknown") {
                            currententry->threat = SCORE_UNKNOWN;
                        } else if(tmp=="low") {
                            currententry->threat = SCORE_LOW;
                        } else if(tmp=="medium") {
                            currententry->threat = SCORE_MEDIUM;
                        } else if(tmp=="high") {   
                            currententry->threat = SCORE_HIGH;
                        } else {
                        	errorstate = PROTOCOL_ERROR_SECURITY_LEVEL_UNKNOWN;
                            return false;
                        }
                    }

                        // Grab the falsepos info
                    i = atts.index(protocolnamespace,falseposattr);
                    if(i!=-1) {
                        tmp = atts.value(i);
                        if(tmp=="unknown") {
                            currententry->falsepos = SCORE_UNKNOWN;
                        } else if(tmp=="low") {
                            currententry->falsepos = SCORE_LOW;
                        } else if(tmp=="medium") {
                            currententry->falsepos = SCORE_MEDIUM;
                        } else if(tmp=="high") {
                            currententry->falsepos = SCORE_HIGH;
                        } else {
                        	errorstate = PROTOCOL_ERROR_SECURITY_FALSEPOS_UNKNOWN;
                            return false;
                        }
                    }
                    parsestate = PROTOCOL_STATE_SECURITY;
                    return true;
                }

				if(localName=="pragma") {
                        // Grab the pragma name
                    i = atts.index(protocolnamespace,nameattr);
                    if(i!=-1) {
                        tmp = atts.value(i);
                        currententry->pragmaname.append(tmp);
                    } else {
                        currententry->pragmaname.append(QString());  // Null string.
                    }
                    parsestate = PROTOCOL_STATE_ENTRY_PRAGMA;
                    return true;
                }
                break;

			case PROTOCOL_STATE_NETWORK:
				if(localName=="tcp") {
				    currentnetuse = new ProtocolNetUse();
				    currentnetuse->type = IPPROTO_TCP;
						// Handle Source attribute
					i = atts.index(protocolnamespace,sourceattr);
					if(i!=-1) {
						tmp = atts.value(i);
						if(tmp=="client") {
							currentnetuse->source = ENTITY_CLIENT;
						} else if(tmp=="server") {
							currentnetuse->source = ENTITY_SERVER;
						} else {
							errorstate = PROTOCOL_ERROR_TCP_SOURCE_UNKNOWN;
                            return false;
						}
					}
						// Handle Dest attribute
					i = atts.index(protocolnamespace,destattr);
					if(i!=-1) {
						tmp = atts.value(i);
						if(tmp=="client") {
							currentnetuse->dest = ENTITY_CLIENT;
						} else if(tmp=="server") {
							currentnetuse->dest = ENTITY_SERVER;
						} else {
							errorstate = PROTOCOL_ERROR_TCP_DEST_UNKNOWN;
                            return false;
						}
					}
					parsestate = PROTOCOL_STATE_TCP;
					return true;
				}
				if(localName=="udp") {
				    currentnetuse = new ProtocolNetUse();
				    currentnetuse->type = IPPROTO_UDP;
						// Handle Source attribute
					i = atts.index(protocolnamespace,sourceattr);
					if(i!=-1) {
						tmp = atts.value(i);
						if(tmp=="client") {
							currentnetuse->source = ENTITY_CLIENT;
						} else if(tmp=="server") {
							currentnetuse->source = ENTITY_SERVER;
						} else {
							errorstate = PROTOCOL_ERROR_UDP_SOURCE_UNKNOWN;
                            return false;
						}
					}
						// Handle Dest attribute
					i = atts.index(protocolnamespace,destattr);
					if(i!=-1) {
						tmp = atts.value(i);
						if(tmp=="client") {
							currentnetuse->dest = ENTITY_CLIENT;
						} else if(tmp=="server") {
							currentnetuse->dest = ENTITY_SERVER;
						} else {
							errorstate = PROTOCOL_ERROR_UDP_DEST_UNKNOWN;
                            return false;
						}
					}
					
						// Check for direction attribute
					i = atts.index(protocolnamespace,directionattr);
					if(i!=-1) {
						currentnetuse->bidirectional = true;
					}
					parsestate = PROTOCOL_STATE_UDP;
					return true;
				}
				if(localName=="icmp") {
				    currentnetuse = new ProtocolNetUse();
				    currentnetuse->type = IPPROTO_ICMP;
						// Handle Source attribute
					i = atts.index(protocolnamespace,sourceattr);
					if(i!=-1) {
						tmp = atts.value(i);
						if(tmp=="client") {
							currentnetuse->source = ENTITY_CLIENT;
						} else if(tmp=="server") {
							currentnetuse->source = ENTITY_SERVER;
						} else {
							errorstate = PROTOCOL_ERROR_ICMP_SOURCE_UNKNOWN;
                            return false;
						}
					}
						// Handle Dest attribute
					i = atts.index(protocolnamespace,destattr);
					if(i!=-1) {
						tmp = atts.value(i);
						if(tmp=="client") {
							currentnetuse->dest = ENTITY_CLIENT;
						} else if(tmp=="server") {
							currentnetuse->dest = ENTITY_SERVER;
						} else {
							errorstate = PROTOCOL_ERROR_ICMP_DEST_UNKNOWN;
                            return false;
						}
					}
				    parsestate = PROTOCOL_STATE_ICMP;
				    return true;
				}
				if(localName=="ip") {
				    currentnetuse = new ProtocolNetUse();
				    currentnetuse->type = 0;    // Dummy.
						
						// Handle the Protocol attribute.
				    i = atts.index(protocolnamespace,protocolattr);
				    if(i!=-1) {
						tmp = atts.value(i);
                        x = tmp.toUInt(&ok);
                        if(ok==false) {
                        	errorstate = PROTOCOL_ERROR_IP_PROTOCOL_ATTR_NOT_UINT;
                            return false;
                        }
                        if(x<0 || x>255) {
                            errorstate = PROTOCOL_ERROR_IP_PROTOCOL_ATTR_OUT_OF_RANGE;
                            return false;
                        }
                        currentnetuse->type = x;
				    } else {
    					errorstate = PROTOCOL_ERROR_IP_PROTOCOL_NOT_FOUND;
                        return false;
				    }
						// Handle Source attribute
					i = atts.index(protocolnamespace,sourceattr);
					if(i!=-1) {
						tmp = atts.value(i);
						if(tmp=="client") {
							currentnetuse->source = ENTITY_CLIENT;
						} else if(tmp=="server") {
							currentnetuse->source = ENTITY_SERVER;
						} else {
							errorstate = PROTOCOL_ERROR_IP_SOURCE_UNKNOWN;
                            return false;
						}
					}
						// Handle Dest attribute
					i = atts.index(protocolnamespace,destattr);
					if(i!=-1) {
						tmp = atts.value(i);
						if(tmp=="client") {
							currentnetuse->dest = ENTITY_CLIENT;
						} else if(tmp=="server") {
							currentnetuse->dest = ENTITY_SERVER;
						} else {
							errorstate = PROTOCOL_ERROR_IP_DEST_UNKNOWN;
                            return false;
						}
					}
					
						// Check for direction attribute
					i = atts.index(protocolnamespace,directionattr);
					if(i!=-1) {
						currentnetuse->bidirectional = true;
					}
					parsestate = PROTOCOL_STATE_IP;
					return true;
				}

				break;

			case PROTOCOL_STATE_TCP:
				if(localName=="source") {
					parsestate = PROTOCOL_STATE_TCP_SOURCE;
					return true;
				}
				if(localName=="dest") {
					parsestate = PROTOCOL_STATE_TCP_DEST;
					return true;
				}
				if(localName=="description") {
                    doNetuseLanguage(atts);
					parsestate = PROTOCOL_STATE_TCP_DESCRIPTION;
					return true;
				}
				if(localName=="pragma") {
                        // Grab the pragma name
                    i = atts.index(protocolnamespace,nameattr);
                    if(i!=-1) {
                        tmp = atts.value(i);
                        currentnetuse->pragmaname.append(tmp);
                    } else {
                        currentnetuse->pragmaname.append(QString());  // Null string.
                    }
                    parsestate = PROTOCOL_STATE_TCP_PRAGMA;
                    return true;
                }
				break;
				
			case PROTOCOL_STATE_UDP:
				if(localName=="source") {
					parsestate = PROTOCOL_STATE_UDP_SOURCE;
					return true;
				}
				if(localName=="dest") {
					parsestate = PROTOCOL_STATE_UDP_DEST;
					return true;
				}
				if(localName=="description") {
                    doNetuseLanguage(atts);
					parsestate = PROTOCOL_STATE_UDP_DESCRIPTION;
					return true;
				}
				if(localName=="pragma") {
                        // Grab the pragma name
                    i = atts.index(protocolnamespace,nameattr);
                    if(i!=-1) {
                        tmp = atts.value(i);
                        currentnetuse->pragmaname.append(tmp);
                    } else {
                        currentnetuse->pragmaname.append(QString());  // Null string.
                    }
                    parsestate = PROTOCOL_STATE_UDP_PRAGMA;
                    return true;
                }
				break;
				
			case PROTOCOL_STATE_ICMP:
				if(localName=="type") {
                    currentnetusedetail = new ProtocolNetUseDetail();
                 	currentnetusedetail->alternate = false;
                 	currentnetusedetail->rangetype = PORTRANGE_RANGE;
                 	currentnetusedetail->code = -1;
                        // Grab the type number
                    i = atts.index(protocolnamespace,valueattr);
                    if(i==-1) {
                    	errorstate = PROTOCOL_ERROR_TYPE_VALUE_ATTR_NOT_FOUND;
                        return false;
                    }
                    tmp = atts.value(i);
                    currentnetusedetail->type = tmp.toUInt(&ok);
                    if(ok==false) {
                    	errorstate = PROTOCOL_ERROR_TYPE_VALUE_ATTR_NOT_UINT;
                        return false;
                    }
				
						// Grab the ICMP code.
					i = atts.index(protocolnamespace,codeattr);
					if(i!=-1) {
						tmp = atts.value(i);
                	    currentnetusedetail->code = tmp.toUInt(&ok);
            	        if(ok==false) {
        	            	errorstate = PROTOCOL_ERROR_TYPE_CODE_ATTR_NOT_UINT;
    	                    return false;
	                    }
					}
				
					parsestate = PROTOCOL_STATE_ICMP_TYPE;
					return true;
				}
				if(localName=="description") {
                    doNetuseLanguage(atts);
					parsestate = PROTOCOL_STATE_ICMP_DESCRIPTION;
					return true;
				}
				if(localName=="pragma") {
                        // Grab the pragma name
                    i = atts.index(protocolnamespace,nameattr);
                    if(i!=-1) {
                        tmp = atts.value(i);
                        currentnetuse->pragmaname.append(tmp);
                    } else {
                        currentnetuse->pragmaname.append(QString());  // Null string.
                    }
                    parsestate = PROTOCOL_STATE_ICMP_PRAGMA;
                    return true;
                }
				break;
				
			case PROTOCOL_STATE_IP:
				if(localName=="description") {
                    doNetuseLanguage(atts);
					parsestate = PROTOCOL_STATE_IP_DESCRIPTION;
					return true;
				}
				if(localName=="pragma") {
                        // Grab the pragma name
                    i = atts.index(protocolnamespace,nameattr);
                    if(i!=-1) {
                        tmp = atts.value(i);
                        currentnetuse->pragmaname.append(tmp);
                    } else {
                        currentnetuse->pragmaname.append(QString());  // Null string.
                    }
                    parsestate = PROTOCOL_STATE_IP_PRAGMA;
                    return true;
                }
			    break;
			    
            case PROTOCOL_STATE_TCP_SOURCE:
            case PROTOCOL_STATE_UDP_SOURCE:
            case PROTOCOL_STATE_TCP_DEST:
            case PROTOCOL_STATE_UDP_DEST:
                if(localName=="port") {
                    currentnetusedetail = new ProtocolNetUseDetail();
                    currentnetusedetail->rangetype = PORTRANGE_RANGE;
                 	currentnetusedetail->alternate = false;
                    currentnetusedetail->start = 0;
                    currentnetusedetail->end = 0;
                        
                        // Grab the port number
                    i = atts.index(protocolnamespace,portnumattr);
                    if(i==-1) {
                    	errorstate = PROTOCOL_ERROR_PORT_PORTNUM_ATTR_NOT_FOUND;
                        return false;
                    }
                    tmp = atts.value(i);
                               
                    if(tmp=="any") {
                        currentnetusedetail->rangetype = PORTRANGE_ANY;
                        currentnetusedetail->start = 0;
                        currentnetusedetail->end = 65535;
                    } else if(tmp=="privileged") {
                        currentnetusedetail->rangetype = PORTRANGE_PRIVILEGED;
                        currentnetusedetail->start = 0;
                        currentnetusedetail->end = 1023;
                    } else if(tmp=="nonprivileged") {
                        currentnetusedetail->rangetype = PORTRANGE_NONPRIVILEGED;
                        currentnetusedetail->start = 1024;
                        currentnetusedetail->end = 65535;
                    } else if(tmp=="dynamic") {
                        currentnetusedetail->rangetype = PORTRANGE_DYNAMIC;
                        currentnetusedetail->start = 1024;
                        currentnetusedetail->end = 65535;
                    } else { 
                        currentnetusedetail->start = tmp.toUInt(&ok);
                        if(ok==false) {
                        	errorstate = PROTOCOL_ERROR_PORT_PORTNUM_ATTR_NOT_UINT;
                            return false;
                        }
                        currentnetusedetail->end = currentnetusedetail->start;
                    }
                    	// Should check for the alternative flag around here somewhere.
                    
					switch(parsestate) {
		        	    case PROTOCOL_STATE_TCP_SOURCE:
    		        		parsestate = PROTOCOL_STATE_TCP_SOURCE_PORT;
        		    		break;
			            case PROTOCOL_STATE_UDP_SOURCE:
			            	parsestate = PROTOCOL_STATE_UDP_SOURCE_PORT;
			            	break;
            			case PROTOCOL_STATE_TCP_DEST:
            				parsestate = PROTOCOL_STATE_TCP_DEST_PORT;
            				break;
            				
            			case PROTOCOL_STATE_UDP_DEST:
            				parsestate = PROTOCOL_STATE_UDP_DEST_PORT;
            				break;
            			default:
            			    break;
     				}
                    return true;
                }
                if(localName=="portrange") {
                    currentnetusedetail = new ProtocolNetUseDetail();
                    currentnetusedetail->rangetype = PORTRANGE_RANGE;
                    currentnetusedetail->alternate = false;
                        // Grab the start port number
                    i = atts.index(protocolnamespace,portstartattr);
                    if(i==-1) {
                    	errorstate = PROTOCOL_ERROR_PORTRANGE_START_ATTR_NOT_FOUND;
                        return false;
                    }
                    tmp = atts.value(i);
                    currentnetusedetail->start = tmp.toUInt(&ok);
                    if(ok==false) {
                    	errorstate = PROTOCOL_ERROR_PORTRANGE_START_ATTR_NOT_UINT;
                        return false;
                    }

                        // Grab the end port number
                    i = atts.index(protocolnamespace,portendattr);
                    if(i==-1) {
                    	errorstate = PROTOCOL_ERROR_PORTRANGE_END_ATTR_NOT_FOUND;
                        return false;
                    }
                    tmp = atts.value(i);
                	currentnetusedetail->end = tmp.toUInt(&ok);
                    if(ok==false) {
                    	errorstate = PROTOCOL_ERROR_PORTRANGE_END_ATTR_NOT_UINT;
                        return false;
                    }
                    if(currentnetusedetail->end < currentnetusedetail->start) {
                    	errorstate = PROTOCOL_ERROR_PORTRANGE_END_LESS_START;
                        return false;
                    }
                    
					switch(parsestate) {
		        	    case PROTOCOL_STATE_TCP_SOURCE:
    		        		parsestate = PROTOCOL_STATE_TCP_SOURCE_PORTRANGE;
        		    		break;
			            case PROTOCOL_STATE_UDP_SOURCE:
			            	parsestate = PROTOCOL_STATE_UDP_SOURCE_PORTRANGE;
			            	break;
            			case PROTOCOL_STATE_TCP_DEST:
            				parsestate = PROTOCOL_STATE_TCP_DEST_PORTRANGE;
            				break;
            				
            			case PROTOCOL_STATE_UDP_DEST:
            				parsestate = PROTOCOL_STATE_UDP_DEST_PORTRANGE;
            				break;
            		    default:
            		        break;
     				}
                    return true;
                }
                break;

            default:
                break;
        }
    }
    unknowndepth++;
    return true;
}
    
///////////////////////////////////////////////////////////////////////////
void ProtocolDB::doNetuseLanguage(const QXmlAttributes &atts) {
    int i,j;                    
    QString tmp;
    
    loaddescription = false;
    i = atts.index(protocolnamespace,langattr);
    if(i!=-1) {
        tmp = atts.value(i);
    } else {
        tmp = "en";
    }
    if(currentnetuse->descriptionlanguage.isNull()) {
        loaddescription = true;
        currentnetuse->descriptionlanguage = tmp;
    } else {
            // Which language is more important?
            // (Which appears first in the list of acceptable
            // languages.)
        i = languagelist.findIndex(currentnetuse->descriptionlanguage);
        i = i==-1 ? 10000 : i;
        j = languagelist.findIndex(tmp);
        j = j==-1 ? 10000 : j;
        if(j<i) {
            loaddescription = true;
            currentnetuse->descriptionlanguage = tmp;
        }
    }
}

///////////////////////////////////////////////////////////////////////////
bool ProtocolDB::endElement(const QString &/*namespaceURI*/, const QString &/*localName*/,
        const QString &/*qName*/) {

    if(unknowndepth==0) {
        switch(parsestate) {
            case PROTOCOL_STATE_PROTOCOLDB:
                parsestate = PROTOCOL_STATE_FINISHED;
                return true;

            case PROTOCOL_STATE_ENTRY:
                    // We are just exiting an entry.
                db.append(currententry); // Add it to the end of our list.
                currententry = 0;
                parsestate = PROTOCOL_STATE_PROTOCOLDB;
                return true;

            case PROTOCOL_STATE_LONGNAME:
            case PROTOCOL_STATE_DESCRIPTION:
            case PROTOCOL_STATE_SECURITY:
			case PROTOCOL_STATE_NETWORK:
			case PROTOCOL_STATE_CLASSIFICATION:
			case PROTOCOL_STATE_ENTRY_PRAGMA:
                parsestate = PROTOCOL_STATE_ENTRY;
                return true;
                
			case PROTOCOL_STATE_TCP:
			case PROTOCOL_STATE_UDP:
			        // If no port info was given for the source ports or dest ports,
			        // then we assume that they mean any port. So we just add an any
			        // port range entry to the list.
			    if(currentnetuse->sourcedetaillist.count()==0) {
                    currentnetusedetail = new ProtocolNetUseDetail();
                    currentnetusedetail->rangetype = PORTRANGE_ANY;
                 	currentnetusedetail->alternate = false;
                    currentnetusedetail->start = 0;
                    currentnetusedetail->end = 65535;
    				currentnetuse->sourcedetaillist.append(currentnetusedetail);
	    			currentnetusedetail = 0;
			    }
			    if(currentnetuse->destdetaillist.count()==0) {
                    currentnetusedetail = new ProtocolNetUseDetail();
                    currentnetusedetail->rangetype = PORTRANGE_ANY;
                 	currentnetusedetail->alternate = false;
                    currentnetusedetail->start = 0;
                    currentnetusedetail->end = 65535;
    				currentnetuse->destdetaillist.append(currentnetusedetail);
	    			currentnetusedetail = 0;
			    }
			        // This fall through is intentional.
			case PROTOCOL_STATE_ICMP:
			case PROTOCOL_STATE_IP:
				currententry->networkuse.append(currentnetuse);
				currentnetuse = 0;
				parsestate = PROTOCOL_STATE_NETWORK;
				return true;

			case PROTOCOL_STATE_TCP_SOURCE:
			case PROTOCOL_STATE_TCP_DEST:
			case PROTOCOL_STATE_TCP_DESCRIPTION:
			case PROTOCOL_STATE_TCP_PRAGMA:
				parsestate = PROTOCOL_STATE_TCP;
				return true;
			
			case PROTOCOL_STATE_UDP_SOURCE:
			case PROTOCOL_STATE_UDP_DEST:
			case PROTOCOL_STATE_UDP_DESCRIPTION:
			case PROTOCOL_STATE_UDP_PRAGMA:
			    parsestate = PROTOCOL_STATE_UDP;
				return true;

			case PROTOCOL_STATE_ICMP_TYPE:
				currentnetuse->sourcedetaillist.append(currentnetusedetail);
				parsestate = PROTOCOL_STATE_ICMP;
				return true;
			
			case PROTOCOL_STATE_ICMP_DESCRIPTION:
			case PROTOCOL_STATE_ICMP_PRAGMA:
				parsestate = PROTOCOL_STATE_ICMP;
				return true;
			
			case PROTOCOL_STATE_IP_DESCRIPTION:
			case PROTOCOL_STATE_IP_PRAGMA:
				parsestate = PROTOCOL_STATE_IP;
				return true;

			case PROTOCOL_STATE_TCP_SOURCE_PORT:
			case PROTOCOL_STATE_TCP_SOURCE_PORTRANGE:
				currentnetuse->sourcedetaillist.append(currentnetusedetail);
				currentnetusedetail = 0;
				parsestate = PROTOCOL_STATE_TCP_SOURCE;
				return true;
			
			case PROTOCOL_STATE_TCP_DEST_PORT:
			case PROTOCOL_STATE_TCP_DEST_PORTRANGE:
				currentnetuse->destdetaillist.append(currentnetusedetail);
				currentnetusedetail = 0;
				parsestate = PROTOCOL_STATE_TCP_DEST;
				return true;
				
			case PROTOCOL_STATE_UDP_SOURCE_PORT:
			case PROTOCOL_STATE_UDP_SOURCE_PORTRANGE:
				currentnetuse->sourcedetaillist.append(currentnetusedetail);
				currentnetusedetail = 0;
				parsestate = PROTOCOL_STATE_UDP_SOURCE;
				return true;

			case PROTOCOL_STATE_UDP_DEST_PORT:
			case PROTOCOL_STATE_UDP_DEST_PORTRANGE:
				currentnetuse->destdetaillist.append(currentnetusedetail);
				currentnetusedetail = 0;
				parsestate = PROTOCOL_STATE_UDP_DEST;
				return true;
								
            default:
                return false;
        }
    }
    unknowndepth--;
    return true;
}

///////////////////////////////////////////////////////////////////////////
bool ProtocolDB::characters(const QString &ch) {
    if(unknowndepth) {
        return true;
    }

    switch(parsestate) {
        case PROTOCOL_STATE_LONGNAME:
            if(loadlongname) {
                currententry->longname = ch;
            }
            return true;

        case PROTOCOL_STATE_DESCRIPTION:
            if(loaddescription) {
                currententry->description = ch;
            }
            return true;

        case PROTOCOL_STATE_ENTRY_PRAGMA:
            currententry->pragmavalue.append(ch);
            return true;
            		
		case PROTOCOL_STATE_TCP_DESCRIPTION:
		case PROTOCOL_STATE_UDP_DESCRIPTION:
		case PROTOCOL_STATE_ICMP_DESCRIPTION:
            if(loaddescription) {
                currentnetuse->description = ch;
            }
			return true;

	    case PROTOCOL_STATE_TCP_PRAGMA:
	    case PROTOCOL_STATE_UDP_PRAGMA:
	    case PROTOCOL_STATE_ICMP_PRAGMA:
            currentnetuse->pragmavalue.append(ch);
            return true;	
			
        default:
            break;
    }
    return true;
}

///////////////////////////////////////////////////////////////////////////
void ProtocolDB::setDocumentLocator(QXmlLocator *l) {
    xmllocator = l;
}

///////////////////////////////////////////////////////////////////////////
bool ProtocolDB::error(const QXmlParseException &exception) {
	printParseException(exception);
	errorstate = PROTOCOL_ERROR_PARSE_ERROR;
	return false;
}

///////////////////////////////////////////////////////////////////////////
bool ProtocolDB::fatalError(const QXmlParseException &exception) {
	printParseException(exception);
	errorstate = PROTOCOL_ERROR_PARSE_ERROR;
	return false;
}

///////////////////////////////////////////////////////////////////////////
bool ProtocolDB::warning(const QXmlParseException &exception) {
	printParseException(exception);
	errorstate = PROTOCOL_ERROR_PARSE_ERROR;
	return false;
}

///////////////////////////////////////////////////////////////////////////
QString ProtocolDB::errorString() {
	switch(errorstate) {
		case PROTOCOL_ERROR_NOERROR:
			return i18n("No error (You should not see this).");
        case PROTOCOL_ERROR_OPEN_ERROR:
            return i18n("Unable to open the network protocol database XML file.");
	    case PROTOCOL_ERROR_PARSE_ERROR:
	        return i18n("XML Parse error:\n%1").arg(parseerror);
		case PROTOCOL_ERROR_ENTRY_NAME_ATTR_NOT_FOUND:
			return i18n("'protocol' tag requires a 'name' attribute, but none was found.");
		case PROTOCOL_ERROR_SECURITY_LEVEL_UNKNOWN:
			return i18n("'threat' attribute has an unrecognised value.");
		case PROTOCOL_ERROR_SECURITY_FALSEPOS_UNKNOWN:
			return i18n("'falsepos' attribute has an unrecognised value.");
		case PROTOCOL_ERROR_PORT_PORTNUM_ATTR_NOT_FOUND:
			return i18n("'port' element requires a 'portnum' attribute, but none was found.");
		case PROTOCOL_ERROR_PORT_PORTNUM_ATTR_NOT_UINT:
			return i18n("'portnum' attribute is not a valid unsigned integer.");
		case PROTOCOL_ERROR_PORTRANGE_START_ATTR_NOT_FOUND:
			return i18n("'portrange' element requires a 'start' attribute, but none was found.");
		case PROTOCOL_ERROR_PORTRANGE_START_ATTR_NOT_UINT:
			return i18n("'start' attribute is not a valid unsigned integer.");
		case PROTOCOL_ERROR_PORTRANGE_END_ATTR_NOT_FOUND:
			return i18n("'portrange' element requires a 'end' attribute, but none was found.");
		case PROTOCOL_ERROR_PORTRANGE_END_ATTR_NOT_UINT:
			return i18n("'end' attribute is not a valid unsigned integer.");
		case PROTOCOL_ERROR_PORTRANGE_END_LESS_START:
			return i18n("'start' attribute must be greater than 'end' attribute.");
		case PROTOCOL_ERROR_TCP_SOURCE_UNKNOWN:
		case PROTOCOL_ERROR_UDP_SOURCE_UNKNOWN:
		case PROTOCOL_ERROR_ICMP_SOURCE_UNKNOWN:
		case PROTOCOL_ERROR_IP_SOURCE_UNKNOWN:
			return i18n("'source' attribute must be one of 'client', 'server' or 'host'.");
		case PROTOCOL_ERROR_TCP_DEST_UNKNOWN:
		case PROTOCOL_ERROR_UDP_DEST_UNKNOWN:
		case PROTOCOL_ERROR_ICMP_DEST_UNKNOWN:
		case PROTOCOL_ERROR_IP_DEST_UNKNOWN:
			return i18n("'dest' attribute must be one of 'client', 'server' or 'host'.");
		case PROTOCOL_ERROR_TYPE_VALUE_ATTR_NOT_FOUND:
			return i18n("'type' element requires a 'value' attribute, but none was found.");
		case PROTOCOL_ERROR_TYPE_VALUE_ATTR_NOT_UINT:
			return i18n("'value' attribute is not a valid unsigned integer.");
		case PROTOCOL_ERROR_TYPE_CODE_ATTR_NOT_UINT:
			return i18n("'code' attribute is not a valid unsigned integer.");
		case PROTOCOL_ERROR_CLASSIFICATION_CLASS_UNKNOWN:
		    return i18n("'class' attribute has an unrecognised value.");
        case PROTOCOL_ERROR_IP_PROTOCOL_NOT_FOUND:
			return i18n("'ip' element requires a 'protocol' attribute, but none was found.");
        case PROTOCOL_ERROR_IP_PROTOCOL_ATTR_NOT_UINT:
   			return i18n("'protocol' attribute is not a valid unsigned integer.");
        case PROTOCOL_ERROR_IP_PROTOCOL_ATTR_OUT_OF_RANGE:
            return i18n("'protocol' attribute is out of range. (Must be 8 bit).");

		default:
			return i18n("Unknown error. (You should never see this).");
	}
}

///////////////////////////////////////////////////////////////////////////
void ProtocolDB::printParseException(const QXmlParseException &exception) {
	parseerror.append(i18n("Line: %1, Column: %2 %3, %4, %5\n")
	    .arg(exception.lineNumber())
	    .arg(exception.columnNumber())
	    .arg((const char *)exception.systemId())
	    .arg((const char *)exception.publicId())
	    .arg((const char *)exception.message()));
}

///////////////////////////////////////////////////////////////////////////
// We have a hash mapping port numbers to related entries in the protocol
// database.
//
void ProtocolDB::buildPortHash() {
    ProtocolEntry *entry;

    for(entry=db.first(); entry!=0; entry=db.next()) {
        addEntryToPortHash(entry);
    }
}

///////////////////////////////////////////////////////////////////////////
void ProtocolDB::addEntryToPortHash(ProtocolEntry *entry) {
    ProtocolNetUse *netuse;
    ProtocolNetUseDetail *detail;
    uint i;

    for(netuse=entry->networkuse.first(); netuse!=0; netuse=entry->networkuse.next()) {
                
        for(detail=netuse->sourcedetaillist.first(); detail!=0; detail=netuse->sourcedetaillist.next()) {
            if(detail->rangetype==PORTRANGE_RANGE) {  // We only do normal ranges.
                if(netuse->type==IPPROTO_ICMP) {
                    addEntryToHash(entry,netuse->type,detail->type);
                } else {
                    for(i=detail->start; i<=detail->end; i++) {
                        addEntryToHash(entry,netuse->type,i);
                    }
                }
            }
        }
                
        for(detail=netuse->destdetaillist.first(); detail!=0; detail=netuse->destdetaillist.next()) {
            if(detail->rangetype==PORTRANGE_RANGE) {  // We only do normal ranges.
                if(netuse->type==IPPROTO_ICMP) {
                    addEntryToHash(entry,netuse->type,detail->type);
                } else {
                    for(i=detail->start; i<=detail->end; i++) {
                        addEntryToHash(entry,netuse->type,i);
                    }
                }
            }                
        }
    }
}

///////////////////////////////////////////////////////////////////////////
long ProtocolDB::hashKey(uchar type, uint port) {
    return (long)((((uint)type)<<24)|port);
}

///////////////////////////////////////////////////////////////////////////
void ProtocolDB::addEntryToHash(ProtocolEntry *entry, uchar type, uint port) {
    QList<ProtocolEntry> *bucket;
    long key;

    key = hashKey(type,port);
    bucket = porthash.find(key);
    if(bucket==0) {
        bucket = new QList<ProtocolEntry>;
        porthash.insert(key,bucket);
    }
    bucket->append(entry);
}

///////////////////////////////////////////////////////////////////////////
void ProtocolDB::removeEntryFromPortHash(ProtocolEntry *entry) {
    QIntDictIterator< QList<ProtocolEntry> > it(porthash);
    QList<ProtocolEntry> *bucket;
        
        // Search through the whole port hash removing any references to
        // the entry.
    while(it.current()) {
        bucket = it.current();
        bucket->removeRef(entry);
        ++it;
    }
}

///////////////////////////////////////////////////////////////////////////
QList<ProtocolDB::ProtocolEntry> *ProtocolDB::lookup(uchar type, uint port) {
    return porthash.find(hashKey(type,port));
}

///////////////////////////////////////////////////////////////////////////
ProtocolDB::ProtocolEntry *ProtocolDB::lookup(const QString &name) {
    QListIterator<ProtocolEntry> *dbit;
    ProtocolEntry *proto;
    
    dbit = newDatabaseIterator();   // Yes, linear search.
    for(;dbit->current(); ++(*dbit)) {
        if(dbit->current()->name==name) {
            proto = dbit->current();
            delete dbit;
            return proto;
        }    
    }
    delete dbit;
    return 0;
}
    
///////////////////////////////////////////////////////////////////////////
QListIterator<ProtocolDB::ProtocolEntry> *ProtocolDB::newDatabaseIterator() {
    return new QListIterator<ProtocolDB::ProtocolEntry>(db);
}

///////////////////////////////////////////////////////////////////////////
void ProtocolDB::insertEntry(ProtocolEntry *entry) {
    db.append(entry);
    addEntryToPortHash(entry);
}

///////////////////////////////////////////////////////////////////////////
bool ProtocolDB::takeEntry(ProtocolEntry *entry) {
    db.setAutoDelete(false);    // Just temp.
    if(!db.removeRef(entry)) {
        db.setAutoDelete(true);
        return false;
    }
    db.setAutoDelete(true);
    removeEntryFromPortHash(entry);
    return true;
}

///////////////////////////////////////////////////////////////////////////
bool ProtocolDB::removeEntry(ProtocolEntry *entry) {
    if(takeEntry(entry)) {
        delete entry;
        return true;
    } else {
        return false;
    }
}
