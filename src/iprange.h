/***************************************************************************
                          iprange.h  -  description
                             -------------------
    begin                : Thu May 10 08:08:00 EST 2001
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
#ifndef IPRANGE_H
#define IPRANGE_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <qstring.h>

enum IPRangeType {invalid,domainname,ip,iprange};
class IPRange {
public:

IPRange() {
    digested = false;
}

IPRange(const std::string &a) {
    setAddress(a);
}
        
~IPRange() {

}

void setAddress(const std::string &a) {
    address = a;
    digested = false;
}

///////////////////////////////////////////////////////////////////////////
std::string getAddress() const {
    return address;
}

///////////////////////////////////////////////////////////////////////////
IPRangeType getType() {
    if(!digested) {
        digest();
        digested = true;
    }
    return type;
}

///////////////////////////////////////////////////////////////////////////
void digest() {
#if 0
    KRegExp sanity("^[0-9a-zA-Z./-]*$");
    KRegExp domainnametest("^([a-zA-Z0-9-]+\\.)+[a-zA-Z0-9-]+$");
    KRegExp iptest("^([0-9]+)\\.([0-9]+)\\.([0-9]+)\\.([0-9]+)$");
    KRegExp ipmaskedtest("^([0-9]+)\\.([0-9]+)\\.([0-9]+)\\.([0-9]+)/([0-9]+)$");
    KRegExp ipmasked2test("^([0-9]+)\\.([0-9]+)\\.([0-9]+)\\.([0-9]+)/([0-9]+)\\.([0-9]+)\\.([0-9]+)\\.([0-9]+)$");
    
    long ipbyte;
    uint bitmask;
    mask = 32;

        // Smoke text
    if(sanity.match((const char *)address)==false) {
        type = invalid;
        return;
    }

    if(address.length()==0) {
        type = invalid;
        return;
    }

        // Test against the domainname regexp.
    if(domainnametest.match((const char *)address)) {
        type = domainname;
        mask = 32;
        return;
    }
    
        // Ok, now lets try the IP address regexp.
    if(iptest.match((const char *)address)==true) {
        ipbyte = atol(iptest.group(1));    // Yep, it returns char *.
        if(ipbyte<0 || ipbyte>255) {
            type = invalid;
            return;
        }
        ipbyte = atol(iptest.group(2));
        if(ipbyte<0 || ipbyte>255) {
            type = invalid;
            return;
        }
        ipbyte = atol(iptest.group(3));
        if(ipbyte<0 || ipbyte>255) {
            type = invalid;
            return;
        }
        ipbyte = atol(iptest.group(4));
        if(ipbyte<0 || ipbyte>255) {
            type = invalid;
            return;
        }
        type = ip;
        mask = 32;
        return;
    }

        // Ok, now lets try the IP address regexp.
    if(ipmaskedtest.match((const char *)address)==true) {
        ipbyte = atol(ipmaskedtest.group(1));    // Yep, it returns char *.
        if(ipbyte<0 || ipbyte>255) {
            type = invalid;
            return;
        }
        ipbyte = atol(ipmaskedtest.group(2));
        if(ipbyte<0 || ipbyte>255) {
            type = invalid;
            return;
        }
        ipbyte = atol(ipmaskedtest.group(3));
        if(ipbyte<0 || ipbyte>255) {
            type = invalid;
            return;
        }
        ipbyte = atol(ipmaskedtest.group(4));
        if(ipbyte<0 || ipbyte>255) {
            type = invalid;
            return;
        }
            // Mask byte.
        ipbyte = atol(ipmaskedtest.group(5));
        if(ipbyte<0 || ipbyte>32) {
            type = invalid;
            return;
        }
        mask = ipbyte;
        type = iprange;
        return;
    }
    
    bitmask = 0;
    if(ipmasked2test.match((const char *)address)==true) {
        ipbyte = atol(ipmasked2test.group(1));    // Yep, it returns char *.
        if(ipbyte<0 || ipbyte>255) {
            type = invalid;
            return;
        }
        ipbyte = atol(ipmasked2test.group(2));
        if(ipbyte<0 || ipbyte>255) {
            type = invalid;
            return;
        }
        ipbyte = atol(ipmasked2test.group(3));
        if(ipbyte<0 || ipbyte>255) {
            type = invalid;
            return;
        }
        ipbyte = atol(ipmasked2test.group(4));
        if(ipbyte<0 || ipbyte>255) {
            type = invalid;
            return;
        }
        ipbyte = atol(ipmasked2test.group(5));
        if(ipbyte<0 || ipbyte>255) {
            type = invalid;
            return;
        }
            // Build up the bit mask.
        bitmask = ((uint)ipbyte)<<24;
        ipbyte = atol(ipmasked2test.group(6));
        if(ipbyte<0 || ipbyte>255) {
            type = invalid;
            return;
        }
        bitmask |= ((uint)ipbyte)<<16;
        ipbyte = atol(ipmasked2test.group(7));
        if(ipbyte<0 || ipbyte>255) {
            type = invalid;
            return;
        }
        bitmask |= ((uint)ipbyte)<<8;
        ipbyte = atol(ipmasked2test.group(8));
        if(ipbyte<0 || ipbyte>255) {
            type = invalid;
            return;
        }
        bitmask |= ((uint)ipbyte);
        type = iprange;
        if(bitmask==0) {
            mask = 0;
        } else {
                // Convert the 255.255.0.0 style mask in bitmask
                // to a simple number (like 16 here)
            mask = 32;
            while((bitmask&1)==0) {
                bitmask >>= 1;
                mask--;
            }
        }
        
        return;
    }
    type = invalid;
#endif
}

///////////////////////////////////////////////////////////////////////////
uint getMask() {
    if(!digested) {
        digest();
        digested = true;
    }
    return mask;
}    
private:
    std::string     address;
    bool        digested;
    IPRangeType type;
    uint        mask;
};

#endif

