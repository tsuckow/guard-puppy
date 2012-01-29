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

#pragma once

#include <boost/regex.hpp>

enum IPRangeType 
{
    invalid,
    domainname,
    ip,
    iprange
};

class IPRange 
{
    std::string address;
    bool        digested;
    IPRangeType type;
    uint        mask;
public:

    IPRange() 
    {
        digested = false;
    }

    IPRange(std::string const & a) 
    {
        setAddress(a);
    }

    ~IPRange() {

    }

    void setAddress(const std::string &a) 
    {
        address = a;
        digest();
    }

    ///////////////////////////////////////////////////////////////////////////
    std::string getAddress() const 
    {
        return address;
    }

    ///////////////////////////////////////////////////////////////////////////
    IPRangeType getType() 
    {
        if(!digested) {
            digest();
            digested = true;
        }
        return type;
    }

    long toLong( std::string const & s )
    {
        return boost::lexical_cast<long>(s);
    }

    ///////////////////////////////////////////////////////////////////////////
    void digest() 
    {
        boost::regex sanity("^[0-9a-zA-Z./-]*$");
        boost::regex domainnametest("^([a-zA-Z0-9-]+\\.)+[a-zA-Z0-9-]+$");
        boost::regex iptest("^([0-9]+)\\.([0-9]+)\\.([0-9]+)\\.([0-9]+)$");
        boost::regex ipmaskedtest("^([0-9]+)\\.([0-9]+)\\.([0-9]+)\\.([0-9]+)/([0-9]+)$");
        boost::regex ipmasked2test("^([0-9]+)\\.([0-9]+)\\.([0-9]+)\\.([0-9]+)/([0-9]+)\\.([0-9]+)\\.([0-9]+)\\.([0-9]+)$");

        long ipbyte;
        uint bitmask;
        mask = 32;

        // Smoke text
        if(boost::regex_match( address, sanity )==false) 
        {
            type = invalid;
            return;
        }

        if(address.length()==0) 
        {
            type = invalid;
            return;
        }

        // Test against the domainname regexp.
        if(boost::regex_match(address, domainnametest)) 
        {
            type = domainname;
            mask = 32;
            return;
        }

        // Ok, now lets try the IP address regexp.
        boost::smatch what;
        if(boost::regex_match(address, what, iptest)==true) 
        {
            ipbyte = toLong(what[1]);    // Yep, it returns char *.
            if(ipbyte<0 || ipbyte>255) 
            {
                type = invalid;
                return;
            }
            ipbyte = toLong(what[2]);
            if(ipbyte<0 || ipbyte>255) 
            {
                type = invalid;
                return;
            }
            ipbyte = toLong(what[3]);
            if(ipbyte<0 || ipbyte>255) 
            {
                type = invalid;
                return;
            }
            ipbyte = toLong(what[4]);
            if(ipbyte<0 || ipbyte>255) 
            {
                type = invalid;
                return;
            }
            type = ip;
            mask = 32;
            return;
        }

        // Ok, now lets try the IP address regexp.
        if(boost::regex_match(address, what, ipmaskedtest)==true) 
        {
            ipbyte = toLong( what[1] );
            if(ipbyte<0 || ipbyte>255) 
            {
                type = invalid;
                return;
            }
            ipbyte = toLong( what[2] );
            if(ipbyte<0 || ipbyte>255) 
            {
                type = invalid;
                return;
            }
            ipbyte = toLong( what[3] );
            if(ipbyte<0 || ipbyte>255) 
            {
                type = invalid;
                return;
            }
            ipbyte = toLong( what[4] );
            if(ipbyte<0 || ipbyte>255) 
            {
                type = invalid;
                return;
            }
            // Mask byte.
            ipbyte = toLong( what[5] );
            if(ipbyte<0 || ipbyte>32) 
            {
                type = invalid;
                return;
            }
            mask = ipbyte;
            type = iprange;
            return;
        }

        bitmask = 0;
        if(boost::regex_match(address, what, ipmasked2test)==true) 
        {
            ipbyte = toLong( what[1] );
            if(ipbyte<0 || ipbyte>255) 
            {
                type = invalid;
                return;
            }
            ipbyte = toLong( what[2] );
            if(ipbyte<0 || ipbyte>255) 
            {
                type = invalid;
                return;
            }
            ipbyte = toLong( what[3] );
            if(ipbyte<0 || ipbyte>255) 
            {
                type = invalid;
                return;
            }
            ipbyte = toLong( what[4] );
            if(ipbyte<0 || ipbyte>255) 
            {
                type = invalid;
                return;
            }
            ipbyte = toLong( what[5] );
            if(ipbyte<0 || ipbyte>255) 
            {
                type = invalid;
                return;
            }
            // Build up the bit mask.
            bitmask = ((uint)ipbyte)<<24;
            ipbyte = toLong( what[6] );
            if(ipbyte<0 || ipbyte>255) 
            {
                type = invalid;
                return;
            }
            bitmask |= ((uint)ipbyte)<<16;
            ipbyte = toLong( what[7] );
            if(ipbyte<0 || ipbyte>255) 
            {
                type = invalid;
                return;
            }
            bitmask |= ((uint)ipbyte)<<8;
            ipbyte = toLong( what[8] );
            if(ipbyte<0 || ipbyte>255) 
            {
                type = invalid;
                return;
            }
            bitmask |= ((uint)ipbyte);
            type = iprange;
            if(bitmask==0) 
            {
                mask = 0;
            } 
            else 
            {
                // Convert the 255.255.0.0 style mask in bitmask
                // to a simple number (like 16 here)
                mask = 32;
                while((bitmask&1)==0) 
                {
                    bitmask >>= 1;
                    mask--;
                }
            }

            return;
        }
        type = invalid;
    }

    ///////////////////////////////////////////////////////////////////////////
    uint getMask() const
    {
       return mask;
    }    

    bool operator==( IPRange const & rhs ) const
    {
        return address == rhs.address;
    }
};

