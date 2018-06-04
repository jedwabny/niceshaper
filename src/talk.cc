/*
 *  NiceShaper - Dynamic Traffic Management
 *
 *  Copyright (C) 2004-2016 Mariusz Jedwabny <mariusz@jedwabny.net>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of this archive for
 *  more details.
 */

#include "talk.h"

#include <cstring>
#include <unistd.h>

#include <iostream>
#include <string>

#include "main.h"
#include "logger.h"

Talk::Talk ()
{
    // Nothing
}

Talk::~Talk ()
{
    // Nothing
}

int Talk::sendBool(int pipe, bool value)
{
    char cbuf = BOOL_FALSE;

    if (value == true) cbuf = BOOL_TRUE;
    else cbuf = BOOL_FALSE;

    if (write(pipe, &cbuf, 1) == -1) { log->error(312, "int Talk::sendBool"); return -1; }
    
    return 0;    
}

int Talk::recvBool(int pipe, bool &value)
{
    char cbuf;
    
    if (read(pipe, &cbuf, 1) != 1) {
        log->error(310, "int Talk::recvBool");
        return -1;
    }
    
    if (cbuf == BOOL_TRUE) value = true;
    else if (cbuf == BOOL_FALSE) value = false;
    else {
        log->error(311, "int Talk::recvBool");
        return -1;
    }
    
    return 0;
}

int Talk::sendText(int pipe, std::string msg)
{
    std::string msg_portion;
    std::string buf;
    unsigned int pos;

    if (msg.size() > MAX_LONG_BUF_SIZE) { log->error(313, "int Talk::sendText"); return -1; }

    pos = 0;

    do {
        msg_portion = msg.substr(pos, MAX_MESSAGE_SIZE);
        buf = static_cast<char>(msg_portion.size() + PROTO_BASE);
        buf += msg_portion;
        write (pipe, buf.c_str(), buf.size());
        pos += MAX_MESSAGE_SIZE;    
    } while (msg_portion.size() == MAX_MESSAGE_SIZE);

    return 0;
}

int Talk::recvText(int pipe, std::string &msg)
{
    char buf[MAX_MESSAGE_SIZE];
    char cbuf;
    //int msg_len, got_msg_len;
    unsigned int msg_len;
    int msg_len_got;
    bool is_another_portion;

    msg = "";

    do {
        if (read(pipe, &cbuf, 1) != 1) { log->error(310, "int Talk::recvText"); return -1; }

        msg_len = static_cast<unsigned int>(cbuf) - static_cast<unsigned int>(PROTO_BASE);

        if (msg_len > MAX_MESSAGE_SIZE) { log->error(313, "int Talk::recvText"); return -1; }

        if (msg_len < MAX_MESSAGE_SIZE) is_another_portion = false;
        else if (msg_len == MAX_MESSAGE_SIZE) is_another_portion = true;

        msg_len_got = 0;
        strcpy(buf, "");
        buf[msg_len]=0;
        while (msg_len)
        {
            if ((msg_len_got=read(pipe, buf+msg_len_got, msg_len)) <= 0 ) { log->error(310, "int Talk::recvText"); return -1; }
            msg_len -= static_cast<unsigned int>(msg_len_got);
        }
        msg += std::string(buf);
        if (msg.size() > MAX_LONG_BUF_SIZE) { log->error(313, "int Talk::recvText"); return -1; }
    } while (is_another_portion);
    
    return 0;
}

int Talk::sendTextVector(int pipe, std::vector <std::string> &msgv)
{
    std::string buf;
    unsigned int pos = 0;

    while (pos < msgv.size()) {
        if (sendBool(pipe, true) == -1) { return -1; };
        if (sendText(pipe, msgv.at(pos)) == -1) { return -1; }
        pos++; 
    }

    if (sendBool(pipe, false) == -1) { return -1; };

    return 0;
}
 
int Talk::recvTextVector(int pipe, std::vector <std::string> &msgv)
{
    std::string msg;
    bool another_part = false;

    msgv.clear();
 
    while (true) {
        if (recvBool(pipe, another_part) == -1) { return -1; }
        if (!another_part) return 0;
        if (recvText(pipe, msg) == -1) { return -1; };
        msgv.push_back(msg);
    }
   
    return 0;
}


