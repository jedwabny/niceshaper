#ifndef TALK_H
#define TALK_H

#include "main.h"

#include <string>
#include <vector>

class Talk
{
    public:
        Talk();
        ~Talk();
         // Fundamental data types
        int sendBool(int pipe, bool);
        int recvBool(int pipe, bool &);
        int sendText(int pipe, std::string);
        int recvText(int pipe, std::string &);
        // Wrappers on fundamentals to exchange string vectors
        int sendTextVector(int pipe, std::vector <std::string> &);
        int recvTextVector(int pipe, std::vector <std::string> &);
    private:
        //
        static const char BOOL_TRUE = 0x1E;
        static const char BOOL_FALSE = 0x1F;
        //
        static const char PROTO_BASE = 0x20;
        //
        static const unsigned int MAX_MESSAGE_SIZE = 0x7F - 0x01 - static_cast<unsigned int>(PROTO_BASE);
};

#endif
