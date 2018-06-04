#ifndef AUX_H
#define AUX_H

#include <string>
#include <vector>

#include "main.h"

namespace aux {
    // Text processing
    std::string trim (std::string, bool);
    std::string trim_legacy (std::string);
    std::string trim_strict (std::string);
    std::string awk (std::string, unsigned int);
    std::string awk (std::string, std::string, unsigned int);
    unsigned int awk_size(std::string source);
    // Numbers processing
    int power (int, int);
    unsigned int compute_quantum (unsigned int);
    std::string int_to_str(int);
    std::string int_to_str(unsigned int);
    std::string int_to_str(int, unsigned int);
    std::string int_to_hex(int);
    unsigned int str_to_uint (std::string);
    int str_to_int (std::string);
    double str_to_double (std::string);
    __u64 str_to_u64(std::string);
    unsigned int str_fwmark_to_uint (std::string);
    bool is_uint (std::string);
    void shift (unsigned int &, unsigned int &);
    // Net related
    std::string trim_dev (std::string);
    int dot_to_bit (std::string);
    std::string bit_to_dot (int);
    std::string ip_to_hostname (std::string);
    int split_ip (const std::string, std::string &, std::string &);
    int split_ip_port (std::string, std::string &, int &);
    // Configure processing
    int fpv_section_i (std::vector < std::string >::iterator &, std::vector < std::string >::iterator &, std::vector < std::string > &, std::string); // begin, end, fpv, section 
    std::string value_of_param (std::string, std::string);
    // Units processing
    EnumUnits get_unit (std::string);
    std::string unit_to_str (EnumUnits arg, bool);
    unsigned int unit_convert (std::string, EnumUnits);
    unsigned int unit_convert(unsigned int, EnumUnits);
    // Vectors related
    bool is_in_vector (std::vector < std::string > &, std::string);
    bool is_in_vector (std::vector < unsigned int > &, unsigned int);
}

#endif
