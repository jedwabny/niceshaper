/*
 *      NiceShaper - Dynamic Traffic Management
 *
 *      Copyright (C) 2004-2016 Mariusz Jedwabny <mariusz@jedwabny.net>
 *
 *      This file is subject to the terms and conditions of the GNU General Public
 *      License.  See the file COPYING in the main directory of this archive for
 *      more details.
 */

#include "class.h"

#include <cstdlib>

#include <iostream>
#include <string>
#include <vector>

#include "main.h"
#include "logger.h"
#include "filter.h"
#include "sys.h"
#include "tests.h"
#include "aux.h"

Trigger::Trigger ()
{
    TriggerNsLow = 0;
    TriggerNsCeil = 0;
    UseNsLow = false;
    UseNsCeil = false;
    UseTrigger = false;
    Active = false;
}

Trigger::~Trigger ()
{
    //
}

int Trigger::storeReplaced (std::string buf)
{
    std::string option, param, value;

    if (buf.empty()) { log->error (11, buf); return -1; }

    option = aux::awk(buf, 1);
    param = aux::awk(buf, 2);
    value = aux::awk(buf, 3);

    if ((option != "alter") && (option != "quota")) { log->error (11, buf); return -1; }

    if ((param == "low") && (value == "no")) UseNsLow = false;
    else if ((param == "ceil") && (value == "no")) UseNsCeil = false;
    else if ((param == "rate") && (value == "no")) { UseNsLow = false; UseNsCeil = false; }
    else if (param == "low") {
        TriggerNsLow = aux::unit_convert(value, BITS);
        UseNsLow = true;
    }
    else if (param == "ceil") {
        TriggerNsCeil = aux::unit_convert(value, BITS);
        UseNsCeil = true;
    }
    else if (param == "rate") {
        TriggerNsLow = TriggerNsCeil = aux::unit_convert(value, BITS);
        UseNsLow = UseNsCeil = true;
    }
    else { log->error (11, buf); return -1; }

    if ((TriggerNsLow > MAX_RATE) || (TriggerNsLow && (TriggerNsLow < MIN_RATE))) { log->error(806, buf); return -1; }
    if ((TriggerNsCeil > MAX_RATE) || (TriggerNsCeil && (TriggerNsCeil < MIN_RATE))) { log->error(806, buf); return -1; }

    return 0;
}

TriggerAlter::TriggerAlter()
{
    TimePeriodFrom = 0;
    TimePeriodTo = 0;
}

TriggerAlter::~TriggerAlter()
{
}

int TriggerAlter::store (std::string buf) 
{
    std::string option, param, value;

    if (buf.empty()) return 0;

    option = aux::awk(buf, 1);
    param = aux::awk(buf, 2);
    value = aux::awk(buf, 3);

    if (option == "alter") {
        if ((param == "low") || (param == "ceil") || (param == "rate")) {
            if (storeReplaced(buf) == -1) return -1;
        }
        else if (param == "time-period") {
            if (value == "no") { UseTrigger = false; return 0; }
            if (value.find_first_not_of("0123456789:-") != std::string::npos) { log->error(801, buf); return -1; }
            TimePeriodFrom = aux::str_to_uint(aux::awk(aux::awk(value, "-", 1), ":", 1))*60 + aux::str_to_uint(aux::awk(aux::awk(value, "-", 1), ":", 2));
            TimePeriodTo = aux::str_to_uint(aux::awk(aux::awk(value, "-", 2), ":", 1))*60 + aux::str_to_uint(aux::awk(aux::awk(value, "-", 2), ":", 2));
            if ((TimePeriodFrom > 1440) || (TimePeriodTo > 1440)) { log->error(801, buf); return -1; }
            if (TimePeriodFrom == 1440) TimePeriodFrom = 0;
            if (TimePeriodTo == 1440) TimePeriodTo = 0;
            if (TimePeriodFrom == TimePeriodTo) { log->error(801, buf); return -1; }
            UseTrigger = true;
        }
        else { log->error (11, buf); return -1; }
    }

    return 0;
}

int TriggerAlter::check(unsigned int dmin)
{
    if (!UseTrigger) return 0;
    if (!UseNsLow && !UseNsCeil) return 0;    

    if (((TimePeriodFrom < TimePeriodTo) && (dmin >= TimePeriodFrom) && (dmin <= TimePeriodTo)) ||
            ((TimePeriodFrom > TimePeriodTo) && ((dmin >= TimePeriodFrom) || (dmin <= TimePeriodTo)))) {
        if (!Active) {
            Active = true;
            return 1;
        }
    } else {
        if (Active) {
            Active = false;
            return 2;
        }
    }

    return 0;
}

TriggerQuota::TriggerQuota ()
{
    LimitDay = 0;
    LimitWeek = 0;
    LimitMonth = 0;
    ResetDmin = 0;
    ResetWday = 1;
    ResetMday = 1;
    TotalDay = 0;
    TotalWeek = 0;
    TotalMonth = 0;
    TotalMinor = 0;
    IsDayResetted = false;
    IsWeekResetted = false;
    IsMonthResetted = false;
}

TriggerQuota::~TriggerQuota ()
{
}

int TriggerQuota::store (std::string buf)
{
    std::string option, param, value;

    if (buf.empty()) return 0;

    option = aux::awk(buf, 1);
    param = aux::awk(buf, 2);
    value = aux::awk(buf, 3);

    if (option == "quota") {
        if ((param == "low") || (param == "ceil") || (param == "rate")) {
            if (storeReplaced(buf) == -1) return -1;
        }
        else if (param == "day") {
            if (value == "no") { LimitDay = 0; }
            else {
                if (readQuota(value, LimitDay) == -1) { log->error(102, buf); return -1; }
                if (LimitDay == 0) { log->error(102, buf); return -1; }
            }
        }
        else if (param == "week") {
            if (value == "no") { LimitWeek = 0; }
            else {
                if (readQuota(value, LimitWeek) == -1) { log->error(102, buf); return -1; }
                if (LimitWeek == 0) { log->error(102, buf); return -1; }
            }
        }
        else if (param == "month") {
            if (value == "no") { LimitMonth = 0; }
            else {
                if (readQuota(value, LimitMonth) == -1) { log->error(102, buf); return -1; }
                if (LimitMonth == 0) { log->error(102, buf); return -1; }
            }
        }
        else if (param == "reset-hour") {
            if (value.find_first_not_of("0123456789:") != std::string::npos) { log->error(102, buf); return -1; }
            ResetDmin = aux::str_to_uint(aux::awk(value, ":", 1))*60 + aux::str_to_uint(aux::awk(value, ":", 2));
            if (ResetDmin > 1440) { log->error(102, buf); return -1; }
            if (ResetDmin == 1440) ResetDmin = 0;
        }
        else if (param == "reset-wday") {
            ResetWday = aux::str_to_uint(value);
            if (!aux::is_uint(value) || (ResetWday > 7)) { log->error(102, buf); return -1; }
        }
        else if (param == "reset-mday") {
            ResetMday = aux::str_to_uint(value);
            if (!aux::is_uint(value) || (ResetMday > 31)) { log->error(102, buf); return -1; }
        }
        else { log->error (11, buf); return -1; }
    }

    return 0;
}

int TriggerQuota::readQuota (std::string arg, unsigned int &res)
{
    size_t pos = 0;
    std::string sub;

    pos = arg.find_first_not_of ("0123456789");
    if (arg.empty() || (pos == 0)) { return -1; }
    if (pos == std::string::npos) { res = aux::str_to_uint(arg); return 0; };
    
    sub = arg.substr(pos, std::string::npos);

    if ((sub == "MB") || (sub == "mB")) res = aux::str_to_uint(arg);
    else if ((sub == "GB") || (sub == "gB")) res = aux::str_to_uint(arg)*1000;
    else if ((sub == "TB") || (sub == "tB")) res = aux::str_to_uint(arg)*1000000;
    else {
        log->warning(13, arg);
        res = aux::str_to_uint(arg);
    }

    return 0;
}

int TriggerQuota::totalize (unsigned int rate)
{
    unsigned int total_major = 0;

    TotalMinor += (rate >> 3); // bits -> Bytes
    total_major = (TotalMinor >> 20); // take out MBytes
    TotalMinor ^= (total_major << 20); // detach taked out MBytes (TotalMinor % 1048576)
    if (LimitDay) TotalDay += total_major;
    if (LimitWeek) TotalWeek += total_major;
    if (LimitMonth) TotalMonth += total_major;

    return 0;
}

int TriggerQuota::check (unsigned int dmin, unsigned int wday, unsigned int mday, bool mday_last)
{
    if (LimitDay || LimitWeek || LimitMonth) UseTrigger = true;

    if (!UseTrigger) return 0;
    if (!UseNsLow && !UseNsCeil) return 0;

    if (LimitDay) {
        if ((dmin == ResetDmin) && (!IsDayResetted)) { TotalDay = 0; IsDayResetted = true; }
        else if (dmin != ResetDmin) IsDayResetted = false;
    }

    if (LimitWeek) {
        if ((wday == ResetWday) && (!IsWeekResetted)) { TotalWeek = 0; IsWeekResetted = true; }
        else if (wday != ResetWday) IsWeekResetted = false;
    }

    if (LimitMonth) {
        if (((mday == ResetMday) || (mday_last && (mday < ResetMday))) && (!IsMonthResetted)) { TotalMonth = 0; IsMonthResetted = true; }
        else if ((mday != ResetMday) && !(mday_last && (mday < ResetMday))) IsMonthResetted = false;
    }

    if ((LimitDay && (TotalDay > LimitDay)) || 
            (LimitWeek && (TotalWeek > LimitWeek)) || 
            (LimitMonth && (TotalMonth > LimitMonth))) {
        if (!Active) {
            Active = true;
            return 1;
        }
    }
    else {
        if (Active) {
            Active = false;
            return 2;
        }
    }

    return 0;
}

std::string TriggerQuota::dumpCounters ()
{
    if (TotalDay || TotalWeek || TotalMonth) {
        return (aux::int_to_str(TotalDay) + " " + aux::int_to_str(TotalWeek) + " " + aux::int_to_str(TotalMonth));
    }

    return "";
}

void TriggerQuota::setCounters (unsigned int counter_day, unsigned int counter_week, unsigned int counter_month)
{
    TotalDay = counter_day;
    TotalWeek = counter_week;
    TotalMonth = counter_month;

    return;
}

