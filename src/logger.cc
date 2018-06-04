/*
 *      NiceShaper - Dynamic Traffic Management
 *
 *      Copyright (C) 2004-2016 Mariusz Jedwabny <mariusz@jedwabny.net>
 *
 *      This file is subject to the terms and conditions of the GNU General Public
 *      License.  See the file COPYING in the main directory of this archive for
 *      more details.
 */

#include "logger.h"

#include <syslog.h> 
#include <fcntl.h>
#include <unistd.h>

#include <string> 
#include <iostream> 

#include "main.h"
#include "aux.h"
#include "config.h"

Logger::Logger ()
{
    Lang = EN;
    ErrorLogged = false;
    LogOnTerminal = true;
    LogToSyslog = true;
    LogToFile = false;
    DoNotPutNewLineChar = false;
    MissingNewLineChar = false;
    LogFile = "";
    //
    ReqRecoverQos = false;
    ReqRecoverIpt = false;
    ReqRecoverMissU32Perf = false;
}

Logger::~Logger ()
{
    // Nothing
}

std::string Logger::getErrorMessage(int mesid)
{
    std::string message = "";

    if      (( mesid == 11 ) && ( Lang == PL_UTF8 )) message = "Nieznana dyrektywa, parametr lub wartość";
    else if (( mesid == 11 ) && ( Lang == EN )) message = "Unknown directive, parameter or value";
    else if (( mesid == 12 ) && ( Lang == PL_UTF8 )) message = "Wykryto uszkodzenie w łańcuchu iptables";
    else if (( mesid == 12 ) && ( Lang == EN )) message = "Damage in iptables chain detected";
    else if (( mesid == 13 ) && ( Lang == PL_UTF8 )) message = "Błędna wartość parametru reload. Parametr musi się mieścić w zakresie 0.1s do 60s";
    else if (( mesid == 13 ) && ( Lang == EN )) message = "Wrong reload value. Must be in the range of 0.1s to 60s";
    else if (( mesid == 14 ) && ( Lang == PL_UTF8 )) message = "Błędna wartość parametru mode, poprawne to download i upload";
    else if (( mesid == 14 ) && ( Lang == EN )) message = "Wrong mode, use download or upload";
    else if (( mesid == 15 ) && ( Lang == PL_UTF8 )) message = "Brak sekcji do uruchomienia";
    else if (( mesid == 15 ) && ( Lang == EN )) message = "Nothing to run";
    else if (( mesid == 16 ) && ( Lang == PL_UTF8 )) message = "Nieznany interfejs sieciowy";
    else if (( mesid == 16 ) && ( Lang == EN )) message = "Unknown network interface";
    else if (( mesid == 17 ) && ( Lang == PL_UTF8 )) message = "Nie obsługiwany scheduler";
    else if (( mesid == 17 ) && ( Lang == EN )) message = "Unrecognized scheduler";
    else if (( mesid == 18 ) && ( Lang == PL_UTF8 )) message = "Błędna podsieć";
    else if (( mesid == 18 ) && ( Lang == EN )) message = "Wrong subnet";
    else if (( mesid == 19 ) && ( Lang == PL_UTF8 )) message = "Section speed jest wymagane";
    else if (( mesid == 19 ) && ( Lang == EN )) message = "Section speed is required";    
    else if (( mesid == 20 ) && ( Lang == PL_UTF8 )) message = "Section shape jest wymagane";
    else if (( mesid == 20 ) && ( Lang == EN )) message = "Section shape is required";
    else if (( mesid == 21 ) && ( Lang == PL_UTF8 )) message = "Mode jest wymagane";
    else if (( mesid == 21 ) && ( Lang == EN )) message = "Mode is required";
    else if (( mesid == 22 ) && ( Lang == PL_UTF8 )) message = "Przynajmniej jeden filtr w klasie jest wymagany";
    else if (( mesid == 22 ) && ( Lang == EN )) message = "At least one filter in a class is required";
    else if (( mesid == 23 ) && ( Lang == PL_UTF8 )) message = "Przynajmniej jedna klasa jest wymagana";
    else if (( mesid == 23 ) && ( Lang == EN )) message = "At least one class is required";
    else if (( mesid == 24 ) && ( Lang == PL_UTF8 )) message = "Błąd składni";
    else if (( mesid == 24 ) && ( Lang == EN )) message = "Syntax error";
    else if (( mesid == 25 ) && ( Lang == PL_UTF8 )) message = "Zbyt długa linia konfiguracji";
    else if (( mesid == 25 ) && ( Lang == EN )) message = "Configuration line is too long";
    else if (( mesid == 26 ) && ( Lang == PL_UTF8 )) message = "Nie można czytać z pliku";
    else if (( mesid == 26 ) && ( Lang == EN )) message = "Can't read from file";
    else if (( mesid == 27 ) && ( Lang == PL_UTF8 )) message = "Nie można pisać do pliku";
    else if (( mesid == 27 ) && ( Lang == EN )) message = "Can't write to the file";
    else if (( mesid == 28 ) && ( Lang == PL_UTF8 )) message = "Błędne użycie parametru linii poleceń";
    else if (( mesid == 28 ) && ( Lang == EN )) message = "Command line syntax error";
    else if (( mesid == 29 ) && ( Lang == PL_UTF8 )) message = "Błędny adres IP";
    else if (( mesid == 29 ) && ( Lang == EN )) message = "Incorrect IP address";
    else if (( mesid == 30 ) && ( Lang == PL_UTF8 )) message = "Nie można było uruchomić sekcji";
    else if (( mesid == 30 ) && ( Lang == EN )) message = "Can't start section";
    else if (( mesid == 31 ) && ( Lang == PL_UTF8 )) message = "Błędna jednostka transferu";
    else if (( mesid == 31 ) && ( Lang == EN )) message = "Wrong traffic unit";
    else if (( mesid == 33 ) && ( Lang == PL_UTF8 )) message = "Podany interfejs sieciowy nie należy do sekcji";
    else if (( mesid == 33 ) && ( Lang == EN )) message = "Given network interface doesn't belong to the section";
    else if (( mesid == 37 ) && ( Lang == PL_UTF8 )) message = "Filtr u32 wymaga maski sieciowej ciągłej bitowo";
    else if (( mesid == 37 ) && ( Lang == EN )) message = "Use solid netmask with u32 filter";
    else if (( mesid == 38 ) && ( Lang == PL_UTF8 )) message = "Nie odnaleziono otwarcia sekcji";
    else if (( mesid == 38 ) && ( Lang == EN )) message = "Can't find section opening tag";
    else if (( mesid == 39 ) && ( Lang == PL_UTF8 )) message = "Nie odnaleziono konfiguracji sekcji";
    else if (( mesid == 39 ) && ( Lang == EN )) message = "Can't find section configuration";
    else if (( mesid == 40 ) && ( Lang == PL_UTF8 )) message = "Section shape nie może być większe od section speed";
    else if (( mesid == 40 ) && ( Lang == EN )) message = "Section shape must not be bigger than section speed";
    else if (( mesid == 44 ) && ( Lang == PL_UTF8 )) message = "NiceShaper jest już uruchomiony";
    else if (( mesid == 44 ) && ( Lang == EN )) message = "NiceShaper alredy running";
    else if (( mesid == 45 ) && ( Lang == PL_UTF8 )) message = "NiceShaper nie jest uruchomiony";
    else if (( mesid == 45 ) && ( Lang == EN )) message = "NiceShaper is not running";
    else if (( mesid == 46 ) && ( Lang == PL_UTF8 )) message = "Odczytanie pliku konfiguracyjnego nie powiodło sie";
    else if (( mesid == 46 ) && ( Lang == EN )) message = "Can't read configuration file";
    else if (( mesid == 47 ) && ( Lang == PL_UTF8 )) message = "Odczytanie pliku klas nie powiodło się";
    else if (( mesid == 47 ) && ( Lang == EN )) message = "Can't read classes file";
    else if (( mesid == 48 ) && ( Lang == PL_UTF8 )) message = "Nie można utworzyć pliku";
    else if (( mesid == 48 ) && ( Lang == EN )) message = "Can't create file";
    else if (( mesid == 49 ) && ( Lang == PL_UTF8 )) message = "Nawiązanie połączenia nie powiodło się";
    else if (( mesid == 49 ) && ( Lang == EN )) message = "Connection failed";
    else if (( mesid == 50 ) && ( Lang == PL_UTF8 )) message = "Błędny port TCP/UDP";
    else if (( mesid == 50 ) && ( Lang == EN )) message = "Wrong TCP/UDP port";
    else if (( mesid == 51 ) && ( Lang == PL_UTF8 )) message = "Nie udało się użyć adresu lokalnego";
    else if (( mesid == 51 ) && ( Lang == EN )) message = "Can't assign to the local address";
    else if (( mesid == 52 ) && ( Lang == PL_UTF8 )) message = "Błąd komunikacji z kernelem poprzez netlink";
    else if (( mesid == 52 ) && ( Lang == EN )) message = "Communication with kernel via netlink error";
    else if (( mesid == 53 ) && ( Lang == PL_UTF8 )) message = "Błąd wewnętrzny";
    else if (( mesid == 53 ) && ( Lang == EN )) message = "Internal error";
    else if (( mesid == 54 ) && ( Lang == PL_UTF8 )) message = "Zbyt dluga nazwa sekcji. Maksymalnie " + aux::int_to_str(MAX_SECTION_NAME_SIZE) +" znaków";
    else if (( mesid == 54 ) && ( Lang == EN )) message = "Section name too long. Maximum " + aux::int_to_str(MAX_SECTION_NAME_SIZE) +" chars";
    else if (( mesid == 55 ) && ( Lang == PL_UTF8 )) message = "Zbyt dluga nazwa klasy. Maksymalnie " + aux::int_to_str(MAX_CLASS_NAME_SIZE) +" znaków";
    else if (( mesid == 55 ) && ( Lang == EN )) message = "Class name too long. Maximum " + aux::int_to_str(MAX_CLASS_NAME_SIZE) +" chars";
    else if (( mesid == 56 ) && ( Lang == PL_UTF8 )) message = "Brak parametru, klasy nie zostaną utworzone";
    else if (( mesid == 56 ) && ( Lang == EN )) message = "Missing parameter, omit attempt to generate classess";
    else if (( mesid == 57 ) && ( Lang == PL_UTF8 )) message = "Niepoprawne hasło lub brak hasła";
    else if (( mesid == 57 ) && ( Lang == EN )) message = "Bad or missing password";
    else if (( mesid == 58 ) && ( Lang == PL_UTF8 )) message = "Parametr uruchomieniowy --remote wymaga parametru --password";
    else if (( mesid == 58 ) && ( Lang == EN )) message = "Runtime parameter --remote requires --password";
    else if (( mesid == 59 ) && ( Lang == PL_UTF8 )) message = "Błędna podsieć";
    else if (( mesid == 59 ) && ( Lang == EN )) message = "Wrong subnet";
    // Filters
    else if ((mesid == 60) && (Lang == PL_UTF8)) message = "Niepoprawny filtr";
    else if ((mesid == 60) && (Lang == EN)) message = "Bad filter";
    else if ((mesid == 61) && (Lang == PL_UTF8)) message = "Niepoprawny filtr. Błędny stan";
    else if ((mesid == 61) && (Lang == EN)) message = "Bad filter. Invalid state";
    else if ((mesid == 62) && (Lang == PL_UTF8)) message = "Niepoprawny filtr. Test proto jest wymagany dla portów";
    else if ((mesid == 62) && (Lang == EN)) message = "Bad filter. Proto test is required to use ports";
    else if ((mesid == 64) && (Lang == PL_UTF8)) message = "Niepoprawny filtr. Test to-local wyklucza dstip";
    else if ((mesid == 64) && (Lang == EN)) message = "Bad filter. The to-local test squeezes out the dstip";
    else if ((mesid == 65) && (Lang == PL_UTF8)) message = "Niepoprawny filtr. Test from-local wyklucza srcip";
    else if ((mesid == 65) && (Lang == EN)) message = "Bad filter. The from-local test squeezes out the srcip";
    else if ((mesid == 66) && (Lang == PL_UTF8)) message = "Niepoprawny filtr. Zainicjowanie struktury U32 nie powiodło się";
    else if ((mesid == 66) && (Lang == EN)) message = "Bad filter. Prepare U32 failed";
    else if ((mesid == 67) && (Lang == PL_UTF8)) message = "Niepoprawny filtr. Błędny protokół";
    else if ((mesid == 67) && (Lang == EN)) message = "Bad filter. Bad protocol";
    else if ((mesid == 68) && (Lang == PL_UTF8)) message = "Niepoprawny filtr. Testy to-local oraz from-local nie mogą występować jednocześnie";
    else if ((mesid == 68) && (Lang == EN)) message = "Bad filter. Don't use to-local with from-local in the same filter";
    else if ((mesid == 69) && (Lang == PL_UTF8)) message = "Nie można wybrać poprawnego testu srcip/dstip, ze względu na brak informacji o trybie filtra (mode download/upload sekcji)";
    else if ((mesid == 69) && (Lang == EN)) message = "Cant't choose proper srcip/dstip because of unknown flow direction";
    else if ((mesid == 70) && (Lang == PL_UTF8)) message = "Niepoprawny filtr. Test to-local wymaga in-iface";
    else if ((mesid == 70) && (Lang == EN)) message = "Bad filter. The to-local test requires the in-iface";
    else if ((mesid == 71) && (Lang == PL_UTF8)) message = "Niepoprawny filtr. Test from-local wymaga out-iface";
    else if ((mesid == 71) && (Lang == EN)) message = "Bad filter. The from-local test requires the out-iface";
    else if ((mesid == 72) && (Lang == PL_UTF8)) message = "Niepoprawny filtr. Użycie testu in-iface w łańcuchu POSTROUTING jest niepoprawne";
    else if ((mesid == 72) && (Lang == EN)) message = "Bad filter. Using in-iface test in POSTROUTING chain is incorrect";
    else if ((mesid == 73) && (Lang == PL_UTF8)) message = "Niepoprawny filtr. Użycie testu out-iface w łańcuchu PREROUTING jest niepoprawne";
    else if ((mesid == 73) && (Lang == EN)) message = "Bad filter. Using out-iface test in PREROUTING chain is incorrect";
    else if ((mesid == 74) && (Lang == PL_UTF8)) message = "Niepoprawny filtr. Użycie interfejsu IMQ klasy wymaga wskazania interfejsu fizycznego w teście out-iface (lub in-iface dla iptables hook PREROUTING)";
    else if ((mesid == 74) && (Lang == EN)) message = "Bad filter. It's required to set physical interface in out-iface test (or in in-iface if iptables hook is PREROUTING) while using IMQ virtual interface";
    else if ((mesid == 75) && (Lang == PL_UTF8)) message = "Niepoprawny filtr. Interfejs sieciowy filtra nie może się różnić od interfejsu klasy";
    else if ((mesid == 75) && (Lang == EN)) message = "Bad filter. Filter interface must be identical as a class's network interface";
    else if ((mesid == 76) && (Lang == PL_UTF8)) message = "Niepoprawny filtr. Interfejs sieciowy testu in-iface nie może być taki sam jak interfejs klasy";
    else if ((mesid == 76) && (Lang == EN)) message = "Bad filter. The in-iface test interface must not be identical to the class interface";
    // General configuration messages
    else if ((mesid == 101) && ( Lang == PL_UTF8 )) message = "Nieznany parametr lub wartość";
    else if ((mesid == 101) && ( Lang == EN )) message = "Unknown parameter or value";
    else if ((mesid == 102) && ( Lang == PL_UTF8 )) message = "Niepoprawna wartość parametru";
    else if ((mesid == 102) && ( Lang == EN )) message = "Bad value";
    else if ((mesid == 103) && ( Lang == PL_UTF8 )) message = "Klasy typu do-not-shape oraz wrapper wymagają parametru iface-<dev> speed";
    else if ((mesid == 103) && ( Lang == EN )) message = "Classes do-not-shape and wrapper types require iface-<dev> speed";
    else if ((mesid == 104) && ( Lang == PL_UTF8 )) message = "Nazwa dyrektywy user musi zostać zamieniona na host";
    else if ((mesid == 104) && ( Lang == EN )) message = "The name of the user directive needs to be changed to host";
    // Deprecated options
    else if ((mesid == 150) && ( Lang == PL_UTF8 )) message = "Podana opcja jest przestarzała, użyj iptables imq-autoredirect [yes|no]";
    else if ((mesid == 150) && ( Lang == EN )) message = "Given option is deprecated, use iptables imq-autoredirect [true|false]";
    else if ((mesid == 151) && ( Lang == PL_UTF8 )) message = "Podana opcja została przeniesiona do sekcji global";
    else if ((mesid == 151) && ( Lang == EN )) message = "Given option is moved to global section";
    else if ((mesid == 152) && ( Lang == PL_UTF8 )) message = "Podana opcja jest przestarzała, użyj odpowiedniego nagłówka klasy";
    else if ((mesid == 152) && ( Lang == EN )) message = "Given option is deprecated, use proper class header";
    else if ((mesid == 153) && ( Lang == PL_UTF8 )) message = "Opcje status listen oraz stats listen zostały wycofane, użyj listen address";
    else if ((mesid == 153) && ( Lang == EN )) message = "Options status listen and stats listen are removed, use listen address instead";
    else if ((mesid == 154) && ( Lang == PL_UTF8 )) message = "Opcje status password oraz stats password zostały wycofane, użyj listen password";
    else if ((mesid == 154) && ( Lang == EN )) message = "Options status password and stats password are removed, use listen password instead";
    else if ((mesid == 155) && ( Lang == PL_UTF8 )) message = "Opcje stats {owner|group|mode|rewrite} zostały wycofane, użyj status {file-owner|file-group|file-mode|file-rewrite}";
    else if ((mesid == 155) && ( Lang == EN )) message = "Options stats {owner|group|mode|rewrite} are removed, use status {file-owner|file-group|file-mode|file-rewrite} instead";
    else if ((mesid == 158) && (Lang == PL_UTF8)) message = "Parametr usunięty w wersji 1.2rc1";
    else if ((mesid == 158) && (Lang == EN)) message = "Parameter is removed from version 1.2rc1";
    // Filesystem operations
    else if ((mesid == 201) && ( Lang == PL_UTF8 )) message = "Nie można otworzyć pliku";
    else if ((mesid == 201) && ( Lang == EN )) message = "Can't open file";
    // Inter processess and network communication
    else if ((mesid == 301) && ( Lang == PL_UTF8 )) message = "Przyjęcie połączenia sieciowego zakończone niepowodzeniem";
    else if ((mesid == 301) && ( Lang == EN )) message = "Accepting connection on a socket failed";
    else if ((mesid == 310) && ( Lang == PL_UTF8 )) message = "Błąd komunikacji. Nie odebrano żadnych danych";
    else if ((mesid == 310) && ( Lang == EN )) message = "Communication error. No data received";
    else if ((mesid == 311) && ( Lang == PL_UTF8 )) message = "Błąd komunikacji. Odebrano nieoczekiwany komunikat";
    else if ((mesid == 311) && ( Lang == EN )) message = "Communication error. Unexpected message";
    else if ((mesid == 312) && ( Lang == PL_UTF8 )) message = "Błąd komunikacji. Przesłanie danych zakończone niepowodzeniem";
    else if ((mesid == 312) && ( Lang == EN )) message = "Communication error. Data sending failed";
    else if ((mesid == 313) && ( Lang == PL_UTF8 )) message = "Błąd komunikacji. Wiadomość zbyt długa";
    else if ((mesid == 313) && ( Lang == EN )) message = "Communication error. Message too long";
    else if ((mesid == 314) && ( Lang == PL_UTF8 )) message = "Błąd komunikacji. Niepoprawne dane do wysłania";
    else if ((mesid == 314) && ( Lang == EN )) message = "Communication error. Unexpected datas to send";
    // Process and threads management
    else if ((mesid == 401) && ( Lang == PL_UTF8 )) message = "Utworzenie procesu potomnego zakończone niepowodzeniem. Problem systemowy";
    else if ((mesid == 401) && ( Lang == EN )) message = "Error occurred on fork process. System problem";
    else if ((mesid == 402) && ( Lang == PL_UTF8 )) message = "Utworzenie wątku obsługi kontrolera zakończone niepowodzeniem. Poważny problem systemu operacyjnego";
    else if ((mesid == 402) && ( Lang == EN )) message = "Could not create controller handler thread. Serious system problem";
    else if ((mesid == 403) && ( Lang == PL_UTF8 )) message = "Utworzenie mutexa dla socketu supervisora zakończone niepowodzeniem. Poważny problem systemu operacyjnego";
    else if ((mesid == 403) && ( Lang == EN )) message = "Supervisor Socket Mutex init failed. Serious system problem";
    else if ((mesid == 404) && ( Lang == PL_UTF8 )) message = "Tylko użytkownik root może używać NiceShapera (z wyjątkiem komendy status --remote)";
    else if ((mesid == 404) && ( Lang == EN )) message = "Only root user may use NiceShaper (except for status --remote command)";
    else if ((mesid == 405) && ( Lang == PL_UTF8 )) message = "Utworzenie wątku obsługi zapisu statusu zakończone niepowodzeniem. Poważny problem systemu operacyjnego";
    else if ((mesid == 405) && ( Lang == EN )) message = "Could not create the status writer thread. Serious system problem";
    else if ((mesid == 406) && ( Lang == PL_UTF8 )) message = "Utworzenie mutexa dla sterowania wątkami zakończone niepowodzeniem. Poważny problem systemu operacyjnego";
    else if ((mesid == 406) && ( Lang == EN )) message = "Threads Control Mutex init failed. Serious system problem";
    // QOS
    else if ((mesid == 501) && ( Lang == PL_UTF8 )) message = "Wykryto szkodzenie w strukturze HTB";
    else if ((mesid == 501) && ( Lang == EN )) message = "Damage in HTB framework detected";
    else if ((mesid == 502) && ( Lang == PL_UTF8 )) message = "Napotkano brak opcji performance counters filtrów U32 (CONFIG_CLS_U32_PERF) w uruchomionym kernelu. Zamiennie użyte zostaną filtry iptables, jednak, rekonfiguracja kernela jest zalecanym rozwiązaniem";
    else if ((mesid == 502) && ( Lang == EN )) message = "Performance counters support for U32 filters (CONFIG_CLS_U32_PERF) is probably missing. Iptables rules will be used instead, however, kernel reconfiguration is recommended";
    else if ((mesid == 503) && ( Lang == PL_UTF8 )) message = "Najprawdopodobniej napotkano błąd kernela 3.14 (i kilku następnych), uniemożliwiający odczytanie ostatniego filtra U32 w kompilacji x86. Nastąpi próba obejścia problemu";
    else if ((mesid == 503) && ( Lang == EN )) message = "Probably Kernel 3.14 (and several newer) bug, which makes impossible to read last U32 filter on the interface under x86. Try to workaround";
    // Iptables 
    else if ((mesid == 701) && (Lang == PL_UTF8)) message = "Niepoprawna wartość iptables hook. Poprawne to PREROUTING i POSTROUTING";
    else if ((mesid == 701) && (Lang == EN)) message = "Bad iptables hook value. Must be PREROUTING or POSTROUTING";
    else if ((mesid == 702) && (Lang == PL_UTF8)) message = "Niepoprawny iptables hook-mode. Poprawne to append oraz insert";
    else if ((mesid == 702) && (Lang == EN)) message = "Bad iptables hook-mode. Must be append or insert";
    else if ((mesid == 703) && (Lang == PL_UTF8)) message = "Brak komendy iptables";
    else if ((mesid == 703) && (Lang == EN)) message = "Missing iptables command";
    else if ((mesid == 704) && (Lang == PL_UTF8)) message = "Brak komendy tc";
    else if ((mesid == 704) && (Lang == EN)) message = "Missing tc command";
    else if ((mesid == 705) && (Lang == PL_UTF8)) message = "Wykonanie iptables-restore zakończone niepowodzeniem. Należy spróbować z fallback iptables. W celach diagnostycznych pozostawiono wygenerowany plik batch";
    else if ((mesid == 705) && (Lang == EN)) message = "iptables-restore error occurred. Try run again with fallback iptables directive. To diagnose batch file was not removed";
    else if ((mesid == 706) && (Lang == PL_UTF8)) message = "Niepoprawna wartość iptables target. Poprawne to ACCEPT i RETURN";
    else if ((mesid == 706) && (Lang == EN)) message = "Bad iptables target value. Must be ACCEPT or RETURN";
    else if ((mesid == 799) && (Lang == PL_UTF8)) message = "Wygenerowanie filtrów iptables zakończone niepowodzeniem";
    else if ((mesid == 799) && (Lang == EN)) message = "Generating iptables rules failed";
    // Bad values and configuration syntax error
    else if ((mesid == 801) && (Lang == PL_UTF8)) message = "Niepoprawna wartość alter time-period";
    else if ((mesid == 801) && (Lang == EN)) message = "Bad alter time-period value";
    else if ((mesid == 802) && (Lang == PL_UTF8)) message = "Burst sekcji musi być większe lub równe największemu burst klas podległych";
    else if ((mesid == 802) && (Lang == EN)) message = "Section burst must be equal or bigger than it's classes biggest burst value";
    else if ((mesid == 803) && (Lang == PL_UTF8)) message = "Suma wartości parametrów section speed, jest większa lub równa zadeklarowanej szybkości interfejsu";
    else if ((mesid == 803) && (Lang == EN)) message = "Sections speeds sum greater or equal than declared iface speed";
    else if ((mesid == 804) && (Lang == PL_UTF8)) message = "Suma wartości parametrów section speed oraz fallback-rate, jest większa lub równa zadeklarowanej szybkości interfejsu";
    else if ((mesid == 804) && (Lang == EN)) message = "Sections speeds sum and fallback-rate greater or equal than declared iface speed";
    else if ((mesid == 805) && (Lang == PL_UTF8)) message = "Błędna wartość parametru status rewrite. Parametr musi byc z zakresu 1s do 3600s";
    else if ((mesid == 805) && (Lang == EN)) message = "Wrong status rewrite value. Must be in range of 1s to 3600s";
    else if ((mesid == 806) && (Lang == PL_UTF8)) message = "Wartość nie może być wyższa od " + aux::int_to_str(aux::unit_convert(MAX_RATE, MBITS)) + aux::unit_to_str(MBITS, 0) + " ani niższa od " + aux::int_to_str(aux::unit_convert(MIN_RATE, BITS)) + aux::unit_to_str(BITS, 0);
    else if ((mesid == 806) && (Lang == EN)) message = "Value cannot be greater than " + aux::int_to_str(aux::unit_convert(MAX_RATE, MBITS)) + aux::unit_to_str(MBITS, 0) + " or less than " + aux::int_to_str(aux::unit_convert(MIN_RATE, BITS)) + aux::unit_to_str(BITS, 0);
    else if ((mesid == 807) && (Lang == PL_UTF8)) message = "Strict musi się mieścić w przedziale 0 do 100";
    else if ((mesid == 807) && (Lang == EN)) message = "Strict has to be a value in the range of 0 to 100";
    else if ((mesid == 808) && (Lang == PL_UTF8)) message = "Brak zdefiniowanych podsieci - brak dyrektywy local-subnets";
    else if ((mesid == 808) && (Lang == EN)) message = "Missing local subnets, local-subnets directive is required";
    else if ((mesid == 809) && (Lang == PL_UTF8)) message = "Przekroczono dopuszczalną liczbę uruchomionych sekcji";
    else if ((mesid == 809) && (Lang == EN)) message = "Allowed sections number in run directive exceeded";
    else if ((mesid == 810) && (Lang == PL_UTF8)) message = "Niepoprawne żądanie";
    else if ((mesid == 810) && (Lang == EN)) message = "Bad request";
    else if ((mesid == 811) && (Lang == PL_UTF8)) message = "Parametr set-mark wymaga markowania pakietów na interfejsie klasy - użyj mark-on-ifaces";
    else if ((mesid == 811) && (Lang == EN)) message = "Parameter set-mark requires packet marking on class iface, use mark-on-ifaces";
    else if ((mesid == 812) && (Lang == PL_UTF8)) message = "Podany filtr wymaga markowania pakietów na interfejsie klasy - użyj mark-on-ifaces";
    else if ((mesid == 812) && (Lang == EN)) message = "Given filter requires packet marking on class interface - use mark-on-ifaces";
    else if ((mesid == 813) && (Lang == PL_UTF8)) message = "Przekroczono dopuszczalną liczbę uruchomionych klas";
    else if ((mesid == 813) && (Lang == EN)) message = "Allowed classes number exceeded";
    else if ((mesid == 814) && (Lang == PL_UTF8)) message = "Klasa typu wrapper wymaga parametru rate";
    else if ((mesid == 814) && (Lang == EN)) message = "Wrapper class requires the rate parameter";
    else if ((mesid == 815) && (Lang == PL_UTF8)) message = "Host w uproszczonej postaci wymaga skonfigurowanej dyrektywy auto-hosts";
    else if ((mesid == 815) && (Lang == EN)) message = "Simplified host requires the auto-hosts directive to be configured";
    else if ((mesid == 850) && (Lang == PL_UTF8)) message = "Błąd składni";
    else if ((mesid == 850) && (Lang == EN)) message = "Syntax error";
    else if ((mesid == 851) && (Lang == PL_UTF8)) message = "Makra dozwolone są wyłącznie w plikach klas";
    else if ((mesid == 851) && (Lang == EN)) message = "Macros are valid inside the classes files only";
    else if ((mesid == 852) && (Lang == PL_UTF8)) message = "Include jest zabronione wewnątrz makra";
    else if ((mesid == 852) && (Lang == EN)) message = "Include inside a macro is illegal";
    else if ((mesid == 853) && (Lang == PL_UTF8)) message = "Zagnieżdzanie makr jest zabronione";
    else if ((mesid == 853) && (Lang == EN)) message = "Macro inside another macro is illegal";
    else if ((mesid == 854) && (Lang == PL_UTF8)) message = "Przetworzenie makra zakończone niepowodzeniem";
    else if ((mesid == 854) && (Lang == EN)) message = "Macro proceeding failed";
    else if ((mesid == 855) && (Lang == PL_UTF8)) message = "Niepoprawne wartości parametrów makra";
    else if ((mesid == 855) && (Lang == EN)) message = "Bad macro's parameters";
    else if ((mesid == 856) && (Lang == PL_UTF8)) message = "Niepoprawny typ makra";
    else if ((mesid == 856) && (Lang == EN)) message = "Bad macro type";
    else if ((mesid == 857) && (Lang == PL_UTF8)) message = "Niepoprawna liczba parametrów makra";
    else if ((mesid == 857) && (Lang == EN)) message = "Bad number of macro's parameters";
    else if ((mesid == 858) && (Lang == PL_UTF8)) message = "Niedozwolony lub zdublowany parametr _classid_, _filterid_ lub _set-mark_";
    else if ((mesid == 858) && (Lang == EN)) message = "Illegal or duplicated parameter _classid_ or _filterid_ or _set-mark_";
    else if ((mesid == 859) && (Lang == PL_UTF8)) message = "Zdublowany parametr mark lub set-mark";
    else if ((mesid == 859) && (Lang == EN)) message = "The mark or set-mark parameter duplicated";    
    else if ((mesid == 860) && (Lang == PL_UTF8)) message = "Parametr set-mark filtra jest niedozwolony (wycofany)";
    else if ((mesid == 860) && (Lang == EN)) message = "Parameter set-mark in filter is illegal (deprecated)";    
    else if ((mesid == 861) && (Lang == PL_UTF8)) message = "Parametr match sekcji jest niedozwolony (wycofany) i zastąpiony przez local-subnets sekcji global";
    else if ((mesid == 861) && (Lang == EN)) message = "Parameter match in functional section is illegal (deprecated) and superseded by local-subnets within global section";
    else if ((mesid == 862) && (Lang == PL_UTF8)) message = "Wartość parametru set-mark nie może się powtarzać";
    else if ((mesid == 862) && (Lang == EN)) message = "Value of set-mark parameter must not be repeated";    
    else if ((mesid == 863) && (Lang == PL_UTF8)) message = "Nazwy klas muszą być unikalne w ramach sekcji. Wykryto duplikat";
    else if ((mesid == 863) && (Lang == EN)) message = "Classes names within the section must be unique. Duplicate detected";
    else if ((mesid == 864) && (Lang == PL_UTF8)) message = "Klasa typu virtual nie współpracuje z interfejsami IMQ";
    else if ((mesid == 864) && (Lang == EN)) message = "Virtual class doesn't work with IMQ interfaces";
    else if ((mesid == 865) && (Lang == PL_UTF8)) message = "Test to-local wymaga interfejsu IMQ, gdyż ingress shaping nie jest obsługiwany";
    else if ((mesid == 865) && (Lang == EN)) message = "To-local test requires IMQ interface, because ingress shaping is not supported";
    else if ((mesid == 866) && (Lang == PL_UTF8)) message = "Interfejs sieciowy nie może być współdzielony przez klasy pracujące w trybie download z klasami w trybie upload";
    else if ((mesid == 866) && (Lang == EN)) message = "Network interface can't share both download mode and upload mode classes";
    else if ((mesid == 867) && (Lang == PL_UTF8)) message = "Klasy typów wrapper oraz do-not-shape, jeśli występują samodzielnie na interfejsie (to znaczy, bez towarzystwa klas standardowych), wymagają wskazania kierunku przepływu kontrolowanego na tym interfejsie ruchu. Użyj parametru iface-<dev> mode download|upload";
    else if ((mesid == 867) && (Lang == EN)) message = "The wrapper and do-not-shape classes, if work alone on the interface (it means, not together with standard classes), require to set the flow direction of traffic controlled on this interface. Use iface-<dev> mode download|upload parameter";
    // Internal errors
    else if ((mesid == 998) && (Lang == PL_UTF8)) message = "Błąd wewnętrzny. Nie można było ustalić trybu klasy";
    else if ((mesid == 998) && (Lang == EN)) message = "Internal error. Can't determine class mode";
    else if ((mesid == 999) && (Lang == PL_UTF8)) message = "Błąd wewnętrzny, zgłoś autorowi NiceShapera";
    else if ((mesid == 999) && (Lang == EN)) message = "Internal error, please send a bug report to author";
    // Unknown error
    else if ( Lang == PL_UTF8 ) message = "Nieznany błąd";
    else message = "Unknown error";
    
    return message;
}

std::string Logger::getWarningMessage (int mesid) 
{
    std::string message = "";

    if (( mesid == 1 ) && ( Lang == PL_UTF8 )) message = "Podana opcja jest przestarzała";
    else if (( mesid == 1 ) && ( Lang == EN )) message = "Given option is deprecated";
//    else if (( mesid == 2 ) && ( Lang == PL_UTF8 )) message = "Uzyto niestandardowego łańcucha iptables";
//    else if (( mesid == 2 ) && ( Lang == EN )) message = "Probably wrong iptables hook";
    else if (( mesid == 3 ) && ( Lang == PL_UTF8 )) message = "Brak parametru download-section, użyto wartości domyślnej";
    else if (( mesid == 3 ) && ( Lang == EN )) message = "Missing download-section parameter, using default value";
    else if (( mesid == 4 ) && ( Lang == PL_UTF8 )) message = "Brak parametru upload-section, użyto wartości domyślnej";
    else if (( mesid == 4 ) && ( Lang == EN )) message = "Missing upload-section parameter, using default value";
    else if (( mesid == 5 ) && ( Lang == PL_UTF8 )) message = "Brak parametru, użyto wartości domyślnej";
    else if (( mesid == 5 ) && ( Lang == EN )) message = "Missing parameter, using default value";
    else if (( mesid == 6 ) && ( Lang == PL_UTF8 )) message = "Brak parametru, klasy nie zostaną utworzone";
    else if (( mesid == 6 ) && ( Lang == EN )) message = "Missing parameter, omit attempt to generate classes";
//    else if (( mesid == 7 ) && ( Lang == PL_UTF8 )) message = "Podana opcja jest przestarzała, użyj iptables hook";
//    else if (( mesid == 7 ) && ( Lang == EN )) message = "Given option is deprecated, use iptables hook instead";
    else if (( mesid == 11 ) && ( Lang == PL_UTF8 )) message = "Aliasy interfejsów nie są rozróżniane";
    else if (( mesid == 11 ) && ( Lang == EN )) message = "Interface alias is useless, only physical part is needed";
    else if (( mesid == 12 ) && ( Lang == PL_UTF8 )) message = "Błędna jednostka przepustowości, zostanie użyte b/s";
    else if (( mesid == 12 ) && ( Lang == EN )) message = "Wrong unit, using b/s instead";
    else if (( mesid == 13 ) && ( Lang == PL_UTF8 )) message = "Błędna jednostka quoty, zostanie użyte MB";
    else if (( mesid == 13 ) && ( Lang == EN )) message = "Wrong quota unit, using MB instead";
    else if (( mesid == 14 ) && (Lang == PL_UTF8)) message = "Liczniki wyzwalacza quota nie będą zapisywane a inicjalizacja reguł iptables, przechodzi w znacznie wolniejszy tryb fallback! Brakujący ważny katalog";
    else if (( mesid == 14 ) && (Lang == EN)) message = "Quota counters will be lost after restart. Iptables initialization switched to fallback mode, thus will be much slower! Missing important directory";
    else if (( mesid == 15 ) && (Lang == PL_UTF8)) message = "Polecenie iptables-restore nie zostanie użyte! Nie można utworzyć pliku";
    else if (( mesid == 15 ) && (Lang == EN)) message = "The iptables-restore command won't be used! Can't create file";
    else if (( mesid == 16 ) && (Lang == PL_UTF8)) message = "Tryb szybkiego startu nie zostanie użyty! Brak wymaganego pliku binarnego iptables-save";
    else if (( mesid == 16 ) && (Lang == EN)) message = "Fallback to slow start method! Missing required iptables-save executable";
    else if (( mesid == 17 ) && (Lang == PL_UTF8)) message = "Tryb szybkiego startu nie zostanie użyty! Brak wymaganego pliku binarnego iptables-restore";
    else if (( mesid == 17 ) && (Lang == EN)) message = "Fallback to slow start method! Missing required iptables-restore executable";
    else if (( mesid == 18 ) && ( Lang == PL_UTF8 )) message = "Dyrektywa oraz komenda stats są przestarzałe i zastąpione przez status";
    else if (( mesid == 18 ) && ( Lang == EN )) message = "The stats directives and command are deprecated, use status instead";
    else if ( Lang == PL_UTF8 ) message = "Nieznane ostrzeżenie";
    else message = "Unknown warning";

    return message;
}

std::string Logger::getInfoMessage (int mesid) 
{
    std::string message = "";

    if (( mesid == 1 ) && ( Lang == PL_UTF8 )) message = "Start";
    else if (( mesid == 1 ) && ( Lang == EN )) message = "Start";
    else if (( mesid == 2 ) && ( Lang == PL_UTF8 )) message = "Stop";
    else if (( mesid == 2 ) && ( Lang == EN )) message = "Stop";
    else if (( mesid == 3 ) && ( Lang == PL_UTF8 )) message = "Uruchamianie sekcji";
    else if (( mesid == 3 ) && ( Lang == EN )) message = "Starting section";
    else if (( mesid == 4 ) && ( Lang == PL_UTF8 )) message = "Zatrzymywanie sekcji";
    else if (( mesid == 4 ) && ( Lang == EN )) message = "Stopping section";
    else if (( mesid == 5 ) && ( Lang == PL_UTF8 )) message = "Uruchamianie NiceShapera";
    else if (( mesid == 5 ) && ( Lang == EN )) message = "Starting NiceShaper";
    else if (( mesid == 6 ) && ( Lang == PL_UTF8 )) message = "Zatrzymywanie NiceShapera";
    else if (( mesid == 6 ) && ( Lang == EN )) message = "Stopping NiceShaper";
    else if (( mesid == 7 ) && ( Lang == PL_UTF8 )) message = "System";
    else if (( mesid == 7 ) && ( Lang == EN )) message = "System";
    else if (( mesid == 8 ) && ( Lang == PL_UTF8 )) message = "Timer";
    else if (( mesid == 8 ) && ( Lang == EN )) message = "Timer";
    else if (( mesid == 9 ) && ( Lang == PL_UTF8 )) message = "Raport obciążenia - czas przeładowania minimalny/średni/maksymalny";
    else if (( mesid == 9 ) && ( Lang == EN )) message = "Workload report - time of reload minimum/average/maximum";
    else if (( mesid == 10 ) && ( Lang == PL_UTF8 )) message = "Tworzenie filtrów iptables";
    else if (( mesid == 10 ) && ( Lang == EN )) message = "Creating iptables rules";
    else if (( mesid == 11 ) && ( Lang == PL_UTF8 )) message = "Oczekiwanie przez " + aux::int_to_str(config->getReqRecoverWait()) + "s, przed uruchomieniem procedury odzyskiwania";
    else if (( mesid == 11 ) && ( Lang == EN )) message = "Waiting for " + aux::int_to_str(config->getReqRecoverWait()) + "s before recovery attempt";
    else if (( mesid == 12 ) && ( Lang == PL_UTF8 )) message = "Uruchomienie procedury odzyskiwania";
    else if (( mesid == 12 ) && ( Lang == EN )) message = "Starting recovery procedure";
    else if (( mesid == 13 ) && ( Lang == PL_UTF8 )) message = "Procedura odzyskiwania zakończona sukcesem";
    else if (( mesid == 13 ) && ( Lang == EN )) message = "Recovery procedure proceeded successfully";
    else if (( mesid == 45 ) && ( Lang == PL_UTF8 )) message = "NiceShaper nie jest uruchomiony";
    else if (( mesid == 45 ) && ( Lang == EN )) message = "NiceShaper is not running";
    // 
    else if (( mesid == 100 ) && ( Lang == PL_UTF8 )) message = "Ze względu na użytą dyrektywę debug iptables, plik inicjujący reguły iptables nie zostanie usunięty";
    else if (( mesid == 100 ) && ( Lang == EN )) message = "Iptables initialization script won't be removed because of debug iptables directive";
    else if ( Lang == PL_UTF8 ) message = "Nieznany komunikat";
    else message = "Unknown information";
    
    return message;
}

void Logger::error (int message_id)
{
    ErrorLogged = true;

    dump ("", getErrorMessage(message_id), "");
}

void Logger::error (int message_id, std::string explanation)
{
    ErrorLogged = true;

    dump ("", getErrorMessage(message_id), explanation);
}

void Logger::error (std::string section_name, int message_id, std::string explanation)
{
    ErrorLogged = true;

    dump (section_name, getErrorMessage(message_id), explanation);
}

void Logger::error (std::string section_name, int message_id)
{
    ErrorLogged = true;

    dump (section_name, getErrorMessage(message_id), "");
}

void Logger::warning (int message_id)
{
    dump("", getWarningMessage(message_id), "");
}

void Logger::warning (int message_id, std::string explanation)
{
    dump("", getWarningMessage(message_id), explanation);
}

void Logger::warning (std::string section_name, int message_id, std::string explanation)
{
    dump(section_name, getWarningMessage(message_id), explanation);
}

void Logger::warning (std::string section_name, int message_id)
{
    dump(section_name, getWarningMessage(message_id), "");
}

void Logger::info (int message_id)
{
    dump ("", getInfoMessage(message_id), "");
}

void Logger::info (int message_id, std::string explanation)
{
    dump ("", getInfoMessage(message_id), explanation);
}

void Logger::info (std::string section_name, int message_id, std::string explanation)
{
    dump (section_name, getInfoMessage(message_id), explanation);
}

void Logger::info (std::string section_name, int message_id)
{
    dump (section_name, getInfoMessage(message_id), "");
}

void Logger::dump (std::string section_name, std::string message, std::string explanation)
{
    std::string result;

    if (section_name.size()) result = "[" + section_name + "] " + message;
    else result = message;

    if (explanation.size()) result += ": " + explanation + ".";
    else result += ".";

    if (LogOnTerminal) onTerminal( result );
    if (LogToSyslog) toSyslog( result );
    if (LogToFile) toLogFile( result );
}

void Logger::setLogFile (std::string log_file) 
{ 
    LogFile = log_file;     
    
    if ( log_file == "" ) LogToFile = false;     
    else LogToFile = true;    
}

void Logger::onTerminal (std::string message)
{
    if (!DoNotPutNewLineChar) {
        if (MissingNewLineChar) 
        {   
            std::cout << std::endl;
            MissingNewLineChar = false;
        }    
        if (message.size()) 
        {
            std::cout << message << std::endl;
        }
    }
    else {
        std::cout << message << std::flush;
        DoNotPutNewLineChar = false;
        MissingNewLineChar = true;
    }   
}

void Logger::toSyslog (std::string message)
{
    setlogmask (LOG_UPTO (LOG_NOTICE));
    openlog ("niceshaper", LOG_PID | LOG_NDELAY, LOG_LOCAL1);
    syslog (LOG_NOTICE, message.c_str(), getuid ());
    closelog();
}

void Logger::toLogFile (std::string message)
{
    int fd;

    fd = open(LogFile.c_str(), O_CREAT | O_WRONLY | O_APPEND, S_IRUSR|S_IWUSR);
    write(fd, message.c_str(), message.size());
    write(fd, "\n", 1 );
    close(fd);
}

void Logger::dumpFooter() 
{
    std::string message = "";

    onTerminal (" ");
    onTerminal ("  NiceShaper version: " + VERSION );
    onTerminal ("  http://niceshaper.jedwabny.net");
    onTerminal (" ");
}

void Logger::dumpHelp()
{
    dumpFooter();

    onTerminal ( "  Usage: niceshaper {start|stop|restart|status|show} [options]              ");
    onTerminal ( "                                                                            ");
    onTerminal ( "  start|restart options:                                                    ");
    onTerminal ( "  --confdir </path>          - overwrite configuration directory location   ");
    onTerminal ( "  --conffile <path>          - overwrite configuration file path            ");
    onTerminal ( "  --classfile <path>         - overwrite classes file path                  ");
    onTerminal ( "  --no-daemon                - don't move the process into the background   ");
    onTerminal ( "                                                                            ");
    onTerminal ( "  status|show - remote niceshaper access options:                           ");
    onTerminal ( "  --remote <ip[:port]>       - connect to remote NiceShaper                 ");
    onTerminal ( "                               (must be configured with status listen)      ");
    onTerminal ( "  --password <password>      - connect to remote NiceShaper using password  ");
    onTerminal ( "                               (must be configured with status password)    ");
    onTerminal ( "  status options:                                                           ");
    onTerminal ( "  --unit <unit>              - overwrite configured status unit             ");
    onTerminal ( "  --watch <1-60>             - monitor status with given in seconds interval");
    onTerminal ( "                                                                            ");
    onTerminal ( "  show options:                                                             ");
    onTerminal ( "  --running {config|classes} - dump running configuration or classes        ");
    onTerminal ( "                                                                            ");
 
}

