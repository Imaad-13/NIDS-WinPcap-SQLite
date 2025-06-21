#include <pcap.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <winsock2.h>
#include <sqlite3.h>
#include <fstream>
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <chrono>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

using namespace std;
using namespace chrono;

// Structure to hold signature data
struct Signature {
    string signature;
    string protocol;
    string src_ip;
    string dest_ip;
    int src_port;
    int dest_port;
    string action;
    string description;
    int severity;
};

// Signature storage and packet counters
vector<Signature> signatures;
string targetIP;

//  Rate limiting and UDP flood detection settings
unordered_map<string, int> packetRateMap;
unordered_map<string, system_clock::time_point> lastSeenMap;
unordered_map<string, int> udpPacketCount;
unordered_map<string, steady_clock::time_point> udpTimeMap;
const int UDP_THRESHOLD = 100;
const int UDP_TIME_WINDOW = 2;

//  SYN flood detection maps
unordered_map<string, int> synPacketCount;
unordered_map<string, steady_clock::time_point> synTimeMap;

//  Ignore SSDP/Multicast on 239.255.255.250:1900
const string SSDP_IP = "239.255.255.250";
const int SSDP_PORT = 1900;

//  SYN Flood Configuration
const int SYN_THRESHOLD = 50;
const int TIME_WINDOW = 1;

//  Cooldown mechanism for rate limiting alerts
unordered_map<string, time_t> alertCooldown;

//  Converts IP to string format
string ipToString(u_long ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    return string(inet_ntoa(addr));
}

// Generates an alert when a signature is matched
void generateAlert(const Signature& sig, const string& srcIP, const string& destIP) {
    cout << "ALERT: " << sig.description
         << " [Severity: " << sig.severity << "]"
         << " - Action: " << sig.action
         << " | Src IP: " << srcIP
         << " -> Dest IP: " << destIP << endl;
}

//  Generates a custom alert for specific types (SYN, UDP, etc.)
void generateAlert(const string& alertMsg, const string& srcIP, const string& destIP, int srcPort, int destPort, int severity) {
    cout << "ALERT: " << alertMsg
         << " [Severity: " << severity << "]"
         << " | Src IP: " << srcIP
         << " -> Dest IP: " << destIP
         << " | Src Port: " << srcPort
         << " -> Dest Port: " << destPort << endl;
}

//  Rate limiting: Checks if an alert can be triggered
bool canTriggerAlert(const string& signature) {
    time_t now = time(nullptr);
    if (alertCooldown.find(signature) == alertCooldown.end() || now - alertCooldown[signature] > 5) {
        alertCooldown[signature] = now;
        return true;
    }
    return false;
}

//  Loads signatures from SQLite database
void loadSignaturesFromDB(const string& dbFileName) {
    sqlite3* db;
    sqlite3_stmt* stmt;

    if (sqlite3_open(dbFileName.c_str(), &db) != SQLITE_OK) {
        cerr << "Error opening database: " << sqlite3_errmsg(db) << endl;
        return;
    }

    string sqlQuery = "SELECT signature, protocol, src_ip, dest_ip, src_port, dest_port, action, description, severity FROM signatures";
    if (sqlite3_prepare_v2(db, sqlQuery.c_str(), -1, &stmt, 0) != SQLITE_OK) {
        cerr << "Error preparing query: " << sqlite3_errmsg(db) << endl;
        sqlite3_close(db);
        return;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Signature sig;
        sig.signature = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        sig.protocol = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        sig.src_ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        sig.dest_ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        sig.src_port = sqlite3_column_int(stmt, 4);
        sig.dest_port = sqlite3_column_int(stmt, 5);
        sig.action = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        sig.description = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        sig.severity = sqlite3_column_int(stmt, 8);

        signatures.push_back(sig);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    cout << "Loaded " << signatures.size() << " signatures from the database.\n";
}

//  Handles packet rate for destination IP
void updatePacketRate(const string& destIP) {
    auto now = system_clock::now();
    if (lastSeenMap.find(destIP) != lastSeenMap.end()) {
        auto duration = duration_cast<seconds>(now - lastSeenMap[destIP]).count();
        if (duration > 1) {
            packetRateMap[destIP] = 0;
        }
    }
    lastSeenMap[destIP] = now;
    packetRateMap[destIP]++;
}

//  Checks if the packet rate exceeds threshold (Flooding)
bool isFlooding(const string& destIP, int threshold) {
    return packetRateMap[destIP] > threshold;
}

//  Checks for signature match with protocol and port filters
void checkForSignature(const string& srcIP, const string& destIP, const string& protocol, int srcPort, int destPort, const u_char* tcpHeader) {
    for (const auto& sig : signatures) {
        if ((sig.protocol == "Any" || sig.protocol == protocol) &&
            (sig.src_ip == "Any" || sig.src_ip == srcIP) &&
            (sig.dest_ip == "Any" || sig.dest_ip == destIP) &&
            (sig.src_port == 0 || sig.src_port == srcPort) &&
            (sig.dest_port == 0 || sig.dest_port == destPort)) {

            // Skip SSDP/Multicast Traffic
            if (destIP == SSDP_IP && destPort == SSDP_PORT) {
                continue;
            }

            //  TCP SYN Flood Detection
            if (protocol == "TCP" && sig.signature == "TCP_SYN_FLOOD") {
                if (tcpHeader && (tcpHeader[13] & 0x02)) {  // Check SYN flag
                    synPacketCount[destIP]++;
                    auto now = steady_clock::now();

                    if (synPacketCount[destIP] > SYN_THRESHOLD) {
                        auto duration = duration_cast<seconds>(now - synTimeMap[destIP]);
                        if (duration.count() <= TIME_WINDOW && canTriggerAlert("SYN_FLOOD")) {
                            generateAlert("Potential SYN Flood detected", srcIP, destIP, srcPort, destPort, 5);
                        }
                        synPacketCount[destIP] = 0;
                        synTimeMap[destIP] = now;
                    }
                }
                continue;
            }

            // Default signature check
            if (canTriggerAlert(sig.signature)) {
                generateAlert(sig, srcIP, destIP);
            }
        }
    }
}

// Handles captured packets and matches with signatures
void packetHandler(u_char* userData, const struct pcap_pkthdr* packetHeader, const u_char* packetData) {
    const int ethernetHeaderSize = 14;
    const u_char* ipHeader = packetData + ethernetHeaderSize;

    // Check if packet is IPv4
    if ((ipHeader[0] >> 4) != 4) {
        return;
    }

    u_long srcIP = *(reinterpret_cast<const u_long*>(ipHeader + 12));
    u_long destIP = *(reinterpret_cast<const u_long*>(ipHeader + 16));

    string srcIPStr = ipToString(srcIP);
    string destIPStr = ipToString(destIP);

    // Filter packets by target IP
    if (destIPStr != targetIP) {
        return;
    }

    // Extract protocol and port details
    int protocolType = ipHeader[9];
    string protocol;
    int srcPort = 0, destPort = 0;
    const u_char* tcpHeader = nullptr;

    if (protocolType == IPPROTO_TCP) {
        protocol = "TCP";
        tcpHeader = ipHeader + (ipHeader[0] & 0x0F) * 4;
        srcPort = ntohs(*(reinterpret_cast<const u_short*>(tcpHeader)));
        destPort = ntohs(*(reinterpret_cast<const u_short*>(tcpHeader + 2)));
    }
    else if (protocolType == IPPROTO_UDP) {
        protocol = "UDP";
        const u_char* udpHeader = ipHeader + (ipHeader[0] & 0x0F) * 4;
        srcPort = ntohs(*(reinterpret_cast<const u_short*>(udpHeader)));
        destPort = ntohs(*(reinterpret_cast<const u_short*>(udpHeader + 2)));
    }
    else {
        return;
    }

    // Detect UDP Flooding
    if (protocol == "UDP") {
        udpPacketCount[destIPStr]++;
        auto now = steady_clock::now();

        if (udpTimeMap.find(destIPStr) == udpTimeMap.end()) {
            udpTimeMap[destIPStr] = now;
        }
        else {
            auto duration = duration_cast<seconds>(now - udpTimeMap[destIPStr]).count();
            if (duration <= UDP_TIME_WINDOW && udpPacketCount[destIPStr] > UDP_THRESHOLD) {
                if (canTriggerAlert("UDP_FLOOD")) {
                    generateAlert("Potential UDP Flood detected", srcIPStr, destIPStr, srcPort, destPort, 4);
                }
                udpPacketCount[destIPStr] = 0;
                udpTimeMap[destIPStr] = now;
            }
        }
    }

    //  Signature Matching
    checkForSignature(srcIPStr, destIPStr, protocol, srcPort, destPort, tcpHeader);
}

//  Main Program
int main() {
    pcap_if_t* allDevs;
    pcap_if_t* dev;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&allDevs, errbuf) == -1) {
        cerr << "Error finding devices: " << errbuf << endl;
        return 1;
    }

    int i = 1;
    for (dev = allDevs; dev != NULL; dev = dev->next) {
        cout << i++ << ": " << (dev->description ? dev->description : "Unknown device") << endl;
    }

    int devNum;
    cout << "Select the network interface to monitor: ";
    cin >> devNum;

    dev = allDevs;
    for (i = 1; i < devNum && dev != NULL; i++) {
        dev = dev->next;
    }

    if (dev == NULL) {
        cerr << "Invalid device selected." << endl;
        pcap_freealldevs(allDevs);
        return 1;
    }

    cout << "Enter target IP to monitor: ";
    cin >> targetIP;

    //  Load signatures from the correct database
    string dbFileName = "C:\\Imaad\\MINIProject SEM6\\nids.db";
    loadSignaturesFromDB(dbFileName);

    pcap_t* handle = pcap_open_live(dev->name, 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        cerr << "Error opening device: " << errbuf << endl;
        pcap_freealldevs(allDevs);
        return 1;
    }

    cout << "Monitoring traffic on target IP: " << targetIP << "...\n";
    pcap_loop(handle, 0, packetHandler, NULL);

    pcap_close(handle);
    pcap_freealldevs(allDevs);
    return 0;
}