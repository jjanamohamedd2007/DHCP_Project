// ============================================================
//  DHCP Protocol Simulation Using C++  (class-based version)
//  Course : Programming for Cybersecurity - CST301
//  Idea   : A client (PC) asks a DHCP server for an IP address
//           using the 4 DORA messages. The server keeps a small
//           pool of addresses and hands them out one by one.
// ============================================================
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
using namespace std;

// ------------------------------------------------------------
// Class 1: IPPool  -> stores the addresses and who owns them
// ------------------------------------------------------------
class IPPool {
private:
    vector<string> addresses;   // e.g. 192.168.1.10
    vector<string> owners;      // MAC of the owner, "" = free

public:
    IPPool(const string& prefix, int firstHost, int count) {
        for (int i = 0; i < count; i++) {
            addresses.push_back(prefix + to_string(firstHost + i));
            owners.push_back("");
        }
    }

    int size() const { return (int)addresses.size(); }
    string ipAt(int i) const { return addresses[i]; }
    string ownerAt(int i) const { return owners[i]; }

    // index of the first free address, or -1 if the pool is empty
    int findFree() const {
        for (int i = 0; i < size(); i++)
            if (owners[i] == "") return i;
        return -1;
    }

    // index of the address already leased to this MAC, or -1
    int findByMac(const string& mac) const {
        for (int i = 0; i < size(); i++)
            if (owners[i] == mac) return i;
        return -1;
    }

    int findByIp(const string& ip) const {
        for (int i = 0; i < size(); i++)
            if (addresses[i] == ip) return i;
        return -1;
    }

    int freeCount() const {
        int c = 0;
        for (int i = 0; i < size(); i++)
            if (owners[i] == "") c++;
        return c;
    }

    void assign(int index, const string& mac) { owners[index] = mac; }
    void release(int index) { owners[index] = ""; }
    void clearAll() { for (int i = 0; i < size(); i++) owners[i] = ""; }
};

// ------------------------------------------------------------
// Class 2: DhcpServer -> answers DISCOVER and REQUEST
// ------------------------------------------------------------
class DhcpServer {
private:
    IPPool pool;

public:
    DhcpServer() : pool("192.168.1.", 10, 4) {}   // .10 to .13

    // Server side of step 1+2: returns the IP to offer, or "" if none
    string handleDiscover(const string& mac) {
        int old = pool.findByMac(mac);        // client already has a lease?
        if (old != -1) return pool.ipAt(old);
        int free = pool.findFree();
        if (free == -1) return "";
        return pool.ipAt(free);
    }

    // Server side of step 3+4: true = ACK, false = NAK
    bool handleRequest(const string& mac, const string& ip) {
        int idx = pool.findByIp(ip);
        if (idx == -1) return false;
        if (pool.ownerAt(idx) != "" && pool.ownerAt(idx) != mac) return false;
        pool.assign(idx, mac);
        return true;
    }

    // Returns the released IP, or "" if the MAC had no lease
    string handleRelease(const string& mac) {
        int idx = pool.findByMac(mac);
        if (idx == -1) return "";
        pool.release(idx);
        return pool.ipAt(idx);
    }

    void reset() { pool.clearAll(); }
    const IPPool& getPool() const { return pool; }
};

// ------------------------------------------------------------
// Class 3: Client (PC)
// ------------------------------------------------------------
class Client {
private:
    int number;
    string mac;
    string ip;          // "" = no address yet

public:
    Client(int n) : number(n), ip("") {
        // simulated MAC address built from the PC number
        string hex = "0123456789ABCDEF";
        mac = "AA:BB:CC:00:";
        mac += hex[(n / 16) % 16];
        mac += hex[n % 16];
        mac += ":01";
    }

    int getNumber() const { return number; }
    string getMac() const { return mac; }
    string getIp() const { return ip; }
    bool hasIp() const { return ip != ""; }
    void clearIp() { ip = ""; }

    // Runs the whole DORA conversation. show = print the messages
    bool requestIp(DhcpServer& server, bool show) {
        if (show)
            cout << "[PC" << number << "] DHCP DISCOVER  (broadcast, MAC "
                 << mac << ")\n";

        string offered = server.handleDiscover(mac);
        if (offered == "") {
            if (show) {
                cout << "[Server] No free address in the pool -> no OFFER sent\n";
                cout << "[PC" << number << "] IP allocation FAILED\n";
            }
            return false;
        }
        if (show) {
            cout << "[Server] DHCP OFFER     -> " << offered << "\n";
            cout << "[PC" << number << "] DHCP REQUEST   for " << offered << "\n";
        }

        if (server.handleRequest(mac, offered)) {
            ip = offered;
            if (show) {
                cout << "[Server] DHCP ACK       -> lease confirmed\n";
                cout << "[PC" << number << "] SUCCESS, allocated IP = " << ip << "\n";
            }
            return true;
        }
        if (show) cout << "[Server] DHCP NAK       -> request refused\n";
        return false;
    }
};

// ------------------------------------------------------------
// Helper functions
// ------------------------------------------------------------
void printMenu() {
    cout << "\n==========================================\n";
    cout << "        DHCP SIMULATION - MAIN MENU\n";
    cout << "==========================================\n";
    cout << " 1) Test case 1: IP address available\n";
    cout << " 2) Test case 2: No IP address available\n";
    cout << " 3) Connect a new PC to the network\n";
    cout << " 4) Show network status\n";
    cout << " 5) Disconnect a PC (release its IP)\n";
    cout << " 0) Exit\n";
    cout << "------------------------------------------\n";
    cout << "Your choice: ";
}

void printStatus(const vector<Client>& clients, const DhcpServer& server) {
    cout << "\n---------------- NETWORK STATUS ----------------\n";
    cout << left << setw(8) << "PC" << setw(20) << "MAC" << "IP address\n";
    if (clients.empty()) cout << "(no PCs connected yet)\n";
    for (size_t i = 0; i < clients.size(); i++) {
        cout << left << setw(8) << ("PC" + to_string(clients[i].getNumber()))
             << setw(20) << clients[i].getMac()
             << (clients[i].hasIp() ? clients[i].getIp() : "Not Assigned") << "\n";
    }
    const IPPool& p = server.getPool();
    cout << "\nPool: " << p.freeCount() << " free / " << p.size() << " total\n";
    for (int i = 0; i < p.size(); i++)
        cout << "  " << p.ipAt(i) << "  "
             << (p.ownerAt(i) == "" ? "FREE" : "USED by " + p.ownerAt(i)) << "\n";
    cout << "------------------------------------------------\n";
}

// reads one line and accepts it only if it is a whole number
bool readNumber(int& value) {
    string line;
    if (!getline(cin, line)) return false;
    if (line.empty() || line.size() > 6) { value = -1; return true; }
    for (size_t i = 0; i < line.size(); i++)
        if (line[i] < '0' || line[i] > '9') { value = -1; return true; }
    value = stoi(line);
    return true;
}

// ------------------------------------------------------------
// main
// ------------------------------------------------------------
int main() {
    DhcpServer server;
    vector<Client> clients;
    int nextPc = 1;
    int choice = -1;

    cout << "==========================================\n";
    cout << "   DHCP PROTOCOL SIMULATION USING C++\n";
    cout << "==========================================\n";
    cout << "DHCP server started. Address pool: 192.168.1.10 - 192.168.1.13\n";

    while (true) {
        printMenu();
        if (!readNumber(choice)) { cout << "\n"; break; }   // end of input
        cout << "\n";

        if (choice == 1) {
            // ---- Test case 1: an address is available ----
            server.reset(); clients.clear(); nextPc = 1;
            cout << ">>> Test case 1: the pool is empty, so an IP is available.\n\n";
            clients.push_back(Client(nextPc++));
            clients.back().requestIp(server, true);
        }
        else if (choice == 2) {
            // ---- Test case 2: no address is available ----
            server.reset(); clients.clear(); nextPc = 1;
            int total = server.getPool().size();
            cout << ">>> Test case 2: first " << total
                 << " PCs take every address...\n";
            for (int i = 0; i < total; i++) {
                clients.push_back(Client(nextPc++));
                clients.back().requestIp(server, false);
            }
            cout << "    Pool is now full. A new PC joins:\n\n";
            clients.push_back(Client(nextPc++));
            clients.back().requestIp(server, true);
        }
        else if (choice == 3) {
            clients.push_back(Client(nextPc++));
            clients.back().requestIp(server, true);
        }
        else if (choice == 4) {
            printStatus(clients, server);
        }
        else if (choice == 5) {
            cout << "Enter the PC number to disconnect: ";
            int n;
            if (!readNumber(n)) break;
            bool done = false;
            for (size_t i = 0; i < clients.size(); i++) {
                if (clients[i].getNumber() == n && clients[i].hasIp()) {
                    string ip = server.handleRelease(clients[i].getMac());
                    clients[i].clearIp();
                    cout << "[PC" << n << "] DHCP RELEASE -> " << ip
                         << " is free again\n";
                    done = true;
                }
            }
            if (!done) cout << "PC" << n << " does not exist or has no IP address.\n";
        }
        else if (choice == 0) {
            cout << "Simulation finished. Goodbye!\n";
            break;
        }
        else {
            cout << "Invalid choice! Please enter a number from the menu (0-5).\n";
        }
    }
    return 0;
}
