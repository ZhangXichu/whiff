#include <pcap.h>
#include <iostream>
#include <iomanip>
#include <ctime>
#include <whiff.hpp>


int main(int argc, char* argv[])
{
    try {
        whiff::Whiff app = whiff::Whiff::from_args(argc, argv);
        app.run();
    } catch (const std::exception& e) {
        std::cerr << "[-] Error: " << e.what() << "\n";
        return 1;
    }
    return 0;

    return 0;
}