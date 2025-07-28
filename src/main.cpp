#include <pcap.h>
#include <iostream>
#include <iomanip>
#include <ctime>
#include <whiff.hpp>
#include <loguru.hpp>


int main(int argc, char* argv[])
{
    loguru::Options options;
    options.verbosity_flag = nullptr; 
    loguru::init(argc, argv, options);
    loguru::g_stderr_verbosity = loguru::Verbosity_INFO;

    loguru::add_file("log/whiff.log", loguru::Append, loguru::Verbosity_MAX);

    LOG_F(INFO, "Launching Whiff");

    try {
        auto app = whiff::Whiff::from_args(argc, argv);
        app->run();
    } catch (const std::exception& e) 
    {
        LOG_F(ERROR, "Error: %s", e.what());
        return 1;
    }
    return 0;

    return 0;
}