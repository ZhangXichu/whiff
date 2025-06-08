#include "signal_handler.hpp"
#include <csignal>
#include <iostream>

namespace whiff {

std::function<void()> SignalHandler::callback = nullptr;

void SignalHandler::set_callback(const std::function<void()>& cb) {
    callback = cb;
}

void SignalHandler::setup() {
    std::signal(SIGINT, handle_signal);
}

void SignalHandler::handle_signal(int sig) {
    if (sig == SIGINT) {
        std::cout << "\n[!] Ctrl+C detected. Stopping capture...\n";
        if (callback) callback();
    }
}

}