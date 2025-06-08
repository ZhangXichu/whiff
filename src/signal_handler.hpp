#pragma once
#include <functional>

namespace whiff {

class SignalHandler {
public:
    static void set_callback(const std::function<void()>& cb);
    static void setup();

private:
    static void handle_signal(int sig);
    static std::function<void()> callback;
};

}