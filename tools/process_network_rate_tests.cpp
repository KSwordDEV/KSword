#include "../shared/usermode/backend/network/NetworkRate.h"
#include <cassert>
#include <iostream>
int main() {
    using namespace ks::network;
    const NetworkRateSample first{1024,2048,10000000,true};
    const NetworkRateSample next{4096,10240,20000000,true};
    const auto active=CalculateNetworkRate(first,next);
    assert(active.known&&active.receivedKBps==3&&active.sentKBps==8&&active.totalKBps==11);
    auto idle=next;idle.tick100ns+=10000000;
    const auto zero=CalculateNetworkRate(next,idle);
    assert(zero.known&&zero.totalKBps==0);
    auto noCapture=next;noCapture.available=false;
    assert(!CalculateNetworkRate(first,noCapture).known);
    assert(!CalculateNetworkRate(noCapture,idle).known);
    assert(!CalculateNetworkRate({},first).known);
    assert(!CalculateNetworkRate(first,first).known);
    assert(!CalculateNetworkRate(next,first).known);
    auto reset=next;reset.receivedBytes=0;
    assert(!CalculateNetworkRate(first,reset).known);
    reset=next;reset.sentBytes=0;
    assert(!CalculateNetworkRate(first,reset).known);
    auto half=next;half.tick100ns=15000000;
    assert(CalculateNetworkRate(first,half).totalKBps==22);
    // Resuming an old cumulative counter must establish a new interval first.
    auto pause=next;pause.available=false;
    auto resume=NetworkRateSample{10000000,20000000,90000000,true};
    assert(!CalculateNetworkRate(pause,resume).known);
    auto live=resume;live.tick100ns+=10000000;live.sentBytes+=1024;
    assert(CalculateNetworkRate(resume,live).sentKBps==1);
    std::cout<<"PROCESS_NETWORK_RATE=PASS ACTIVE_IDLE_UNAVAILABLE_RESET_RESUME=1\n";
}
