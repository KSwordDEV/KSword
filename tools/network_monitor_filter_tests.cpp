#include <cassert>
#include <iostream>

static void addAddress(NetworkDock::MonitorFilterRuleGroupCompiled& group,const QString& text,bool local){
    std::pair<std::uint32_t,std::uint32_t> v4;ks::r3::network::NetworkAddressPrefix v6;bool ipv6=false;QString normalized;
    assert(tryParseMonitorAddressText(text,v4,v6,ipv6,normalized));
    if(ipv6)(local?group.localIpv6PrefixList:group.remoteIpv6PrefixList).push_back(v6);
    else (local?group.localAddressRangeList:group.remoteAddressRangeList).push_back(v4);
}
int main(){
    using Group=NetworkDock::MonitorFilterRuleGroupCompiled;
    std::pair<std::uint32_t,std::uint32_t> v4;ks::r3::network::NetworkAddressPrefix v6;bool ipv6=false;QString normalized;
    assert(tryParseMonitorAddressText(QStringLiteral("2001:0db8:0000::1"),v4,v6,ipv6,normalized)&&ipv6&&normalized==QStringLiteral("2001:db8::1"));
    assert(tryParseMonitorAddressText(QStringLiteral("2001:db8:abcd:ffff::1/48"),v4,v6,ipv6,normalized)&&normalized==QStringLiteral("2001:db8:abcd::/48"));
    for(const auto* invalid:{"example.com","2001:db8::/129","2001:db8::/-1","2001:db8::/wat","2001:db8::/","[2001:db8::1]:443","2001:db8::1-2001:db8::2"})
        assert(!tryParseMonitorAddressText(QString::fromLatin1(invalid),v4,v6,ipv6,normalized));
    Group group;assert(!group.hasAnyCondition());addAddress(group,QStringLiteral("2001:db8::/32"),false);assert(group.hasAnyCondition());
    ks::network::PacketRecord packet;packet.processId=42;packet.localAddress="::1";packet.remoteAddress="2001:db8:ffff::1";packet.remotePort=443;packet.totalPacketSize=100;
    const auto matches=[&]{return NetworkDock::packetMatchesMonitorFilterGroup(packet,group);};
    assert(matches());packet.remoteAddress="2001:db9::1";assert(!matches());
    addAddress(group,QStringLiteral("192.0.2.1-192.0.2.10"),false);
    packet.remoteAddress="192.0.2.1";assert(matches());packet.remoteAddress="192.0.2.10";assert(matches());packet.remoteAddress="192.0.2.11";assert(!matches());
    packet.remoteAddress="2001:db8::2";assert(matches());
    addAddress(group,QStringLiteral("::1"),true);assert(matches());packet.localAddress="::2";assert(!matches());packet.localAddress="::1";
    group.processIdList={42};group.remotePortRangeList={{443,443}};group.packetSizeRangeList={{100,200}};assert(matches());
    packet.processId=43;assert(!matches());packet.processId=42;packet.remotePort=80;assert(!matches());packet.remotePort=443;packet.totalPacketSize=99;assert(!matches());packet.totalPacketSize=100;
    group=Group{};addAddress(group,QStringLiteral("::/0"),false);packet.remoteAddress="fe80::1234";assert(matches());packet.remoteAddress="192.0.2.1";assert(!matches());
    group=Group{};addAddress(group,QStringLiteral("2001:db8:0:0:8000::/65"),false);
    packet.remoteAddress="2001:db8:0:0:ffff::1";assert(matches());packet.remoteAddress="2001:db8:0:0:7fff::1";assert(!matches());
    group=Group{};addAddress(group,QStringLiteral("::ffff:192.0.2.0/120"),false);
    packet.remoteAddress="::ffff:192.0.2.5";assert(matches());packet.remoteAddress="192.0.2.5";assert(!matches());
    group=Group{};addAddress(group,QStringLiteral("0.0.0.0/0"),false);addAddress(group,QStringLiteral("::/0"),false);
    packet.remoteAddress="192.0.2.5";assert(matches());packet.remoteAddress="2001:db8::1";assert(matches());packet.remoteAddress="2001:db8::/32";assert(!matches());packet.remoteAddress="example.com";assert(!matches());
    std::cout<<"NETWORK_MONITOR_FILTER=PASS ipv4_ipv6_cidr_ranges_or_within_and_across no_network_io\n";
}
