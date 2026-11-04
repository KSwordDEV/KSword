#pragma once
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace ks::r3::location {
struct Value {
    bool known = false, present = false, deviceOpenFailed = false;
    DWORD type = 0, win32Error = 0;
    std::uint32_t driverStatus = 0;
    long ntStatus = 0;
    std::vector<std::uint8_t> bytes;
};
struct Operation {
    bool success = false;
    DWORD win32Error = 0;
    std::uint32_t driverStatus = 0;
    long ntStatus = 0;
    bool deviceOpenFailed = false;
};
class Registry {
public:
    virtual ~Registry() = default;
    virtual Value read(bool policy, const wchar_t* name) = 0;
    virtual Operation write(bool policy, const wchar_t* name, DWORD type, const std::vector<std::uint8_t>& bytes) = 0;
    virtual Operation remove(bool policy, const wchar_t* name) = 0;
};
class SystemRegistry final : public Registry {
public:
    explicit SystemRegistry(bool driver) : driver_(driver) {}
    Value read(bool policy, const wchar_t* name) override;
    Operation write(bool policy, const wchar_t* name, DWORD type, const std::vector<std::uint8_t>& bytes) override;
    Operation remove(bool policy, const wchar_t* name) override;
private:
    bool driver_;
};
struct Coordinate { double latitude=0, longitude=0, altitude=0, errorRadius=0, altitudeAccuracy=0; };
enum class CoordinateSystem { Wgs84, Gcj02, Bd09 };
Coordinate convert(const Coordinate& value, CoordinateSystem from, CoordinateSystem to);
Value readConsent(bool desktop);
struct Snapshot { Value values[5]; bool valid[5]{}; double numbers[5]{}; };
struct Mutation { bool success=false, partial=false; std::size_t attempted=0, completed=0; Operation operations[5]; Snapshot after; };
const wchar_t* valueName(std::size_t index);
Snapshot readDefault(Registry& registry);
Mutation writeDefault(Registry& registry, const Coordinate& value);
Mutation clearDefault(Registry& registry);
Operation setProvider(Registry& registry, bool disabled);
struct Service { bool available=false; DWORD state=0, error=0; };
Service serviceStatus();
Operation resetServiceCache();
struct LiveFix { bool success=false, timedOut=false; long hresult=0; Coordinate coordinate; bool accuracyKnown=false, altitudeAccuracyKnown=false, sourceKnown=false; std::uint32_t source=0; };
LiveFix liveFix(DWORD timeoutMs);
}
