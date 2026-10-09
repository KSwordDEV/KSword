// Injected API fixtures exercise the production enumerator without enumerating
// real filters, accessing files, or opening a driver. The included collector is
// extracted afresh by Invoke-FilePropertyCollectionTests.ps1 on each invocation.

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <string>
#include <stdexcept>
#include <vector>
#define QStringLiteral(x) x
namespace file_dock_detail {
struct PropertyDocument {
    int notes = 0, fields = 0;
    std::uint64_t lastStatus = 0;
    PropertyDocument& note(const char*) { ++notes; return *this; }
    PropertyDocument& field(const char*, std::uint64_t value) { ++fields; lastStatus = value; return *this; }
};
}
static std::uint64_t formatHexValue(std::uint64_t value, int) { return value; }
#include "native_filter_collection.inc"
static int assertions = 0;
#define CHECK(x) do { ++assertions; if (!(x)) { std::cerr << "FAIL line " << __LINE__ << ": " << #x << '\n'; return 1; } } while (0)
int main() {
    const auto end = [](HANDLE, void*, DWORD, DWORD*) { return HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS); };
    for (ULONG bad : {0UL, 6UL, 32UL, 0xFFFFFFF8UL}) {
        file_dock_detail::PropertyDocument doc;
        int closed = 0, records = 0;
        auto first = [bad](void* buffer, DWORD, DWORD* bytes, HANDLE* handle) {
            std::array<ULONG, 8> payload{bad, 10, 0, 0, 0, 20, 0, 0};
            std::memcpy(buffer, payload.data(), sizeof(payload)); *bytes = sizeof(payload);
            *handle = reinterpret_cast<HANDLE>(1); return S_OK;
        };
        enumerateNativeFilterRecords(doc, first, end, [&](HANDLE){++closed;},
            [&](const void*, std::size_t){++records;});
        CHECK(closed == 1);
        CHECK(records == (bad == 0 ? 1 : 0));
        CHECK(doc.notes == (bad == 0 ? 0 : 1));
        CHECK(doc.fields == 0);
    }
    {
        file_dock_detail::PropertyDocument doc; int closed = 0; std::vector<ULONG> values;
        auto first = [](void* buffer, DWORD, DWORD* bytes, HANDLE* handle) {
            std::array<ULONG, 8> payload{16, 10, 0, 0, 0, 20, 0, 0};
            std::memcpy(buffer, payload.data(), sizeof(payload)); *bytes = sizeof(payload);
            *handle = reinterpret_cast<HANDLE>(1); return S_OK;
        };
        enumerateNativeFilterRecords(doc, first, end, [&](HANDLE){++closed;},
            [&](const void* buffer, std::size_t bytes){
                if (bytes != 16) throw std::runtime_error("record boundary");
                ULONG value = 0; std::memcpy(&value, static_cast<const std::uint8_t*>(buffer)+4, 4); values.push_back(value);
            });
        CHECK(closed == 1); CHECK(values.size() == 2);
        CHECK(values[0] == 10); CHECK(values[1] == 20); CHECK(doc.notes == 0);
    }
    {
        file_dock_detail::PropertyDocument doc; int firstCalls = 0, nextCalls = 0, closed = 0, records = 0;
        std::vector<DWORD> firstSizes, nextSizes;
        auto first = [&](void* buffer, DWORD size, DWORD* bytes, HANDLE* handle) {
            firstSizes.push_back(size);
            if (++firstCalls == 1) return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
            std::memset(buffer, 0, 16); *bytes = 16; *handle = reinterpret_cast<HANDLE>(1); return S_OK;
        };
        auto next = [&](HANDLE, void* buffer, DWORD size, DWORD* bytes) {
            nextSizes.push_back(size); ++nextCalls;
            if (nextCalls == 1) return HRESULT_FROM_WIN32(ERROR_MORE_DATA);
            if (nextCalls == 2) { std::memset(buffer, 0, 16); *bytes = 16; return S_OK; }
            return HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS);
        };
        enumerateNativeFilterRecords(doc, first, next, [&](HANDLE){++closed;}, [&](const void*, std::size_t){++records;});
        CHECK(firstCalls == 2); CHECK(nextCalls == 3); CHECK(records == 2); CHECK(closed == 1);
        CHECK(firstSizes == std::vector<DWORD>({16384, 32768}));
        CHECK(nextSizes == std::vector<DWORD>({32768, 65536, 65536}));
        CHECK(doc.notes == 0); CHECK(doc.fields == 0);
    }
    {
        file_dock_detail::PropertyDocument doc; int closed = 0, records = 0;
        auto first = [](void* buffer, DWORD, DWORD* bytes, HANDLE* handle) {
            std::memset(buffer, 0, 18); const ULONG offset = 16;
            std::memcpy(buffer, &offset, 4); *bytes = 18; *handle = reinterpret_cast<HANDLE>(1); return S_OK;
        };
        enumerateNativeFilterRecords(doc, first, end, [&](HANDLE){++closed;}, [&](const void*, std::size_t){++records;});
        CHECK(closed == 1); CHECK(records == 1); CHECK(doc.notes == 1);
    }
    {
        file_dock_detail::PropertyDocument doc; int closed = 0, records = 0;
        auto first = [](void*, DWORD size, DWORD* bytes, HANDLE* handle) {
            *bytes = size + 1; *handle = reinterpret_cast<HANDLE>(1); return S_OK;
        };
        enumerateNativeFilterRecords(doc, first, end, [&](HANDLE){++closed;}, [&](const void*, std::size_t){++records;});
        CHECK(closed == 1); CHECK(records == 0); CHECK(doc.notes == 1);
    }
    {
        file_dock_detail::PropertyDocument doc; int closed = 0, records = 0;
        auto first = [](void*, DWORD, DWORD*, HANDLE* handle) {
            *handle = reinterpret_cast<HANDLE>(1); return E_ACCESSDENIED;
        };
        enumerateNativeFilterRecords(doc, first, end, [&](HANDLE){++closed;}, [&](const void*, std::size_t){++records;});
        CHECK(closed == 1); CHECK(records == 0); CHECK(doc.fields == 1);
        CHECK(doc.lastStatus == static_cast<std::uint32_t>(E_ACCESSDENIED));
    }
    {
        file_dock_detail::PropertyDocument doc; int firstCalls = 0, closed = 0, records = 0;
        DWORD lastSize = 0;
        auto first = [&](void*, DWORD size, DWORD*, HANDLE*) {
            ++firstCalls; lastSize = size; return HRESULT_FROM_WIN32(ERROR_MORE_DATA);
        };
        enumerateNativeFilterRecords(doc, first, end, [&](HANDLE){++closed;}, [&](const void*, std::size_t){++records;});
        CHECK(firstCalls == 11); CHECK(lastSize == 16U * 1024U * 1024U);
        CHECK(closed == 0); CHECK(records == 0); CHECK(doc.fields == 1);
    }
    std::cout << "FILTER_NATIVE_REGRESSION_SUCCESS assertions=" << assertions << '\n';
}
