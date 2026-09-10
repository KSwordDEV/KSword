#pragma once

#include <cstddef>
#include <cstdint>

namespace ks::dwm_order::runtime
{
    // These are semantic roles, never RVAs or Windows build numbers.
    enum class Node : std::uint8_t
    {
        FindWindow, DesktopList, ZOrder, UpdateScene, DestroyWindow, SyncedData,
        Reevaluate, InsertTree, PrecedingVisual, InsertAfter, InsertRelative,
        SendLink, ProxyInsert, WindowListCtor, BandChange, Count
    };
    enum class Binding : std::uint8_t { None, DesktopManager, CriticalSection, Vtable };
    enum class Section : std::uint8_t { Code, ReadOnly, Writable };
    struct Reference
    {
        std::uint16_t displacement;
        std::uint16_t nextInstruction;
        Section section;
        Node node; // Count means an external dependency, not another model node.
        Binding binding;
        const char* importName;
        // Cross-fragment branches are resolved through PE chained unwind records.
        std::uint16_t targetFragment = UINT16_MAX;
        std::uint16_t targetOffset = 0;
        std::uint8_t width = 4;
    };
    struct Fragment
    {
        const unsigned char* bytes;
        const unsigned char* mask;
        std::uint16_t length;
        const Reference* references;
        std::uint16_t referenceCount;
    };
    struct Pattern
    {
        Node node;
        const unsigned char* bytes;
        const unsigned char* mask;
        std::uint16_t length;
        const Reference* references;
        std::uint16_t referenceCount;
        // Additional fragments in RVA order; the primary fragment is index zero.
        const Fragment* fragments = nullptr;
        std::uint16_t fragmentCount = 0;
    };
    struct Layout
    {
        std::uint32_t dataDwmWindow, dataHwnd, dataBand, dataDesktop, dataVisual;
    };
    enum class Failure : std::uint32_t
    {
        None, InvalidImage, MissingPattern, AmbiguousPattern, ReferenceMismatch,
        InvalidVtable, InvalidCfg, InvalidWindowList, InvalidFragments
    };
    struct Resolved
    {
        std::uint32_t functions[static_cast<unsigned>(Node::Count)]{};
        std::uint32_t desktopManager = 0, criticalSection = 0, vtable = 0;
        std::uint32_t windowListOffset = 0;
        std::uint32_t destroySlot = 0, zOrderSlot = 0, updateSlot = 0, tableSlots = 0;
        Layout layout{};
        std::uint32_t model = 0;
    };

    // Pure read-only inspection of an image-layout PE. loadBase is the base used
    // by absolute pointers in its data (actual module base, or preferred base in
    // an offline unrelocated fixture). Does not load or invoke any image code.
    // On failure 'result' is cleared, so partial matches can never be executed.
    Failure Resolve(const void* image, std::size_t bytes, std::uintptr_t loadBase,
        Resolved& result, Node* failedNode = nullptr);
}
