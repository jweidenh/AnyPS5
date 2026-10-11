#pragma once

#include "prx/libSceAgcDriver/Graphics/include/Context.hpp"
#include <cstddef>
#include <cstdint>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/mman.h>
#endif

class OversizedDescriptorMemory {
public:
    static constexpr std::size_t Unit = 65536;
    static constexpr std::size_t Bytes = 6 * Unit;

    OversizedDescriptorMemory() {
#ifdef _WIN32
        block = VirtualAlloc(nullptr, Bytes, MEM_RESERVE, PAGE_NOACCESS);
        AgcDriver::Graphics::Require(block != nullptr, "cannot reserve oversized descriptor test memory");
#else
        block = mmap(nullptr, Bytes, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        AgcDriver::Graphics::Require(block != MAP_FAILED, "cannot reserve oversized descriptor test memory");
#endif
    }
    ~OversizedDescriptorMemory() {
#ifdef _WIN32
        VirtualFree(block, 0, MEM_RELEASE);
#else
        munmap(block, Bytes);
#endif
    }
    OversizedDescriptorMemory(const OversizedDescriptorMemory&) = delete;
    OversizedDescriptorMemory& operator=(const OversizedDescriptorMemory&) = delete;

    void Commit(std::size_t first, std::size_t count, bool readOnly = false) {
        AgcDriver::Graphics::Require(first < 6 && count != 0 && count <= 6 - first, "invalid oversized descriptor test memory range");
        auto* start = static_cast<std::byte*>(block) + first * Unit;
#ifdef _WIN32
        AgcDriver::Graphics::Require(VirtualAlloc(start, count * Unit, MEM_COMMIT, readOnly ? PAGE_READONLY : PAGE_READWRITE) == start, "cannot commit oversized descriptor test memory");
#else
        AgcDriver::Graphics::Require(mprotect(start, count * Unit, readOnly ? PROT_READ : PROT_READ | PROT_WRITE) == 0, "cannot commit oversized descriptor test memory");
#endif
    }
    std::uint64_t Address(std::size_t unit = 0) const { return reinterpret_cast<std::uintptr_t>(block) + unit * Unit; }
    void* Data() const { return block; }

private:
    void* block = nullptr;
};
