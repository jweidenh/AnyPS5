#include "SceTypes.hpp"
#include "prx/libc/include/general/VabiMacros.hpp"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <stdexcept>
#include <string>
#ifdef _WIN32
#include <cstdio>
#include <windows.h>
#include <psapi.h>
#endif
#ifdef __linux__
#include <cstdio>
#include <fstream>
#include <sys/mman.h>
#include <unistd.h>
#endif

extern "C" {
int APS5_VABI sceSysmoduleIsLoaded(std::uint16_t id);
int APS5_VABI sceSysmoduleLoadModule(std::uint16_t id);
int APS5_VABI sceSysmoduleUnloadModule(std::uint16_t id);
int APS5_VABI sceSysmoduleLoadModuleInternal(std::uint32_t id);
int APS5_VABI sceSysmoduleUnloadModuleInternal(std::uint32_t id);
int APS5_VABI sceSysmoduleLoadModuleInternalWithArg(std::uint32_t id, int argc, void* argv, std::uint64_t unk, int* ret);
int APS5_VABI sceSysmoduleGetModuleInfoForUnwind(std::uint64_t addr, int flags, ModuleInfoForUnwind* info);
int APS5_VABI sceSysmoduleGetModuleHandleInternal(std::uint32_t id, std::int32_t* handle);
int APS5_VABI sceKernelDlsym(std::int32_t handle, const char* symbol, void** addr);
}

namespace {

void Require(bool value) { if (!value) std::abort(); }

template <typename TFunction>
bool ThrowsRuntimeError(TFunction function) {
    try {
        function();
    } catch (const std::runtime_error&) {
        return true;
    }
    return false;
}

constexpr std::uint16_t kFiberModuleId = 0x0006;
constexpr std::uint16_t kUltModuleId = 0x0007;
constexpr int kInvalidValue = static_cast<int>(0x805A1000);
constexpr int kModuleUnloaded = static_cast<int>(0x805A1001);
constexpr std::uint32_t kInternalFlag = 0x80000000u;
constexpr std::uint16_t kAcmModuleId = 0x010b;
constexpr std::uint16_t kTrophy2ModuleId = 0x0110;
constexpr std::uint16_t kVoiceChatModuleId = 0x0114;
constexpr std::uint16_t kPsmlModuleId = 0x0137;
constexpr std::uint32_t kAgcModuleId = 0x80000094;

#ifdef __linux__
struct Mapping {
    std::uint64_t start = 0;
    std::uint64_t end = 0;
    std::string path;
};

Mapping MapsEntry(std::uint64_t address) {
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        unsigned long long start = 0;
        unsigned long long end = 0;
        char path[4096] = {};
        const int parsed = std::sscanf(line.c_str(), "%llx-%llx %*s %*x %*x:%*x %*u %4095s", &start, &end, path);
        if (parsed >= 2 && address >= start && address < end) return Mapping{start, end, parsed == 3 ? path : ""};
    }
    std::abort();
}

void RequireUnwindMatchesMaps(const void* pointer) {
    const auto address = reinterpret_cast<std::uint64_t>(pointer);
    const auto expected = MapsEntry(address);
    ModuleInfoForUnwind info{};
    Require(sceSysmoduleGetModuleInfoForUnwind(address, 0, &info) == 0);
    Require(info.st_size == sizeof(ModuleInfoForUnwind));
    Require(info.seg0_addr == expected.start && info.seg0_size == expected.end - expected.start);
    Require(std::string(info.name) == expected.path.substr(0, sizeof(info.name) - 1));
    Require(info.eh_frame_hdr_addr == 0 && info.eh_frame_addr == 0 && info.eh_frame_size == 0);
}

void CheckUnwindInfo() {
    RequireUnwindMatchesMaps(reinterpret_cast<const void*>(&RequireUnwindMatchesMaps));
    RequireUnwindMatchesMaps(reinterpret_cast<const void*>(&sceSysmoduleGetModuleInfoForUnwind));
    int local = 0;
    RequireUnwindMatchesMaps(&local);
    const auto page = static_cast<std::size_t>(sysconf(_SC_PAGESIZE));
    void* anonymous = mmap(nullptr, page, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    Require(anonymous != MAP_FAILED);
    RequireUnwindMatchesMaps(anonymous);
    Require(munmap(anonymous, page) == 0);
    void* gap = mmap(nullptr, page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    Require(gap != MAP_FAILED && munmap(gap, page) == 0);
    ModuleInfoForUnwind info{};
    bool threw = false;
    try {
        sceSysmoduleGetModuleInfoForUnwind(reinterpret_cast<std::uint64_t>(gap), 0, &info);
    } catch (const std::runtime_error&) {
        threw = true;
    }
    Require(threw);
}
#endif

#ifdef _WIN32
void RequireUnwindImage(bool value, const char* detail) {
    if (!value) {
        std::fprintf(stderr, "unwind image fixture: %s\n", detail);
        std::abort();
    }
}

void RequireUnwindMatchesRegion(const void* pointer) {
    const auto address = reinterpret_cast<std::uint64_t>(pointer);
    MEMORY_BASIC_INFORMATION expected{};
    Require(VirtualQuery(pointer, &expected, sizeof(expected)) != 0);
    char mapped[4096] = {};
    const DWORD length = GetMappedFileNameA(GetCurrentProcess(), expected.BaseAddress, mapped, sizeof(mapped) - 1);
    mapped[length] = '\0';
    for (int repeat = 0; repeat < 3; ++repeat) {
        ModuleInfoForUnwind info{};
        std::memset(&info, 0xa5, sizeof(info));
        Require(sceSysmoduleGetModuleInfoForUnwind(address, 0, &info) == 0);
        Require(info.st_size == sizeof(ModuleInfoForUnwind));
        if (info.seg0_addr != reinterpret_cast<std::uint64_t>(expected.BaseAddress) || info.seg0_size != expected.RegionSize) {
            std::fprintf(stderr, "cached unwind region mismatch for %p: expected base %p size %zu, got base 0x%llx size %llu\n",
                pointer, expected.BaseAddress, expected.RegionSize, static_cast<unsigned long long>(info.seg0_addr),
                static_cast<unsigned long long>(info.seg0_size));
            std::abort();
        }
        Require(info.name[sizeof(info.name) - 1] == '\0');
        Require(std::strncmp(info.name, mapped, sizeof(info.name) - 1) == 0);
        Require(info.eh_frame_hdr_addr == 0 && info.eh_frame_addr == 0 && info.eh_frame_size == 0);
    }
}

void CheckUnwindImagePages(std::size_t page) {
    static char data[128 * 1024] = {};
    RequireUnwindImage(page > 1 && page <= sizeof(data) / 4, "buffer must contain at least four system pages");
    const auto begin = reinterpret_cast<std::uintptr_t>(data);
    auto* first = data + (page - begin % page) % page;
    MEMORY_BASIC_INFORMATION region{};
    RequireUnwindImage(VirtualQuery(first, &region, sizeof(region)) != 0, "VirtualQuery failed");
    RequireUnwindImage(region.Type == MEM_IMAGE && region.State == MEM_COMMIT, "buffer must be committed image memory");
    RequireUnwindImage(region.BaseAddress == first && region.RegionSize >= 3 * page, "buffer must span three equal-protection pages");
    HMODULE image = nullptr;
    RequireUnwindImage(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(first), &image) != 0, "buffer must belong to a loader image");
    RequireUnwindImage(image == GetModuleHandleW(nullptr) && region.AllocationBase == image, "buffer must belong to the executable image");
    for (std::size_t offset : {std::size_t{0}, page + 1, 2 * page, page, 2 * page + 1, std::size_t{1}, page + 1, std::size_t{0}}) {
        MEMORY_BASIC_INFORMATION current{};
        RequireUnwindImage(VirtualQuery(first + offset, &current, sizeof(current)) != 0, "page query failed");
        RequireUnwindImage(current.Type == MEM_IMAGE && current.State == region.State && current.Protect == region.Protect &&
            current.AllocationBase == region.AllocationBase, "queried pages must share the executable image region");
        RequireUnwindImage(current.BaseAddress == first + offset / page * page && current.RegionSize == region.RegionSize - offset / page * page,
            "queried pages must have a common region end");
        RequireUnwindMatchesRegion(first + offset);
    }
    std::printf("unwind image page queries passed: page=%zu, offsets=8, repeats=3\n", page);
}

void CheckUnwindInfo() {
    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    const std::size_t page = system.dwPageSize;
    CheckUnwindImagePages(page);
    RequireUnwindMatchesRegion(reinterpret_cast<const void*>(&RequireUnwindMatchesRegion));
    RequireUnwindMatchesRegion(reinterpret_cast<const void*>(&sceSysmoduleGetModuleInfoForUnwind));
    RequireUnwindMatchesRegion(reinterpret_cast<const void*>(&GetModuleHandleW));
    static int data = 1;
    static const char text[] = "unwind region";
    RequireUnwindMatchesRegion(&data);
    RequireUnwindMatchesRegion(text);
    RequireUnwindMatchesRegion(reinterpret_cast<const void*>(&RequireUnwindMatchesRegion));
    int local = 0;
    RequireUnwindMatchesRegion(&local);
    auto* memory = static_cast<char*>(VirtualAlloc(nullptr, 3 * page, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    Require(memory != nullptr);
    RequireUnwindMatchesRegion(memory);
    DWORD previous = 0;
    Require(VirtualProtect(memory + 2 * page, page, PAGE_READONLY, &previous) != 0);
    RequireUnwindMatchesRegion(memory);
    RequireUnwindMatchesRegion(memory + 2 * page);
    Require(VirtualFree(memory, 0, MEM_RELEASE) != 0);
    RequireUnwindMatchesRegion(memory);
}
#endif

}

int main() {
    Require(sceSysmoduleIsLoaded(0) == kInvalidValue);
    Require(sceSysmoduleLoadModule(0) == kInvalidValue);
    Require(sceSysmoduleUnloadModule(0) == kInvalidValue);
    for (std::uint32_t id : {0u, kInternalFlag}) {
        Require(sceSysmoduleLoadModuleInternal(id) == kInvalidValue);
        Require(sceSysmoduleUnloadModuleInternal(id) == kInvalidValue);
        int result = 0x5a5a5a5a;
        Require(sceSysmoduleLoadModuleInternalWithArg(id, 0, nullptr, 0, &result) == kInvalidValue);
        Require(result == 0x5a5a5a5a);
    }

    Require(sceSysmoduleIsLoaded(kFiberModuleId) == kModuleUnloaded);
    Require(sceSysmoduleLoadModuleInternal(kFiberModuleId) == 0);
    Require(sceSysmoduleIsLoaded(kFiberModuleId) == 0);
    Require(sceSysmoduleLoadModuleInternal(kFiberModuleId) == 0);
    Require(sceSysmoduleUnloadModuleInternal(kFiberModuleId) == 0);
    Require(sceSysmoduleIsLoaded(kFiberModuleId) == 0);
    Require(sceSysmoduleUnloadModuleInternal(kFiberModuleId) == 0);
    Require(sceSysmoduleIsLoaded(kFiberModuleId) == kModuleUnloaded);
    Require(sceSysmoduleUnloadModuleInternal(kFiberModuleId) == kModuleUnloaded);

    Require(sceSysmoduleIsLoaded(kUltModuleId) == kModuleUnloaded);
    Require(sceSysmoduleUnloadModule(kUltModuleId) == kModuleUnloaded);
    Require(sceSysmoduleLoadModule(kUltModuleId) == 0);
    Require(sceSysmoduleIsLoaded(kUltModuleId) == 0);
    Require(sceSysmoduleUnloadModule(kUltModuleId) == 0);
    Require(sceSysmoduleIsLoaded(kUltModuleId) == kModuleUnloaded);

    Require(sceSysmoduleIsLoaded(kAcmModuleId) == kModuleUnloaded);
    Require(sceSysmoduleUnloadModule(kAcmModuleId) == kModuleUnloaded);
    Require(sceSysmoduleLoadModule(kAcmModuleId) == 0);
    Require(sceSysmoduleIsLoaded(kAcmModuleId) == 0);
    Require(sceSysmoduleUnloadModule(kAcmModuleId) == 0);
    Require(sceSysmoduleIsLoaded(kAcmModuleId) == kModuleUnloaded);

    constexpr std::uint16_t kShareModuleId = 0x010f;
    Require(sceSysmoduleIsLoaded(kShareModuleId) == kModuleUnloaded);
    Require(sceSysmoduleLoadModule(kShareModuleId) == 0);
    Require(sceSysmoduleIsLoaded(kShareModuleId) == 0);
    Require(sceSysmoduleUnloadModule(kShareModuleId) == 0);
    Require(sceSysmoduleIsLoaded(kShareModuleId) == kModuleUnloaded);

    Require(sceSysmoduleIsLoaded(kTrophy2ModuleId) == kModuleUnloaded);
    Require(sceSysmoduleLoadModuleInternal(kTrophy2ModuleId) == 0);
    Require(sceSysmoduleIsLoaded(kTrophy2ModuleId) == 0);
    Require(sceSysmoduleLoadModuleInternal(kTrophy2ModuleId) == 0);
    Require(sceSysmoduleUnloadModuleInternal(kTrophy2ModuleId) == 0);
    Require(sceSysmoduleIsLoaded(kTrophy2ModuleId) == 0);
    Require(sceSysmoduleUnloadModuleInternal(kTrophy2ModuleId) == 0);
    Require(sceSysmoduleIsLoaded(kTrophy2ModuleId) == kModuleUnloaded);
    Require(sceSysmoduleUnloadModuleInternal(kTrophy2ModuleId) == kModuleUnloaded);

    Require(sceSysmoduleIsLoaded(kVoiceChatModuleId) == kModuleUnloaded);
    Require(sceSysmoduleUnloadModule(kVoiceChatModuleId) == kModuleUnloaded);
    Require(sceSysmoduleLoadModule(kVoiceChatModuleId) == 0);
    Require(sceSysmoduleIsLoaded(kVoiceChatModuleId) == 0);
    Require(sceSysmoduleUnloadModule(kVoiceChatModuleId) == 0);
    Require(sceSysmoduleIsLoaded(kVoiceChatModuleId) == kModuleUnloaded);

    Require(sceSysmoduleIsLoaded(kPsmlModuleId) == kModuleUnloaded);
    Require(sceSysmoduleUnloadModule(kPsmlModuleId) == kModuleUnloaded);
    Require(sceSysmoduleLoadModule(kPsmlModuleId) == 0);
    Require(sceSysmoduleIsLoaded(kPsmlModuleId) == 0);
    Require(sceSysmoduleUnloadModule(kPsmlModuleId) == 0);
    Require(sceSysmoduleIsLoaded(kPsmlModuleId) == kModuleUnloaded);

    Require(sceSysmoduleUnloadModuleInternal(kAgcModuleId) == kModuleUnloaded);
    Require(sceSysmoduleLoadModuleInternal(kAgcModuleId) == 0);
    Require(sceSysmoduleLoadModuleInternal(kAgcModuleId) == 0);
    Require(sceSysmoduleUnloadModuleInternal(kAgcModuleId) == 0);
    Require(sceSysmoduleUnloadModuleInternal(kAgcModuleId) == 0);
    Require(sceSysmoduleUnloadModuleInternal(kAgcModuleId) == kModuleUnloaded);
#if defined(__linux__) || defined(_WIN32)
    CheckUnwindInfo();
#endif

    std::int32_t handle = -1;
    Require(sceSysmoduleGetModuleHandleInternal(kFiberModuleId, &handle) == kModuleUnloaded);
    Require(handle == -1);
    Require(ThrowsRuntimeError([] { sceSysmoduleGetModuleHandleInternal(0, nullptr); }));
    Require(ThrowsRuntimeError([&] { sceSysmoduleGetModuleHandleInternal(0, &handle); }));
    Require(ThrowsRuntimeError([] { sceSysmoduleGetModuleHandleInternal(kFiberModuleId, nullptr); }));
    Require(ThrowsRuntimeError([&] { sceSysmoduleGetModuleHandleInternal(0x00ffffffu, &handle); }));

    Require(sceSysmoduleLoadModule(kFiberModuleId) == 0);
    Require(sceSysmoduleGetModuleHandleInternal(kFiberModuleId, &handle) == 0);
    Require(handle >= 0);
    std::int32_t again = -1;
    Require(sceSysmoduleGetModuleHandleInternal(kFiberModuleId, &again) == 0);
    Require(again == handle);
    void* symbol = nullptr;
    Require(sceKernelDlsym(handle, "sceFiberOptParamInitialize", &symbol) == 0);
    Require(symbol != nullptr);
    Require(sceSysmoduleUnloadModule(kFiberModuleId) == 0);
    Require(sceSysmoduleGetModuleHandleInternal(kFiberModuleId, &handle) == kModuleUnloaded);

    constexpr std::uint16_t kAudioPropagationModuleId = 0x0120;
    std::int32_t audioPropagationHandle = -1;
    Require(sceSysmoduleGetModuleHandleInternal(kAudioPropagationModuleId, &audioPropagationHandle) == kModuleUnloaded);
    Require(audioPropagationHandle == -1);

    Require(sceSysmoduleIsLoaded(kAudioPropagationModuleId) == kModuleUnloaded);
    Require(sceSysmoduleLoadModule(kAudioPropagationModuleId) == 0);
    Require(sceSysmoduleIsLoaded(kAudioPropagationModuleId) == 0);
    Require(sceSysmoduleGetModuleHandleInternal(kAudioPropagationModuleId, &audioPropagationHandle) == 0);
    Require(audioPropagationHandle >= 0);
    void* audioPropagationSymbol = nullptr;
    Require(sceKernelDlsym(audioPropagationHandle, "sceAudioPropagationSystemCreate", &audioPropagationSymbol) == 0);
    Require(audioPropagationSymbol != nullptr);

    Require(sceSysmoduleUnloadModule(kAudioPropagationModuleId) == 0);
    Require(sceSysmoduleIsLoaded(kAudioPropagationModuleId) == kModuleUnloaded);
    Require(sceSysmoduleGetModuleHandleInternal(kAudioPropagationModuleId, &audioPropagationHandle) == kModuleUnloaded);
}
