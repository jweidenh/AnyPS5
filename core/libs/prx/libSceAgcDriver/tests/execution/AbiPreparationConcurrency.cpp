#include "VulkanTestDevice.hpp"
#include "Optimization/ResourceProgram.hpp"
#include "prx/libSceAgcDriver/Execution/include/Driver.hpp"
#include "prx/libSceAgcDriver/Execution/include/Driver/Shaders/ShaderRegistry.hpp"
#include "prx/libSceAgcDriver/Execution/include/ShaderPreparation.hpp"
#include "prx/libSceAgcDriver/Execution/include/ShaderPreparationScope.hpp"
#include "prx/libc/include/general/VabiMacros.hpp"
#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <future>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

extern "C" int APS5_VABI sceAgcCreateInterpolantMapping_0100(ShaderRegister*, const Shader*, const Shader*);

namespace {

using namespace AgcDriver::DriverDetail;

constexpr const char* TranslationFailure = "s_sendmsghalt 1 at pc 0 halts the wave";

void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

template<typename TAction>
void ExpectFailure(TAction action, const char* expected) {
    try { action(); }
    catch (const std::exception& error) {
        Require(std::string(error.what()).find(expected) != std::string::npos, error.what());
        return;
    }
    throw std::runtime_error("expected shader ABI preparation failure");
}

class PixelFixture {
public:
    struct Header {
        Shader shader{};
        std::array<ShaderRegister, 3> registers{};
        std::array<ShaderRegister, 1> context{{{0x1b6, 0x8001}}};
    } header;

    explicit PixelFixture(std::uint32_t instruction = 0xbf800000u) : code{instruction, 0xbf810000u} {
        const auto address = reinterpret_cast<std::uintptr_t>(code.data());
        header.shader.file_header = 0x34333231u;
        header.shader.version = 0x18;
        header.shader.type = 1;
        header.shader.header_size = sizeof(header);
        header.shader.shader_size = sizeof(code);
        header.shader.code = code.data();
        header.shader.sh_registers = header.registers.data();
        header.shader.num_sh_registers = header.registers.size();
        header.shader.cx_registers = header.context.data();
        header.shader.num_cx_registers = header.context.size();
        header.registers = {{{0x008, static_cast<std::uint32_t>(address >> 8u)}, {0x009, static_cast<std::uint32_t>(address >> 40u)}, {0x00b, 0}}};
    }

    PixelFixture(const PixelFixture&) = delete;
    PixelFixture& operator=(const PixelFixture&) = delete;

    ShaderSnapshot Snapshot() const {
        ShaderSnapshot snapshot{reinterpret_cast<std::uintptr_t>(code.data()), reinterpret_cast<std::uintptr_t>(&header), 1, {code.begin(), code.end()}, {}};
        snapshot.header.resize(sizeof(header));
        std::memcpy(snapshot.header.data(), &header, sizeof(header));
        return snapshot;
    }

    AgcDriver::QueueState State() const {
        AgcDriver::QueueState state{};
        for (const auto reg : header.registers) state.shader[reg.offset] = reg.value;
        for (const auto reg : header.context) state.context[reg.offset] = reg.value;
        return state;
    }

private:
    alignas(256) std::array<std::uint32_t, 2> code;
};

void ScopeLocking() {
    for (const bool deferred : {false, true}) {
        ShaderSnapshot snapshot{};
        std::promise<void> entered;
        auto started = entered.get_future();
        std::promise<void> constructed;
        auto opened = constructed.get_future();
        std::future<void> worker;
        bool running = false;
        bool blocked = false;
        bool constructorDeferred = false;
        {
            ShaderPreparationTransaction held;
            worker = std::async(std::launch::async, [&] {
                entered.set_value();
                auto scope = deferred ? std::make_unique<AgcDriver::ShaderPreparationScope>(std::defer_lock) : std::make_unique<AgcDriver::ShaderPreparationScope>();
                constructed.set_value();
                ShaderPreparationTransaction transaction(std::defer_lock);
                static_cast<void>(transaction.Read(snapshot));
                transaction.Commit();
                scope->Commit();
            });
            running = started.wait_for(std::chrono::seconds(5)) == std::future_status::ready;
            constructorDeferred = opened.wait_for(deferred ? std::chrono::milliseconds(5000) : std::chrono::milliseconds(100)) == std::future_status::ready;
            blocked = worker.wait_for(std::chrono::milliseconds(100)) == std::future_status::timeout;
            held.Commit();
        }
        worker.get();
        Require(running && constructorDeferred == deferred, "shader preparation scope changed its constructor lock contract");
        Require(blocked, "shader preparation scope read shared state without the writer");
    }
}

void PreparationWhileWriterHeld(const PixelFixture& invalid, bool mapping) {
    std::array<ShaderRegister, 32> output{};
    for (auto& reg : output) reg = {0xdead, 0xdeadbeef};
    std::future<void> worker;
    bool prepared = false;
    {
        ShaderPreparationTransaction held;
        worker = std::async(std::launch::async, [&] {
            ExpectFailure([&] {
                if (mapping) sceAgcCreateInterpolantMapping_0100(output.data(), nullptr, &invalid.header.shader);
                else AgcDriverResolveShaderAbi_nid_postfix(&invalid.header.shader, {}, {});
            }, TranslationFailure);
        });
        prepared = worker.wait_for(std::chrono::seconds(5)) == std::future_status::ready;
        held.Commit();
    }
    worker.get();
    Require(prepared, mapping ? "interpolant ABI preparation waited for an unrelated publication transaction" : "ABI preparation waited for an unrelated publication transaction");
    Require(std::ranges::all_of(output, [](const auto& reg) { return reg.offset == 0xdead && reg.value == 0xdeadbeef; }), "failed interpolant preparation published output registers");
}

void ConcurrentPublication(AgcDriver::VulkanDevice& device, const PixelFixture& fixture) {
    auto snapshot = fixture.Snapshot();
    const auto state = fixture.State();
    std::promise<void> start;
    const auto started = start.get_future().share();
    std::vector<std::future<void>> workers;
    workers.reserve(4);
    bool blocked = true;
    {
        ShaderPreparationTransaction held;
        try {
            for (unsigned index = 0; index < 4; ++index) {
                workers.push_back(std::async(std::launch::async, [&] {
                    started.wait();
                    ShaderPreparationTransaction transaction(std::defer_lock);
                    ResolveRegisteredShaderAbi(transaction, snapshot, device, state);
                    transaction.Commit();
                }));
            }
        } catch (...) {
            start.set_value();
            held.Commit();
            throw;
        }
        start.set_value();
        for (auto& worker : workers) blocked &= worker.wait_for(std::chrono::milliseconds(100)) == std::future_status::timeout;
        {
            std::lock_guard lock(snapshot.prepared->mutex);
            Require(snapshot.prepared->entries.empty() && snapshot.prepared->registeredAbis.empty(), "shader ABI was published without the writer");
        }
        held.Commit();
    }
    for (auto& worker : workers) worker.get();
    Require(blocked, "shader ABI resolution bypassed a publication transaction");
    Require(snapshot.prepared->registeredAbis.size() == 1 && !snapshot.prepared->entries.empty(), "racing ABI resolutions lost or duplicated publication");
    const auto entries = snapshot.prepared->entries;
    for (std::size_t index = 0; index < entries.size(); ++index) {
        for (std::size_t other = index + 1; other < entries.size(); ++other) Require(entries[index].handle->artifact != entries[other].handle->artifact, "racing ABI resolutions duplicated a prepared entry");
    }
    for (unsigned iteration = 0; iteration < 2; ++iteration) {
        ShaderPreparationTransaction transaction(std::defer_lock);
        ResolveRegisteredShaderAbi(transaction, snapshot, device, state);
        transaction.Commit();
    }
    Require(snapshot.prepared->registeredAbis.size() == 1 && snapshot.prepared->entries.size() == entries.size(), "a committed ABI was published twice");
    {
        ShaderPreparationTransaction transaction;
        auto& staged = transaction.Edit(snapshot);
        staged.entries.clear();
        staged.registeredAbis.clear();
        ResolveRegisteredShaderAbi(transaction, snapshot, device, state);
        Require(staged.registeredAbis.size() == 1 && staged.entries.size() == entries.size(), "a staged ABI removal bypassed preparation");
        Require(std::ranges::all_of(entries, [&](const auto& entry) {
            return std::ranges::any_of(staged.entries, [&](const auto& restored) { return restored.handle->artifact == entry.handle->artifact && restored.codeOffset == entry.codeOffset; });
        }), "a staged ABI removal changed its prepared variants");
        transaction.Commit();
    }
    Require(snapshot.prepared->registeredAbis.size() == 1 && snapshot.prepared->entries.size() == entries.size(), "staged ABI preparation was not committed");
}

void NestedFailure(AgcDriver::VulkanDevice& device, const PixelFixture& fixture, const PixelFixture& invalid) {
    auto snapshot = fixture.Snapshot();
    {
        ShaderPreparationTransaction transaction(std::defer_lock);
        ResolveRegisteredShaderAbi(transaction, snapshot, device, fixture.State());
        std::array<ShaderRegister, 32> output{};
        ExpectFailure([&] { sceAgcCreateInterpolantMapping_0100(output.data(), nullptr, &invalid.header.shader); }, TranslationFailure);
        ExpectFailure([&] { transaction.Commit(); }, "transaction was aborted");
    }
    Require(snapshot.prepared->entries.empty() && snapshot.prepared->registeredAbis.empty(), "failed interpolant mapping committed an enclosing ABI transaction");
}

}

int main() {
    try {
        ScopeLocking();
        auto device = OpenVulkanTestDevice();
        if (!device) return VulkanTestSkipped;
        PixelFixture invalid(0xbf910001u);
        AgcDriverRegisterShader_nid_postfix(&invalid.header.shader);
        PreparationWhileWriterHeld(invalid, false);
        PreparationWhileWriterHeld(invalid, true);
        PixelFixture fixture;
        ConcurrentPublication(*device, fixture);
        NestedFailure(*device, fixture, invalid);
        AgcDriverShutdown_nid_postfix();
        std::cout << "concurrent shader ABI preparation tests passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        try { AgcDriverShutdown_nid_postfix(); }
        catch (const std::exception& shutdownError) { std::cerr << shutdownError.what() << '\n'; }
        return 1;
    }
}
