#include <cassert>
#include <cstdint>
#include "../../internals/include/internals/capabilities.hpp"
#include "../../internals/include/internals/draw.hpp"
#include "../../internals/include/internals/input.hpp"
#include "../../internals/include/internals/snapshot.hpp"

using namespace internals;

struct Backend final : DrawBackend {
    std::uint32_t begins = 0, ends = 0, submissions = 0;
    void BeginFrame() noexcept override { ++begins; }
    void EndFrame() noexcept override { ++ends; }
    void Submit(const DrawSubmission& submission) noexcept override {
        assert(submission.vertices != nullptr);
        assert(submission.indices != nullptr);
        assert(submission.vertex_count != 0);
        ++submissions;
    }
};

struct State { std::uint32_t objects = 0; };

int main() {
    FeatureCapabilities capabilities{0x7, 0x3, 0x3};
    assert(capabilities.available() == 3);
    assert(capabilities.allows(2));
    assert(!capabilities.allows(4));

    SnapshotPublisher<State> snapshots;
    snapshots.Publish(State{42});
    State state{};
    snapshots.Consume(state);
    assert(state.objects == 42 && snapshots.sequence() == 1);
    assert(snapshots.TryConsume(state));

    static DrawList draw;
    Backend backend;
    draw.AddRect({0, 0}, {20, 10}, Color{255, 0, 0});
    draw.AddText({1, 1}, "OK\n\xFF", Color{}, 1.0f);
    assert(draw.command_count() == 2);
    assert(draw.stats().invalid_utf8_bytes == 1);
    draw.Submit(backend);
    assert(backend.begins == 1 && backend.ends == 1 && backend.submissions == 2);
    assert(!draw.overflowed());
    draw.Reset();
    for (std::uint32_t i = 0; i <= DrawList::kMaxCommands; ++i)
        draw.AddRect({0, 0}, {1, 1}, Color{});
    assert(draw.overflowed());

    PadInput pad;
    PadState buttons{};
    buttons.connected = true;
    buttons.buttons = static_cast<std::uint32_t>(PadButton::Cross);
    pad.Update(buttons, 1.0f / 60.0f);
    assert(pad.Pressed(PadButton::Cross));
    assert(pad.navigation().activate);

    ActivationTracker activation;
    InputSettings settings{};
    settings.aim_enabled = true;
    settings.primary = PadButton::L2;
    buttons.buttons = static_cast<std::uint32_t>(PadButton::L2);
    buttons.l2 = 255;
    assert(activation.Update(buttons, settings, false).active);
    assert(!activation.Update(PadState{}, settings, false).active);
    assert(activation.Update(buttons, settings, false).waiting_for_neutral);
    buttons.buttons = 0;
    buttons.l2 = 0;
    assert(!activation.Update(buttons, settings, false).waiting_for_neutral);

    return 0;
}
