#pragma once

#include <cstdint>

namespace internals {

// Values match the Orbis scePad button bit field, but this header deliberately
// has no Orbis dependency so host tests can provide simulated states.
enum class PadButton : std::uint32_t {
    None     = 0x00000000u,
    L3       = 0x00000002u,
    R3       = 0x00000004u,
    Options  = 0x00000008u,
    Up       = 0x00000010u,
    Right    = 0x00000020u,
    Down     = 0x00000040u,
    Left     = 0x00000080u,
    L2       = 0x00000100u,
    R2       = 0x00000200u,
    L1       = 0x00000400u,
    R1       = 0x00000800u,
    Triangle = 0x00001000u,
    Circle   = 0x00002000u,
    Cross    = 0x00004000u,
    Square   = 0x00008000u,
    TouchPad = 0x00100000u,
};

struct PadState {
    std::uint32_t buttons = 0;
    std::int16_t left_x = 0;
    std::int16_t left_y = 0;
    std::int16_t right_x = 0;
    std::int16_t right_y = 0;
    std::uint8_t l2 = 0;
    std::uint8_t r2 = 0;
    bool connected = false;
};

enum class BindingCombination : std::uint8_t {
    Either = 0,
    Both,
};

// Hold and Toggle use the configured binding. Always ignores it, while OnFire
// follows weapon_firing. Every mode requires a connected pad and aim_enabled.
enum class ActivationMode : std::uint8_t {
    Hold = 0,
    Toggle,
    Always,
    OnFire,
};

// MenuConfig storage for controller-driven aim activation. Both feature gates
// default off. The menu owner consumes menu_enabled; ActivationTracker consumes
// aim_enabled and the current menu visibility supplied to Update().
struct InputSettings {
    PadButton primary = PadButton::L2;
    PadButton secondary = PadButton::None;
    BindingCombination combination = BindingCombination::Either;
    ActivationMode mode = ActivationMode::Hold;
    // Zero accepts any nonzero trigger axis. Digital trigger bits always count.
    std::uint8_t analog_threshold = 96;
    bool menu_enabled = false;
    bool aim_enabled = false;
    bool disable_aim_when_menu_open = true;
};

struct ActivationState {
    bool active = false;
    bool activated = false;
    bool deactivated = false;
    bool binding_down = false;
    bool blocked_by_menu = false;
    bool waiting_for_neutral = false;
};

// Stateful edge detection, but otherwise a pure host-testable transform: no
// Orbis calls, wall-clock dependence, allocation, or hidden global state.
class ActivationTracker {
public:
    ActivationTracker() noexcept = default;

    ActivationState Update(const PadState& state, const InputSettings& settings,
                           bool weapon_firing, bool menu_open = false) noexcept;
    void Reset() noexcept;

    const ActivationState& state() const noexcept { return state_; }

private:
    ActivationState state_{};
    bool previous_binding_down_ = false;
    bool toggled_ = false;
    bool waiting_for_neutral_ = false;
};

enum class PadConnection : std::uint8_t {
    Uninitialized = 0,
    Connected,
    Disconnected,
    Reconnecting,
    Fault,
};

struct PadHealth {
    PadConnection connection = PadConnection::Uninitialized;
    std::int32_t user_id = -1;
    std::uint32_t read_failures = 0;
    std::uint32_t reconnect_attempts = 0;
    bool active_user = false;
};

// Edge/repeat state for the existing menu plus left-stick navigation. D-pad
// events take precedence when both a hat direction and the stick are active.
struct MenuNavigation {
    int selection_delta = 0;
    int adjustment_delta = 0;
    bool toggle_open = false;
    bool close = false;
    bool previous_tab = false;
    bool next_tab = false;
    bool activate = false;
    bool reset = false;
    bool unload = false;
};

class PadInput {
public:
    PadInput() noexcept = default;

    // On Orbis, initializes scePad and opens the standard pad for user_id.
    // Host builds return false; use Update() to inject simulated input.
    bool Initialize(std::int32_t user_id) noexcept;
    // Follows sceUserServiceGetForegroundUser across sign-in/controller changes.
    // Requires libSceUserService when linked into the Orbis payload.
    bool InitializeActiveUser() noexcept;
    void Shutdown() noexcept;

    // Polls the opened Orbis pad and advances edges/repeat by delta_seconds.
    // Fatal/read errors close a bad handle and reconnect with bounded backoff.
    bool Poll(float delta_seconds) noexcept;
    // Host-testable state injection; also useful for an external pad reader.
    void Update(const PadState& state, float delta_seconds) noexcept;

    bool Down(PadButton button) const noexcept;
    bool Pressed(PadButton button) const noexcept;
    bool Released(PadButton button) const noexcept;
    bool Repeat(PadButton button) const noexcept;

    void SetRepeatTiming(float initial_delay, float interval) noexcept;
    void SetReconnectTiming(float initial_delay, float maximum_delay) noexcept;

    const PadState& state() const noexcept { return state_; }
    bool initialized() const noexcept { return handle_ >= 0; }
    bool connected() const noexcept { return state_.connected; }
    std::int32_t user_id() const noexcept { return user_id_; }
    const PadHealth& health() const noexcept { return health_; }
    const MenuNavigation& navigation() const noexcept { return navigation_; }

private:
    static constexpr std::uint32_t kButtonBitCount = 24;

    void ResetButtons() noexcept;
    void ClosePad() noexcept;
    bool OpenPad(std::int32_t user_id, bool follow_active_user) noexcept;
    void BuildNavigation() noexcept;
    void ScheduleReconnect() noexcept;
    int AxisDirection(std::int16_t value, int previous) const noexcept;
    bool AxisRepeat(int direction, int previous, float& deadline) noexcept;

    PadState state_{};
    std::uint32_t previous_buttons_ = 0;
    std::uint32_t pressed_buttons_ = 0;
    std::uint32_t released_buttons_ = 0;
    std::uint32_t repeat_buttons_ = 0;
    float repeat_deadlines_[kButtonBitCount]{};
    float elapsed_ = 0.0f;
    float initial_repeat_delay_ = 0.38f;
    float repeat_interval_ = 0.075f;
    std::int32_t handle_ = -1;
    std::int32_t user_id_ = -1;
    bool follow_active_user_ = false;
    bool suppress_until_neutral_ = false;
    PadHealth health_{};
    MenuNavigation navigation_{};
    int stick_x_direction_ = 0;
    int stick_y_direction_ = 0;
    float stick_x_deadline_ = 0.0f;
    float stick_y_deadline_ = 0.0f;
    float reconnect_delay_ = 0.25f;
    float reconnect_maximum_delay_ = 2.0f;
    float next_reconnect_seconds_ = 0.0f;
    std::uint32_t reconnect_backoff_ = 0;
};

} // namespace internals
