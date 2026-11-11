#include "../include/internals/input.hpp"

#if defined(__PS4__)
#include <cstddef>
extern "C" {
struct ScePadAnalogStick { std::uint8_t x; std::uint8_t y; };
struct ScePadAnalogButtons { std::uint8_t l2; std::uint8_t r2; std::uint8_t padding[2]; };
struct ScePadData {
    std::uint32_t buttons;
    ScePadAnalogStick left_stick;
    ScePadAnalogStick right_stick;
    ScePadAnalogButtons analog_buttons;
    unsigned char orientation[16];
    unsigned char acceleration[12];
    unsigned char angular_velocity[12];
    unsigned char touch_data[24];
    bool connected;
    std::uint64_t timestamp;
    unsigned char extension[16];
    std::uint8_t count;
    unsigned char reserved[15];
};
static_assert(sizeof(ScePadData) == 120, "ScePadData ABI mismatch");
static_assert(offsetof(ScePadData, connected) == 76, "ScePadData connected ABI mismatch");
static_assert(offsetof(ScePadData, timestamp) == 80, "ScePadData timestamp ABI mismatch");
static_assert(offsetof(ScePadData, count) == 104, "ScePadData count ABI mismatch");
int scePadInit(void);
int scePadOpen(int user_id, int type, int index, void* parameter);
int scePadClose(int handle);
int scePadReadState(int handle, ScePadData* data);
int sceUserServiceInitialize(void* parameter);
int sceUserServiceGetForegroundUser(std::int32_t* user_id);
}
#endif

namespace internals {
namespace {
constexpr std::uint32_t Mask(PadButton button) noexcept {
    return static_cast<std::uint32_t>(button);
}
bool BindingDown(PadButton button, const PadState& state, std::uint8_t threshold) noexcept {
    if (button == PadButton::None) return false;
    if ((state.buttons & Mask(button)) != 0) return true;
    const std::uint8_t axis = button == PadButton::L2 ? state.l2
                              : button == PadButton::R2 ? state.r2 : 0;
    return axis != 0 && axis >= threshold;
}
bool AnyBindingDown(const PadState& state, const InputSettings& settings) noexcept {
    return BindingDown(settings.primary, state, settings.analog_threshold) ||
           BindingDown(settings.secondary, state, settings.analog_threshold);
}
bool CombinedBindingDown(const PadState& state, const InputSettings& settings) noexcept {
    const bool primary = BindingDown(settings.primary, state, settings.analog_threshold);
    const bool secondary = BindingDown(settings.secondary, state, settings.analog_threshold);
    if (settings.combination == BindingCombination::Either) return primary || secondary;
    if (settings.primary == PadButton::None) return secondary;
    if (settings.secondary == PadButton::None) return primary;
    return primary && secondary;
}
#if defined(__PS4__)
std::int16_t Axis(std::uint8_t value) noexcept {
    return static_cast<std::int16_t>(static_cast<int>(value) - 128);
}
#endif
float PositiveDelta(float delta) noexcept {
    return __builtin_isfinite(delta) && delta > 0.0f ? delta : 0.0f;
}
#if defined(__PS4__)
// Namespace storage avoids __cxa_guard dependencies in the minimal Orbis link.
bool pad_initialized = false;
bool user_service_initialized = false;
float next_user_check = 0.0f;
#endif
}

ActivationState ActivationTracker::Update(const PadState& state, const InputSettings& settings,
                                          bool weapon_firing, bool menu_open) noexcept {
    ActivationState next{};
    next.blocked_by_menu = menu_open && settings.disable_aim_when_menu_open;

    if (!state.connected) {
        // A disconnect is also a latch reset. In particular, a held Toggle
        // binding must not activate aim again when the controller returns.
        previous_binding_down_ = false;
        toggled_ = false;
        waiting_for_neutral_ = true;
    } else {
        next.binding_down = AnyBindingDown(state, settings);
        const bool required_binding_down = CombinedBindingDown(state, settings);
        if (waiting_for_neutral_ && !next.binding_down) waiting_for_neutral_ = false;

        const bool enabled = settings.aim_enabled && !next.blocked_by_menu &&
                             !waiting_for_neutral_;
        if (settings.mode != ActivationMode::Toggle || !enabled) toggled_ = false;

        switch (settings.mode) {
        case ActivationMode::Hold:
            next.active = enabled && required_binding_down;
            break;
        case ActivationMode::Toggle:
            if (enabled && required_binding_down && !previous_binding_down_) toggled_ = !toggled_;
            next.active = enabled && toggled_;
            break;
        case ActivationMode::Always:
            next.active = enabled;
            break;
        case ActivationMode::OnFire:
            next.active = enabled && weapon_firing;
            break;
        }
        previous_binding_down_ = required_binding_down;
    }

    next.activated = next.active && !state_.active;
    next.deactivated = !next.active && state_.active;
    next.waiting_for_neutral = waiting_for_neutral_;
    state_ = next;
    return state_;
}

void ActivationTracker::Reset() noexcept {
    state_ = ActivationState{};
    previous_binding_down_ = false;
    toggled_ = false;
    waiting_for_neutral_ = false;
}

void PadInput::ResetButtons() noexcept {
    previous_buttons_ = pressed_buttons_ = released_buttons_ = repeat_buttons_ = 0;
    for (float& deadline : repeat_deadlines_) deadline = 0.0f;
    navigation_ = MenuNavigation{};
    stick_x_direction_ = stick_y_direction_ = 0;
}

void PadInput::ClosePad() noexcept {
#if defined(__PS4__)
    if (handle_ >= 0) scePadClose(handle_);
#endif
    handle_ = -1;
    state_ = PadState{};
    health_.connection = PadConnection::Disconnected;
    ResetButtons();
}

bool PadInput::OpenPad(std::int32_t user_id, bool follow_active_user) noexcept {
    user_id_ = user_id;
    follow_active_user_ = follow_active_user;
    health_.user_id = user_id;
    health_.active_user = follow_active_user;
#if defined(__PS4__)
    // Initialized once for the resident process.
    if (!pad_initialized) {
        if (scePadInit() < 0) {
            health_.connection = PadConnection::Fault;
            return false;
        }
        pad_initialized = true;
    }
    handle_ = scePadOpen(user_id, 0, 0, nullptr);
    if (handle_ < 0) {
        health_.connection = PadConnection::Disconnected;
        return false;
    }
    health_.connection = PadConnection::Connected;
    return true;
#else
    (void)user_id;
    (void)follow_active_user;
    return false;
#endif
}

bool PadInput::Initialize(std::int32_t user_id) noexcept {
    Shutdown();
    return OpenPad(user_id, false);
}

bool PadInput::InitializeActiveUser() noexcept {
    Shutdown();
    follow_active_user_ = true;
#if defined(__PS4__)
    // Initialized once for the resident process.
    if (!user_service_initialized) {
        if (sceUserServiceInitialize(nullptr) < 0) {
            health_.connection = PadConnection::Fault;
            return false;
        }
        user_service_initialized = true;
    }
    std::int32_t user = -1;
    if (sceUserServiceGetForegroundUser(&user) < 0 || user < 0) {
        health_.connection = PadConnection::Disconnected;
        ScheduleReconnect();
        return false;
    }
    return OpenPad(user, true);
#else
    health_.connection = PadConnection::Disconnected;
    return false;
#endif
}

void PadInput::Shutdown() noexcept {
    ClosePad();
    health_ = PadHealth{};
    elapsed_ = 0.0f;
    next_reconnect_seconds_ = 0.0f;
    reconnect_backoff_ = 0;
    suppress_until_neutral_ = false;
}

void PadInput::ScheduleReconnect() noexcept {
    ClosePad();
    health_.connection = PadConnection::Reconnecting;
    reconnect_delay_ = reconnect_delay_ > 0.0f ? reconnect_delay_ : 0.25f;
    const unsigned shift = reconnect_backoff_ < 4 ? reconnect_backoff_ : 4;
    float delay = reconnect_delay_ * static_cast<float>(1u << shift);
    if (delay > reconnect_maximum_delay_) delay = reconnect_maximum_delay_;
    next_reconnect_seconds_ = elapsed_ + delay;
    if (reconnect_backoff_ < 8) ++reconnect_backoff_;
    ++health_.reconnect_attempts;
}

bool PadInput::Poll(float delta_seconds) noexcept {
#if defined(__PS4__)
    const float delta = PositiveDelta(delta_seconds);
    if (handle_ < 0) {
        if (elapsed_ >= next_reconnect_seconds_) {
            std::int32_t user = user_id_;
            if (follow_active_user_) {
                user = -1;
                if (sceUserServiceGetForegroundUser(&user) < 0) user = -1;
            }
            if (user >= 0 && OpenPad(user, follow_active_user_)) {
                reconnect_backoff_ = 0;
                suppress_until_neutral_ = true;
            } else {
                ScheduleReconnect();
            }
        }
        Update(PadState{}, delta);
        return false;
    }
    if (follow_active_user_) {
        // Rate-limit foreground-user polling.
        if (elapsed_ >= next_user_check) {
            next_user_check = elapsed_ + 1.0f;
            std::int32_t active = -1;
            if (sceUserServiceGetForegroundUser(&active) == 0 && active >= 0 && active != user_id_) {
                ClosePad();
                if (!OpenPad(active, true)) ScheduleReconnect();
                Update(PadState{}, delta);
                return false;
            }
        }
    }
    ScePadData data{};
    if (scePadReadState(handle_, &data) < 0 || !data.connected) {
        ++health_.read_failures;
        ScheduleReconnect();
        Update(PadState{}, delta);
        return false;
    }
    PadState state{};
    state.buttons = data.buttons;
    state.left_x = Axis(data.left_stick.x);
    state.left_y = Axis(data.left_stick.y);
    state.right_x = Axis(data.right_stick.x);
    state.right_y = Axis(data.right_stick.y);
    state.l2 = data.analog_buttons.l2;
    state.r2 = data.analog_buttons.r2;
    state.connected = true;
    health_.connection = PadConnection::Connected;
    Update(state, delta);
    return true;
#else
    (void)delta_seconds;
    return false;
#endif
}

void PadInput::Update(const PadState& state, float delta_seconds) noexcept {
    const float delta = PositiveDelta(delta_seconds);
    elapsed_ += delta;
    const std::uint32_t buttons = state.connected ? state.buttons : 0u;
    pressed_buttons_ = buttons & ~previous_buttons_;
    released_buttons_ = previous_buttons_ & ~buttons;
    repeat_buttons_ = pressed_buttons_;
    for (std::uint32_t bit = 0; bit < kButtonBitCount; ++bit) {
        const std::uint32_t mask = 1u << bit;
        if (pressed_buttons_ & mask) {
            repeat_deadlines_[bit] = elapsed_ + initial_repeat_delay_;
        } else if ((buttons & mask) && (previous_buttons_ & mask)) {
            float& deadline = repeat_deadlines_[bit];
            if (initial_repeat_delay_ <= 0.0f || repeat_interval_ <= 0.0f) {
                repeat_buttons_ |= mask;
            } else {
                unsigned emitted = 0;
                while (elapsed_ >= deadline && emitted < 64) {
                    repeat_buttons_ |= mask;
                    deadline += repeat_interval_;
                    ++emitted;
                }
                if (emitted == 64 && elapsed_ >= deadline) deadline = elapsed_ + repeat_interval_;
            }
        } else if (!(buttons & mask)) {
            repeat_deadlines_[bit] = 0.0f;
        }
    }
    previous_buttons_ = buttons;
    state_ = state;
    if (!state.connected) state_.buttons = 0;
    if (suppress_until_neutral_) {
        pressed_buttons_ = released_buttons_ = repeat_buttons_ = 0;
        if (buttons == 0) suppress_until_neutral_ = false;
    }
    BuildNavigation();
}

int PadInput::AxisDirection(std::int16_t value, int previous) const noexcept {
    if (value > 72 && previous <= 72) return 1;
    if (value < -72 && previous >= -72) return -1;
    return 0;
}

bool PadInput::AxisRepeat(int direction, int previous, float& deadline) noexcept {
    if (direction == 0) {
        deadline = 0.0f;
        return false;
    }
    if (direction != previous) {
        deadline = elapsed_ + initial_repeat_delay_;
        return true;
    }
    if (elapsed_ >= deadline) {
        deadline = elapsed_ + repeat_interval_;
        return true;
    }
    return false;
}

void PadInput::BuildNavigation() noexcept {
    navigation_ = MenuNavigation{};
    const bool l3 = Down(PadButton::L3);
    const bool r3 = Down(PadButton::R3);
    navigation_.toggle_open = l3 && r3 && (Pressed(PadButton::L3) || Pressed(PadButton::R3));
    navigation_.unload = Down(PadButton::Options) && Pressed(PadButton::Triangle);
    navigation_.close = Pressed(PadButton::Circle);
    navigation_.activate = Pressed(PadButton::Cross);
    navigation_.reset = Pressed(PadButton::Square);
    navigation_.previous_tab = Pressed(PadButton::L1);
    navigation_.next_tab = Pressed(PadButton::R1);
    if (Repeat(PadButton::Up)) navigation_.selection_delta = -1;
    else if (Repeat(PadButton::Down)) navigation_.selection_delta = 1;
    if (Repeat(PadButton::Left)) navigation_.adjustment_delta = -1;
    else if (Repeat(PadButton::Right)) navigation_.adjustment_delta = 1;
    const int previous_x = stick_x_direction_;
    const int previous_y = stick_y_direction_;
    stick_x_direction_ = state_.right_x > 72 ? 1 : state_.right_x < -72 ? -1 : 0;
    stick_y_direction_ = state_.right_y > 72 ? 1 : state_.right_y < -72 ? -1 : 0;
    if (navigation_.selection_delta == 0 && AxisRepeat(stick_y_direction_, previous_y, stick_y_deadline_))
        navigation_.selection_delta = stick_y_direction_;
    if (navigation_.adjustment_delta == 0 && AxisRepeat(stick_x_direction_, previous_x, stick_x_deadline_))
        navigation_.adjustment_delta = stick_x_direction_;
}

bool PadInput::Down(PadButton button) const noexcept {
    return state_.connected && (state_.buttons & Mask(button)) != 0;
}
bool PadInput::Pressed(PadButton button) const noexcept { return (pressed_buttons_ & Mask(button)) != 0; }
bool PadInput::Released(PadButton button) const noexcept { return (released_buttons_ & Mask(button)) != 0; }
bool PadInput::Repeat(PadButton button) const noexcept { return (repeat_buttons_ & Mask(button)) != 0; }
void PadInput::SetRepeatTiming(float initial_delay, float interval) noexcept {
    initial_repeat_delay_ = PositiveDelta(initial_delay);
    repeat_interval_ = PositiveDelta(interval);
}
void PadInput::SetReconnectTiming(float initial_delay, float maximum_delay) noexcept {
    reconnect_delay_ = PositiveDelta(initial_delay);
    reconnect_maximum_delay_ = reconnect_delay_;
    if (PositiveDelta(maximum_delay) >= reconnect_delay_) reconnect_maximum_delay_ = maximum_delay;
}

} // namespace internals
