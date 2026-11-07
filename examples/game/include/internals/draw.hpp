#pragma once

#include <cstddef>
#include <cstdint>

namespace internals {

struct Vec2 {
    float x = 0.0f;
    float y = 0.0f;

    constexpr Vec2() = default;
    constexpr Vec2(float x_value, float y_value) : x(x_value), y(y_value) {}
};

struct Rect {
    float left = 0.0f;
    float top = 0.0f;
    float right = 0.0f;
    float bottom = 0.0f;

    constexpr Rect() = default;
    constexpr Rect(float left_value, float top_value, float right_value, float bottom_value)
        : left(left_value), top(top_value), right(right_value), bottom(bottom_value) {}

    static constexpr Rect FromMinMax(Vec2 minimum, Vec2 maximum) {
        return Rect(minimum.x, minimum.y, maximum.x, maximum.y);
    }
};

struct Color {
    std::uint8_t r = 255;
    std::uint8_t g = 255;
    std::uint8_t b = 255;
    std::uint8_t a = 255;

    constexpr Color() = default;
    constexpr Color(std::uint8_t red, std::uint8_t green, std::uint8_t blue,
                    std::uint8_t alpha = 255)
        : r(red), g(green), b(blue), a(alpha) {}

    constexpr Color WithAlpha(std::uint8_t alpha) const {
        return Color(r, g, b, alpha);
    }
};

struct DrawVertex {
    Vec2 position;
    // Negative coordinates denote a solid vertex. Non-negative coordinates sample
    // the single-channel embedded font atlas supplied by GetBitmapFont().
    Vec2 uv{-1.0f, -1.0f};
    Color color{};
};

// The atlas is a horizontal strip of 96 glyphs. Each glyph uses six by eight
// pixels; the first five bytes are columns, bit zero being the top pixel. The
// final row and column are blank. Backends can expand this data once at init.
struct BitmapFont {
    const std::uint8_t* glyphs;
    std::uint32_t first_character;
    std::uint32_t character_count;
    std::uint32_t glyph_width;
    std::uint32_t glyph_height;
    std::uint32_t bytes_per_glyph;
    std::uint32_t atlas_width;
    std::uint32_t atlas_height;
};

const BitmapFont& GetBitmapFont() noexcept;

struct DrawSubmission {
    const DrawVertex* vertices;
    const std::uint16_t* indices;
    std::uint32_t vertex_count;
    std::uint32_t index_count;
    Rect clip;
    bool clip_enabled;
};

class DrawBackend {
public:
    virtual ~DrawBackend() = default;
    // DrawList brackets all commands in one frame so stateful backends can share
    // a single rasterization budget. Existing backends need no frame state.
    virtual void BeginFrame() noexcept {}
    virtual void Submit(const DrawSubmission& submission) = 0;
    virtual void EndFrame() noexcept {}
};

// Per-frame drawing counters. Peak values are retained across Reset() calls;
// all other values describe the frame currently being built.
struct DrawStats {
    std::uint32_t commands = 0;
    std::uint32_t vertices = 0;
    std::uint32_t indices = 0;
    std::uint32_t peak_commands = 0;
    std::uint32_t peak_vertices = 0;
    std::uint32_t peak_indices = 0;
    std::uint32_t text_commands = 0;
    std::uint32_t glyph_quads = 0;
    std::uint32_t text_bytes = 0;
    std::uint32_t fallback_glyphs = 0;
    std::uint32_t invalid_utf8_bytes = 0;
    std::uint32_t truncated_texts = 0;
    std::uint32_t clipped_texts = 0;
    std::uint32_t clipped_glyphs = 0;
    std::uint32_t dropped_commands = 0;
    std::uint32_t overflow_events = 0;
};

// A persistent, fixed-capacity geometry command buffer. Reset it at the start
// of each frame; no operation in this class allocates memory.
class DrawList {
public:
    static constexpr std::uint32_t kMaxCommands = 8192;
    static constexpr std::uint32_t kMaxVertices = 32768;
    static constexpr std::uint32_t kMaxIndices = 49152;
    static constexpr std::uint32_t kMaxClipDepth = 16;
    // Text APIs never inspect beyond this many bytes, even for unterminated or
    // malformed input. Valid non-ASCII code points use the '?' glyph fallback.
    static constexpr std::size_t kMaxTextBytes = 16384;

    DrawList() noexcept;

    void Reset() noexcept;
    void Submit(DrawBackend& backend) const noexcept;

    bool PushClip(Rect clip) noexcept;
    void PopClip() noexcept;

    void AddLine(Vec2 start, Vec2 end, Color color, float thickness = 1.0f) noexcept;
    void AddRect(Vec2 minimum, Vec2 maximum, Color color) noexcept;
    void AddRectOutline(Vec2 minimum, Vec2 maximum, Color color,
                        float thickness = 1.0f) noexcept;
    void AddCircle(Vec2 center, float radius, Color color,
                   std::uint32_t segments = 0) noexcept;
    void AddCircleOutline(Vec2 center, float radius, Color color,
                          float thickness = 1.0f, std::uint32_t segments = 0) noexcept;
    Vec2 AddText(Vec2 position, const char* text, Color color,
                 float scale = 1.0f) noexcept;

    static Vec2 MeasureText(const char* text, float scale = 1.0f) noexcept;

    bool overflowed() const noexcept { return overflowed_; }
    const DrawStats& stats() const noexcept { return stats_; }
    std::uint32_t command_count() const noexcept { return stats_.commands; }
    std::uint32_t vertex_count() const noexcept { return stats_.vertices; }
    std::uint32_t index_count() const noexcept { return stats_.indices; }

private:
    struct Command {
        std::uint32_t vertex_offset;
        std::uint32_t index_offset;
        std::uint32_t vertex_count;
        std::uint32_t index_count;
        Rect clip;
        bool clip_enabled;
    };

    Command* Reserve(std::uint32_t vertices, std::uint32_t indices) noexcept;
    void NoteOverflow() noexcept;
    void WriteQuad(Command& command, Vec2 a, Vec2 b, Vec2 c, Vec2 d,
                   Color color) noexcept;
    void WriteRect(Command& command, Vec2 minimum, Vec2 maximum, Color color) noexcept;
    void WriteGlyphQuad(Command& command, std::uint32_t quad, Vec2 position,
                        std::uint32_t glyph, Color color, float scale) noexcept;
    bool ClipIsEmpty() const noexcept;

    DrawVertex vertices_[kMaxVertices]{};
    std::uint16_t indices_[kMaxIndices]{};
    Command commands_[kMaxCommands]{};
    Rect clips_[kMaxClipDepth]{};
    bool clip_enabled_[kMaxClipDepth]{};
    DrawStats stats_{};
    std::uint32_t clip_depth_ = 0;
    bool overflowed_ = false;
};

} // namespace internals
