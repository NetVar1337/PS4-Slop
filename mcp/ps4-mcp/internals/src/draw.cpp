#include "../include/internals/draw.hpp"


namespace internals {
namespace {

// Printable ASCII, encoded as five vertical columns per glyph.
constexpr std::uint8_t kGlyphs[96][5] = {
    {0x00,0x00,0x00,0x00,0x00}, {0x00,0x00,0x5f,0x00,0x00}, {0x00,0x07,0x00,0x07,0x00},
    {0x14,0x7f,0x14,0x7f,0x14}, {0x24,0x2a,0x7f,0x2a,0x12}, {0x23,0x13,0x08,0x64,0x62},
    {0x36,0x49,0x55,0x22,0x50}, {0x00,0x05,0x03,0x00,0x00}, {0x00,0x1c,0x22,0x41,0x00},
    {0x00,0x41,0x22,0x1c,0x00}, {0x14,0x08,0x3e,0x08,0x14}, {0x08,0x08,0x3e,0x08,0x08},
    {0x00,0x50,0x30,0x00,0x00}, {0x08,0x08,0x08,0x08,0x08}, {0x00,0x60,0x60,0x00,0x00},
    {0x20,0x10,0x08,0x04,0x02}, {0x3e,0x51,0x49,0x45,0x3e}, {0x00,0x42,0x7f,0x40,0x00},
    {0x42,0x61,0x51,0x49,0x46}, {0x21,0x41,0x45,0x4b,0x31}, {0x18,0x14,0x12,0x7f,0x10},
    {0x27,0x45,0x45,0x45,0x39}, {0x3c,0x4a,0x49,0x49,0x30}, {0x01,0x71,0x09,0x05,0x03},
    {0x36,0x49,0x49,0x49,0x36}, {0x06,0x49,0x49,0x29,0x1e}, {0x00,0x36,0x36,0x00,0x00},
    {0x00,0x56,0x36,0x00,0x00}, {0x08,0x14,0x22,0x41,0x00}, {0x14,0x14,0x14,0x14,0x14},
    {0x00,0x41,0x22,0x14,0x08}, {0x02,0x01,0x51,0x09,0x06}, {0x32,0x49,0x79,0x41,0x3e},
    {0x7e,0x11,0x11,0x11,0x7e}, {0x7f,0x49,0x49,0x49,0x36}, {0x3e,0x41,0x41,0x41,0x22},
    {0x7f,0x41,0x41,0x22,0x1c}, {0x7f,0x49,0x49,0x49,0x41}, {0x7f,0x09,0x09,0x09,0x01},
    {0x3e,0x41,0x49,0x49,0x7a}, {0x7f,0x08,0x08,0x08,0x7f}, {0x00,0x41,0x7f,0x41,0x00},
    {0x20,0x40,0x41,0x3f,0x01}, {0x7f,0x08,0x14,0x22,0x41}, {0x7f,0x40,0x40,0x40,0x40},
    {0x7f,0x02,0x0c,0x02,0x7f}, {0x7f,0x04,0x08,0x10,0x7f}, {0x3e,0x41,0x41,0x41,0x3e},
    {0x7f,0x09,0x09,0x09,0x06}, {0x3e,0x41,0x51,0x21,0x5e}, {0x7f,0x09,0x19,0x29,0x46},
    {0x46,0x49,0x49,0x49,0x31}, {0x01,0x01,0x7f,0x01,0x01}, {0x3f,0x40,0x40,0x40,0x3f},
    {0x1f,0x20,0x40,0x20,0x1f}, {0x3f,0x40,0x38,0x40,0x3f}, {0x63,0x14,0x08,0x14,0x63},
    {0x07,0x08,0x70,0x08,0x07}, {0x61,0x51,0x49,0x45,0x43}, {0x00,0x7f,0x41,0x41,0x00},
    {0x02,0x04,0x08,0x10,0x20}, {0x00,0x41,0x41,0x7f,0x00}, {0x04,0x02,0x01,0x02,0x04},
    {0x40,0x40,0x40,0x40,0x40}, {0x00,0x01,0x02,0x04,0x00}, {0x20,0x54,0x54,0x54,0x78},
    {0x7f,0x48,0x44,0x44,0x38}, {0x38,0x44,0x44,0x44,0x20}, {0x38,0x44,0x44,0x48,0x7f},
    {0x38,0x54,0x54,0x54,0x18}, {0x08,0x7e,0x09,0x01,0x02}, {0x0c,0x52,0x52,0x52,0x3e},
    {0x7f,0x08,0x04,0x04,0x78}, {0x00,0x44,0x7d,0x40,0x00}, {0x20,0x40,0x44,0x3d,0x00},
    {0x7f,0x10,0x28,0x44,0x00}, {0x00,0x41,0x7f,0x40,0x00}, {0x7c,0x04,0x18,0x04,0x78},
    {0x7c,0x08,0x04,0x04,0x78}, {0x38,0x44,0x44,0x44,0x38}, {0x7c,0x14,0x14,0x14,0x08},
    {0x08,0x14,0x14,0x18,0x7c}, {0x7c,0x08,0x04,0x04,0x08}, {0x48,0x54,0x54,0x54,0x20},
    {0x04,0x3f,0x44,0x40,0x20}, {0x3c,0x40,0x40,0x20,0x7c}, {0x1c,0x20,0x40,0x20,0x1c},
    {0x3c,0x40,0x30,0x40,0x3c}, {0x44,0x28,0x10,0x28,0x44}, {0x0c,0x50,0x50,0x50,0x3c},
    {0x44,0x64,0x54,0x4c,0x44}, {0x00,0x08,0x36,0x41,0x00}, {0x00,0x00,0x7f,0x00,0x00},
    {0x00,0x41,0x36,0x08,0x00}, {0x08,0x08,0x2a,0x1c,0x08},
};

const BitmapFont kFont{&kGlyphs[0][0], 32, 96, 6, 8, 5, 576, 8};

float ClampPositive(float value) noexcept {
    return __builtin_isfinite(value) && value > 0.0f ? value : 0.0f;
}

struct DecodedCodePoint {
    std::uint32_t value;
    std::size_t size;
    bool valid;
};

bool IsContinuation(unsigned char value) noexcept {
    return (value & 0xc0u) == 0x80u;
}

// Decode exactly one code point without reading a terminator or crossing the
// caller's byte bound. Invalid input consumes one byte so decoding always
// progresses and each offending byte is observable in the draw counters.
DecodedCodePoint DecodeUtf8(const unsigned char* text, std::size_t remaining) noexcept {
    const unsigned char a = text[0];
    if (a < 0x80u) return {a, 1, true};

    if (a >= 0xc2u && a <= 0xdfu && remaining >= 2 && text[1] != 0 &&
        IsContinuation(text[1])) {
        return {static_cast<std::uint32_t>((a & 0x1fu) << 6) |
                    static_cast<std::uint32_t>(text[1] & 0x3fu),
                2, true};
    }

    if (a >= 0xe0u && a <= 0xefu && remaining >= 3 && text[1] != 0 &&
        text[2] != 0 && IsContinuation(text[1]) && IsContinuation(text[2]) &&
        (a != 0xe0u || text[1] >= 0xa0u) &&
        (a != 0xedu || text[1] < 0xa0u)) {
        return {static_cast<std::uint32_t>((a & 0x0fu) << 12) |
                    static_cast<std::uint32_t>((text[1] & 0x3fu) << 6) |
                    static_cast<std::uint32_t>(text[2] & 0x3fu),
                3, true};
    }

    if (a >= 0xf0u && a <= 0xf4u && remaining >= 4 && text[1] != 0 &&
        text[2] != 0 && text[3] != 0 && IsContinuation(text[1]) &&
        IsContinuation(text[2]) && IsContinuation(text[3]) &&
        (a != 0xf0u || text[1] >= 0x90u) &&
        (a != 0xf4u || text[1] < 0x90u)) {
        return {static_cast<std::uint32_t>((a & 0x07u) << 18) |
                    static_cast<std::uint32_t>((text[1] & 0x3fu) << 12) |
                    static_cast<std::uint32_t>((text[2] & 0x3fu) << 6) |
                    static_cast<std::uint32_t>(text[3] & 0x3fu),
                4, true};
    }

    return {'?', 1, false};
}

bool OverlapsClip(Vec2 minimum, Vec2 maximum, const Rect* clip) noexcept {
    return !clip || (maximum.x > clip->left && minimum.x < clip->right &&
                     maximum.y > clip->top && minimum.y < clip->bottom);
}

struct TextAnalysis {
    Vec2 size{};
    std::uint32_t glyph_count = 0;
    std::uint32_t visible_glyph_count = 0;
    std::uint32_t fallback_count = 0;
    std::uint32_t invalid_count = 0;
    std::uint32_t byte_count = 0;
    bool truncated = false;
};

TextAnalysis AnalyzeText(const char* text, float scale, Vec2 origin,
                         const Rect* clip) noexcept {
    TextAnalysis analysis;
    const unsigned char* bytes = reinterpret_cast<const unsigned char*>(text);
    const Vec2 start = origin;
    std::uint32_t line = 0;
    std::uint32_t widest = 0;
    std::uint32_t lines = 1;
    std::size_t offset = 0;

    while (offset < DrawList::kMaxTextBytes && bytes[offset] != 0) {
        const DecodedCodePoint decoded =
            DecodeUtf8(bytes + offset, DrawList::kMaxTextBytes - offset);
        offset += decoded.size;
        if (!decoded.valid) ++analysis.invalid_count;

        if (decoded.valid && decoded.value == '\n') {
            widest = line > widest ? line : widest;
            line = 0;
            ++lines;
            origin.x = start.x;
            origin.y += 8.0f * scale;
            continue;
        }
        if (decoded.valid && decoded.value == '\r') continue;

        std::uint32_t character = decoded.value;
        if (!decoded.valid || character < kFont.first_character ||
            character >= kFont.first_character + kFont.character_count) {
            character = '?';
            ++analysis.fallback_count;
        }
        ++line;

        if (character != ' ') {
            ++analysis.glyph_count;
            const Vec2 maximum{origin.x + 5.0f * scale, origin.y + 7.0f * scale};
            if (OverlapsClip(origin, maximum, clip)) ++analysis.visible_glyph_count;
        }
        origin.x += 6.0f * scale;
    }

    widest = line > widest ? line : widest;
    analysis.size = {static_cast<float>(widest) * 6.0f * scale,
                     static_cast<float>(lines) * 8.0f * scale};
    analysis.byte_count = static_cast<std::uint32_t>(offset);
    analysis.truncated = offset == DrawList::kMaxTextBytes;
    return analysis;
}

} // namespace

const BitmapFont& GetBitmapFont() noexcept { return kFont; }

DrawList::DrawList() noexcept = default;

void DrawList::Reset() noexcept {
    clip_depth_ = 0;
    stats_.commands = 0;
    stats_.vertices = 0;
    stats_.indices = 0;
    stats_.text_commands = 0;
    stats_.glyph_quads = 0;
    stats_.text_bytes = 0;
    stats_.fallback_glyphs = 0;
    stats_.invalid_utf8_bytes = 0;
    stats_.truncated_texts = 0;
    stats_.clipped_texts = 0;
    stats_.clipped_glyphs = 0;
    stats_.dropped_commands = 0;
    stats_.overflow_events = 0;
    overflowed_ = false;
}

void DrawList::Submit(DrawBackend& backend) const noexcept {
    backend.BeginFrame();
    for (std::uint32_t i = 0; i < stats_.commands; ++i) {
        const Command& command = commands_[i];
        DrawSubmission submission{vertices_ + command.vertex_offset,
                                  indices_ + command.index_offset,
                                  command.vertex_count, command.index_count,
                                  command.clip, command.clip_enabled};
        backend.Submit(submission);
    }
    backend.EndFrame();
}

bool DrawList::PushClip(Rect clip) noexcept {
    if (clip_depth_ >= kMaxClipDepth) {
        NoteOverflow();
        return false;
    }
    if (clip_depth_ != 0 && clip_enabled_[clip_depth_ - 1]) {
        const Rect& parent = clips_[clip_depth_ - 1];
        clip.left = clip.left > parent.left ? clip.left : parent.left;
        clip.top = clip.top > parent.top ? clip.top : parent.top;
        clip.right = clip.right < parent.right ? clip.right : parent.right;
        clip.bottom = clip.bottom < parent.bottom ? clip.bottom : parent.bottom;
    }
    clips_[clip_depth_] = clip;
    clip_enabled_[clip_depth_] = true;
    ++clip_depth_;
    return true;
}

void DrawList::PopClip() noexcept {
    if (clip_depth_ == 0) {
        NoteOverflow();
        return;
    }
    --clip_depth_;
}

bool DrawList::ClipIsEmpty() const noexcept {
    if (clip_depth_ == 0) return false;
    const Rect& clip = clips_[clip_depth_ - 1];
    return clip.right <= clip.left || clip.bottom <= clip.top;
}

void DrawList::NoteOverflow() noexcept {
    overflowed_ = true;
    ++stats_.overflow_events;
}

DrawList::Command* DrawList::Reserve(std::uint32_t vertices, std::uint32_t indices) noexcept {
    if (ClipIsEmpty()) return nullptr;
    if (vertices > kMaxVertices - stats_.vertices ||
        indices > kMaxIndices - stats_.indices || stats_.commands >= kMaxCommands) {
        NoteOverflow();
        ++stats_.dropped_commands;
        return nullptr;
    }
    // A uint16_t index is relative to the command's vertex offset.
    if (vertices != 0 && stats_.vertices + vertices - 1 > 65535u) {
        NoteOverflow();
        ++stats_.dropped_commands;
        return nullptr;
    }
    Command& command = commands_[stats_.commands++];
    command.vertex_offset = stats_.vertices;
    command.index_offset = stats_.indices;
    command.vertex_count = vertices;
    command.index_count = indices;
    command.clip = clip_depth_ ? clips_[clip_depth_ - 1] : Rect{};
    command.clip_enabled = clip_depth_ != 0;
    stats_.vertices += vertices;
    stats_.indices += indices;
    if (stats_.commands > stats_.peak_commands) stats_.peak_commands = stats_.commands;
    if (stats_.vertices > stats_.peak_vertices) stats_.peak_vertices = stats_.vertices;
    if (stats_.indices > stats_.peak_indices) stats_.peak_indices = stats_.indices;
    return &command;
}

void DrawList::WriteQuad(Command& command, Vec2 a, Vec2 b, Vec2 c, Vec2 d,
                         Color color) noexcept {
    const std::uint32_t offset = command.vertex_offset;
    vertices_[offset + 0] = DrawVertex{a, {-1.0f, -1.0f}, color};
    vertices_[offset + 1] = DrawVertex{b, {-1.0f, -1.0f}, color};
    vertices_[offset + 2] = DrawVertex{c, {-1.0f, -1.0f}, color};
    vertices_[offset + 3] = DrawVertex{d, {-1.0f, -1.0f}, color};
    const std::uint32_t index = command.index_offset;
    indices_[index + 0] = 0; indices_[index + 1] = 1; indices_[index + 2] = 2;
    indices_[index + 3] = 0; indices_[index + 4] = 2; indices_[index + 5] = 3;
}

void DrawList::WriteRect(Command& command, Vec2 minimum, Vec2 maximum, Color color) noexcept {
    WriteQuad(command, minimum, {maximum.x, minimum.y}, maximum, {minimum.x, maximum.y}, color);
}

void DrawList::WriteGlyphQuad(Command& command, std::uint32_t quad, Vec2 position,
                              std::uint32_t glyph, Color color, float scale) noexcept {
    const float right = position.x + 5.0f * scale;
    const float bottom = position.y + 7.0f * scale;
    const float u = static_cast<float>(glyph * kFont.glyph_width);
    const float glyph_width = static_cast<float>(kFont.bytes_per_glyph);
    const float glyph_height = static_cast<float>(kFont.glyph_height - 1);
    const std::uint32_t vertex = command.vertex_offset + quad * 4;
    vertices_[vertex + 0] = DrawVertex{position, {u, 0.0f}, color};
    vertices_[vertex + 1] = DrawVertex{{right, position.y}, {u + glyph_width, 0.0f}, color};
    vertices_[vertex + 2] = DrawVertex{{right, bottom}, {u + glyph_width, glyph_height}, color};
    vertices_[vertex + 3] = DrawVertex{{position.x, bottom}, {u, glyph_height}, color};

    const std::uint32_t index = command.index_offset + quad * 6;
    const std::uint16_t base = static_cast<std::uint16_t>(quad * 4);
    indices_[index + 0] = base;
    indices_[index + 1] = static_cast<std::uint16_t>(base + 1);
    indices_[index + 2] = static_cast<std::uint16_t>(base + 2);
    indices_[index + 3] = base;
    indices_[index + 4] = static_cast<std::uint16_t>(base + 2);
    indices_[index + 5] = static_cast<std::uint16_t>(base + 3);
}

void DrawList::AddLine(Vec2 start, Vec2 end, Color color, float thickness) noexcept {
    thickness = ClampPositive(thickness);
    const float dx = end.x - start.x;
    const float dy = end.y - start.y;
    const float length = __builtin_sqrtf(dx * dx + dy * dy);
    if (thickness == 0.0f || !__builtin_isfinite(length) || length <= 0.00001f) return;
    Command* command = Reserve(4, 6);
    if (!command) return;
    const float half = thickness * 0.5f;
    const float nx = -dy / length * half;
    const float ny = dx / length * half;
    WriteQuad(*command, {start.x + nx, start.y + ny}, {end.x + nx, end.y + ny},
              {end.x - nx, end.y - ny}, {start.x - nx, start.y - ny}, color);
}

void DrawList::AddRect(Vec2 minimum, Vec2 maximum, Color color) noexcept {
    if (minimum.x > maximum.x) { const float t = minimum.x; minimum.x = maximum.x; maximum.x = t; }
    if (minimum.y > maximum.y) { const float t = minimum.y; minimum.y = maximum.y; maximum.y = t; }
    if (maximum.x <= minimum.x || maximum.y <= minimum.y) return;
    Command* command = Reserve(4, 6);
    if (command) WriteRect(*command, minimum, maximum, color);
}

void DrawList::AddRectOutline(Vec2 minimum, Vec2 maximum, Color color, float thickness) noexcept {
    if (minimum.x > maximum.x) { const float t = minimum.x; minimum.x = maximum.x; maximum.x = t; }
    if (minimum.y > maximum.y) { const float t = minimum.y; minimum.y = maximum.y; maximum.y = t; }
    thickness = ClampPositive(thickness);
    if (thickness == 0.0f || maximum.x <= minimum.x || maximum.y <= minimum.y) return;
    // Four independent rectangles avoid miter gaps and share no command storage.
    AddRect({minimum.x, minimum.y}, {maximum.x, minimum.y + thickness}, color);
    AddRect({minimum.x, maximum.y - thickness}, {maximum.x, maximum.y}, color);
    AddRect({minimum.x, minimum.y + thickness}, {minimum.x + thickness, maximum.y - thickness}, color);
    AddRect({maximum.x - thickness, minimum.y + thickness}, {maximum.x, maximum.y - thickness}, color);
}

void DrawList::AddCircle(Vec2 center, float radius, Color color, std::uint32_t segments) noexcept {
    if (!__builtin_isfinite(radius) || radius <= 0.0f || !__builtin_isfinite(center.x) || !__builtin_isfinite(center.y)) return;
    if (segments == 0) {
        const float estimate = __builtin_ceilf(radius * 0.7f);
        segments = estimate < 12.0f ? 12u : (estimate > 64.0f ? 64u : static_cast<std::uint32_t>(estimate));
    }
    if (segments < 3) segments = 3;
    if (segments > 128) segments = 128;
    Command* command = Reserve(segments + 1, segments * 3);
    if (!command) return;
    const std::uint32_t vertex = command->vertex_offset;
    const std::uint32_t index = command->index_offset;
    vertices_[vertex] = DrawVertex{center, {-1.0f, -1.0f}, color};
    constexpr float kTau = 6.28318530717958647692f;
    for (std::uint32_t i = 0; i < segments; ++i) {
        const float angle = kTau * static_cast<float>(i) / static_cast<float>(segments);
        vertices_[vertex + i + 1] = DrawVertex{{center.x + __builtin_cosf(angle) * radius,
                                                center.y + __builtin_sinf(angle) * radius},
                                               {-1.0f, -1.0f}, color};
        indices_[index + i * 3 + 0] = 0;
        indices_[index + i * 3 + 1] = static_cast<std::uint16_t>(i + 1);
        indices_[index + i * 3 + 2] = static_cast<std::uint16_t>((i + 1) % segments + 1);
    }
}

void DrawList::AddCircleOutline(Vec2 center, float radius, Color color, float thickness,
                                std::uint32_t segments) noexcept {
    thickness = ClampPositive(thickness);
    if (thickness == 0.0f || !__builtin_isfinite(radius) || radius <= 0.0f) return;
    if (segments == 0) {
        const float estimate = __builtin_ceilf(radius * 0.7f);
        segments = estimate < 12.0f ? 12u : (estimate > 64.0f ? 64u : static_cast<std::uint32_t>(estimate));
    }
    if (segments < 3) segments = 3;
    if (segments > 128) segments = 128;
    Command* command = Reserve(segments * 2, segments * 6);
    if (!command) return;
    const std::uint32_t vertex = command->vertex_offset;
    const std::uint32_t index = command->index_offset;
    const float inner = radius > thickness * 0.5f ? radius - thickness * 0.5f : 0.0f;
    const float outer = radius + thickness * 0.5f;
    constexpr float kTau = 6.28318530717958647692f;
    for (std::uint32_t i = 0; i < segments; ++i) {
        const float angle = kTau * static_cast<float>(i) / static_cast<float>(segments);
        const float x = __builtin_cosf(angle), y = __builtin_sinf(angle);
        vertices_[vertex + i * 2] = DrawVertex{{center.x + x * inner, center.y + y * inner}, {-1,-1}, color};
        vertices_[vertex + i * 2 + 1] = DrawVertex{{center.x + x * outer, center.y + y * outer}, {-1,-1}, color};
        const std::uint16_t next = static_cast<std::uint16_t>((i + 1) % segments);
        const std::uint16_t current = static_cast<std::uint16_t>(i);
        indices_[index + i * 6 + 0] = current * 2;
        indices_[index + i * 6 + 1] = current * 2 + 1;
        indices_[index + i * 6 + 2] = next * 2 + 1;
        indices_[index + i * 6 + 3] = current * 2;
        indices_[index + i * 6 + 4] = next * 2 + 1;
        indices_[index + i * 6 + 5] = next * 2;
    }
}

Vec2 DrawList::MeasureText(const char* text, float scale) noexcept {
    scale = ClampPositive(scale);
    if (!text || scale == 0.0f) return {};
    return AnalyzeText(text, scale, {}, nullptr).size;
}

Vec2 DrawList::AddText(Vec2 position, const char* text, Color color, float scale) noexcept {
    scale = ClampPositive(scale);
    if (!text || scale == 0.0f) return position;

    const Rect* clip = clip_depth_ ? &clips_[clip_depth_ - 1] : nullptr;
    const TextAnalysis analysis = AnalyzeText(text, scale, position, clip);
    stats_.text_bytes += analysis.byte_count;
    stats_.fallback_glyphs += analysis.fallback_count;
    stats_.invalid_utf8_bytes += analysis.invalid_count;
    stats_.clipped_glyphs += analysis.glyph_count - analysis.visible_glyph_count;
    if (analysis.truncated) ++stats_.truncated_texts;
    if (analysis.glyph_count != 0 && analysis.visible_glyph_count == 0) {
        ++stats_.clipped_texts;
        return analysis.size;
    }
    if (analysis.visible_glyph_count == 0) return analysis.size;

    // One submission covers the complete string. Each visible glyph is a
    // textured quad, replacing up to 35 independently rasterized lit pixels.
    Command* command = Reserve(analysis.visible_glyph_count * 4,
                               analysis.visible_glyph_count * 6);
    if (!command) return analysis.size;
    ++stats_.text_commands;

    const unsigned char* bytes = reinterpret_cast<const unsigned char*>(text);
    const Vec2 start = position;
    std::uint32_t quad = 0;
    std::size_t offset = 0;
    while (offset < kMaxTextBytes && bytes[offset] != 0) {
        const DecodedCodePoint decoded = DecodeUtf8(bytes + offset, kMaxTextBytes - offset);
        offset += decoded.size;
        if (decoded.valid && decoded.value == '\n') {
            position.x = start.x;
            position.y += 8.0f * scale;
            continue;
        }
        if (decoded.valid && decoded.value == '\r') continue;

        std::uint32_t character = decoded.value;
        if (!decoded.valid || character < kFont.first_character ||
            character >= kFont.first_character + kFont.character_count) {
            character = '?';
        }
        if (character != ' ') {
            const Vec2 maximum{position.x + 5.0f * scale, position.y + 7.0f * scale};
            if (OverlapsClip(position, maximum, clip)) {
                WriteGlyphQuad(*command, quad, position,
                               character - kFont.first_character, color, scale);
                ++quad;
            }
        }
        position.x += 6.0f * scale;
    }
    stats_.glyph_quads += quad;
    return analysis.size;
}

} // namespace internals
