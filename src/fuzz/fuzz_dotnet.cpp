// src/fuzz/fuzz_dotnet.cpp
// libFuzzer target: the ECMA-335 metadata reader (table layout, heaps, coded
// indices, signature blobs) that managed assemblies go through.

#include "core/dotnet/dotnet_metadata.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>

namespace mdt = hype::mdt;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    hype::MetadataReader r;
    if (!r.init(data, size)) return 0;

    size_t touched = r.version().size();
    (void)r.assembly_name();
    (void)r.string_at(0);
    (void)r.user_string_at(0);

    // cap the per-input work: a crafted row count must not turn one run into
    // a million accessor calls
    constexpr uint32_t kMaxRows = 24;
    for (uint32_t t = 0; t < mdt::kCount; ++t) {
        const uint32_t rows = std::min(r.table_rows(t), kMaxRows);
        for (uint32_t rid = 1; rid <= rows; ++rid) {
            const uint32_t token = (t << 24) | rid;
            touched += r.type_name(token).size() + r.method_name(token).size() +
                       r.field_name(token).size() + r.token_name(token).size();
            (void)r.decode_coded(hype::MetadataReader::Coded::TypeDefOrRef, rid);
            (void)r.call_info(token);
            (void)r.constant_for(t, rid);
        }
    }

    const uint32_t types = std::min(r.table_rows(mdt::TypeDef), kMaxRows);
    for (uint32_t rid = 1; rid <= types; ++rid) {
        const auto td = r.type_def(rid);
        (void)r.type_name((mdt::TypeDef << 24) | rid);
        (void)r.nested_enclosing(rid);
        (void)r.field_decl_type(rid);
        (void)r.method_decl_type(rid);
        touched += td.name + td.ns;   // heap offsets, not strings
    }
    const uint32_t methods = std::min(r.table_rows(mdt::MethodDef), kMaxRows);
    for (uint32_t rid = 1; rid <= methods; ++rid) {
        const auto md = r.method_def(rid);
        const auto sig = r.parse_method_sig(md.sig);
        touched += sig.ret.size() + sig.params.size() + r.method_decl_type(rid);
        (void)r.field_type(md.sig);
    }
    const uint32_t fields = std::min(r.table_rows(mdt::Field), kMaxRows);
    for (uint32_t rid = 1; rid <= fields; ++rid) {
        const auto f = r.field(rid);
        touched += r.field_type(f.sig).size() + r.field_decl_type(rid);
    }
    const uint32_t params = std::min(r.table_rows(mdt::Param), kMaxRows);
    for (uint32_t rid = 1; rid <= params; ++rid) {
        const auto p = r.param(rid);
        touched += p.name + p.seq;   // heap offset + sequence, both integers
    }
    const uint32_t props = std::min(r.table_rows(mdt::Property), kMaxRows);
    for (uint32_t rid = 1; rid <= props; ++rid) {
        const auto p = r.property(rid);
        touched += r.property_type(p.sig).size() + r.property_decl_type(rid);
    }
    const uint32_t events = std::min(r.table_rows(mdt::Event), kMaxRows);
    for (uint32_t rid = 1; rid <= events; ++rid) {
        const auto e = r.event_row(rid);
        touched += e.name + r.event_decl_type(rid);   // heap offset + rid
    }
    const uint32_t sem = std::min(r.table_rows(mdt::MethodSemantics), kMaxRows);
    for (uint32_t rid = 1; rid <= sem; ++rid) (void)r.method_semantics(rid);
    const uint32_t ifaces = std::min(r.table_rows(mdt::InterfaceImpl), kMaxRows);
    for (uint32_t rid = 1; rid <= ifaces; ++rid) (void)r.iface_impl(rid);
    const uint32_t nested = std::min(r.table_rows(mdt::NestedClass), kMaxRows);
    for (uint32_t rid = 1; rid <= nested; ++rid) (void)r.nested_class(rid);
    const uint32_t attrs = std::min(r.table_rows(mdt::CustomAttribute), kMaxRows);
    for (uint32_t rid = 1; rid <= attrs; ++rid) (void)r.custom_attribute(rid);

    // standalone signatures: the local-variable signature table
    const uint32_t sigs = std::min(r.table_rows(mdt::StandAloneSig), kMaxRows);
    for (uint32_t rid = 1; rid <= sigs; ++rid)
        touched += r.parse_local_sig((mdt::StandAloneSig << 24) | rid).size();

    volatile size_t sink = touched;
    (void)sink;
    return 0;
}
