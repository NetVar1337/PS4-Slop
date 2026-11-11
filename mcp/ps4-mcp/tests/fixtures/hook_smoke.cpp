#include <internals/hook.hpp>
#include <cassert>
struct Fixture {
    unsigned char bytes[256]{};
    bool writable=false;
    static bool Write(void* context, std::uintptr_t at, const void* bytes, std::size_t size) noexcept {
        auto& self=*static_cast<Fixture*>(context);
        if (!self.writable) return false;
        std::memcpy(reinterpret_cast<void*>(at),bytes,size); return true;
    }
    static bool Protect(void* context, std::uintptr_t, std::size_t, bool enter) noexcept { static_cast<Fixture*>(context)->writable=enter; return true; }
    static bool Flush(void*,std::uintptr_t,std::size_t) noexcept { return true; }
    static bool Quiet(void*) noexcept { return true; }
};
int main() {
    Fixture fixture;
    unsigned char expected[14]{},replacement[14],trampoline[14];
    std::memset(replacement,0x90,14);std::memset(trampoline,0xcc,14);
    const auto base=reinterpret_cast<std::uintptr_t>(fixture.bytes);
    internals::ReadableRange range{base,base+256};
    internals::MappedMemory mapped{&range,1};
    internals::HookMemory memory{mapped.Reader(),&fixture,&Fixture::Write,&Fixture::Protect,&Fixture::Flush,&Fixture::Quiet};
    internals::HookPlan plan{base,base+128,expected,replacement,trampoline,14,14};
    internals::Hook hook; internals::CallbackGate gate;
    assert(hook.Install(plan,memory));assert(!fixture.writable);
    assert(gate.Enter());assert(!hook.Restore(gate));gate.Leave();
    assert(hook.Restore(gate));assert(std::memcmp(fixture.bytes,expected,14)==0);assert(!fixture.writable);
    internals::Hook second;assert(second.Install(plan,memory));fixture.bytes[0]=0xc3;
    internals::CallbackGate another;assert(!second.Restore(another));assert(fixture.bytes[0]==0xc3);
    assert(second.state()==internals::HookState::Uncertain);
}
