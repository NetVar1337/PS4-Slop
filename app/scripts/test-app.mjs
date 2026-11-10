import assert from 'node:assert/strict';
import { createServer } from 'vite';
const server = await createServer({server:{middlewareMode:true},appType:'custom',optimizeDeps:{noDiscovery:true,include:[]}});
class FakeSource {
  static current;
  handlers = new Map();
  constructor() { FakeSource.current = this; }
  addEventListener(name, fn) { this.handlers.set(name, fn); }
  close() {}
  emit(name, data) { this.handlers.get(name)?.({data:JSON.stringify(data)}); }
}
globalThis.EventSource = FakeSource;
globalThis.fetch = async () => ({ok:true,json:async()=>({ok:true,data:{revision:0,lines:[]}})});
try {
  const events = await server.ssrLoadModule('/src/lib/events.ts');
  const {useOutput} = await server.ssrLoadModule('/src/store/output.ts');
  const {useWatch} = await server.ssrLoadModule('/src/store/watch.ts');
  events.connect();
  const send = (name, data) => FakeSource.current.emit(name, data);
  let detach = useOutput.getState().attach();
  detach(); detach = useOutput.getState().attach();
  for(let seq=1;seq<=5000;seq++) send('output',{seq,ms:seq,text:`line ${seq}`});
  assert.equal(useOutput.getState().lines.length,4096);
  assert.equal(useOutput.getState().lines[0].seq,905);
  send('output',{seq:5000,ms:0,text:'duplicate'});
  assert.equal(useOutput.getState().lines.at(-1).text,'line 5000');
  detach();
  send('output',{seq:5001,ms:0,text:'detached'});
  assert.equal(useOutput.getState().revision,5000);
  let notifications = 0;
  const stop = useWatch.subscribe(()=>notifications++);
  let off = useWatch.getState().attach(); off(); off=useWatch.getState().attach();
  send('watch.values',{attached:true,values:[]});
  assert.equal(notifications,1);
  off(); send('watch.values',{attached:false,values:[]});
  assert.equal(notifications,1); stop();

  // Function list must fill in once background (hyperion) analysis completes.
  // At load the list is seeded from the fast native index; for a .NET/IL image
  // that index holds only the entry stub, and every managed method appears only
  // after analysis finishes and the engine streams hype.progress ready=true.
  // Regression guard for the "shows 1 function" .NET bug.
  {
    const {useDisasm} = await server.ssrLoadModule('/src/store/disasm.ts');
    let analysisReady = false;
    const nativeOnly = {functions:[{va:0x1000,size:6,name:'entry_point'}],total:1};
    const managed = {functions:[
      {va:0x1000,size:6,name:'entry_point'},
      {va:0x2000,size:10,name:'App::Main'},
      {va:0x3000,size:10,name:'App::Run'},
    ],total:3};
    const reply = (data) => ({ok:true,json:async()=>({ok:true,data})});
    globalThis.fetch = async (url, opts) => {
      if (String(url).endsWith('/health')) return {ok:true,json:async()=>({ok:true})};
      const {tool,action} = JSON.parse(opts.body);
      if (tool==='disasm' && action==='load') return reply({ok:true,ready:true});
      if (tool==='disasm' && action==='loaded') return reply({
        ready:true,name:'net.exe',entry_va:0x1000,
        functions:analysisReady?3:1,
        hype:{available:true,ready:analysisReady,progress:analysisReady?1:0.5},
      });
      if (tool==='disasm' && action==='functions') return reply(analysisReady?managed:nativeOnly);
      if (tool==='disasm' && action==='disassemble') return reply({instructions:[]});
      return reply({});
    };

    await useDisasm.getState().loadFile('net.exe');
    // Analysis still running: only the native entry stub is known.
    assert.equal(useDisasm.getState().functions.length,1);
    assert.equal(useDisasm.getState().total,1);

    // Engine reports analysis complete; the store must re-pull the full list.
    analysisReady = true;
    useDisasm.getState().onHypeProgress(true,true);
    for (let i=0;i<50 && useDisasm.getState().total!==3;i++) await new Promise((r)=>setTimeout(r,0));
    assert.equal(useDisasm.getState().total,3);
    assert.equal(useDisasm.getState().functions.length,3);

    // A second ready event on the same edge must not thrash / re-fetch.
    let calls=0; const base=globalThis.fetch;
    globalThis.fetch = async (u,o)=>{calls++;return base(u,o);};
    useDisasm.getState().onHypeProgress(true,true);
    await new Promise((r)=>setTimeout(r,0));
    assert.equal(calls,0);
  }

  // Release builds omit window.__TAURI__. The SDK bridge must still wait for
  // the native handshake and preserve its port/token rather than use 8765.
  {
    const {resolveEndpoint} = await server.ssrLoadModule('/src/lib/endpoint.ts');
    const {getEndpoint} = await server.ssrLoadModule('/src/lib/rpc.ts');
    let reply;
    let invokes = 0;
    globalThis.window = {isTauri:true,__TAURI_INTERNALS__:{invoke:async(cmd)=>{
      assert.equal(cmd,'engine_endpoint');
      invokes++;
      return new Promise((resolve)=>{reply=resolve;});
    }}};
    const pending = resolveEndpoint();
    assert.equal(invokes,1);
    reply({port:43123,token:'handshake-test'});
    assert.deepEqual(await pending,{port:43123,token:'handshake-test'});
    assert.deepEqual(getEndpoint(),{port:43123,token:'handshake-test'});
    for(const invalid of [null,{port:0,token:''},{port:65536,token:''},{port:1.5,token:''},{port:43123,token:null}]) {
      window.__TAURI_INTERNALS__.invoke = async()=>invalid;
      await assert.rejects(resolveEndpoint(),/invalid engine endpoint/);
      assert.deepEqual(getEndpoint(),{port:43123,token:'handshake-test'});
    }
    window.__TAURI_INTERNALS__.invoke = async()=>{throw new Error('native bridge failed');};
    await assert.rejects(resolveEndpoint(),/native bridge failed/);
    globalThis.window = {};
    assert.deepEqual(await resolveEndpoint(),{port:8765,token:''});
  }

  // A failed initial snapshot must not leave stage 0/user forever after the
  // stream connects. Reconnects also re-seed state missed while disconnected.
  {
    const {useEngine} = await server.ssrLoadModule('/src/store/engine.ts');
    const priorSource = FakeSource.current;
    globalThis.window = {isTauri:true,__TAURI_INTERNALS__:{invoke:async()=>{throw new Error('native bridge failed');}}};
    await useEngine.getState().start();
    assert.equal(useEngine.getState().startupError,'native bridge failed');
    assert.equal(useEngine.getState().connected,false);
    assert.equal(FakeSource.current,priorSource);
    globalThis.window = {};
    let available = false;
    let backend = 'ps4';
    let statusReads = 0;
    globalThis.fetch = async (url,opts)=>{
      const {tool,action} = JSON.parse(opts.body);
      assert.equal(tool,'app');
      assert.equal(action,'status');
      statusReads++;
      if (!available) throw new Error('startup snapshot failed');
      return {ok:true,json:async()=>({ok:true,data:{backend,target:{attached:false}}})};
    };
    await useEngine.getState().start();
    assert.equal(useEngine.getState().boot.done,false);
    assert.equal(useEngine.getState().startupError,null);
    assert.equal(statusReads,0);
    FakeSource.current.onopen();
    for(let i=0;i<50 && !useEngine.getState().startupError;i++) await new Promise((r)=>setTimeout(r,0));
    assert.equal(useEngine.getState().startupError,'startup snapshot failed');
    available = true;
    FakeSource.current.onopen();
    for(let i=0;i<50 && !useEngine.getState().boot.done;i++) await new Promise((r)=>setTimeout(r,0));
    assert.equal(useEngine.getState().connected,true);
    assert.equal(useEngine.getState().boot.done,true);
    assert.deepEqual(useEngine.getState().backend,{badge:'ps4',ps4:true});
    assert.equal(useEngine.getState().startupError,null);
    backend = 'user';
    FakeSource.current.onopen();
    for(let i=0;i<50 && useEngine.getState().backend.ps4;i++) await new Promise((r)=>setTimeout(r,0));
    assert.deepEqual(useEngine.getState().backend,{badge:'user',ps4:false});
    send('boot.stage',{stage:6,total:6,label:'ready',done:true});
    assert.equal(useEngine.getState().boot.done,true);
    delete globalThis.window;
  }

  events.disconnect();
  console.log('PASS: bounded output, duplicate frames, output/watch teardown and remount, function-list refresh on analysis-complete, native endpoint handshake and validation, startup snapshot recovery and reconnect');
} finally {await server.close();}
