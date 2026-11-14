// app/scripts/bench-ui.mjs
// frontend benchmarks: the Output panel's server-side render, and a
// 1,000,000-row virtualized list mounted in jsdom (mount, scroll frame and
// filter). Both are component work only, not browser frame time or RSS.

import { createServer } from "vite";
import React from "react";
import { createRoot } from "react-dom/client";
import { flushSync } from "react-dom";
import { renderToString } from "react-dom/server";
import { JSDOM } from "jsdom";
import { writeFileSync } from "node:fs";

const server = await createServer({
  server: { middlewareMode: true },
  appType: "custom",
  optimizeDeps: { noDiscovery: true, include: [] },
});

/** jsdom has no layout, so the virtualizer gets a fixed viewport from us. */
function installDom() {
  const dom = new JSDOM("<!doctype html><html><body></body></html>", {
    pretendToBeVisual: true,
  });
  const w = dom.window;
  const define = (key, value) =>
    Object.defineProperty(globalThis, key, { configurable: true, writable: true, value });
  define("window", w);
  for (const key of [
    "document",
    "navigator",
    "HTMLElement",
    "Element",
    "Node",
    "Event",
    "getComputedStyle",
    "requestAnimationFrame",
    "cancelAnimationFrame",
  ])
    define(key, w[key]);
  define(
    "ResizeObserver",
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  );
  Object.defineProperty(w.HTMLElement.prototype, "clientHeight", {
    configurable: true,
    get: () => 600,
  });
  Object.defineProperty(w.HTMLElement.prototype, "clientWidth", {
    configurable: true,
    get: () => 800,
  });
  return w;
}

async function benchOutputPanel() {
  const { useOutput } = await server.ssrLoadModule("/src/store/output.ts");
  const { default: OutputPanel } = await server.ssrLoadModule(
    "/src/components/panels/OutputPanel.tsx",
  );
  const lines = Array.from({ length: 4096 }, (_, i) => ({
    seq: i + 1,
    ms: 1700000000000 + i,
    text: `line ${i} ${"x".repeat(80)}`,
  }));
  useOutput.setState({ lines, revision: 4096 });
  Object.assign(useOutput.getInitialState(), { lines, revision: 4096 });
  const run = () => renderToString(React.createElement(OutputPanel));
  run();
  const samples = [];
  let html;
  for (let i = 0; i < 7; i++) {
    const start = performance.now();
    html = run();
    samples.push(performance.now() - start);
  }
  return {
    workload: "output_4096_rows_ssr",
    median_ms: [...samples].sort((a, b) => a - b)[3],
    samples_ms: samples,
    html_bytes: Buffer.byteLength(html),
    rendered_rows: (html.match(/class="log-row"/g) || []).length,
    note: "SSR component work only, not browser frame time or RSS",
  };
}

async function benchVirtualList() {
  const w = installDom();
  const { default: VirtualListBench, kBenchRows } = await server.ssrLoadModule(
    "/src/bench/VirtualListBench.tsx",
  );
  const host = w.document.createElement("div");
  w.document.body.appendChild(host);
  const root = createRoot(host);

  const ms = (fn) => {
    const start = performance.now();
    fn();
    return performance.now() - start;
  };

  const mount_ms = ms(() =>
    flushSync(() => root.render(React.createElement(VirtualListBench, { filter: "" }))),
  );

  // jsdom drops scrollTop unless the element scrolls, and the virtualizer reads
  // it back, so the offset lives on the element itself
  const scroller = host.firstElementChild;
  let offset = 0;
  Object.defineProperty(scroller, "scrollTop", {
    configurable: true,
    get: () => offset,
    set: (v) => {
      offset = v;
    },
  });
  scroller.getBoundingClientRect = () => ({
    x: 0,
    y: 0,
    top: 0,
    left: 0,
    right: 800,
    bottom: 600,
    width: 800,
    height: 600,
    toJSON: () => ({}),
  });

  // warm the render path first: the first frames pay for module/JIT setup and
  // would otherwise dominate the samples
  const total = kBenchRows * 20;
  for (let i = 0; i < 10; i++) {
    flushSync(() => {
      scroller.scrollTop = (total * i) / 11;
      scroller.dispatchEvent(new w.Event("scroll"));
    });
  }

  const scroll_samples_ms = [];
  for (let i = 1; i <= 60; i++) {
    scroll_samples_ms.push(
      ms(() =>
        flushSync(() => {
          scroller.scrollTop = (total * i) / 61;
          scroller.dispatchEvent(new w.Event("scroll"));
        }),
      ),
    );
  }

  const filter_ms = ms(() =>
    flushSync(() => root.render(React.createElement(VirtualListBench, { filter: "sub_1400000" }))),
  );

  const rows = host.querySelectorAll("div > div > div").length;
  root.unmount();
  host.remove();

  const sorted = [...scroll_samples_ms].sort((a, b) => a - b);
  return {
    workload: "virtual_list_1m_rows",
    rows: kBenchRows,
    mount_ms,
    // the tenth percentile: the fastest frames still carry the real render
    // cost, while a busy machine only inflates the rest
    scroll_frame_ms: sorted[Math.floor(sorted.length / 10)],
    scroll_median_ms: sorted[Math.floor(sorted.length / 2)],
    scroll_samples_ms,
    filter_ms,
    visible_rows: rows,
    note: "jsdom render work only, not browser frame time or RSS",
  };
}

try {
  const result = {
    workloads: [await benchOutputPanel(), await benchVirtualList()],
  };
  console.log(JSON.stringify(result, null, 2));
  if (process.argv[2]) writeFileSync(process.argv[2], JSON.stringify(result, null, 2) + "\n");
} finally {
  await server.close();
}
