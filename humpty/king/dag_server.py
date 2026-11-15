"""humpty.king.dag_server — Real-time interactive Call Graph DAG & Sunburst Web Server.

Serves an interactive web dashboard powered by Cytoscape.js, D3.js Sunburst, and Server-Sent Events (SSE):
  - View 1: Hierarchical Call Graph DAG (Cytoscape + Dagre)
  - View 2: Multi-layer Radial Sunburst (D3.js Zoomable Sunburst) showing green completion wave
  - Real-time updates as state changes occur in the database (pending -> fuzzing -> trusted)
  - Node inspection: side-by-side view of decompiled C vs. reconstructed C candidate
  - Filter by library status, depth, or regex search

Usage:
  python -m humpty.king.dag_server --db bindumpty-project/runs/<run>/run.db --port 8080
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any, AsyncGenerator

from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
import uvicorn

ROOT = Path(__file__).resolve().parents[2]

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>bindumpty — Live Call Graph DAG & Sunburst</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/dagre@0.8.5/dist/dagre.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/cytoscape-dagre@2.5.0/cytoscape-dagre.min.js"></script>
  <script src="https://d3js.org/d3.v7.min.js"></script>
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --text-muted: #8b949e;
      --accent: #58a6ff;
      --green: #2ea043;
      --amber: #d29922;
      --purple: #a371f7;
      --red: #f85149;
      --gray: #484f58;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); overflow: hidden; height: 100vh; display: flex; flex-direction: column; }
    header { background: var(--card-bg); border-bottom: 1px solid var(--border); padding: 10px 20px; display: flex; align-items: center; justify-content: space-between; gap: 15px; z-index: 10; }
    .title-area { display: flex; align-items: center; gap: 12px; }
    .logo { font-size: 18px; font-weight: 700; color: #fff; letter-spacing: -0.5px; }
    .badge { font-size: 11px; padding: 3px 8px; border-radius: 12px; font-weight: 600; }
    .badge-live { background: rgba(46, 160, 67, 0.2); color: #3fb950; border: 1px solid rgba(46, 160, 67, 0.4); display: flex; align-items: center; gap: 6px; }
    .pulse { width: 8px; height: 8px; border-radius: 50%; background: #3fb950; animation: pulse 1.5s infinite; }
    @keyframes pulse { 0% { opacity: 0.4; } 50% { opacity: 1; } 100% { opacity: 0.4; } }
    
    .view-switcher { display: flex; background: #21262d; border-radius: 6px; padding: 2px; border: 1px solid var(--border); }
    .view-btn { background: transparent; border: none; color: var(--text-muted); padding: 5px 12px; border-radius: 4px; font-size: 12px; font-weight: 600; cursor: pointer; transition: all 0.15s ease; }
    .view-btn.active { background: #30363d; color: #fff; box-shadow: 0 1px 3px rgba(0,0,0,0.3); }

    .stats-bar { display: flex; gap: 10px; align-items: center; font-size: 12px; }
    .stat-pill { padding: 4px 10px; border-radius: 6px; background: rgba(255,255,255,0.05); border: 1px solid var(--border); }
    .stat-pill b { font-weight: 700; }
    .color-trusted { color: #3fb950; }
    .color-fuzzing { color: var(--purple); }
    .color-pending { color: var(--text-muted); }
    .color-failed { color: var(--red); }

    .controls { display: flex; gap: 10px; align-items: center; }
    input, select, button { background: var(--bg); border: 1px solid var(--border); color: var(--text); padding: 6px 12px; border-radius: 6px; font-size: 13px; }
    input:focus, select:focus { outline: none; border-color: var(--accent); }
    button { cursor: pointer; font-weight: 500; background: #21262d; transition: all 0.15s ease; }
    button:hover { background: #30363d; border-color: #8b949e; }
    button.primary { background: #238636; border-color: rgba(240,246,252,0.1); color: #fff; }
    button.primary:hover { background: #2ea043; }

    #main-container { flex: 1; display: flex; position: relative; overflow: hidden; }
    #cy { flex: 1; height: 100%; background: #090d13; }
    #sunburst-container { flex: 1; height: 100%; background: #090d13; display: none; align-items: center; justify-content: center; position: relative; }
    
    #drawer { width: 500px; background: var(--card-bg); border-left: 1px solid var(--border); display: flex; flex-direction: column; transform: translateX(100%); transition: transform 0.25s cubic-bezier(0.16, 1, 0.3, 1); z-index: 20; position: absolute; right: 0; top: 0; bottom: 0; box-shadow: -5px 0 25px rgba(0,0,0,0.5); }
    #drawer.open { transform: translateX(0); }
    .drawer-header { padding: 14px 18px; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; }
    .drawer-title { font-size: 15px; font-weight: 600; color: #fff; display: flex; align-items: center; gap: 8px; }
    .close-btn { background: transparent; border: none; font-size: 18px; color: var(--text-muted); cursor: pointer; }
    .close-btn:hover { color: #fff; }
    .drawer-content { flex: 1; overflow-y: auto; padding: 18px; display: flex; flex-direction: column; gap: 14px; font-size: 13px; }
    
    .meta-box { background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 12px; display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
    .meta-item { display: flex; flex-direction: column; }
    .meta-label { font-size: 11px; color: var(--text-muted); }
    .meta-val { font-weight: 600; font-family: monospace; font-size: 12px; }

    .code-box { background: #090d13; border: 1px solid var(--border); border-radius: 6px; overflow: hidden; display: flex; flex-direction: column; }
    .code-box-header { background: #161b22; padding: 6px 12px; font-size: 12px; font-weight: 600; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
    pre { padding: 12px; font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace; font-size: 12px; line-height: 1.45; overflow-x: auto; color: #e6edf3; max-height: 250px; }

    #live-ticker { position: absolute; bottom: 12px; left: 12px; background: rgba(22, 27, 34, 0.9); border: 1px solid var(--border); border-radius: 6px; padding: 8px 14px; font-size: 12px; display: flex; align-items: center; gap: 10px; z-index: 10; pointer-events: none; backdrop-filter: blur(4px); }
  </style>
</head>
<body>
  <header>
    <div class="title-area">
      <div class="logo">bindumpty</div>
      <div class="badge badge-live"><div class="pulse"></div> LIVE</div>
      <div class="view-switcher">
        <button id="view-dag" class="view-btn active">🕸️ DAG</button>
        <button id="view-sunburst" class="view-btn">☀️ Sunburst</button>
      </div>
    </div>
    
    <div class="stats-bar" id="stats-bar">
      <div class="stat-pill">Total: <b id="stat-total">0</b></div>
      <div class="stat-pill">Trusted: <b id="stat-trusted" class="color-trusted">0</b></div>
      <div class="stat-pill">Fuzzing: <b id="stat-fuzzing" class="color-fuzzing">0</b></div>
      <div class="stat-pill">Pending: <b id="stat-pending" class="color-pending">0</b></div>
      <div class="stat-pill">Failed: <b id="stat-failed" class="color-failed">0</b></div>
    </div>

    <div class="controls">
      <input type="text" id="filter-symbol" placeholder="Root symbol (e.g. CPXbaropt)" value="CPXbaropt">
      <select id="filter-depth">
        <option value="1">Depth 1</option>
        <option value="2" selected>Depth 2</option>
        <option value="3">Depth 3</option>
        <option value="4">Depth 4</option>
        <option value="6">Depth 6</option>
        <option value="10">All Reachable</option>
      </select>
      <label style="font-size: 12px; display: flex; align-items: center; gap: 4px; cursor: pointer;">
        <input type="checkbox" id="hide-libs" checked> Hide Libraries
      </label>
      <button class="primary" id="btn-refresh">Load</button>
      <button id="btn-fit">Reset View</button>
    </div>
  </header>

  <div id="main-container">
    <div id="cy"></div>
    <div id="sunburst-container"></div>

    <div id="drawer">
      <div class="drawer-header">
        <div class="drawer-title" id="drawer-fn-name">Function Details</div>
        <button class="close-btn" id="drawer-close">&times;</button>
      </div>
      <div class="drawer-content">
        <div class="meta-box">
          <div class="meta-item"><span class="meta-label">Address</span><span class="meta-val" id="drawer-addr">-</span></div>
          <div class="meta-item"><span class="meta-label">State</span><span class="meta-val" id="drawer-state">-</span></div>
          <div class="meta-item"><span class="meta-label">Size</span><span class="meta-val" id="drawer-size">-</span></div>
          <div class="meta-item"><span class="meta-label">Confidence</span><span class="meta-val" id="drawer-conf">-</span></div>
        </div>

        <div class="code-box">
          <div class="code-box-header"><span>Reconstructed Candidate C (LLM)</span><span id="drawer-cand-badge" class="badge"></span></div>
          <pre><code id="drawer-candidate">/* No candidate synthesized yet */</code></pre>
        </div>

        <div class="code-box">
          <div class="code-box-header"><span>Decompiled C (Ghidra / Kuna)</span></div>
          <pre><code id="drawer-decompiled">/* No decompiled C source available */</code></pre>
        </div>
      </div>
    </div>

    <div id="live-ticker">
      <div class="color-trusted">●</div>
      <span id="ticker-msg">Connected to live event stream.</span>
    </div>
  </div>

  <script>
    let cy = null;
    let selectedNodeId = null;
    let currentMode = "dag"; // "dag" | "sunburst"
    let sunburstData = null;

    const STATE_COLORS = {
      "trusted": "#3fb950",
      "proven": "#2ea043",
      "fuzzing": "#a371f7",
      "developing": "#d29922",
      "repairing": "#d29922",
      "ready": "#58a6ff",
      "pending": "#484f58",
      "failed": "#f85149",
      "divergent": "#f85149"
    };

    function initCy() {
      cy = cytoscape({
        container: document.getElementById('cy'),
        style: [
          {
            selector: 'node',
            style: {
              'label': 'data(label)',
              'color': '#ffffff',
              'font-size': '11px',
              'text-valign': 'center',
              'text-halign': 'center',
              'background-color': 'data(color)',
              'width': 'mapData(size, 16, 500, 40, 90)',
              'height': 'mapData(size, 16, 500, 40, 90)',
              'border-width': 2,
              'border-color': '#30363d',
              'text-outline-color': '#0d1117',
              'text-outline-width': 2,
              'transition-property': 'background-color, border-color, width, height',
              'transition-duration': '0.3s'
            }
          },
          {
            selector: 'node:selected',
            style: {
              'border-width': 4,
              'border-color': '#58a6ff',
              'shadow-blur': 15,
              'shadow-color': '#58a6ff',
              'shadow-opacity': 0.8
            }
          },
          {
            selector: 'edge',
            style: {
              'width': 1.5,
              'line-color': '#30363d',
              'target-arrow-color': '#30363d',
              'target-arrow-shape': 'triangle',
              'curve-style': 'bezier',
              'arrow-scale': 0.8
            }
          },
          {
            selector: 'edge[kind = "indirect_resolved"]',
            style: {
              'line-color': '#a371f7',
              'target-arrow-color': '#a371f7',
              'line-style': 'dashed'
            }
          }
        ]
      });

      cy.on('tap', 'node', function(evt) {
        const node = evt.target;
        openDrawer(node.data());
      });

      cy.on('tap', function(evt) {
        if (evt.target === cy) {
          closeDrawer();
        }
      });
    }

    async function loadGraph() {
      const root = document.getElementById('filter-symbol').value.trim();
      const depth = document.getElementById('filter-depth').value;
      const hideLibs = document.getElementById('hide-libs').checked;

      if (currentMode === "sunburst") {
        await loadSunburst();
        return;
      }

      let url = `/api/graph?depth=${depth}&hide_libs=${hideLibs}`;
      if (root) url += `&root=${encodeURIComponent(root)}`;

      try {
        const res = await fetch(url);
        const data = await res.json();

        // Update stats
        if (data.stats) {
          document.getElementById('stat-total').innerText = data.stats.total || 0;
          document.getElementById('stat-trusted').innerText = data.stats.trusted || 0;
          document.getElementById('stat-fuzzing').innerText = data.stats.fuzzing || 0;
          document.getElementById('stat-pending').innerText = data.stats.pending || 0;
          document.getElementById('stat-failed').innerText = data.stats.failed || 0;
        }

        const elements = [];
        data.nodes.forEach(n => {
          elements.push({
            group: 'nodes',
            data: {
              id: String(n.id),
              label: n.name.length > 20 ? n.name.slice(0, 18) + '…' : n.name,
              fullName: n.name,
              address: n.address,
              state: n.state,
              size: n.size || 32,
              confidence: n.confidence || 0.0,
              color: STATE_COLORS[n.state] || '#484f58',
              is_library: n.is_library
            }
          });
        });

        data.edges.forEach((e, idx) => {
          elements.push({
            group: 'edges',
            data: {
              id: 'e_' + idx,
              source: String(e.source),
              target: String(e.target),
              kind: e.kind
            }
          });
        });

        cy.elements().remove();
        cy.add(elements);

        cy.layout({
          name: 'dagre',
          rankDir: 'TB',
          nodeSep: 50,
          rankSep: 80,
          padding: 30
        }).run();

      } catch (err) {
        console.error("Failed to load graph:", err);
      }
    }

    // --- D3 Sunburst Implementation ------------------------------------------
    async function loadSunburst() {
      const root = document.getElementById('filter-symbol').value.trim() || "CPXbaropt";
      const depth = document.getElementById('filter-depth').value;
      const hideLibs = document.getElementById('hide-libs').checked;

      const url = `/api/sunburst?root=${encodeURIComponent(root)}&depth=${depth}&hide_libs=${hideLibs}`;
      try {
        const res = await fetch(url);
        sunburstData = await res.json();
        renderSunburst(sunburstData);
      } catch (e) {
        console.error("Failed to load sunburst:", e);
      }
    }

    function renderSunburst(data) {
      const container = document.getElementById('sunburst-container');
      container.innerHTML = '';
      const width = container.clientWidth || 800;
      const height = container.clientHeight || 600;
      const radius = Math.min(width, height) / 2 - 20;

      const hierarchy = d3.hierarchy(data)
          .sum(d => (d.children && d.children.length > 0) ? 0 : (d.size || 32))
          .sort((a, b) => b.value - a.value);

      const maxD = Math.max(hierarchy.height, 1);
      const partition = d3.partition().size([2 * Math.PI, maxD + 1]);
      const root = partition(hierarchy);
      root.each(d => d.current = d);

      const svg = d3.select(container)
        .append("svg")
        .attr("viewBox", [-width / 2, -height / 2, width, height])
        .style("font-family", "-apple-system, BlinkMacSystemFont, sans-serif")
        .style("width", "100%")
        .style("height", "100%");

      const arc = d3.arc()
          .startAngle(d => d.x0)
          .endAngle(d => d.x1)
          .padAngle(d => Math.min((d.x1 - d.x0) / 2, 0.005))
          .padRadius(radius / 2)
          .innerRadius(d => d.y0 * radius / (maxD + 1))
          .outerRadius(d => Math.max(d.y0 * radius / (maxD + 1), d.y1 * radius / (maxD + 1) - 1));

      const path = svg.append("g")
        .selectAll("path")
        .data(root.descendants().slice(1))
        .join("path")
          .attr("fill", d => STATE_COLORS[d.data.state] || "#484f58")
          .attr("fill-opacity", d => (d.children ? 0.9 : 0.75))
          .attr("d", d => arc(d.current))
          .style("cursor", "pointer")
          .on("click", (event, p) => {
              openDrawer({
                id: p.data.id,
                fullName: p.data.name,
                address: p.data.address,
                state: p.data.state,
                size: p.data.size,
                confidence: p.data.confidence || 0.0
              });
          });

      path.append("title")
          .text(d => `${d.ancestors().map(d => d.data.name).reverse().join(" → ")}\nState: ${d.data.state.toUpperCase()}\nSize: ${d.data.size} B`);

      // Center root circle
      svg.append("circle")
          .datum(root)
          .attr("r", radius / (maxD + 1))
          .attr("fill", d => STATE_COLORS[d.data.state] || "#3fb950")
          .attr("stroke", "#30363d")
          .attr("stroke-width", 2)
          .style("cursor", "pointer")
          .on("click", () => {
            openDrawer({
              id: data.id,
              fullName: data.name,
              address: data.address,
              state: data.state,
              size: data.size,
              confidence: data.confidence || 0.0
            });
          });

      svg.append("text")
          .attr("text-anchor", "middle")
          .attr("fill", "#ffffff")
          .attr("dy", "0.35em")
          .style("font-size", "11px")
          .style("font-weight", "bold")
          .style("pointer-events", "none")
          .text(data.name.length > 14 ? data.name.slice(0, 12) + "…" : data.name);
    }

    // --- Drawer & Details ----------------------------------------------------
    async function openDrawer(nodeData) {
      if (!nodeData || !nodeData.id) return;
      selectedNodeId = nodeData.id;
      document.getElementById('drawer-fn-name').innerText = nodeData.fullName || nodeData.name;
      document.getElementById('drawer-addr').innerText = nodeData.address;
      document.getElementById('drawer-state').innerText = (nodeData.state || "PENDING").toUpperCase();
      document.getElementById('drawer-state').style.color = STATE_COLORS[nodeData.state] || '#fff';
      document.getElementById('drawer-size').innerText = (nodeData.size || 32) + " B";
      document.getElementById('drawer-conf').innerText = ((nodeData.confidence || 0.0) * 100).toFixed(0) + "%";

      try {
        const res = await fetch(`/api/function/${nodeData.id}`);
        const fn = await res.json();
        document.getElementById('drawer-decompiled').innerText = fn.decompiled_code || "/* No decompiled C available */";
        document.getElementById('drawer-candidate').innerText = fn.candidate_code || "/* No candidate synthesized yet */";
      } catch (e) {
        console.error(e);
      }

      document.getElementById('drawer').classList.add('open');
    }

    function closeDrawer() {
      document.getElementById('drawer').classList.remove('open');
      selectedNodeId = null;
    }

    // --- Live Event Stream (SSE) ---------------------------------------------
    function connectEventStream() {
      const evtSource = new EventSource("/api/events/live");
      evtSource.onmessage = function(event) {
        const ev = JSON.parse(event.data);
        if (ev.type === "connected") return;
        const ticker = document.getElementById('ticker-msg');
        ticker.innerText = `[${ev.kind}] Function #${ev.function_id} → ${ev.to_state}`;

        // Update Cytoscape node if in DAG mode
        if (cy && ev.function_id) {
          const node = cy.$('#' + ev.function_id);
          if (node.length > 0) {
            const newState = ev.to_state;
            const newColor = STATE_COLORS[newState] || '#484f58';
            node.data('state', newState);
            node.data('color', newColor);

            node.animate({
              style: { 'border-width': 8, 'border-color': '#fff' }
            }, {
              duration: 200,
              complete: function() {
                node.animate({
                  style: { 'border-width': 2, 'border-color': '#30363d' }
                }, { duration: 300 });
              }
            });
          }
        }

        // If in Sunburst mode, refresh sunburst colors
        if (currentMode === "sunburst") {
          loadSunburst();
        }

        if (selectedNodeId === String(ev.function_id)) {
          openDrawer({ id: ev.function_id, state: ev.to_state });
        }
      };
      evtSource.onerror = function() {
        document.getElementById('ticker-msg').innerText = "Reconnecting to live events...";
      };
    }

    document.addEventListener("DOMContentLoaded", () => {
      initCy();
      loadGraph();
      connectEventStream();

      document.getElementById('btn-refresh').onclick = () => {
        if (currentMode === "dag") loadGraph();
        else loadSunburst();
      };
      document.getElementById('btn-fit').onclick = () => {
        if (currentMode === "dag") cy.fit(null, 40);
        else loadSunburst();
      };
      document.getElementById('drawer-close').onclick = closeDrawer;

      // Mode Switcher
      document.getElementById('view-dag').onclick = function() {
        currentMode = "dag";
        this.classList.add('active');
        document.getElementById('view-sunburst').classList.remove('active');
        document.getElementById('cy').style.display = 'block';
        document.getElementById('sunburst-container').style.display = 'none';
        loadGraph();
      };

      document.getElementById('view-sunburst').onclick = function() {
        currentMode = "sunburst";
        this.classList.add('active');
        document.getElementById('view-dag').classList.remove('active');
        document.getElementById('cy').style.display = 'none';
        document.getElementById('sunburst-container').style.display = 'flex';
        loadSunburst();
      };
    });
  </script>
</body>
</html>
"""


def create_app(db_path: str) -> FastAPI:
    app = FastAPI(title="bindumpty DAG & Sunburst Live")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    def get_conn():
        con = sqlite3.connect(db_path, timeout=30.0)
        con.row_factory = sqlite3.Row
        return con

    @app.get("/", response_class=HTMLResponse)
    def index():
        return HTML_TEMPLATE

    @app.get("/api/graph")
    def get_graph(root: str | None = None, depth: int = 2, hide_libs: bool = True):
        con = get_conn()
        cur = con.cursor()

        # Gather summary stats
        cur.execute("SELECT state, count(*) FROM functions GROUP BY state")
        state_counts = {r[0]: r[1] for r in cur.fetchall()}
        total_fns = sum(state_counts.values())

        stats = {
            "total": total_fns,
            "trusted": state_counts.get("trusted", 0) + state_counts.get("proven", 0),
            "fuzzing": state_counts.get("fuzzing", 0),
            "pending": state_counts.get("pending", 0),
            "failed": state_counts.get("failed", 0) + state_counts.get("divergent", 0),
        }

        # Subtree query
        if root:
            cur.execute("SELECT id, name, address, size, state, confidence, fingerprint FROM functions WHERE name = ? OR name LIKE ?",
                        (root, f"{root}%"))
            roots = cur.fetchall()
            if not roots:
                return {"nodes": [], "edges": [], "stats": stats}
            
            root_ids = [r["id"] for r in roots]
            frontier = set(root_ids)
            visited_nodes = set(root_ids)
            matched_edges = []

            for d in range(depth):
                if not frontier:
                    break
                q_placeholders = ",".join("?" for _ in frontier)
                cur.execute(f"SELECT caller_id, callee_id, kind FROM call_edges WHERE caller_id IN ({q_placeholders})", list(frontier))
                next_frontier = set()
                for e in cur.fetchall():
                    cid, ceid, kind = e["caller_id"], e["callee_id"], e["kind"]
                    matched_edges.append({"source": cid, "target": ceid, "kind": kind})
                    if ceid not in visited_nodes:
                        visited_nodes.add(ceid)
                        next_frontier.add(ceid)
                frontier = next_frontier

            q_all = ",".join("?" for _ in visited_nodes)
            cur.execute(f"SELECT id, name, address, size, state, confidence, fingerprint FROM functions WHERE id IN ({q_all})", list(visited_nodes))
            all_fns = cur.fetchall()
        else:
            limit = 300
            lib_filter = "WHERE fingerprint IS NULL OR fingerprint NOT LIKE 'vendor%'" if hide_libs else ""
            cur.execute(f"SELECT id, name, address, size, state, confidence, fingerprint FROM functions {lib_filter} LIMIT ?", (limit,))
            all_fns = cur.fetchall()
            fn_ids = {r["id"] for r in all_fns}
            if fn_ids:
                q_ids = ",".join("?" for _ in fn_ids)
                cur.execute(f"SELECT caller_id, callee_id, kind FROM call_edges WHERE caller_id IN ({q_ids}) AND callee_id IN ({q_ids})", list(fn_ids) + list(fn_ids))
                matched_edges = [{"source": e["caller_id"], "target": e["callee_id"], "kind": e["kind"]} for e in cur.fetchall()]
            else:
                matched_edges = []

        nodes = []
        for r in all_fns:
            is_lib = bool(r["fingerprint"] and r["fingerprint"].startswith("vendor"))
            if hide_libs and is_lib and (not root or r["id"] not in root_ids):
                continue
            nodes.append({
                "id": r["id"],
                "name": r["name"],
                "address": f"0x{r['address']:x}" if isinstance(r["address"], int) else str(r["address"]),
                "size": r["size"] or 32,
                "state": r["state"],
                "confidence": r["confidence"] or 0.0,
                "is_library": is_lib,
            })

        con.close()
        return {"nodes": nodes, "edges": matched_edges, "stats": stats}

    @app.get("/api/sunburst")
    def get_sunburst(root: str = "CPXbaropt", depth: int = 4, hide_libs: bool = True):
        con = get_conn()
        cur = con.cursor()
        cur.execute("SELECT id, name, address, size, state, confidence, fingerprint FROM functions WHERE name = ? OR name LIKE ? LIMIT 1",
                    (root, f"{root}%"))
        root_row = cur.fetchone()
        if not root_row:
            con.close()
            return {"name": root, "state": "pending", "size": 32, "children": []}

        root_id, name, addr, size, state = (
            root_row["id"], root_row["name"], root_row["address"],
            root_row["size"], root_row["state"]
        )

        def get_children(fn_id: int, current_depth: int, visited: set[int]) -> list[dict]:
            if current_depth >= depth:
                return []
            cur.execute("SELECT callee_id, kind FROM call_edges WHERE caller_id = ?", (fn_id,))
            edges = cur.fetchall()
            children = []
            for e in edges:
                cid = e["callee_id"]
                if cid in visited:
                    continue
                cur.execute("SELECT id, name, address, size, state, confidence, fingerprint FROM functions WHERE id = ?", (cid,))
                c_row = cur.fetchone()
                if not c_row:
                    continue
                is_lib = bool(c_row["fingerprint"] and c_row["fingerprint"].startswith("vendor"))
                if hide_libs and is_lib:
                    continue
                node = {
                    "id": c_row["id"],
                    "name": c_row["name"],
                    "address": f"0x{c_row['address']:x}" if isinstance(c_row["address"], int) else str(c_row["address"]),
                    "size": max(c_row["size"] or 32, 16),
                    "state": c_row["state"],
                    "confidence": c_row["confidence"] or 0.0,
                    "is_library": is_lib,
                    "children": get_children(cid, current_depth + 1, visited | {cid})
                }
                children.append(node)
            return children

        tree = {
            "id": root_id,
            "name": name,
            "address": f"0x{addr:x}" if isinstance(addr, int) else str(addr),
            "size": max(size or 32, 32),
            "state": state,
            "confidence": root_row["confidence"] or 0.0,
            "children": get_children(root_id, 0, {root_id})
        }
        con.close()
        return tree

    @app.get("/api/function/{fn_id}")
    def get_function(fn_id: int):
        con = get_conn()
        cur = con.cursor()
        cur.execute("SELECT id, name, address, size, state, confidence, demangled_sig, decompiled_code FROM functions WHERE id = ?", (fn_id,))
        fn = cur.fetchone()
        if not fn:
            con.close()
            raise HTTPException(status_code=404, detail="Function not found")

        cur.execute("SELECT source_code, status FROM candidates WHERE function_id = ? ORDER BY id DESC LIMIT 1", (fn_id,))
        cand = cur.fetchone()

        con.close()
        return {
            "id": fn["id"],
            "name": fn["name"],
            "address": f"0x{fn['address']:x}" if isinstance(fn["address"], int) else str(fn["address"]),
            "size": fn["size"],
            "state": fn["state"],
            "confidence": fn["confidence"],
            "demangled_sig": fn["demangled_sig"],
            "decompiled_code": fn["decompiled_code"],
            "candidate_code": cand["source_code"] if cand else None,
            "candidate_status": cand["status"] if cand else None,
        }

    @app.get("/api/events/live")
    async def live_events():
        async def event_generator() -> AsyncGenerator[str, None]:
            last_seq = 0
            con = get_conn()
            cur = con.cursor()
            cur.execute("SELECT coalesce(max(seq), 0) FROM events")
            last_seq = cur.fetchone()[0]

            yield f"data: {json.dumps({'type': 'connected', 'seq': last_seq})}\n\n"

            while True:
                cur.execute("SELECT id, seq, kind, function_id, candidate_id, ts, payload_json FROM events WHERE seq > ? ORDER BY seq ASC LIMIT 50", (last_seq,))
                rows = cur.fetchall()
                for r in rows:
                    last_seq = r["seq"]
                    to_state = r["kind"].split(":")[-1] if r["kind"].startswith("state:") else r["kind"]
                    raw_payload = r["payload_json"]
                    if isinstance(raw_payload, str):
                        try:
                            payload = json.loads(raw_payload)
                        except Exception:
                            payload = {}
                    else:
                        payload = raw_payload or {}
                    data = {
                        "id": r["id"],
                        "seq": r["seq"],
                        "kind": r["kind"],
                        "function_id": r["function_id"],
                        "candidate_id": r["candidate_id"],
                        "to_state": to_state,
                        "created_at": str(r["ts"]),
                        "payload": payload,
                    }
                    yield f"data: {json.dumps(data)}\n\n"
                await asyncio.sleep(0.5)

        return StreamingResponse(event_generator(), media_type="text/event-stream")

    return app


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="bindumpty dag")
    ap.add_argument("--db", default="./bindumpty-project/runs/20261115-200441-run/run.db",
                    help="path to bindumpty run.db")
    ap.add_argument("--host", default="0.0.0.0", help="host to bind")
    ap.add_argument("--port", type=int, default=8080, help="port to bind")
    args = ap.parse_args(argv)

    if not os.path.exists(args.db):
        print(f"Database not found at {args.db}", file=sys.stderr)
        return 1

    app = create_app(args.db)
    print(f"bindumpty DAG + Sunburst server listening at http://{args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
