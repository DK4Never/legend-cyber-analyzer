// server.js — Legend Cyber Analyzer (Pro-secured build)
// Requires: npm i express body-parser sqlite3 whoiser node-fetch dotenv stripe openai

import express from "express";
import path from "path";
import bodyParser from "body-parser";
import fetch from "node-fetch";
import dns from "dns";
import net from "net";
import sqlite3 from "sqlite3";
import dotenv from "dotenv";
import Stripe from "stripe";
import whoiser from "whoiser";
import { fileURLToPath } from "url";

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.static(path.join(__dirname, "public")));
app.use(bodyParser.json());

// === Database ===
const db = new sqlite3.Database("./visitors.db", (err) => {
  db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      target TEXT,
      type TEXT,
      payload TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

  if (err) console.error("Database connection error:", err.message);
  else console.log("Connected to visitors.db");
});

const OPENAI_KEY = process.env.OPENAI_API_KEY || null;
const SHODAN_KEY = process.env.SHODAN_API_KEY || null;
const STRIPE_SECRET = process.env.STRIPE_SECRET_KEY || null;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || null;

let stripe = STRIPE_SECRET ? new Stripe(STRIPE_SECRET) : null;

// ========== HELPERS ==========
const resolveToIp = async (host) => {
  try {
    const r = await dns.promises.lookup(host);
    return r.address;
  } catch {
    return null;
  }
};

const ipGeo = async (ip) => {
  try {
    const r = await fetch(`http://ip-api.com/json/${ip}?fields=status,message,country,regionName,city,isp,org,query,as`);
    if (r.ok) return await r.json();
  } catch {}
  return null;
};

const rdapLookup = async (target, type) => {
  const url = type === "ip" ? `https://rdap.org/ip/${target}` : `https://rdap.org/domain/${target}`;
  try {
    const r = await fetch(url);
    if (r.ok) return await r.json();
  } catch {}
  return null;
};

const whoisLookup = async (domain) => {
  try {
    return await whoiser(domain);
  } catch {
    return null;
  }
};

const shodanLookup = async (ip) => {
  if (!SHODAN_KEY) return null;
  try {
    const url = `https://api.shodan.io/shodan/host/${ip}?key=${SHODAN_KEY}`;
    const r = await fetch(url);
    if (r.ok) return await r.json();
    return { error: `shodan:${r.status}` };
  } catch (e) {
    return { error: e.message };
  }
};

const scanPort = (host, port, timeout = 1000) =>
  new Promise((resolve) => {
    const socket = new net.Socket();
    let status = "closed";
    socket.setTimeout(timeout);
    socket.once("connect", () => {
      status = "open";
      socket.destroy();
    });
    socket.once("timeout", () => socket.destroy());
    socket.once("error", () => {});
    socket.once("close", () => resolve({ port, status }));
    socket.connect(port, host);
  });

const scanPorts = async (host, ports) => {
  const out = [];
  for (const p of ports) {
    try {
      out.push(await scanPort(host, p));
    } catch {
      out.push({ port: p, status: "error" });
    }
  }
  return out;
};

// Basic heuristic
const heuristicScore = (out) => {
  let s = 50;
  if (out.checks?.https === false) s += 15;
  if (out.checks?.rdap === false) s += 10;
  if (out.geo?.isp && /google/i.test(out.geo.isp)) s -= 8;
  return Math.max(0, Math.min(100, s));
};

// Common ports
const COMMON_PORTS = [80, 443, 21, 22, 25, 53, 110, 143, 161, 3306, 3389, 5900, 8080, 8443, 587, 993, 995, 2082, 2083, 8444];

// === Stripe: store paid sessions ===
const paidSessions = new Set();

// === Routes ===

// 🧠 Basic /api/scan
app.post("/api/scan", async (req, res) => {
  const { target, type } = req.body || {};
  if (!target) return res.status(400).json({ error: "missing target" });

  let t = type || (/^\d+\.\d+\.\d+\.\d+$/.test(target) ? "ip" : "domain");
  const out = { target, type: t, when: new Date().toISOString(), checks: {} };

  try {
    if (t === "domain" || t === "ip") {
      out.rdap = await rdapLookup(target, t);
      out.checks.rdap = !!out.rdap;
      if (t === "domain") out.whois = await whoisLookup(target);
      const ip = t === "ip" ? target : await resolveToIp(target);
      out.resolved_ip = ip || null;
      if (ip) out.geo = await ipGeo(ip);
      if (t === "domain") {
        try {
          const r = await fetch("https://" + target);
          out.checks.https = r.ok;
          out.https_status = r.status;
        } catch {
          out.checks.https = false;
        }
      }
    } else {
      out.hints = { suggestion: `Search ${target} on GitHub, Twitter, etc.` };
    }

    out.score = heuristicScore(out);
    db.run("INSERT INTO scans (target,type,payload) VALUES (?,?,?)", [target, t, JSON.stringify(out)]);
    res.json(out);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// 🛡️ Pro /api/deepscan (requires verified payment)
app.post("/api/deepscan", async (req, res) => {
  const { target, session_id } = req.body || {};
  if (!target || !session_id) return res.status(400).json({ error: "missing target or session_id" });

  // Verify Stripe session
  if (!paidSessions.has(session_id)) {
    return res.status(403).json({ error: "Pro access required (no valid payment session)" });
  }

  try {
    const out = { target, when: new Date().toISOString(), details: {} };
    const isDomain = /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(target);

    if (isDomain) out.details.whois = await whoisLookup(target);
    out.details.rdap = await rdapLookup(target, isDomain ? "domain" : "ip");

    const ip = isDomain ? await resolveToIp(target) : (/^\d+\.\d+\.\d+\.\d+$/.test(target) ? target : null);
    out.resolved_ip = ip || null;
    if (ip) {
      out.details.geo = await ipGeo(ip);
      out.details.ports = await scanPorts(ip, COMMON_PORTS.slice(0, 20));
      if (SHODAN_KEY) out.details.shodan = await shodanLookup(ip);
    }

    out.score = heuristicScore(out);
    db.run("INSERT INTO scans (target,type,payload) VALUES (?,?,?)", [target, "deepscan", JSON.stringify(out)]);
    res.json(out);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// 💳 Create Stripe checkout
app.post("/api/create-checkout-session", async (req, res) => {
  if (!stripe) return res.status(400).json({ error: "Stripe not configured" });
  const { target } = req.body || {};

  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "payment",
      line_items: [
        {
          price_data: {
            currency: "usd",
            product_data: { name: "Legend Cyber Pro Scan" },
            unit_amount: 199,
          },
          quantity: 1,
        },
      ],
      metadata: { target },
      success_url: `${process.env.PUBLIC_URL || "http://localhost:3000"}?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.PUBLIC_URL || "http://localhost:3000"}?canceled=true`,
    });
    res.json({ url: session.url });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// 🧾 Stripe Webhook (verifies payments)
app.post("/api/stripe-webhook", express.raw({ type: "application/json" }), (req, res) => {
  const sig = req.headers["stripe-signature"];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error("Webhook signature error:", err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    paidSessions.add(session.id);
    console.log("✅ Payment verified for session:", session.id);
  }

  res.json({ received: true });
});

// === Server start ===
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Legend Cyber Analyzer running on port ${PORT}`));
