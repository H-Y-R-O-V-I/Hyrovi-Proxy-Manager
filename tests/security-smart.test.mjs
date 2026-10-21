import test from "node:test";
import assert from "node:assert/strict";
import { analyzeSite, analyzeAutomaticActivity } from "../backend/internal/security_smart.js";

const site = (overrides = {}) => ({
  host: "sample.hyrovi.com", source: "VPS", configured: true,
  requests: 200, failures: 1, automationSignals: 0, writes: 0, clientSignatures: 3,
  ...overrides,
});

test("low sample never produces a definite security score", () => {
  const result = analyzeSite(site({requests: 4, failures: 4, automationSignals: 4}));
  assert.equal(result.score, null);
  assert.equal(result.assessment, "too-little-data");
  assert.deepEqual(result.evidence, []);
});

test("high HTTP errors and obvious automation signals are explained", () => {
  const result = analyzeSite(site({requests: 100, failures: 70, automationSignals: 55}));
  assert.equal(result.score, 75);
  assert.equal(result.assessment, "investigate");
  assert.deepEqual(result.evidence.map(x => x.code), ["http_errors", "automation_hints"]);
});

test("many legitimate API writes alone never implies an attack", () => {
  const result = analyzeSite(site({requests: 60, writes: 50}));
  assert.equal(result.score, 0);
  assert.equal(result.assessment, "no-specific-signal");
  assert.deepEqual(result.evidence.map(x => x.points), [0]);
});

test("untrusted negative and excessive counters cannot break analysis", () => {
  const result = analyzeSite(site({requests: "garbage", failures: -1, automationSignals: Infinity}));
  assert.equal(result.requests, 0);
  assert.equal(result.score, null);
});

test("aggregate report is bounded and contains no device or network IDs", () => {
  const input = site({requests: 80, failures: 35, ip: "10.0.0.4",
    userAgent: "sample-private-ua", deviceKey: "abcdef", cookie: "secret"});
  const report = analyzeAutomaticActivity({websites: [input]});
  assert.equal(report.mode, "aggregate-security-only");
  assert.equal(report.totalHosts, 1);
  assert.equal(report.hostsToReview, 1);
  const text = JSON.stringify(report);
  for (const secret of ["10.0.0.4", "sample-private-ua", "abcdef", "secret"]) {
    assert.ok(!text.includes(secret), `must not export ${secret}`);
  }
});
