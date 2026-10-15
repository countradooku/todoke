// The TypeScript bindings (the npm package BoltFFI packs into
// ../target-tests/wasm/pkg) as a web page or Node would load them. The
// core does not run in a browser yet (browser mode comes later): starting
// one is refused, and everything else loads and answers.

import assert from "node:assert/strict";
import { test } from "node:test";

import { Core, KeyStoragePolicy } from "../../target-tests/wasm/pkg/node.js";

const settings = {
  home: "/todoke",
  downloads: "/todoke/downloads",
  lan: false,
  allowLoopback: false,
  hidden: false,
  historyDays: 7,
  keyStorage: KeyStoragePolicy.File,
};

test("the module loads and knows its version", () => {
  assert.match(Core.version(), /^\d+\.\d+\.\d+/);
});

test("a core does not start in the browser yet", () => {
  // Fallible constructors give null in TypeScript (BoltFFI 0.31.1).
  assert.equal(Core.new(settings), null);
});

test("malformed settings are refused too", () => {
  assert.equal(Core.new({ ...settings, home: "relative" }), null);
});
