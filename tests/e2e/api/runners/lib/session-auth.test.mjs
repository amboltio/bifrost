// Unit tests for routing in-script calls through the administrator session. Run directly:
// `node session-auth.test.mjs`. Same shape as chained-vars.test.mjs next door.
import assert from "node:assert";
import { SEND_HELPER, sessionAuthHelper, routeScriptCallsThroughSession } from "./session-auth.mjs";

let passed = 0;
function test(name, fn) {
  fn();
  passed++;
  console.log(`  ok - ${name}`);
}

const BASE = "http://localhost:8080";
const script = (...lines) => ({ listen: "test", script: { type: "text/javascript", exec: lines } });

// Runs the helper against a stub pm and returns the request it handed to pm.sendRequest.
function sent(req, vars = { adminAuthHeader: "tok", baseUrl: BASE }) {
  let seen = null;
  const pm = { variables: { get: (k) => vars[k] }, sendRequest: (r) => { seen = r; } };
  new Function("pm", "req", `${sessionAuthHelper("adminAuthHeader").join("\n")}\n${SEND_HELPER}(req, function () {});`)(pm, req);
  return seen;
}

test("a call to this gateway's /api gets the token, whatever shape the request takes", () => {
  assert.deepEqual(sent(`${BASE}/api/providers`).header, { "Authorization": "tok" });
  assert.deepEqual(sent({ url: `${BASE}/api/providers`, method: "POST", header: { "Content-Type": "application/json" } }).header, { "Content-Type": "application/json", "Authorization": "tok" });
  assert.deepEqual(sent({ url: `${BASE}/api/logs/1`, header: [{ key: "Accept", value: "*/*" }] }).header, [{ key: "Accept", value: "*/*" }, { key: "Authorization", value: "tok" }]);
  assert.equal(sent({ url: `${BASE}/api/logs/1`, header: "Accept: */*" }).header, "Accept: */*\nAuthorization: tok");
  assert.deepEqual(sent({ url: { raw: `${BASE}/api/providers` } }).header, { "Authorization": "tok" });
  assert.deepEqual(sent({ url: "{{baseUrl}}/api/providers" }).header, { "Authorization": "tok" });
  assert.deepEqual(sent({ url: "{{base_url}}/api/providers" }).header, { "Authorization": "tok" });
  assert.deepEqual(sent({ url: `${BASE}/api/providers` }, { adminAuthHeader: 'tok', base_url: `${BASE}/` }).header, { Authorization: 'tok' });
});

test("a token the script already set is kept, in any letter case", () => {
  assert.deepEqual(sent({ url: `${BASE}/api/providers`, header: { "authorization": "own" } }).header, { "authorization": "own" });
  assert.deepEqual(sent({ url: `${BASE}/api/providers`, header: [{ key: "Authorization", value: "own" }] }).header, [{ key: "Authorization", value: "own" }]);
});

test("calls that are not to this gateway's /api, or with no token configured, go out unchanged", () => {
  const inference = { url: `${BASE}/v1/chat/completions`, method: "POST", header: { "Content-Type": "application/json" } };
  assert.equal(sent(inference), inference);
  const fixture = { url: "http://127.0.0.1:8792/__reset", method: "POST" };
  assert.equal(sent(fixture), fixture);
  const elsewhere = { url: "https://example.com/api/thing" };
  assert.equal(sent(elsewhere), elsewhere);
  const noToken = { url: `${BASE}/api/providers` };
  assert.equal(sent(noToken, { baseUrl: BASE }), noToken);
});

test("every script that calls pm.sendRequest is rewritten, at every level", () => {
  const collection = {
    event: [script("pm.sendRequest(BASE + '/api/x', function () {});")],
    item: [
      {
        name: "folder",
        event: [script("pm.sendRequest({ url: BASE + '/api/y' }, cb);")],
        item: [{ name: "row", event: [script("var a = 1;", "pm.sendRequest(u, cb); pm.sendRequest(v, cb);")], request: {} }],
      },
    ],
  };
  assert.equal(routeScriptCallsThroughSession(collection, "adminAuthHeader"), 3);
  const row = collection.item[0].item[0].event[0].script.exec;
  assert.deepEqual(row.slice(0, sessionAuthHelper("adminAuthHeader").length), sessionAuthHelper("adminAuthHeader"));
  const body = row.slice(sessionAuthHelper("adminAuthHeader").length).join("\n");
  assert.equal(body, `var a = 1;\n${SEND_HELPER}(u, cb); ${SEND_HELPER}(v, cb);`);
});

test("scripts that make no call, or manage the token themselves, are left alone, and a second pass changes nothing", () => {
  const plain = script("pm.test('x', function () {});");
  const lockout = script("pm.request.headers.remove('Authorization');", "pm.sendRequest(BASE + '/api/x', cb);");
  const calls = script("pm.sendRequest(BASE + '/api/x', cb);");
  const collection = { item: [{ name: "row", event: [plain, lockout, calls], request: {} }] };
  const before = JSON.parse(JSON.stringify([plain, lockout]));
  assert.equal(routeScriptCallsThroughSession(collection, "adminAuthHeader"), 1);
  assert.deepEqual([plain, lockout], before);
  const once = JSON.stringify(collection);
  assert.equal(routeScriptCallsThroughSession(collection, "adminAuthHeader"), 0);
  assert.equal(JSON.stringify(collection), once);
});

console.log(`${passed} passed`);
