// Route callback management requests through the canonical session supplied by the runner.
// Calls to fixtures and third-party hosts never receive this credential.
export const SEND_HELPER = "__bfSend";
const CALL = "pm.sendRequest(";
const TOKEN_HEADER = "Authorization";

// The helper's source, reading the token from the collection variable tokenVar.
export function sessionAuthHelper(tokenVar) {
  return [
    `function ${SEND_HELPER}(req, cb) {`,
    `  var token = pm.variables.get('${tokenVar}'), base = pm.variables.get('baseUrl') || pm.variables.get('base_url') || '';`,
    "  if (typeof req === 'string') { req = { url: req, method: 'GET' }; }",
    "  var url = String((req && req.url && req.url.raw) || (req && req.url) || '');",
    "  var ours = (base !== '' && url.indexOf(base.replace(/\\/+$/, '') + '/api/') === 0) || url.indexOf('{{baseUrl}}/api/') === 0 || url.indexOf('{{base_url}}/api/') === 0;",
    "  if (token && ours) {",
    `    var named = function (k) { return String(k).toLowerCase() === '${TOKEN_HEADER.toLowerCase()}'; };`,
    "    var h = req.header;",
    "    if (Array.isArray(h)) {",
    `      if (!h.some(function (x) { return x && named(x.key); })) { h = h.concat([{ key: '${TOKEN_HEADER}', value: token }]); }`,
    "    } else if (typeof h === 'string') {",
    `      if (!/^authorization\\s*:/im.test(h)) { h = h + (h ? '\\n' : '') + '${TOKEN_HEADER}: ' + token; }`,
    "    } else {",
    `      h = Object.assign({}, h || {}); if (!Object.keys(h).some(named)) { h['${TOKEN_HEADER}'] = token; }`,
    "    }",
    "    req = Object.assign({}, req, { header: h });",
    "  }",
    "  return pm.sendRequest(req, cb);",
    "}",
  ];
}

// Rewrites every collection, folder and request script that calls pm.sendRequest to go through
// the helper, and returns how many scripts it rewrote. Running it again changes nothing.
export function routeScriptCallsThroughSession(collection, tokenVar) {
  let rewritten = 0;
  const visit = (events) => {
    for (const event of events || []) {
      const script = event && event.script;
      if (!script || script.exec == null) continue;
      const source = Array.isArray(script.exec) ? script.exec.join("\n") : String(script.exec);
      if (!source.includes(CALL) || source.includes(TOKEN_HEADER) || source.includes(`function ${SEND_HELPER}(`)) continue;
      script.exec = [...sessionAuthHelper(tokenVar), ...source.split(CALL).join(`${SEND_HELPER}(`).split("\n")];
      rewritten++;
    }
  };
  const walk = (items) => {
    for (const item of items || []) {
      visit(item.event);
      walk(item.item);
    }
  };
  visit(collection.event);
  walk(collection.item);
  return rewritten;
}
