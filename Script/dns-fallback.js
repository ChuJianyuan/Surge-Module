
/*
 * Surge DNS Fallback v2.1
 * Compact Logging Edition
 *
 * Sequential DoH failover
 * Circuit breaker with auto-recovery
 * One success log per DNS resolution
 * IPv4 A records only
 */

const SERVERS = [
  "https://120.76.130.89:16666/dns-query",
  "https://dns02.shanhai.you:16666/dns-query",
  "https://dns03.shanhai.you:16666/dns-query"
];

const TIMEOUT = 2;
const FAIL_LIMIT = 2;
const COOLDOWN = 120000;
const TTL = 60;
const DEBUG = false;

const STORE_KEY = "airport-dns-fallback-v2";

function log(message, important = false) {
  if (DEBUG || important) {
    console.log("[DNS] " + message);
  }
}

function defaultState() {
  return SERVERS.map(() => ({
    failures: 0,
    openUntil: 0
  }));
}

function loadState() {
  try {
    const raw = $persistentStore.read(STORE_KEY);
    if (!raw) return defaultState();

    const saved = JSON.parse(raw);
    if (!Array.isArray(saved) ||
        saved.length !== SERVERS.length) {
      return defaultState();
    }

    return saved.map(item => ({
      failures:
        item && Number.isFinite(item.failures)
          ? Math.max(0, item.failures)
          : 0,
      openUntil:
        item && Number.isFinite(item.openUntil)
          ? Math.max(0, item.openUntil)
          : 0
    }));
  } catch (e) {
    log("State reset: " + e.message, true);
    return defaultState();
  }
}

let state = loadState();

function saveState() {
  try {
    const ok = $persistentStore.write(
      JSON.stringify(state),
      STORE_KEY
    );
    if (!ok) log("State save failed", true);
  } catch (e) {
    log("Storage error: " + e.message, true);
  }
}

function markSuccess(index) {
  const entry = state[index];
  const recovering = entry.openUntil !== 0;
  const changed =
    entry.failures !== 0 ||
    entry.openUntil !== 0;

  if (changed) {
    entry.failures = 0;
    entry.openUntil = 0;
    saveState();
  }

  if (recovering) {
    log("Recovered #" + (index + 1), true);
  }
}

function markFailure(index, reason) {
  const entry = state[index];

  entry.failures += 1;

  log(
    "Failed #" + (index + 1) +
    ": " + reason,
    true
  );

  if (entry.failures >= FAIL_LIMIT) {
    entry.failures = FAIL_LIMIT;
    entry.openUntil = Date.now() + COOLDOWN;

    log(
      "Circuit OPEN #" + (index + 1) +
      " for 120s",
      true
    );
  }

  saveState();
}

function makeQuery(domain) {
  const name = domain.replace(/\.$/, "");

  if (!name || name.length > 253) {
    throw new Error("Invalid domain length");
  }

  const bytes = [
    0x12, 0x34, 0x01, 0x00,
    0, 1, 0, 0, 0, 0, 0, 0
  ];

  for (const label of name.split(".")) {
    const chars = Array.from(
      label, c => c.charCodeAt(0)
    );

    if (!chars.length ||
        chars.length > 63 ||
        chars.some(c => c > 127)) {
      throw new Error("Invalid DNS label");
    }

    bytes.push(chars.length, ...chars);
  }

  bytes.push(0, 0, 1, 0, 1);
  return new Uint8Array(bytes);
}

function parseAnswer(data) {
  if (!(data instanceof Uint8Array) ||
      data.length < 12) {
    throw new Error("Invalid DNS response");
  }

  const u16 = p => (data[p] << 8) | data[p + 1];

  if (u16(0) !== 0x1234 ||
      !(data[2] & 0x80) ||
      (data[2] & 0x02) ||
      (data[3] & 15) !== 0 ||
      u16(4) !== 1) {
    throw new Error("DNS status error");
  }

  function skipName(pos) {
    for (let n = 0; n < 128; n++) {
      if (pos >= data.length)
        throw new Error("Truncated name");

      const len = data[pos++];

      if ((len & 0xc0) === 0xc0) {
        if (pos >= data.length)
          throw new Error("Invalid pointer");
        return pos + 1;
      }

      if ((len & 0xc0) !== 0)
        throw new Error("Invalid label");

      if (len === 0) return pos;

      pos += len;

      if (pos > data.length)
        throw new Error("Truncated label");
    }

    throw new Error("Invalid DNS name");
  }

  let pos = skipName(12);

  if (pos + 4 > data.length ||
      u16(pos) !== 1 ||
      u16(pos + 2) !== 1) {
    throw new Error("Unexpected question");
  }

  pos += 4;

  const ips = [];

  for (let i = 0; i < u16(6); i++) {
    pos = skipName(pos);

    if (pos + 10 > data.length)
      throw new Error("Truncated answer");

    const type = u16(pos);
    const klass = u16(pos + 2);
    const len = u16(pos + 8);

    pos += 10;

    if (pos + len > data.length)
      throw new Error("Truncated RDATA");

    if (type === 1 && klass === 1 && len === 4) {
      ips.push(
        Array.from(
          data.slice(pos, pos + 4)
        ).join(".")
      );
    }

    pos += len;
  }

  if (!ips.length)
    throw new Error("No IPv4 records");

  return [...new Set(ips)];
}

function tryNext(index, body) {
  if (index >= SERVERS.length) {
    log("All DNS servers failed", true);
    $done({});
    return;
  }

  const entry = state[index];
  const remaining = entry.openUntil - Date.now();

  if (remaining > 0) {
    log(
      "SKIP #" + (index + 1) +
      " (" + Math.ceil(remaining / 1000) + "s)"
    );
    tryNext(index + 1, body);
    return;
  }

  if (entry.openUntil !== 0) {
    log(
      "Retry after cooldown #" + (index + 1),
      true
    );
  }

  log(
    "Trying #" + (index + 1) +
    ": " + SERVERS[index]
  );

  $httpClient.post({
    url: SERVERS[index],
    headers: {
      "Content-Type": "application/dns-message",
      "Accept": "application/dns-message"
    },
    body: body,
    timeout: TIMEOUT,
    "binary-mode": true
  }, (error, response, data) => {
    try {
      if (error ||
          !response ||
          response.status !== 200) {
        throw new Error(
          String(error ||
            "HTTP " + (response && response.status))
        );
      }

      const addresses = parseAnswer(data);

      markSuccess(index);

      // Always log the actual successful DNS server
      log(
        "Success #" + (index + 1) +
        " [" + SERVERS[index] + "]" +
        ": " + addresses.join(", "),
        true
      );

      $done({
        addresses: addresses,
        ttl: TTL
      });

    } catch (e) {
      markFailure(index, e.message);
      tryNext(index + 1, body);
    }
  });
}

try {
  const body = makeQuery($domain);
  tryNext(0, body);
} catch (e) {
  log("Fatal error: " + e.message, true);
  $done({});
}
