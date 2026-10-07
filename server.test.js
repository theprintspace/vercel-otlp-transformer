// A delivery Vercel abandons mid-body must not take the process down (1 Oct 2026:
// three "Error: aborted" rejections in five seconds exhausted Railway's restart
// policy and the drain stayed dark for a week). Run: npm test
process.env.SIGNOZ_INGEST_TOKEN ||= "test-token";
const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const net = require("node:net");
const { server } = require("./server.js");

const listen = () => new Promise((resolve) => server.listen(0, () => resolve(server.address().port)));
const get = (port, path) => new Promise((resolve, reject) =>
  http.get({ port, path }, (res) => { res.resume(); res.on("end", () => resolve(res.statusCode)); }).on("error", reject));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

test("a delivery aborted mid-body is dropped, the server lives on and keeps answering", async () => {
  const port = await listen();
  try {
    let crashed = null;
    const onRejection = (err) => { crashed = err; };
    process.on("unhandledRejection", onRejection);

    // Vercel starts a 100-byte delivery, sends a fragment, then resets the connection.
    const sock = net.connect(port, "127.0.0.1");
    await new Promise((r) => sock.on("connect", r));
    sock.write("POST /vercel HTTP/1.1\r\nHost: t\r\nContent-Type: application/x-ndjson\r\nContent-Length: 100\r\n\r\n{\"message\":\"half");
    await sleep(50);
    sock.destroy();
    await sleep(100);

    process.off("unhandledRejection", onRejection);
    assert.equal(crashed, null, "the aborted read escaped the handler");
    assert.equal(server.listening, true);
    assert.equal(await get(port, "/health"), 200);
  } finally {
    await new Promise((r) => server.close(r));
  }
});

test("an empty delivery is acknowledged 204; unknown paths are 404", async () => {
  const port = await listen();
  try {
    const status = await new Promise((resolve, reject) => {
      const req = http.request({ port, path: "/vercel", method: "POST", headers: { "Content-Type": "application/x-ndjson" } },
        (res) => { res.resume(); res.on("end", () => resolve(res.statusCode)); });
      req.on("error", reject);
      req.end("");
    });
    assert.equal(status, 204);
    assert.equal(await get(port, "/nope"), 404);
  } finally {
    await new Promise((r) => server.close(r));
  }
});
