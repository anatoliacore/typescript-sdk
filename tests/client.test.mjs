import assert from "node:assert/strict"
import test from "node:test"

import { AnatoliaCore, verifyWebhook } from "../dist/index.js"

test("client keeps the API key in headers and marks redirects as errors", async () => {
  let captured
  const fakeFetch = async (url, init) => {
    captured = { url, init }
    return new Response(JSON.stringify([{ id: "instance-1" }]), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    })
  }
  const client = new AnatoliaCore({ apiKey: `ac_live_${"x".repeat(64)}`, fetch: fakeFetch })
  const result = await client.createInstance({ name: "one" }, "stable-idempotency-key")
  assert.equal(result[0].id, "instance-1")
  assert.equal(captured.url.toString().includes("ac_live_"), false)
  assert.equal(captured.init.headers["X-API-Key"].startsWith("ac_live_"), true)
  assert.equal(captured.init.headers["Idempotency-Key"], "stable-idempotency-key")
  assert.equal(captured.init.redirect, "error")
})

test("client rejects insecure base URLs", () => {
  assert.throws(
    () => new AnatoliaCore({ apiKey: `ac_live_${"x".repeat(64)}`, baseUrl: "http://example.com/api" }),
    /HTTPS/,
  )
  assert.throws(
    () => new AnatoliaCore({ apiKey: `ac_live_${"x".repeat(64)}`, timeoutMs: 0 }),
    /timeoutMs/,
  )
})

test("client exposes operation metadata for polling", async () => {
  const fakeFetch = async () => new Response(JSON.stringify({ id: "instance-1" }), {
    status: 202,
    headers: {
      "Content-Type": "application/json",
      "X-Operation-ID": "operation-1",
      "Operation-Location": "/api/public/v1/operations/operation-1",
    },
  })
  const client = new AnatoliaCore({ apiKey: `ac_live_${"x".repeat(64)}`, fetch: fakeFetch })
  const result = await client.requestWithMetadata("POST", "/instances", { body: { name: "one" } })
  assert.equal(result.operationId, "operation-1")
  assert.equal(result.data.id, "instance-1")
})

test("webhook verifier checks signature timestamp and event id", async () => {
  const secret = "whsec_test-secret"
  const body = '{"id":"event-1","type":"instance.created"}'
  const timestamp = "1700000000"
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  )
  const digest = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${timestamp}.${body}`)),
  )
  const signature = `v1=${Array.from(digest, (value) => value.toString(16).padStart(2, "0")).join("")}`
  const event = await verifyWebhook(secret, body, { id: "event-1", timestamp, signature }, { nowSeconds: 1700000001 })
  assert.equal(event.type, "instance.created")
  await assert.rejects(
    verifyWebhook(secret, body, { id: "event-1", timestamp, signature: "v1=bad" }, { nowSeconds: 1700000001 }),
    /signature/,
  )
})
