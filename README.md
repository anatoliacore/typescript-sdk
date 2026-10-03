# AnatoliaCore TypeScript SDK

```bash
npm install @anatoliacore/sdk
```

```ts
import { AnatoliaCore } from "@anatoliacore/sdk"

const cloud = new AnatoliaCore({ apiKey: process.env.ANATOLIACORE_API_KEY! })
const instances = await cloud.listInstances()
```

Use this SDK only in trusted server-side runtimes. Never embed customer API
keys in browser or mobile bundles.

Until the first npm release is published, install the checked-out package with
`npm install ./sdk/typescript`.

`requestWithMetadata()` exposes the durable `operationId` returned by every
mutation; pass it to `waitOperation()`. Use `verifyWebhook()` on the original
request bytes before processing any event.
