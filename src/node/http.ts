import type { IncomingMessage, ServerResponse } from 'node:http'

import { createFetchHandler, MAX_BODY_BYTES, type HandlerOptions } from '../handlers.js'

/** A Node request; `body` is what a framework (e.g. `express.json()`) parsed when it read the stream. */
export type NodeRequest = IncomingMessage & { body?: unknown }

/**
 * A `node:http` handler for the three endpoints, also usable as an Express route handler. Dispatches as
 * `createFetchHandler` does; reads the stream itself unless a framework already read it into `req.body`.
 */
export function createNodeHandler(options: HandlerOptions): (req: NodeRequest, res: ServerResponse) => Promise<void> {
	const handle = createFetchHandler(options)
	return async (req, res) => {
		let response: Response
		try {
			// Every method but POST is answered alike (404 or 405), and `Request` refuses some, e.g. TRACE.
			const post = req.method === 'POST'
			const body = post ? await readBody(req) : undefined
			response = await handle(new Request(requestURL(req), { method: post ? 'POST' : 'GET', body }))
		} catch {
			response = Response.json({ error: 'internal server error' }, { status: 500 })
		}
		try {
			res.writeHead(response.status, Object.fromEntries(response.headers))
			res.end(new Uint8Array(await response.arrayBuffer()))
		} catch {
			// The client is gone; there is no one left to answer.
		}
	}
}

function requestURL(req: IncomingMessage): string {
	try {
		return new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`).href
	} catch {
		return new URL(req.url ?? '/', 'http://localhost').href
	}
}

// An unread stream is read here, whatever `req.body` holds: a parser whose content type did not match leaves
// `{}` there without reading. Past the cap the rest is discarded, so the connection stays usable.
async function readBody(req: NodeRequest): Promise<Uint8Array> {
	if (req.readableEnded) {
		const parsed = req.body
		if (parsed instanceof Uint8Array) return parsed
		// Read by something that left no body: an empty one, answered 400.
		if (parsed === undefined) return new Uint8Array()
		return new TextEncoder().encode(typeof parsed === 'string' ? parsed : JSON.stringify(parsed))
	}
	const chunks: Uint8Array[] = []
	let size = 0
	// Chunks are strings after `req.setEncoding()`.
	for await (const chunk of req.iterator({ destroyOnReturn: false }) as AsyncIterable<Uint8Array | string>) {
		const bytes = typeof chunk === 'string' ? new TextEncoder().encode(chunk) : chunk
		chunks.push(bytes)
		size += bytes.byteLength
		if (size > MAX_BODY_BYTES) break
	}
	if (size > MAX_BODY_BYTES) req.resume()
	return Buffer.concat(chunks)
}
