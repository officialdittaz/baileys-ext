import { DEFAULT_ORIGIN } from "../../Defaults/index.js";
import { AbstractSocketClient } from "./types.js";
import { EventEmitter } from "events";

class BunWebSocketWrapper extends EventEmitter {
    constructor(url, options = {}) {
        super();
        this._readyState = 3; // CLOSED

        const headers = {
            Origin: options.origin || DEFAULT_ORIGIN,
            ...(options.headers || {}),
        };

        this._ws = new globalThis.WebSocket(typeof url === "string" ? url : url.toString(), {
            headers,
        });

        this._readyState = 0; // CONNECTING
        this._ws.addEventListener("open", () => {
            this._readyState = 1; // OPEN
            this.emit("open");
        });
        this._ws.addEventListener("message", (event) => {
            let data = event.data;
            if (data instanceof ArrayBuffer) {
                data = Buffer.from(data);
            } else if (typeof data === "string") {
                data = Buffer.from(data);
            }
            this.emit("message", data);
        });
        this._ws.addEventListener("close", (event) => {
            this._readyState = 3; // CLOSED
            this.emit("close", event.code, event.reason);
        });
        this._ws.addEventListener("error", (event) => {
            const error = new Error(event.message || "WebSocket error");
            error.code = event.error?.code || "ECONNRESET";
            if (event.error) {
                error.cause = event.error;
            }

            this.emit("error", error);
        });
    }

    get readyState() {
        return this._readyState;
    }

    send(data, callback) {
        if (this._readyState !== 1) {
            const err = new Error("WebSocket is not open: readyState " + this._readyState);
            err.code = "ENOTOPEN";
            if (callback) callback(err);
            return;
        }

        try {
            this._ws.send(data);
            if (callback) {
                queueMicrotask(() => callback());
            }
        } catch (error) {
            if (!error.code) {
                error.code = "ESEND";
            }
            if (callback) callback(error);
        }
    }

    close(code, reason) {
        if (this._readyState === 2 || this._readyState === 3) return;
        this._readyState = 2; // CLOSING
        try {
            this._ws.close(code, reason);
        } catch {
            // Ignore
        }
    }

    setMaxListeners() {
        return this;
    }

    terminate() {
        this.close();
    }
}

BunWebSocketWrapper.CONNECTING = 0;
BunWebSocketWrapper.OPEN = 1;
BunWebSocketWrapper.CLOSING = 2;
BunWebSocketWrapper.CLOSED = 3;

export class WebSocketClient extends AbstractSocketClient {
    constructor() {
        super(...arguments);
        this.socket = null;
    }

    get isOpen() {
        return this.socket?.readyState === BunWebSocketWrapper.OPEN;
    }

    get isClosed() {
        return this.socket === null || this.socket?.readyState === BunWebSocketWrapper.CLOSED;
    }

    get isClosing() {
        return this.socket === null || this.socket?.readyState === BunWebSocketWrapper.CLOSING;
    }

    get isConnecting() {
        return this.socket?.readyState === BunWebSocketWrapper.CONNECTING;
    }

    connect() {
        if (this.socket) {
            return;
        }

        this.socket = new BunWebSocketWrapper(this.url, {
            origin: DEFAULT_ORIGIN,
            headers: this.config.options?.headers,
            handshakeTimeout: this.config.connectTimeoutMs,
            timeout: this.config.connectTimeoutMs,
            agent: this.config.agent,
        });

        this.socket.setMaxListeners(0);

        const events = [
            "close",
            "error",
            "upgrade",
            "message",
            "open",
            "ping",
            "pong",
            "unexpected-response",
        ];

        for (const event of events) {
            this.socket?.on(event, (...args) => this.emit(event, ...args));
        }
    }

    close() {
        if (!this.socket) {
            return;
        }
        this.socket.close();
        this.socket = null;
    }

    send(str, cb) {
        this.socket?.send(str, cb);
        return Boolean(this.socket);
    }
}
//# sourceMappingURL=websocket.js.map
