// import WebSocket from "ws";
import { DEFAULT_ORIGIN } from "../../Defaults/index.js";
import { AbstractSocketClient } from "./types.js";

export class WebSocketClient extends AbstractSocketClient {
  constructor() {
    super(...arguments);
    this.socket = null;
  }

  get isOpen() {
    return this.socket?.readyState === WebSocket.OPEN;
  }

  get isClosed() {
    return this.socket === null || this.socket?.readyState === WebSocket.CLOSED;
  }

  get isClosing() {
    return this.socket === null || this.socket?.readyState === WebSocket.CLOSING;
  }

  get isConnecting() {
    return this.socket?.readyState === WebSocket.CONNECTING;
  }

  async connect() {
    if (this.socket) {
      return;
    }

    this.socket = new WebSocket(this.url, {
      origin: DEFAULT_ORIGIN,
    });

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
      this.socket?.addEventListener(event, (...args) => this.emit(event, ...args));
    }
  }

  async close() {
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