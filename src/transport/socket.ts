import { connect, Socket } from "node:net";
import { EventEmitter } from "node:events";
import { FrameReader } from "./framer.js";

export interface Transport extends EventEmitter {
  send(frame: Buffer): void;
  close(): void;
}

export class TcpTransport extends EventEmitter implements Transport {
  private reader = new FrameReader();
  private closed = false;

  constructor(private readonly socket: Socket) {
    super();
    socket.on("data", (chunk) => {
      this.reader.feed(chunk);
      let m: Buffer | null;
      while ((m = this.reader.next()) !== null) this.emit("message", m);
    });
    socket.on("error", (err) => this.emit("error", err));
    socket.on("close", () => {
      if (!this.closed) {
        this.closed = true;
        this.emit("close");
      }
    });
  }

  static connect(host: string, port = 445, opts: { timeoutMs?: number; signal?: AbortSignal } = {}): Promise<TcpTransport> {
    return new Promise((resolve, reject) => {
      if (opts.signal?.aborted) { reject(Object.assign(new Error("connection cancelled"), { code: "ECANCELED" })); return; }
      const sock = connect({ host, port });
      const cancel = () => sock.destroy(Object.assign(new Error("connection cancelled"), { code: "ECANCELED" }));
      const onError = (err: Error) => {
        cleanup();
        reject(err);
      };
      const onConnect = () => {
        cleanup();
        resolve(new TcpTransport(sock));
      };
      let timer: NodeJS.Timeout | null = null;
      const cleanup = () => {
        if (timer) clearTimeout(timer);
        opts.signal?.removeEventListener("abort", cancel);
        sock.off("error", onError);
        sock.off("connect", onConnect);
      };
      sock.once("error", onError);
      sock.once("connect", onConnect);
      opts.signal?.addEventListener("abort", cancel, { once: true });
      if (opts.signal?.aborted) cancel();
      if (opts.timeoutMs && opts.timeoutMs > 0) {
        timer = setTimeout(() => {
          sock.destroy(new Error(`connect timeout after ${opts.timeoutMs}ms`));
        }, opts.timeoutMs);
      }
    });
  }

  send(frame: Buffer): void {
    if (this.closed) throw new Error("TcpTransport: closed");
    this.socket.write(frame);
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.socket.destroy();
  }
}
