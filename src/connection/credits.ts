interface Waiter {
  n: number;
  resolve: () => void;
  reject: (error: Error) => void;
}

export class CreditWindow {
  private waiters: Waiter[] = [];
  private failure: Error | undefined;

  constructor(private credits: number) {}

  available(): number {
    return this.credits;
  }

  take(n: number): Promise<void> {
    if (this.failure) return Promise.reject(this.failure);
    if (n <= 0) return Promise.resolve();
    if (this.credits >= n) {
      this.credits -= n;
      return Promise.resolve();
    }
    return new Promise<void>((resolve, reject) => {
      this.waiters.push({ n, resolve, reject });
    });
  }

  fail(error: Error): void {
    this.failure ??= error;
    for (const waiter of this.waiters.splice(0)) waiter.reject(this.failure);
  }

  release(n: number): void {
    if (this.failure) return;
    if (n <= 0) return;
    this.credits += n;
    while (this.waiters.length > 0 && this.credits >= this.waiters[0]!.n) {
      const w = this.waiters.shift()!;
      this.credits -= w.n;
      w.resolve();
    }
  }
}
