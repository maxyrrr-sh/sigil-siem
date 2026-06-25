// Deterministic in-memory localStorage for unit tests — jsdom's Storage can be
// unavailable/flaky under per-file isolation, and token.ts depends on it.

const store = new Map<string, string>();
const mem = {
  get length() {
    return store.size;
  },
  clear() {
    store.clear();
  },
  getItem(key: string) {
    return store.has(key) ? store.get(key)! : null;
  },
  key(index: number) {
    return [...store.keys()][index] ?? null;
  },
  removeItem(key: string) {
    store.delete(key);
  },
  setItem(key: string, value: string) {
    store.set(key, String(value));
  },
} as Storage;

Object.defineProperty(globalThis, 'localStorage', {
  value: mem,
  writable: true,
  configurable: true,
});
