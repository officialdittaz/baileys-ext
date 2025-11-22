export class LRUCache {
    constructor(options = {}) {
        this.max = options.max || 500;
        this.ttl = options.ttl || Infinity;
        this.ttlAutopurge = options.ttlAutopurge || false;
        this.updateAgeOnGet = options.updateAgeOnGet || false;
        this.dispose = options.dispose || null;

        this.cache = new Map();
        this.head = null;
        this.tail = null;
        this.size = 0;

        if (this.ttlAutopurge && this.ttl !== Infinity) {
            this.purgeInterval = setInterval(
                () => {
                    this.purgeStale();
                },
                Math.min(this.ttl, 60000)
            );
        }
    }

    createNode(key, value) {
        return {
            key,
            value,
            timestamp: Date.now(),
            prev: null,
            next: null,
        };
    }

    moveToHead(node) {
        if (node === this.head) return;
        if (node.prev) node.prev.next = node.next;
        if (node.next) node.next.prev = node.prev;
        if (node === this.tail) this.tail = node.prev;

        node.prev = null;
        node.next = this.head;
        if (this.head) this.head.prev = node;
        this.head = node;
        if (!this.tail) this.tail = node;
    }

    addToHead(node) {
        node.prev = null;
        node.next = this.head;
        if (this.head) this.head.prev = node;
        this.head = node;
        if (!this.tail) this.tail = node;
    }

    removeTail() {
        if (!this.tail) return null;

        const node = this.tail;
        if (this.tail.prev) {
            this.tail = this.tail.prev;
            this.tail.next = null;
        } else {
            this.head = null;
            this.tail = null;
        }

        return node;
    }

    isStale(node) {
        if (this.ttl === Infinity) return false;
        return Date.now() - node.timestamp > this.ttl;
    }

    purgeStale() {
        const now = Date.now();
        const keysToDelete = [];

        for (const [key, node] of this.cache.entries()) {
            if (now - node.timestamp > this.ttl) {
                keysToDelete.push(key);
            }
        }

        for (const key of keysToDelete) {
            this.delete(key);
        }
    }

    set(key, value) {
        let node = this.cache.get(key);

        if (node) {
            node.value = value;
            node.timestamp = Date.now();
            this.moveToHead(node);
        } else {
            node = this.createNode(key, value);
            this.cache.set(key, node);
            this.addToHead(node);
            this.size++;

            if (this.size > this.max) {
                const tailNode = this.removeTail();
                if (tailNode) {
                    this.cache.delete(tailNode.key);
                    this.size--;

                    if (this.dispose) {
                        this.dispose(tailNode.value, tailNode.key);
                    }
                }
            }
        }
    }

    get(key) {
        const node = this.cache.get(key);

        if (!node) return undefined;
        if (this.isStale(node)) {
            this.delete(key);
            return undefined;
        }

        if (this.updateAgeOnGet) {
            node.timestamp = Date.now();
        }

        this.moveToHead(node);

        return node.value;
    }

    has(key) {
        const node = this.cache.get(key);
        if (!node) return false;

        if (this.isStale(node)) {
            this.delete(key);
            return false;
        }

        return true;
    }

    delete(key) {
        const node = this.cache.get(key);
        if (!node) return false;
        if (node.prev) node.prev.next = node.next;
        if (node.next) node.next.prev = node.prev;
        if (node === this.head) this.head = node.next;
        if (node === this.tail) this.tail = node.prev;

        this.cache.delete(key);
        this.size--;

        if (this.dispose) {
            this.dispose(node.value, key);
        }

        return true;
    }

    clear() {
        if (this.dispose) {
            for (const [key, node] of this.cache.entries()) {
                this.dispose(node.value, key);
            }
        }

        this.cache.clear();
        this.head = null;
        this.tail = null;
        this.size = 0;
    }

    entries() {
        const result = [];
        let current = this.head;

        while (current) {
            if (!this.isStale(current)) {
                result.push([current.key, current.value]);
            }
            current = current.next;
        }

        return result;
    }

    destroy() {
        if (this.purgeInterval) {
            clearInterval(this.purgeInterval);
        }
        this.clear();
    }
}
