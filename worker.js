// worker.js — полная совместимость с K4Decryptor.js (включая обработку результатов)
class K4Worker {
    constructor() {
        this.isRunning = false;
        this.keysTested = 0;
        this.alphabetMap = {};
        this.cipherIndices = [];
        this.keyIndices = [];

        self.onmessage = (e) => {
            const { type, ...data } = e.data;
            if (type === 'init') this.init(data);
            if (type === 'start') this.start();
            if (type === 'stop') this.stop();
        };
    }

    init({ ciphertext, keyLength, alphabet, knownPlaintext, workerId, totalWorkers }) {
        this.ciphertext = ciphertext;
        this.keyLength = keyLength;
        this.alphabet = alphabet;
        this.knownPlaintext = knownPlaintext?.toUpperCase() || '';
        this.workerId = workerId;
        this.totalWorkers = totalWorkers;

        // Оптимизация: предварительно маппим алфавит и ciphertext
        this.alphabetMap = Object.fromEntries([...alphabet].map((c, i) => [c, i]));
        this.cipherIndices = [...ciphertext].map(c => this.alphabetMap[c] || 0);

        // Инициализация начального ключа
        const totalKeys = Math.pow(alphabet.length, keyLength);
        const keysPerWorker = Math.ceil(totalKeys / totalWorkers);
        this.keyIndices = this.indexToKeyIndices(workerId * keysPerWorker);
        this.currentKey = this.indicesToKey(this.keyIndices);
    }

    indexToKeyIndices(index) {
        const indices = [];
        let remaining = index;
        for (let i = 0; i < this.keyLength; i++) {
            const power = Math.pow(this.alphabet.length, this.keyLength - i - 1);
            indices.push(Math.floor(remaining / power) % this.alphabet.length;
            remaining %= power;
        }
        return indices;
    }

    indicesToKey(indices) {
        return indices.map(i => this.alphabet[i]).join('');
    }

    start() {
        if (this.isRunning) return;
        this.isRunning = true;
        this.process();
    }

    process() {
        if (!this.isRunning) return;

        const BATCH_SIZE = 100000; // Увеличенный размер пачки
        const results = [];
        const startTime = performance.now();

        for (let i = 0; i < BATCH_SIZE && this.isRunning; i++) {
            // Дешифровка (оптимизированная)
            let plaintext = '';
            for (let j = 0; j < this.cipherIndices.length; j++) {
                const cipherIdx = this.cipherIndices[j];
                const keyIdx = this.keyIndices[j % this.keyLength];
                const plainIdx = (cipherIdx - keyIdx + this.alphabet.length) % this.alphabet.length;
                plaintext += this.alphabet[plainIdx];
            }

            // Быстрая проверка knownPlaintext (как в K4Decryptor.js)
            if (this.knownPlaintext && plaintext.includes(this.knownPlaintext)) {
                results.push({
                    key: this.currentKey,
                    plaintext: plaintext,
                    workerId: this.workerId
                });
            }

            this.keysTested++;
            this.nextKey();

            if (performance.now() - startTime > 50) break; // Не блокировать поток
        }

        if (results.length > 0) {
            self.postMessage({ type: 'result', results });
        }

        // Отправка прогресса (как в K4Decryptor.handleWorkerMessage())
        self.postMessage({
            type: 'progress',
            keysTested: this.keysTested,
            workerId: this.workerId
        });

        // Проверка завершения
        const totalKeys = Math.pow(this.alphabet.length, this.keyLength);
        if (this.keysTested >= Math.ceil(totalKeys / this.totalWorkers)) {
            this.stop();
            return;
        }

        setTimeout(() => this.process(), 0);
    }

    nextKey() {
        let carry = 1;
        for (let i = this.keyLength - 1; i >= 0; i--) {
            this.keyIndices[i] += carry;
            carry = Math.floor(this.keyIndices[i] / this.alphabet.length);
            this.keyIndices[i] %= this.alphabet.length;
            if (carry === 0) break;
        }

        this.currentKey = this.indicesToKey(this.keyIndices);

        // Переполнение -> начинаем с начала своего сегмента
        if (carry > 0) {
            const totalKeys = Math.pow(this.alphabet.length, this.keyLength);
            const keysPerWorker = Math.ceil(totalKeys / this.totalWorkers);
            this.keyIndices = this.indexToKeyIndices(this.workerId * keysPerWorker);
            this.currentKey = this.indicesToKey(this.keyIndices);
        }
    }

    stop() {
        this.isRunning = false;
        self.postMessage({ type: 'complete', keysTested: this.keysTested });
    }
}

new K4Worker();
