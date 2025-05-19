// worker.js - Полностью совместимый с вашим K4Decryptor
class K4Worker {
    constructor() {
        this.workerId = 0;
        this.totalWorkers = 1;
        this.keysTested = 0;
        this.isRunning = false;
        this.lastUpdate = 0;
        this.updateInterval = 200; // Частота обновлений (мс)

        // Параметры дешифрования
        this.ciphertext = '';
        this.keyLength = 0;
        this.alphabet = '';
        this.knownPlaintext = '';
        
        // Оптимизации
        this.alphabetIndices = {};
        this.cipherIndices = [];
        this.keyIndices = [];
        this.currentKey = '';

        self.onmessage = (e) => this.handleMessage(e.data);
    }

    handleMessage(data) {
        switch (data.type) {
            case 'init':
                this.initialize(data);
                break;
            case 'start':
                this.startDecryption();
                break;
            case 'stop':
                this.stopDecryption();
                break;
        }
    }

    initialize(params) {
        this.ciphertext = params.ciphertext;
        this.keyLength = parseInt(params.keyLength);
        this.alphabet = params.alphabet;
        this.knownPlaintext = params.knownPlaintext?.toUpperCase() || '';
        this.workerId = parseInt(params.workerId);
        this.totalWorkers = parseInt(params.totalWorkers);

        // Предварительные вычисления
        this.alphabetIndices = this.buildAlphabetMap();
        this.cipherIndices = this.mapTextToIndices(this.ciphertext);
        this.initializeKeySpace();
    }

    buildAlphabetMap() {
        const map = {};
        for (let i = 0; i < this.alphabet.length; i++) {
            map[this.alphabet[i]] = i;
        }
        return map;
    }

    mapTextToIndices(text) {
        return text.split('').map(c => this.alphabetIndices[c]);
    }

    initializeKeySpace() {
        const totalKeys = Math.pow(this.alphabet.length, this.keyLength);
        const keysPerWorker = Math.ceil(totalKeys / this.totalWorkers);
        const startIndex = this.workerId * keysPerWorker;
        
        this.keyIndices = this.indexToKeyIndices(startIndex);
        this.currentKey = this.indicesToKey(this.keyIndices);
    }

    indexToKeyIndices(index) {
        const indices = [];
        let remaining = index;
        
        for (let i = 0; i < this.keyLength; i++) {
            const power = Math.pow(this.alphabet.length, this.keyLength - i - 1);
            indices.push(Math.floor(remaining / power) % this.alphabet.length);
            remaining %= power;
        }
        
        return indices;
    }

    indicesToKey(indices) {
        return indices.map(i => this.alphabet[i]).join('');
    }

    startDecryption() {
        if (this.isRunning) return;
        
        this.isRunning = true;
        this.lastUpdate = performance.now();
        this.decryptBatch();
    }

    stopDecryption() {
        this.isRunning = false;
        this.sendProgress(); // Финальное обновление
        self.postMessage({ type: 'complete', keysTested: this.keysTested });
    }

    decryptBatch() {
        if (!this.isRunning) return;

        const batchStart = performance.now();
        let batchCount = 0;
        const maxBatchTime = 30; // мс

        while (this.isRunning && batchCount < 50000) {
            const plaintext = this.decryptWithCurrentKey();
            
            if (this.checkForKnownText(plaintext)) {
                self.postMessage({
                    type: 'result',
                    key: this.currentKey,
                    plaintext: plaintext,
                    score: this.quickScore(plaintext),
                    workerId: this.workerId
                });
            }

            this.keysTested++;
            batchCount++;
            this.nextKey();

            if (performance.now() - batchStart > maxBatchTime) break;
        }

        // Регулярные обновления прогресса
        if (performance.now() - this.lastUpdate >= this.updateInterval) {
            this.sendProgress();
        }

        // Проверка завершения
        const totalKeys = Math.pow(this.alphabet.length, this.keyLength);
        const keysPerWorker = Math.ceil(totalKeys / this.totalWorkers);
        
        if (this.keysTested >= keysPerWorker) {
            this.stopDecryption();
            return;
        }

        // Продолжение обработки
        setTimeout(() => this.decryptBatch(), 0);
    }

    sendProgress() {
        this.lastUpdate = performance.now();
        self.postMessage({
            type: 'progress',
            keysTested: this.keysTested,
            workerId: this.workerId
        });
    }

    decryptWithCurrentKey() {
        const keyLength = this.keyLength;
        const alphabetSize = this.alphabet.length;
        let plaintext = '';
        
        for (let i = 0; i < this.cipherIndices.length; i++) {
            const cipherIdx = this.cipherIndices[i];
            const keyIdx = this.keyIndices[i % keyLength];
            const plainIdx = (cipherIdx - keyIdx + alphabetSize) % alphabetSize;
            plaintext += this.alphabet[plainIdx];
        }
        
        return plaintext;
    }

    checkForKnownText(plaintext) {
        return this.knownPlaintext && plaintext.includes(this.knownPlaintext);
    }

    quickScore(plaintext) {
        // Минимальная оценка только для базовой фильтрации
        return this.knownPlaintext ? 
            (plaintext.match(new RegExp(this.knownPlaintext, 'g')) || []).length * 100 : 0;
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
        
        // Переполнение - начинаем сначала своего сегмента
        if (carry > 0) {
            const totalKeys = Math.pow(this.alphabet.length, this.keyLength);
            const keysPerWorker = Math.ceil(totalKeys / this.totalWorkers);
            const startIndex = this.workerId * keysPerWorker;
            this.keyIndices = this.indexToKeyIndices(startIndex);
            this.currentKey = this.indicesToKey(this.keyIndices);
        }
    }
}

// Инициализация воркера
const worker = new K4Worker();
