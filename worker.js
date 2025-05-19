// worker.js - Финальная проверенная версия
class K4Worker {
    constructor() {
        // Соответствует параметрам из K4Decryptor.initWorkers()
        this.ciphertext = '';
        this.keyLength = 0;
        this.alphabet = '';
        this.workerId = 0;
        this.totalWorkers = 1;
        this.keysTested = 0;
        this.isRunning = false;
        this.currentKey = null;
        this.alphabetMap = {};

        // Обработчик сообщений
        self.onmessage = (e) => {
            const { type, ...data } = e.data;
            if (type === 'init') this.initialize(data);
            if (type === 'start') this.start();
            if (type === 'stop') this.stop();
        };
    }

    initialize(params) {
        this.ciphertext = params.ciphertext;
        this.keyLength = parseInt(params.keyLength);
        this.alphabet = params.alphabet;
        this.workerId = parseInt(params.workerId);
        this.totalWorkers = parseInt(params.totalWorkers);
        
        // Инициализация алфавита (без изменений)
        this.alphabetMap = {};
        for (let i = 0; i < this.alphabet.length; i++) {
            this.alphabetMap[this.alphabet[i]] = i;
        }
        
        // Начальный ключ (как в вашем коде)
        const totalKeys = Math.pow(this.alphabet.length, this.keyLength);
        const keysPerWorker = Math.ceil(totalKeys / this.totalWorkers);
        this.currentKey = this.generateKey(this.workerId * keysPerWorker);
    }

    generateKey(index) {
        let key = '';
        let remaining = index;
        for (let i = 0; i < this.keyLength; i++) {
            const power = Math.pow(this.alphabet.length, this.keyLength - i - 1);
            const pos = Math.floor(remaining / power) % this.alphabet.length;
            key += this.alphabet[pos];
            remaining %= power;
        }
        return key;
    }

    start() {
        if (this.isRunning) return;
        this.isRunning = true;
        this.process();
    }

    process() {
        if (!this.isRunning) return;

        const batchSize = 50000; // Оптимальный размер пачки
        const results = [];
        const startTime = performance.now();

        for (let i = 0; i < batchSize && this.isRunning; i++) {
            // Дешифровка как в K4Decryptor.js
            let plaintext = '';
            for (let j = 0; j < this.ciphertext.length; j++) {
                const cipherIdx = this.alphabetMap[this.ciphertext[j]];
                const keyIdx = this.alphabetMap[this.currentKey[j % this.keyLength]];
                const plainIdx = (cipherIdx - keyIdx + this.alphabet.length) % this.alphabet.length;
                plaintext += this.alphabet[plainIdx];
            }
            
            results.push({
                key: this.currentKey,
                plaintext: plaintext,
                workerId: this.workerId
            });

            this.keysTested++;
            this.nextKey();

            if (performance.now() - startTime > 50) break; // Не блокировать поток
        }

        if (results.length > 0) {
            self.postMessage({ type: 'result', results: results });
        }

        self.postMessage({
            type: 'progress',
            keysTested: this.keysTested,
            workerId: this.workerId
        });

        // Проверка завершения (как в вашем коде)
        const totalKeys = Math.pow(this.alphabet.length, this.keyLength);
        if (this.keysTested >= Math.ceil(totalKeys / this.totalWorkers)) {
            this.stop();
            return;
        }

        setTimeout(() => this.process(), 0);
    }

    nextKey() {
        let newKey = '';
        let carry = 1;
        
        for (let i = this.keyLength - 1; i >= 0; i--) {
            const currentIdx = this.alphabetMap[this.currentKey[i]];
            const newIdx = (currentIdx + carry) % this.alphabet.length;
            newKey = this.alphabet[newIdx] + newKey;
            carry = Math.floor((currentIdx + carry) / this.alphabet.length);
            
            if (carry === 0) {
                newKey = this.currentKey.substring(0, i) + newKey;
                break;
            }
        }
        
        this.currentKey = carry > 0 
            ? this.generateKey(this.workerId * Math.ceil(
                Math.pow(this.alphabet.length, this.keyLength) / this.totalWorkers
              ))
            : newKey;
    }

    stop() {
        this.isRunning = false;
        self.postMessage({ 
            type: 'complete', 
            keysTested: this.keysTested 
        });
    }
}

new K4Worker();
