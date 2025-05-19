// worker.js - 100% совместим с вашим K4Decryptor.js
class K4Worker {
    constructor() {
        // Параметры из главного файла
        this.ciphertext = '';
        this.keyLength = 0;
        this.alphabet = '';
        this.knownPlaintext = '';
        this.workerId = 0;
        this.totalWorkers = 1;
        
        // Состояние
        this.keysTested = 0;
        this.isRunning = false;
        this.currentKey = null;
        this.alphabetIndices = {};
        
        // Обработчик сообщений
        self.onmessage = (e) => this.handleMessage(e.data);
    }

    handleMessage(data) {
        switch (data.type) {
            case 'init':
                this.ciphertext = data.ciphertext;
                this.keyLength = parseInt(data.keyLength);
                this.alphabet = data.alphabet;
                this.knownPlaintext = data.knownPlaintext?.toUpperCase() || '';
                this.workerId = parseInt(data.workerId);
                this.totalWorkers = parseInt(data.totalWorkers);
                this.prepare();
                break;
                
            case 'start':
                if (!this.isRunning) {
                    this.isRunning = true;
                    this.process();
                }
                break;
                
            case 'stop':
                this.isRunning = false;
                self.postMessage({
                    type: 'complete',
                    keysTested: this.keysTested
                });
                break;
        }
    }

    prepare() {
        // Инициализация алфавита
        this.alphabetIndices = {};
        for (let i = 0; i < this.alphabet.length; i++) {
            this.alphabetIndices[this.alphabet[i]] = i;
        }
        
        // Начальный ключ для этого воркера
        const totalKeys = Math.pow(this.alphabet.length, this.keyLength);
        const keysPerWorker = Math.ceil(totalKeys / this.totalWorkers);
        const startIndex = this.workerId * keysPerWorker;
        this.currentKey = this.indexToKey(startIndex);
    }

    indexToKey(index) {
        let key = '';
        let remaining = index;
        for (let i = 0; i < this.keyLength; i++) {
            const power = Math.pow(this.alphabet.length, this.keyLength - i - 1);
            const pos = Math.floor(remaining / power);
            key += this.alphabet[pos % this.alphabet.length];
            remaining %= power;
        }
        return key;
    }

    process() {
        if (!this.isRunning) return;

        const batchStart = performance.now();
        let batchResults = [];
        let processed = 0;

        while (this.isRunning && processed < 50000) {
            const plaintext = this.decrypt(this.currentKey);
            
            // Только базовая проверка на knownPlaintext
            if (this.knownPlaintext && plaintext.includes(this.knownPlaintext)) {
                batchResults.push({
                    key: this.currentKey,
                    plaintext: plaintext,
                    workerId: this.workerId
                });
            }

            this.keysTested++;
            processed++;
            this.nextKey();

            if (performance.now() - batchStart > 50) break;
        }

        // Отправка результатов
        if (batchResults.length > 0) {
            self.postMessage({
                type: 'result',
                results: batchResults
            });
        }

        // Регулярный отчет о прогрессе
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

        // Следующая итерация
        setTimeout(() => this.process(), 0);
    }

    decrypt(key) {
        const keyIndices = key.split('').map(c => this.alphabetIndices[c] || 0);
        let plaintext = '';
        
        for (let i = 0; i < this.ciphertext.length; i++) {
            const cipherIdx = this.alphabetIndices[this.ciphertext[i]] || 0;
            const keyIdx = keyIndices[i % this.keyLength];
            const plainIdx = (cipherIdx - keyIdx + this.alphabet.length) % this.alphabet.length;
            plaintext += this.alphabet[plainIdx];
        }
        
        return plaintext;
    }

    nextKey() {
        let newKey = '';
        let carry = 1;
        
        for (let i = this.keyLength - 1; i >= 0; i--) {
            const currentIdx = this.alphabetIndices[this.currentKey[i]];
            const newIdx = (currentIdx + carry) % this.alphabet.length;
            newKey = this.alphabet[newIdx] + newKey;
            carry = Math.floor((currentIdx + carry) / this.alphabet.length);
            
            if (carry === 0) {
                newKey = this.currentKey.substring(0, i) + newKey;
                break;
            }
        }
        
        this.currentKey = carry > 0 ? 
            this.indexToKey(this.workerId * Math.ceil(Math.pow(this.alphabet.length, this.keyLength) / this.totalWorkers)) : 
            newKey;
    }
}

// Инициализация
new K4Worker();
