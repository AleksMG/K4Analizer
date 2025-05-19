// worker.js - Оптимизированная версия без дублирования логики оценки
class K4Worker {
    constructor() {
        this.ciphertext = '';
        this.keyLength = 0;
        this.alphabet = '';
        this.knownPlaintext = '';
        this.workerId = 0;
        this.totalWorkers = 1;
        this.keysTested = 0;
        this.batchSize = 50000; // Увеличенный размер пачки
        this.isRunning = false;
        this.currentKey = null;
        this.keySpaceSize = 0;
        this.alphabetIndexMap = {};
        
        // Оптимизации для дешифрования
        this.cipherChars = [];
        this.knownPlaintextUpper = '';
        
        self.onmessage = (e) => this.handleMessage(e.data);
    }

    handleMessage(data) {
        switch (data.type) {
            case 'init':
                this.init(data);
                break;
            case 'start':
                this.start();
                break;
            case 'stop':
                this.stop();
                break;
        }
    }

    init(data) {
        Object.assign(this, {
            ciphertext: data.ciphertext,
            keyLength: data.keyLength,
            alphabet: data.alphabet,
            knownPlaintext: data.knownPlaintext,
            workerId: data.workerId,
            totalWorkers: data.totalWorkers
        });

        this.cipherChars = this.ciphertext.split('');
        this.knownPlaintextUpper = this.knownPlaintext.toUpperCase();
        this.keySpaceSize = Math.pow(this.alphabet.length, this.keyLength);
        this.alphabetIndexMap = this.createAlphabetIndexMap();
        this.initStartKey();
    }

    createAlphabetIndexMap() {
        const map = {};
        for (let i = 0; i < this.alphabet.length; i++) {
            map[this.alphabet[i]] = i;
        }
        return map;
    }

    initStartKey() {
        // Распределение ключевого пространства между воркерами
        const segmentSize = Math.ceil(this.keySpaceSize / this.totalWorkers);
        const startIndex = this.workerId * segmentSize;
        this.currentKey = this.indexToKey(startIndex);
    }

    indexToKey(index) {
        let key = '';
        let remaining = index % this.keySpaceSize;
        
        for (let i = 0; i < this.keyLength; i++) {
            const power = Math.pow(this.alphabet.length, this.keyLength - i - 1);
            const pos = Math.floor(remaining / power);
            key += this.alphabet[pos % this.alphabet.length];
            remaining %= power;
        }
        
        return key;
    }

    start() {
        if (this.isRunning) return;
        this.isRunning = true;
        this.processBatch();
    }

    stop() {
        this.isRunning = false;
        self.postMessage({
            type: 'complete',
            keysTested: this.keysTested
        });
    }

    processBatch() {
        if (!this.isRunning) return;

        const batchStart = performance.now();
        let batchResults = [];
        let processed = 0;

        while (processed < this.batchSize && this.isRunning) {
            const plaintext = this.decrypt(this.cipherChars, this.currentKey);
            
            // Только минимально необходимая проверка
            if (this.knownPlaintextUpper && plaintext.includes(this.knownPlaintextUpper)) {
                batchResults.push({
                    key: this.currentKey,
                    plaintext: plaintext,
                    workerId: this.workerId
                });
            }

            this.keysTested++;
            processed++;
            this.nextKey();

            // Регулировка нагрузки для предотвращения блокировки
            if (performance.now() - batchStart > 50) break;
        }

        if (batchResults.length > 0) {
            self.postMessage({
                type: 'result',
                results: batchResults
            });
        }

        // Отчет о прогрессе каждые 1000 обработанных ключей
        if (this.keysTested % 1000 === 0) {
            self.postMessage({
                type: 'progress',
                keysTested: this.keysTested,
                workerId: this.workerId
            });
        }

        // Проверка завершения работы
        if (this.keysTested >= Math.ceil(this.keySpaceSize / this.totalWorkers)) {
            this.stop();
            return;
        }

        // Продолжение обработки с минимальной задержкой
        setTimeout(() => this.processBatch(), 0);
    }

    nextKey() {
        let newKey = '';
        let carry = 1;

        for (let i = this.keyLength - 1; i >= 0; i--) {
            const currentIndex = this.alphabetIndexMap[this.currentKey[i]];
            const newIndex = (currentIndex + carry) % this.alphabet.length;
            
            newKey = this.alphabet[newIndex] + newKey;
            carry = Math.floor((currentIndex + carry) / this.alphabet.length);
            
            if (carry === 0) {
                newKey = this.currentKey.substring(0, i) + newKey;
                break;
            }
        }

        this.currentKey = carry > 0 ? 
            this.indexToKey(this.workerId * Math.ceil(this.keySpaceSize / this.totalWorkers)) : 
            newKey;
    }

    decrypt(cipherChars, key) {
        const keyChars = key.split('');
        const keyLength = key.length;
        const alphabetLength = this.alphabet.length;
        let plaintext = '';
        
        for (let i = 0; i < cipherChars.length; i++) {
            const cipherIndex = this.alphabetIndexMap[cipherChars[i]];
            const keyIndex = this.alphabetIndexMap[keyChars[i % keyLength]];
            const plainIndex = (cipherIndex - keyIndex + alphabetLength) % alphabetLength;
            plaintext += this.alphabet[plainIndex];
        }
        
        return plaintext;
    }
}

// Инициализация воркера
const worker = new K4Worker();
