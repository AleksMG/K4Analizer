// worker.js
const ENGLISH_FREQ = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
    'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
    'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
    'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
    'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974,
    'Z': 0.074
};

const COMMON_PATTERNS = [
    'THE', 'AND', 'THAT', 'HAVE', 'FOR', 'NOT', 'WITH', 'YOU', 'THIS', 'BUT',
    'HIS', 'FROM', 'THEY', 'WILL', 'WOULD', 'THERE', 'THEIR', 'WHAT', 'ABOUT',
    'WHICH', 'WHEN', 'YOUR', 'WERE', 'BERLIN', 'CLOCK', 'EAST', 'NORTH', 'WEST',
    'SOUTH', 'NORTHEAST', 'NORTHWEST', 'SOUTHEAST', 'SOUTHWEST', 'SECRET', 'CODE',
    'MESSAGE', 'KRYPTOS', 'CIA', 'AGENT', 'COMPASS', 'DIRECTION', 'LATITUDE',
    'LONGITUDE', 'COORDINATE', 'GOVERNMENT', 'WALL', 'UNDERGROUND'
];

class K4Worker {
    constructor() {
        this.alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        this.alphabetIndex = {};
        this.running = false;
        this.keysTested = 0;
        this.lastReportTime = 0;
        this.bestScore = 0;
        this.keyGenerator = null;
        this.workerId = 0;
        this.totalWorkers = 1;
        this.reportInterval = 500;
        this.keysPerBatch = 10000;
        this.ciphertext = '';
        this.keyLength = 0;
        this.knownPlaintext = '';
        
        // Инициализация lookup-таблицы
        this.initAlphabetIndex();
        
        self.onmessage = (e) => this.handleMessage(e.data);
    }

    initAlphabetIndex() {
        for (let i = 0; i < this.alphabet.length; i++) {
            this.alphabetIndex[this.alphabet[i]] = i;
        }
    }

    handleMessage(message) {
        switch (message.type) {
            case 'init':
                this.alphabet = message.alphabet || this.alphabet;
                this.initAlphabetIndex();
                this.ciphertext = message.ciphertext;
                this.keyLength = message.keyLength;
                this.knownPlaintext = message.knownPlaintext;
                this.workerId = message.workerId || 0;
                this.totalWorkers = message.totalWorkers || 1;
                this.keyGenerator = this.createKeyGenerator();
                break;
                
            case 'start':
                if (!this.keyGenerator) {
                    self.postMessage({ type: 'error', message: 'Worker not initialized' });
                    return;
                }
                this.running = true;
                this.startTime = performance.now();
                this.lastReportTime = this.startTime;
                this.processKeys();
                break;
                
            case 'stop':
                this.running = false;
                break;
                
            case 'setRange':
                if (this.keyGenerator) {
                    this.keyGenerator.setRange(message.start, message.end);
                }
                break;
        }
    }

    *createKeyGenerator() {
        const alphabetLength = this.alphabet.length;
        const totalKeys = Math.pow(alphabetLength, this.keyLength);
        const keysPerWorker = Math.ceil(totalKeys / this.totalWorkers);
        const startKey = this.workerId * keysPerWorker;
        const endKey = Math.min(startKey + keysPerWorker, totalKeys);
        
        let currentKey = startKey;
        
        while (currentKey < endKey) {
            let key = '';
            let n = currentKey;
            
            for (let i = 0; i < this.keyLength; i++) {
                key = this.alphabet[n % alphabetLength] + key;
                n = Math.floor(n / alphabetLength);
            }
            
            yield key;
            currentKey++;
            
            // Проверяем не пора ли остановиться
            if (!this.running) break;
        }
    }

    processKeys() {
        if (!this.running) return;
        
        const batchStartTime = performance.now();
        let batchCount = 0;
        let bestBatchResult = null;
        
        while (batchCount < this.keysPerBatch) {
            const { value: key, done } = this.keyGenerator.next();
            
            if (done) {
                if (bestBatchResult) {
                    self.postMessage({
                        type: 'result',
                        key: bestBatchResult.key,
                        plaintext: bestBatchResult.plaintext,
                        score: bestBatchResult.score
                    });
                }
                self.postMessage({ 
                    type: 'complete', 
                    keysTested: this.keysTested 
                });
                this.running = false;
                return;
            }
            
            const plaintext = this.decrypt(key);
            const score = this.scorePlaintext(plaintext);
            
            this.keysTested++;
            batchCount++;
            
            // Сохраняем лучший результат в батче
            if (score > (bestBatchResult?.score || 0)) {
                bestBatchResult = { key, plaintext, score };
            }
            
            // Отправляем прогресс, но не чаще чем reportInterval
            const now = performance.now();
            if (now - this.lastReportTime >= this.reportInterval) {
                const kps = Math.round(this.keysTested / ((now - this.startTime) / 1000));
                self.postMessage({
                    type: 'progress',
                    keysTested: this.keysTested,
                    kps: kps
                });
                this.lastReportTime = now;
            }
            
            // Защита от зависания - yield каждые 50ms
            if (performance.now() - batchStartTime > 50) break;
        }
        
        // Отправляем лучший результат батча
        if (bestBatchResult) {
            self.postMessage({
                type: 'result',
                key: bestBatchResult.key,
                plaintext: bestBatchResult.plaintext,
                score: bestBatchResult.score
            });
        }
        
        // Продолжаем обработку
        setTimeout(() => this.processKeys(), 0);
    }

    decrypt(key) {
        let plaintext = '';
        const keyLength = key.length;
        
        for (let i = 0; i < this.ciphertext.length; i++) {
            const cipherChar = this.ciphertext[i];
            const keyChar = key[i % keyLength];
            
            const cipherPos = this.alphabetIndex[cipherChar];
            const keyPos = this.alphabetIndex[keyChar];
            
            if (cipherPos === undefined || keyPos === undefined) {
                plaintext += '?';
                continue;
            }
            
            const plainPos = (cipherPos - keyPos + 26) % 26;
            plaintext += this.alphabet[plainPos];
        }
        
        return plaintext;
    }

    scorePlaintext(plaintext) {
        let score = 0;
        
        // 1. Проверка известного текста (максимальный приоритет)
        if (this.knownPlaintext && plaintext.includes(this.knownPlaintext)) {
            score += 1000 * this.knownPlaintext.length;
        }
        
        // 2. Частотный анализ (только для стандартного алфавита)
        if (this.alphabet === 'ABCDEFGHIJKLMNOPQRSTUVWXYZ') {
            const freq = {};
            let totalLetters = 0;
            
            for (const char of plaintext) {
                if (this.alphabet.includes(char)) {
                    freq[char] = (freq[char] || 0) + 1;
                    totalLetters++;
                }
            }
            
            if (totalLetters > 0) {
                for (const char in freq) {
                    const expected = ENGLISH_FREQ[char] || 0;
                    const actual = (freq[char] / totalLetters) * 100;
                    score += 100 - Math.abs(expected - actual);
                }
            }
        }
        
        // 3. Общие паттерны
        for (const pattern of COMMON_PATTERNS) {
            const matches = plaintext.match(new RegExp(pattern, 'g'));
            if (matches) {
                score += pattern.length * 25 * matches.length;
            }
        }
        
        // 4. Бонус за пробелы (признак слов)
        const spaceCount = (plaintext.match(/ /g) || []).length;
        score += spaceCount * 15;
        
        // 5. Штраф за неалфавитные символы
        const invalidChars = plaintext.replace(new RegExp(`[${this.alphabet} ]`, 'g'), '').length;
        score -= invalidChars * 10;
        
        return Math.max(0, Math.round(score));
    }
}

// Запускаем воркер
new K4Worker();
