// English letter frequencies (percentages)
const ENGLISH_FREQ = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
    'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
    'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
    'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
    'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974,
    'Z': 0.074
};

// Common English words and patterns
const COMMON_PATTERNS = [
    'THE', 'AND', 'THAT', 'HAVE', 'FOR', 'NOT', 'WITH', 'YOU', 'THIS', 'BUT',
    'HIS', 'FROM', 'THEY', 'WILL', 'WOULD', 'THERE', 'THEIR', 'WHAT', 'ABOUT',
    'WHICH', 'WHEN', 'YOUR', 'WERE', 'BERLIN', 'CLOCK', 'EAST', 'NORTH', 'WEST',
    'SOUTH', 'NORTHEAST', 'NORTHWEST', 'SOUTHEAST', 'SOUTHWEST', 'SECRET', 'CODE',
    'MESSAGE', 'KRYPTOS', 'CIA', 'AGENT', 'COMPASS', 'DIRECTION', 'LATITUDE',
    'LONGITUDE', 'COORDINATES', 'GOVERNMENT', 'INTELLIGENCE', 'WASHINGTON'
];

class K4Worker {
    constructor() {
        // Конфигурация по умолчанию
        this.alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        this.alphabetMap = this.createAlphabetMap(this.alphabet);
        this.running = false;
        this.keysTested = 0;
        this.lastReportTime = 0;
        this.bestScore = 0;
        
        // Оптимизированные параметры
        this.batchSize = 50000; // Увеличенный размер батча
        this.reportInterval = 1000; // Интервал отчетов
        
        // Предварительно компилируем regex для известного текста
        this.knownRegex = null;
        
        self.onmessage = (e) => this.handleMessage(e.data);
    }

    createAlphabetMap(alphabet) {
        const map = {};
        for (let i = 0; i < alphabet.length; i++) {
            map[alphabet[i]] = i;
        }
        return map;
    }

    handleMessage(message) {
        switch (message.type) {
            case 'init':
                this.alphabet = message.alphabet || this.alphabet;
                this.alphabetMap = this.createAlphabetMap(this.alphabet);
                this.ciphertext = message.ciphertext;
                this.keyLength = message.keyLength;
                this.knownPlaintext = message.knownPlaintext;
                this.workerId = message.workerId;
                this.totalWorkers = message.totalWorkers;
                this.batchSize = message.batchSize || this.batchSize;
                this.reportInterval = message.reportInterval || this.reportInterval;
                
                // Оптимизация: предварительно компилируем regex
                if (this.knownPlaintext) {
                    this.knownRegex = new RegExp(this.knownPlaintext, 'g');
                }
                
                // Оптимизация: предварительно вычисляем общие паттерны
                this.compiledPatterns = COMMON_PATTERNS.map(pattern => ({
                    regex: new RegExp(pattern, 'g'),
                    pattern
                }));
                break;
                
            case 'start':
                if (!this.ciphertext) {
                    self.postMessage({ type: 'error', message: 'Worker not initialized' });
                    return;
                }
                this.running = true;
                this.startTime = performance.now();
                this.lastReportTime = this.startTime;
                this.processBatches();
                break;
                
            case 'stop':
                this.running = false;
                break;
        }
    }

    *keyGenerator() {
        const alphabetLength = this.alphabet.length;
        const indices = new Array(this.keyLength).fill(0);
        
        // Инициализация позиции для этого воркера
        let carry = this.workerId;
        for (let i = 0; i < this.keyLength && carry > 0; i++) {
            indices[i] = carry % alphabetLength;
            carry = Math.floor(carry / alphabetLength);
        }
        
        while (true) {
            // Конвертируем индексы в ключ
            const key = indices.map(i => this.alphabet[i]).join('');
            yield key;
            
            // Инкремент с учетом распределения по воркерам
            let pos = 0;
            let increment = this.totalWorkers;
            while (increment > 0 && pos < this.keyLength) {
                const sum = indices[pos] + increment;
                indices[pos] = sum % alphabetLength;
                increment = Math.floor(sum / alphabetLength);
                pos++;
            }
            
            if (increment > 0) break;
        }
    }

    processBatches() {
        if (!this.running) return;

        const generator = this.keyGenerator();
        let batchCount = 0;
        let batchStartTime = performance.now();
        
        while (batchCount < this.batchSize) {
            const { value: key, done } = generator.next();
            if (done) {
                self.postMessage({ type: 'complete', keysTested: this.keysTested });
                this.running = false;
                return;
            }
            
            const plaintext = this.decrypt(key);
            const scoreInfo = this.scorePlaintext(plaintext);
            
            if (scoreInfo.score > 50 || (this.knownPlaintext && scoreInfo.method === 'known-text')) {
                self.postMessage({
                    type: 'result',
                    key,
                    plaintext,
                    score: scoreInfo.score,
                    method: scoreInfo.method,
                    hasKnownWord: scoreInfo.method === 'known-text'
                });
            }
            
            this.keysTested++;
            batchCount++;
            
            // Отправляем прогресс реже для оптимизации
            const now = performance.now();
            if (now - this.lastReportTime >= this.reportInterval) {
                const batchTime = (now - batchStartTime) / 1000;
                const keysPerSecond = Math.round(batchCount / batchTime);
                
                self.postMessage({
                    type: 'progress',
                    keysTested: this.keysTested,
                    keysPerSecond: keysPerSecond
                });
                
                this.lastReportTime = now;
                batchStartTime = now;
                batchCount = 0;
            }
        }
        
        setTimeout(() => this.processBatches(), 0);
    }

    decrypt(key) {
        let plaintext = '';
        const keyLength = key.length;
        const alphabetLength = this.alphabet.length;
        
        for (let i = 0; i < this.ciphertext.length; i++) {
            const cipherChar = this.ciphertext[i];
            const keyChar = key[i % keyLength];
            
            const cipherIndex = this.alphabetMap[cipherChar];
            const keyIndex = this.alphabetMap[keyChar];
            
            if (cipherIndex === undefined || keyIndex === undefined) {
                plaintext += '?';
                continue;
            }
            
            const plainIndex = (cipherIndex - keyIndex + alphabetLength) % alphabetLength;
            plaintext += this.alphabet[plainIndex];
        }
        
        return plaintext;
    }

    scorePlaintext(plaintext) {
        let score = 0;
        let method = 'basic';
        let hasKnownWord = false;
        
        // 1. Проверка известного текста
        if (this.knownRegex) {
            const matches = plaintext.match(this.knownRegex);
            if (matches) {
                score += 1000 * this.knownPlaintext.length * matches.length;
                method = 'known-text';
                hasKnownWord = true;
            }
        }
        
        // 2. Частотный анализ
        if (this.alphabet === 'ABCDEFGHIJKLMNOPQRSTUVWXYZ') {
            const freq = {};
            let totalLetters = 0;
            
            for (const char of plaintext) {
                if (this.alphabetMap[char] !== undefined) {
                    freq[char] = (freq[char] || 0) + 1;
                    totalLetters++;
                }
            }
            
            if (totalLetters > 0) {
                let freqScore = 0;
                for (const char in freq) {
                    const expected = ENGLISH_FREQ[char] || 0;
                    const actual = (freq[char] / totalLetters) * 100;
                    freqScore += 100 - Math.abs(expected - actual);
                }
                score += freqScore;
                
                if (freqScore > 500 && !hasKnownWord) {
                    method = 'frequency';
                }
            }
        }
        
        // 3. Проверка общих паттернов
        let patternScore = 0;
        for (const { regex, pattern } of this.compiledPatterns) {
            const matches = plaintext.match(regex);
            if (matches) {
                patternScore += pattern.length * 25 * matches.length;
            }
        }
        score += patternScore;
        
        if (patternScore > 100 && !hasKnownWord && method === 'basic') {
            method = 'patterns';
        }
        
        // 4. Бонус за пробелы
        let spaceCount = 0;
        for (const char of plaintext) {
            if (char === ' ') spaceCount++;
        }
        score += spaceCount * 15;
        
        // 5. Штраф за неалфавитные символы
        let invalidChars = 0;
        for (const char of plaintext) {
            if (this.alphabetMap[char] === undefined && char !== ' ') {
                invalidChars++;
            }
        }
        score -= invalidChars * 10;
        
        return { 
            score: Math.max(0, score), 
            method,
            hasKnownWord
        };
    }
}

// Start the worker
new K4Worker();
