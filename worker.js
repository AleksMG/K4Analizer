const ENGLISH_FREQ = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
    'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
    'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
    'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
    'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974,
    'Z': 0.074
};

const commonPatterns = [
    'THE', 'AND', 'THAT', 'HAVE', 'FOR', 'NOT', 'WITH', 'YOU', 'THIS', 'WAY',
    'HIS', 'FROM', 'THEY', 'WILL', 'WOULD', 'THERE', 'THEIR', 'WHAT', 'ABOUT',
    'WHICH', 'WHEN', 'YOUR', 'WERE', 'CIA', 'NASA', 'FBI', 'USA', 'RUS',
    'AGENT', 'CODE', 'SECRET', 'MESSAGE', 'WORLD', 'COUNTRY', 'CITY', 'TOWN',
    'PERSON', 'KEY', 'ENEMY', 'ALLY', 'OF', 'TO'
];

const uncommonPatterns = [
    'KRYPTOS', 'BERLINCLOCK', 'EAST', 'NORTH', 'WEST', 'BERLIN', 'CLOCK',
    'SOUTH', 'NORTHEAST', 'NORTHWEST', 'SOUTHEAST', 'SOUTHWEST', 'COMPASS', 'LIGHT',
    'LATITUDE', 'LONGITUDE', 'COORDINATE', 'SHADOW', 'WALL', 'UNDERGROUND', 'PALIMPSEST',
    'ABSCISSA', 'CLOCKWISE', 'DIAGONAL', 'VERTICAL',
    'HORIZONTAL', 'OBELISK', 'PYRAMID', 'SCULPTURE', 'CIPHER', 'ENCRYPT', 'DECRYPT',
    'ALPHABET', 'LETTER', 'SYMBOL', 'SLOWLY', 'DESPERATELY', 'WEAKLY', 'DEEP',
    'LAYER', 'QUESTION', 'ANSWER', 'SOLUTION', 'HIDDEN', 'COVER', 'REVEAL', 'TRUTH', 'MISSION'
];

// Исправленный конструктор SimpleBloomFilter
class SimpleBloomFilter {
    constructor(size = 1024 * 1024 * 8) {
        this.size = size;
        this.buckets = new Uint8Array(Math.ceil(size / 8));
    }

    hash1(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            hash = (hash << 5) - hash + str.charCodeAt(i);
            hash |= 0; // Convert to 32bit integer
        }
        return Math.abs(hash) % this.size;
    }

    hash2(str) {
        let hash = 5381;
        for (let i = 0; i < str.length; i++) {
            hash = (hash * 33) ^ str.charCodeAt(i);
        }
        return Math.abs(hash) % this.size;
    }

    hash3(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            hash = (hash << 7) - hash + str.charCodeAt(i);
            hash |= 0;
        }
        return Math.abs(hash) % this.size;
    }

    add(key) {
        const h1 = this.hash1(key);
        const h2 = this.hash2(key);
        const h3 = this.hash3(key);
        
        this.buckets[Math.floor(h1 / 8)] |= 1 << (h1 % 8);
        this.buckets[Math.floor(h2 / 8)] |= 1 << (h2 % 8);
        this.buckets[Math.floor(h3 / 8)] |= 1 << (h3 % 8);
    }

    test(key) {
        const h1 = this.hash1(key);
        const h2 = this.hash2(key);
        const h3 = this.hash3(key);
        
        return !!( 
            (this.buckets[Math.floor(h1 / 8)] & (1 << (h1 % 8))) &&
            (this.buckets[Math.floor(h2 / 8)] & (1 << (h2 % 8))) &&
            (this.buckets[Math.floor(h3 / 8)] & (1 << (h3 % 8)))
        );
    }
}

class K4Worker {
    constructor() {
        this.alphabet = 'ZXWVUQNMLJIHGFEDCBASOTPYRK';
        this.charMap = new Uint8Array(256);
        this.running = false;
        this.ciphertext = '';
        this.keyLength = 0;
        this.workerId = 0;
        this.totalWorkers = 1;
        this.keysTested = 0;
        this.startTime = 0;
        this.lastReportTime = 0;
        this.bestScore = -Infinity;
        this.bestKey = '';
        this.bestPlaintext = '';
        this.stuckCount = 0;
        this.mode = 'scan';
        this.lastImprovementTime = 0;
        this.testedKeys = new Set();
        this.testedKeysBloom = new SimpleBloomFilter();
        this.useBloomFilter = false;
        this.totalKeysToTest = 0;
        this.completed = false;
        this.adaptiveStrategy = 'auto';
        this.primaryTarget = 'BERLINCLOCK';
        this.primaryTargetFound = false;
        this.primaryResults = [];

        this.charMap.fill(255);
        for (let i = 0; i < this.alphabet.length; i++) {
            this.charMap[this.alphabet.charCodeAt(i)] = i;
        }

        self.onmessage = (e) => {
            const msg = e.data;
            switch (msg.type) {
                case 'init':
                    this.ciphertext = msg.ciphertext.toUpperCase();
                    this.keyLength = parseInt(msg.keyLength);
                    this.workerId = msg.workerId || 0;
                    this.totalWorkers = msg.totalWorkers || 1;
                    this.keysTested = 0;
                    this.bestScore = -Infinity;
                    this.bestKey = this.generateKey(0);
                    this.testedKeys.clear();
                    this.testedKeysBloom = new SimpleBloomFilter();
                    this.totalKeysToTest = Math.pow(26, this.keyLength);
                    this.completed = false;
                    this.primaryTargetFound = false;
                    this.primaryResults = [];
                    this.useBloomFilter = this.keyLength > 12; // Используем Bloom filter для длинных ключей
                    this.adaptiveStrategy = this.keyLength > 12 ? 'optimizeFirst' : 'fullScan';
                    break;
                case 'start':
                    if (!this.running && !this.completed) {
                        this.running = true;
                        this.startTime = performance.now();
                        this.lastImprovementTime = this.startTime;
                        if (!this.primaryTargetFound) {
                            this.mode = 'primarySearch';
                        }
                        this.run();
                    }
                    break;
                case 'stop':
                    this.running = false;
                    break;
                case 'updateBestKey':
                    if (msg.score > this.bestScore) {
                        this.bestScore = msg.score;
                        this.bestKey = msg.key;
                        this.bestPlaintext = msg.plaintext;
                        this.lastImprovementTime = performance.now();
                    }
                    break;
                case 'setStrategy':
                    this.adaptiveStrategy = msg.strategy || 'auto';
                    break;
            }
        };
    }

    generateKey(num) {
        const key = new Array(this.keyLength);
        for (let i = this.keyLength - 1; i >= 0; i--) {
            key[i] = this.alphabet[num % 26];
            num = Math.floor(num / 26);
        }
        return key.join('');
    }

    decrypt(key) {
        let plaintext = '';
        for (let i = 0; i < this.ciphertext.length; i++) {
            const plainPos = (this.charMap[this.ciphertext.charCodeAt(i)] - 
                           this.charMap[key.charCodeAt(i % this.keyLength)] + 26) % 26;
            plaintext += this.alphabet[plainPos];
        }
        return plaintext;
    }

    isKeyTested(key) {
        if (!this.useBloomFilter) {
            return this.testedKeys.has(key);
        }
        return this.testedKeys.size < 100000 ? this.testedKeys.has(key) : this.testedKeysBloom.test(key);
    }

    addTestedKey(key) {
        if (!this.useBloomFilter || this.testedKeys.size < 100000) {
            this.testedKeys.add(key);
        } else {
            this.testedKeysBloom.add(key);
        }
    }

    scoreText(text) {
        const upperText = text.toUpperCase();
        
        // Быстрая проверка основного целевого слова
        if (!this.primaryTargetFound && upperText.includes(this.primaryTarget)) {
            return 1000;
        }

        let score = 0;
        const freq = new Uint16Array(26);
        let totalLetters = 0;
        let consecutiveRepeats = 0;
        let lastChar = '';
        let wordLength = 0;
        let wordScore = 0;

        // Комбинированный анализ за один проход
        for (let i = 0; i < text.length; i++) {
            const code = text.charCodeAt(i);
            
            // Проверка на букву
            if (code >= 65 && code <= 90) {
                const charIdx = code - 65;
                freq[charIdx]++;
                totalLetters++;
                
                // Штраф за повторяющиеся символы
                if (this.alphabet[charIdx] === lastChar) {
                    consecutiveRepeats++;
                    if (consecutiveRepeats > 2) {
                        score -= 20 * (consecutiveRepeats - 2);
                    }
                } else {
                    consecutiveRepeats = 0;
                }
                lastChar = this.alphabet[charIdx];
                
                // Подсчет длины слова
                wordLength++;
            } else if (wordLength > 0) {
                // Награда за слова разумной длины
                if (wordLength >= 3 && wordLength <= 10) {
                    wordScore += wordLength * 2;
                }
                wordLength = 0;
            }
        }

        // Сохраняем старую логику оценки для совместимости
        let oldScore = 0;
        if (totalLetters > 0) {
            for (let i = 0; i < 26; i++) {
                const expected = ENGLISH_FREQ[this.alphabet[i]] || 0;
                const actual = (freq[i] / totalLetters) * 100;
                oldScore += 100 - Math.abs(expected - actual);
            }
        }

        // Поиск распространенных слов (старая логика)
        for (const pattern of commonPatterns) {
            let pos = -1;
            while ((pos = upperText.indexOf(pattern, pos + 1)) !== -1) {
                oldScore += pattern.length * 25;
            }
        }

        // Поиск специальных слов (старая логика)
        for (const pattern of uncommonPatterns) {
            let pos = -1;
            while ((pos = upperText.indexOf(pattern, pos + 1)) !== -1) {
                oldScore += pattern.length * 50;
            }
        }

        // Комбинируем новую и старую оценку
        score = score * 0.3 + oldScore * 0.7 + wordScore;
        
        // Быстрый поиск паттернов с использованием регулярных выражений
        const commonRegex = /(THE|AND|THAT|HAVE|FOR|NOT|WITH|YOU|THIS|HIS|FROM|THEY|WILL)/g;
        const matches = upperText.match(commonRegex);
        if (matches) {
            score += matches.length * 30;
        }

        // Проверка специальных паттернов
        if (upperText.includes('BERLIN') || upperText.includes('CLOCK')) {
            score += 100;
        }

        return Math.round(score);
    }

    async run() {
        const startKey = this.workerId * Math.floor(this.totalKeysToTest / this.totalWorkers);
        const endKey = (this.workerId === this.totalWorkers - 1) ? this.totalKeysToTest : 
                      startKey + Math.floor(this.totalKeysToTest / this.totalWorkers);

        // Выбор стратегии
        const strategy = this.adaptiveStrategy === 'auto' ? 
            (this.keyLength > 5 ? 'optimizeFirst' : 'fullScan') : 
            this.adaptiveStrategy;

        while (this.running && !this.completed) {
            if (strategy === 'optimizeFirst' && this.bestScore < 500) {
                await this.optimizedScan(startKey, endKey);
            } else {
                switch (this.mode) {
                    case 'scan':
                        await this.fullScan(startKey, endKey);
                        break;
                    case 'optimize':
                        await this.optimizeKey();
                        break;
                    case 'explore':
                        await this.exploreRandom();
                        break;
                    case 'primarySearch':
                        await this.findPrimaryTargets(startKey, endKey);
                        this.mode = 'scan';
                        break;
                }
            }
            
            // Проверка завершения
            if (this.keysTested >= (endKey - startKey)) {
                this.completed = true;
                this.running = false;
                self.postMessage({
                    type: 'completed',
                    keysTested: this.keysTested,
                    bestScore: this.bestScore,
                    bestKey: this.bestKey,
                    bestPlaintext: this.bestPlaintext
                });
            }
            
            this.checkProgress();
            this.updateStrategy();
        }
    }

    async optimizedScan(startKey, endKey) {
        const JUMP_SIZE = Math.max(1, Math.floor(Math.pow(26, Math.max(0, this.keyLength - 3))));
        
        for (let keyNum = startKey; keyNum < endKey && this.running; keyNum += JUMP_SIZE) {
            const key = this.generateKey(keyNum);
            if (this.isKeyTested(key)) continue;
            this.addTestedKey(key);
            
            const plaintext = this.decrypt(key);
            const score = this.scoreText(plaintext);
            this.keysTested++;

            if (score > this.bestScore * 0.7) {
                // Если ключ выглядит перспективным, исследуем его окрестности
                await this.exploreNeighborhood(key, Math.floor(JUMP_SIZE / 2));
            }

            if (score > this.bestScore) {
                this.bestScore = score;
                this.bestKey = key;
                this.bestPlaintext = plaintext;
                this.lastImprovementTime = performance.now();
                self.postMessage({
                    type: 'result',
                    key: this.bestKey,
                    plaintext: this.bestPlaintext,
                    score: this.bestScore
                });
            }
        }
    }

    async exploreNeighborhood(baseKey, radius) {
        const baseNum = this.keyToNum(baseKey);
        const startNum = Math.max(0, baseNum - radius);
        const endNum = Math.min(this.totalKeysToTest, baseNum + radius);
        
        for (let keyNum = startNum; keyNum < endNum && this.running; keyNum++) {
            const key = this.generateKey(keyNum);
            if (this.isKeyTested(key)) continue;
            this.addTestedKey(key);
            
            const plaintext = this.decrypt(key);
            const score = this.scoreText(plaintext);
            this.keysTested++;

            if (score > this.bestScore) {
                this.bestScore = score;
                this.bestKey = key;
                this.bestPlaintext = plaintext;
                this.lastImprovementTime = performance.now();
                self.postMessage({
                    type: 'result',
                    key: this.bestKey,
                    plaintext: this.bestPlaintext,
                    score: this.bestScore
                });
            }
        }
    }

    keyToNum(key) {
        let num = 0;
        for (let i = 0; i < key.length; i++) {
            num = num * 26 + this.charMap[key.charCodeAt(i)];
        }
        return num;
    }

    async fullScan(startKey, endKey) {
        const BLOCK_SIZE = 50000;
        for (let keyNum = startKey; keyNum < endKey && this.running; keyNum += BLOCK_SIZE) {
            const blockEnd = Math.min(keyNum + BLOCK_SIZE, endKey);
            
            for (let i = keyNum; i < blockEnd; i++) {
                const key = this.generateKey(i);
                if (this.isKeyTested(key)) continue;
                this.addTestedKey(key);
                
                const plaintext = this.decrypt(key);
                const score = this.scoreText(plaintext);
                this.keysTested++;

                if (score > this.bestScore) {
                    this.bestScore = score;
                    this.bestKey = key;
                    this.bestPlaintext = plaintext;
                    this.lastImprovementTime = performance.now();
                    self.postMessage({
                        type: 'result',
                        key: this.bestKey,
                        plaintext: this.bestPlaintext,
                        score: this.bestScore
                    });
                }
            }

            if (performance.now() - this.lastImprovementTime > 5000) {
                this.mode = 'optimize';
                break;
            }
        }
    }

    async optimizeKey() {
        const keyChars = this.bestKey.split('');
        let improved = false;

        for (let pos = 0; pos < this.keyLength && this.running; pos++) {
            const originalChar = keyChars[pos];
            for (const delta of [-1, 1, -2, 2, -3, 3]) {
                const newCharCode = (this.charMap[originalChar.charCodeAt(0)] + delta + 26) % 26;
                const newChar = this.alphabet[newCharCode];
                keyChars[pos] = newChar;
                const newKey = keyChars.join('');
                
                if (this.isKeyTested(newKey)) continue;
                this.addTestedKey(newKey);
                
                const plaintext = this.decrypt(newKey);
                const score = this.scoreText(plaintext);
                this.keysTested++;

                if (score > this.bestScore) {
                    this.bestScore = score;
                    this.bestKey = newKey;
                    this.bestPlaintext = plaintext;
                    improved = true;
                    this.lastImprovementTime = performance.now();
                    self.postMessage({
                        type: 'result',
                        key: this.bestKey,
                        plaintext: this.bestPlaintext,
                        score: this.bestScore
                    });
                    break;
                }
            }
            keyChars[pos] = originalChar;
        }

        if (!improved) {
            this.stuckCount++;
            if (this.stuckCount > 5) {
                this.mode = 'explore';
                this.stuckCount = 0;
            }
        } else {
            this.stuckCount = 0;
        }
    }

    async exploreRandom() {
        let attempts = 0;
        const maxAttempts = 100;
        let key;
        
        do {
            key = this.generateKey(Math.floor(Math.random() * this.totalKeysToTest));
            attempts++;
        } while (this.isKeyTested(key) && attempts < maxAttempts && this.running);
        
        if (attempts >= maxAttempts || !this.running) {
            this.mode = 'scan';
            return;
        }
        
        this.addTestedKey(key);
        const plaintext = this.decrypt(key);
        const score = this.scoreText(plaintext);
        this.keysTested++;

        if (score > this.bestScore * 0.8) {
            this.mode = 'optimize';
        } else if (performance.now() - this.lastImprovementTime > 10000) {
            this.mode = 'scan';
        }
    }

    async findPrimaryTargets(startKey, endKey) {
        const BLOCK_SIZE = 50000;
        for (let keyNum = startKey; keyNum < endKey && this.running; keyNum += BLOCK_SIZE) {
            const blockEnd = Math.min(keyNum + BLOCK_SIZE, endKey);
            
            for (let i = keyNum; i < blockEnd; i++) {
                const key = this.generateKey(i);
                if (this.isKeyTested(key)) continue;
                this.addTestedKey(key);
                
                const plaintext = this.decrypt(key);
                const score = this.scoreText(plaintext);
                this.keysTested++;

                if (plaintext.includes(this.primaryTarget)) {
                    this.primaryResults.push({ key, plaintext, score });
                    self.postMessage({
                        type: 'primaryResult',
                        key: key,
                        plaintext: plaintext,
                        score: score
                    });
                }
                
                if (score > this.bestScore) {
                    this.bestScore = score;
                    this.bestKey = key;
                    this.bestPlaintext = plaintext;
                    this.lastImprovementTime = performance.now();
                    self.postMessage({
                        type: 'result',
                        key: this.bestKey,
                        plaintext: this.bestPlaintext,
                        score: this.bestScore
                    });
                }
            }

            if (performance.now() - this.lastReportTime > 1000) {
                this.checkProgress();
            }
        }
    }

    updateStrategy() {
        const timeSinceImprovement = performance.now() - this.lastImprovementTime;
        
        if (timeSinceImprovement > 30000) {
            // Долго нет улучшений - пробуем что-то новое
            if (this.mode === 'optimize') {
                this.mode = 'explore';
            } else if (this.mode === 'explore') {
                this.mode = 'scan';
            } else {
                this.mode = 'optimize';
            }
        } else if (timeSinceImprovement > 10000) {
            // Небольшой застой - оптимизируем
            this.mode = 'optimize';
        }
        
        // Для очень длинных ключей чаще используем исследование
        if (this.keyLength > 7 && Math.random() < 0.1) {
            this.mode = 'explore';
        }
    }

    checkProgress() {
        const now = performance.now();
        if (now - this.lastReportTime > 1000) {
            const elapsed = (now - this.startTime) / 1000;
            const kps = elapsed > 0 ? Math.round(this.keysTested / elapsed) : 0;
            const completion = Math.min(100, (this.keysTested / (this.totalKeysToTest / this.totalWorkers)) * 100);
            
            // Оценка оставшегося времени
            let eta = 'N/A';
            if (kps > 0) {
                const remaining = ((this.totalKeysToTest / this.totalWorkers) - this.keysTested) / kps;
                eta = `${Math.floor(remaining / 3600)}h ${Math.floor((remaining % 3600) / 60)}m ${Math.floor(remaining % 60)}s`;
            }
            
            self.postMessage({
                type: 'progress',
                keysTested: this.keysTested,
                totalKeys: this.totalKeysToTest,
                kps: kps,
                completion: completion.toFixed(2),
                eta: eta,
                mode: this.mode,
                bestScore: this.bestScore,
                bestKey: this.bestKey,
                bestPlaintext: this.bestPlaintext,
                quality: this.calculateQualityEstimate(),
                strategy: this.adaptiveStrategy
            });
            
            this.lastReportTime = now;
        }
    }

    calculateQualityEstimate() {
        if (this.bestScore <= 0) return 'Very Low';
        if (this.bestScore < 300) return 'Low';
        if (this.bestScore < 600) return 'Medium';
        if (this.bestScore < 800) return 'High';
        return 'Very High';
    }
}

new K4Worker();
