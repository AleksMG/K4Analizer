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
    'ALPHABET', 'LETTER', 'SYMBOL', 'SLOWLY', 'DESPARATELY', 'WEAKLY', 'DEEP',
    'LAYER', 'QUESTION', 'ANSWER', 'SOLUTION', 'HIDDEN', 'COVER', 'REVEAL', 'TRUTH', 'MISSION'
];

class SimpleBloomFilter {
    constructor(size = 1024 * 1024 * 8) {
        this.size = size;
        this.buckets = new Uint8Array(Math.ceil(size / 8));
    }

    hash1(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            hash = (hash << 5) - hash + str.charCodeAt(i);
            hash |= 0;
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
                    this.useBloomFilter = this.keyLength > 5;
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
        if (!this.primaryTargetFound && upperText.includes(this.primaryTarget)) {
            return 1000;
        }

        let score = 0;
        const freq = new Uint16Array(26);
        let totalLetters = 0;

        // Оригинальный частотный анализ
        for (let i = 0; i < text.length; i++) {
            const code = text.charCodeAt(i);
            if (code >= 65 && code <= 90) {
                freq[code - 65]++;
                totalLetters++;
            }
        }

        if (totalLetters > 0) {
            for (let i = 0; i < 26; i++) {
                const expected = ENGLISH_FREQ[this.alphabet[i]] || 0;
                const actual = (freq[i] / totalLetters) * 100;
                score += 100 - Math.abs(expected - actual);
            }
        }

        // Оригинальный поиск паттернов
        for (const pattern of commonPatterns) {
            let pos = -1;
            while ((pos = upperText.indexOf(pattern, pos + 1)) !== -1) {
                score += pattern.length * 25;
            }
        }

        for (const pattern of uncommonPatterns) {
            let pos = -1;
            while ((pos = upperText.indexOf(pattern, pos + 1)) !== -1) {
                score += pattern.length * 50;
            }
        }

        return Math.round(score);
    }

    async run() {
        const startKey = this.workerId * Math.floor(this.totalKeysToTest / this.totalWorkers);
        const endKey = (this.workerId === this.totalWorkers - 1) ? this.totalKeysToTest : 
                      startKey + Math.floor(this.totalKeysToTest / this.totalWorkers);

        while (this.running && !this.completed) {
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
        }
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

    checkProgress() {
        const now = performance.now();
        if (now - this.lastReportTime > 1000) {
            const elapsed = (now - this.startTime) / 1000;
            const kps = elapsed > 0 ? Math.round(this.keysTested / elapsed) : 0;
            const completion = Math.min(100, (this.keysTested / (this.totalKeysToTest / this.totalWorkers)) * 100);
            
            // Возвращаем оригинальный формат сообщения о прогрессе
            self.postMessage({
                type: 'progress',
                keysTested: this.keysTested,
                totalKeys: this.totalKeysToTest,
                kps: kps,
                completion: completion.toFixed(2),
                bestScore: this.bestScore,
                bestKey: this.bestKey,
                bestPlaintext: this.bestPlaintext
            });
            
            this.lastReportTime = now;
        }
    }
}

new K4Worker();
