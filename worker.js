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
        this.cipherIndices = [];
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
        this.bloomActive = false;
        this.useBloomFilter = false;
        this.totalKeysToTest = 0;
        this.completed = false;
        this.primaryTarget = 'BERLINCLOCK';
        this.primaryTargetFound = false;
        this.primaryResults = [];
        this.commonRegex = new RegExp(commonPatterns.join('|'), 'g');
        this.uncommonRegex = new RegExp(uncommonPatterns.join('|'), 'g');
        this.englishFreqArray = new Float32Array(26);

        this.charMap.fill(255);
        for (let i = 0; i < this.alphabet.length; i++) {
            const char = this.alphabet[i];
            this.charMap[char.charCodeAt(0)] = i;
            this.englishFreqArray[i] = ENGLISH_FREQ[char] || 0;
        }

        self.onmessage = (e) => {
            const msg = e.data;
            switch (msg.type) {
                case 'init':
                    this.handleInit(msg);
                    break;
                case 'start':
                    this.handleStart();
                    break;
                case 'stop':
                    this.handleStop();
                    break;
                case 'updateBestKey':
                    this.handleUpdateBestKey(msg);
                    break;
            }
        };
    }

    handleInit(msg) {
        this.ciphertext = msg.ciphertext.toUpperCase();
        this.cipherIndices = this.precomputeIndices();
        this.keyLength = parseInt(msg.keyLength);
        this.workerId = msg.workerId || 0;
        this.totalWorkers = msg.totalWorkers || 1;
        this.resetState();
        this.useBloomFilter = this.keyLength > 5;
    }

    precomputeIndices() {
        const indices = new Uint8Array(this.ciphertext.length);
        for (let i = 0; i < this.ciphertext.length; i++) {
            indices[i] = this.charMap[this.ciphertext.charCodeAt(i)];
        }
        return indices;
    }

    resetState() {
        this.keysTested = 0;
        this.bestScore = -Infinity;
        this.bestKey = this.generateKey(0);
        this.testedKeys.clear();
        this.testedKeysBloom = new SimpleBloomFilter();
        this.totalKeysToTest = Math.pow(26, this.keyLength);
        this.completed = false;
        this.primaryTargetFound = false;
        this.primaryResults = [];
        this.bloomActive = false;
        this.startTime = 0;
        this.lastReportTime = 0;
        this.stuckCount = 0;
    }

    handleStart() {
        if (!this.running && !this.completed) {
            this.running = true;
            this.startTime = performance.now();
            this.lastImprovementTime = this.startTime;
            this.mode = this.primaryTargetFound ? 'scan' : 'primarySearch';
            this.processKeys();
        }
    }

    handleStop() {
        this.running = false;
    }

    handleUpdateBestKey(msg) {
        if (msg.score > this.bestScore) {
            this.bestScore = msg.score;
            this.bestKey = msg.key;
            this.bestPlaintext = msg.plaintext;
            this.lastImprovementTime = performance.now();
        }
    }

    generateKey(num) {
        const key = new Array(this.keyLength);
        let temp = num;
        for (let i = this.keyLength - 1; i >= 0; i--) {
            key[i] = this.alphabet[temp % 26];
            temp = Math.floor(temp / 26);
        }
        return key.join('');
    }

    decrypt(keyStr) {
        const keyIndices = new Uint8Array(this.keyLength);
        for (let i = 0; i < keyStr.length; i++) {
            keyIndices[i] = this.charMap[keyStr.charCodeAt(i)];
        }

        const plaintext = new Array(this.cipherIndices.length);
        for (let i = 0; i < this.cipherIndices.length; i++) {
            const plainPos = (this.cipherIndices[i] - keyIndices[i % this.keyLength] + 26) % 26;
            plaintext[i] = this.alphabet[plainPos];
        }
        return plaintext.join('');
    }

    isKeyTested(key) {
        if (!this.useBloomFilter) return this.testedKeys.has(key);
        return this.bloomActive ? this.testedKeysBloom.test(key) : this.testedKeys.has(key);
    }

    addTestedKey(key) {
        if (this.useBloomFilter && !this.bloomActive) {
            this.testedKeys.add(key);
            if (this.testedKeys.size >= 100000) {
                this.bloomActive = true;
                this.testedKeys.clear();
            }
        } else if (this.useBloomFilter) {
            this.testedKeysBloom.add(key);
        } else {
            this.testedKeys.add(key);
        }
    }

    scoreText(text) {
        if (text.includes(this.primaryTarget)) return 1000;

        let score = 0;
        const freq = new Uint16Array(26);
        let totalLetters = 0;

        for (let i = 0; i < text.length; i++) {
            const code = text.charCodeAt(i);
            if (code >= 65 && code <= 90) {
                freq[code - 65]++;
                totalLetters++;
            }
        }

        if (totalLetters > 0) {
            for (let i = 0; i < 26; i++) {
                const expected = this.englishFreqArray[i];
                const actual = (freq[i] / totalLetters) * 100;
                score += 100 - Math.abs(expected - actual);
            }
        }

        const commonMatches = (text.match(this.commonRegex) || []).length;
        const uncommonMatches = (text.match(this.uncommonRegex) || []).length;
        score += commonMatches * 25 + uncommonMatches * 50;

        return Math.round(score);
    }

    async processKeys() {
        const startKey = Math.floor(this.totalKeysToTest * this.workerId / this.totalWorkers);
        const endKey = Math.floor(this.totalKeysToTest * (this.workerId + 1) / this.totalWorkers);

        while (this.running && !this.completed) {
            switch (this.mode) {
                case 'primarySearch':
                    await this.searchPrimaryTarget(startKey, endKey);
                    break;
                case 'scan':
                    await this.fullKeyScan(startKey, endKey);
                    break;
                case 'optimize':
                    await this.optimizeCurrentKey();
                    break;
                case 'explore':
                    await this.exploreRandomKeys();
                    break;
            }
            this.checkCompletion(endKey);
            this.checkProgress();
        }
    }

    async searchPrimaryTarget(startKey, endKey) {
        const BLOCK_SIZE = 10000;
        for (let keyNum = startKey; keyNum < endKey && this.running; keyNum += BLOCK_SIZE) {
            const blockEnd = Math.min(keyNum + BLOCK_SIZE, endKey);
            for (let i = keyNum; i < blockEnd; i++) {
                const key = this.generateKey(i);
                if (this.isKeyTested(key)) continue;
                this.addTestedKey(key);
                
                const plaintext = this.decrypt(key);
                this.keysTested++;

                if (plaintext.includes(this.primaryTarget)) {
                    this.handlePrimaryFound(key, plaintext);
                }
            }
            await this.yieldToMain();
        }
        this.mode = 'scan';
    }

    handlePrimaryFound(key, plaintext) {
        this.primaryTargetFound = true;
        const score = this.scoreText(plaintext);
        this.primaryResults.push({ key, plaintext, score });
        self.postMessage({
            type: 'primaryResult',
            key: key,
            plaintext: plaintext,
            score: score
        });
    }

    async fullKeyScan(startKey, endKey) {
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
                    this.updateBestResults(key, plaintext, score);
                }
            }
            await this.yieldToMain();
            this.checkStagnation();
        }
    }

    updateBestResults(key, plaintext, score) {
        this.bestScore = score;
        this.bestKey = key;
        this.bestPlaintext = plaintext;
        this.lastImprovementTime = performance.now();
        self.postMessage({
            type: 'result',
            key: key,
            plaintext: plaintext,
            score: score
        });
    }

    async optimizeCurrentKey() {
        let improved = false;
        const originalKey = this.bestKey;
        const keyChars = originalKey.split('');

        for (let pos = 0; pos < this.keyLength && this.running; pos++) {
            const originalChar = keyChars[pos];
            for (const delta of [-1, 1, -2, 2]) {
                keyChars[pos] = this.getShiftedChar(originalChar, delta);
                const newKey = keyChars.join('');
                if (this.processKeyVariation(newKey)) {
                    improved = true;
                    break;
                }
            }
            if (!improved) keyChars[pos] = originalChar;
            await this.yieldToMain();
        }

        this.handleOptimizationResult(improved, originalKey);
    }

    getShiftedChar(char, delta) {
        const index = (this.charMap[char.charCodeAt(0)] + delta + 26) % 26;
        return this.alphabet[index];
    }

    processKeyVariation(key) {
        if (this.isKeyTested(key)) return false;
        this.addTestedKey(key);
        
        const plaintext = this.decrypt(key);
        const score = this.scoreText(plaintext);
        this.keysTested++;

        if (score > this.bestScore) {
            this.updateBestResults(key, plaintext, score);
            return true;
        }
        return false;
    }

    handleOptimizationResult(improved, originalKey) {
        if (improved) {
            this.stuckCount = 0;
            this.mode = 'optimize';
        } else {
            this.stuckCount++;
            if (this.stuckCount > 2) {
                this.mode = 'explore';
                this.stuckCount = 0;
            }
        }
    }

    async exploreRandomKeys() {
        const MAX_ATTEMPTS = 500;
        for (let i = 0; i < MAX_ATTEMPTS && this.running; i++) {
            const key = this.generateKey(Math.floor(Math.random() * this.totalKeysToTest));
            if (this.processKeyVariation(key)) {
                this.mode = 'optimize';
                break;
            }
            if (i % 50 === 0) await this.yieldToMain();
        }
        this.mode = 'scan';
    }

    checkCompletion(endKey) {
        if (this.keysTested >= (endKey - Math.floor(this.totalKeysToTest * this.workerId / this.totalWorkers))) {
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
    }

    checkStagnation() {
        if (performance.now() - this.lastImprovementTime > 5000) {
            this.mode = 'optimize';
        }
    }

    checkProgress() {
        const now = performance.now();
        if (now - this.lastReportTime > 1000) {
            const elapsed = (now - this.startTime) / 1000;
            const kps = elapsed > 0 ? Math.round(this.keysTested / elapsed) : 0;
            const completion = (this.keysTested / (this.totalKeysToTest / this.totalWorkers)) * 100;

            self.postMessage({
                type: 'progress',
                keysTested: this.keysTested,
                totalKeys: this.totalKeysToTest,
                kps: kps,
                completion: Math.min(100, completion).toFixed(2),
                bestScore: this.bestScore,
                bestKey: this.bestKey,
                bestPlaintext: this.bestPlaintext
            });

            this.lastReportTime = now;
        }
    }

    yieldToMain() {
        return new Promise(resolve => setTimeout(resolve, 0));
    }
}

new K4Worker();
