const ENGLISH_FREQ = new Float32Array(26);
(function() {
    const freqData = {
        'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
        'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
        'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
        'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
        'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974,
        'Z': 0.074
    };
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('').forEach((c, i) => {
        ENGLISH_FREQ[i] = freqData[c] || 0;
    });
})();

const PATTERN_MAP = new Map();
(function() {
    const patterns = [
        ['THE', 25], ['AND', 25], ['THAT', 25], ['HAVE', 25], ['FOR', 25],
        ['NOT', 25], ['WITH', 25], ['YOU', 25], ['THIS', 25], ['WAY', 25],
        ['HIS', 25], ['FROM', 25], ['THEY', 25], ['WILL', 25], ['WOULD', 25],
        ['THERE', 25], ['THEIR', 25], ['WHAT', 25], ['ABOUT', 25], ['WHICH', 25],
        ['WHEN', 25], ['YOUR', 25], ['WERE', 25], ['CIA', 25],
        ['BERLIN', 50], ['CLOCK', 50], ['EAST', 50], ['NORTH', 50], ['WEST', 50],
        ['SOUTH', 50], ['NORTHEAST', 50], ['NORTHWEST', 50], ['SOUTHEAST', 50],
        ['SOUTHWEST', 50], ['SECRET', 50], ['CODE', 50], ['MESSAGE', 50],
        ['KRYPTOS', 50], ['BERLINCLOCK', 50], ['AGENT', 50], ['COMPASS', 50],
        ['LIGHT', 50], ['LATITUDE', 50], ['LONGITUDE', 50], ['COORDINATE', 50],
        ['SHADOW', 50], ['WALL', 50], ['UNDERGROUND', 50]
    ];
    
    patterns.forEach(([pattern, weight]) => {
        const key = pattern.toUpperCase();
        PATTERN_MAP.set(key, {weight, length: key.length});
    });
})();

class K4Worker {
    constructor() {
        this.alphabet = 'ZXWVUQNMLJIHGFEDCBASOTPYRK';
        this.alphabetCodes = new Uint8Array(26);
        this.charMap = new Uint8Array(256);
        this.running = false;
        this.ciphertext = '';
        this.cipherCodes = null;
        this.keyLength = 0;
        this.workerId = 0;
        this.totalWorkers = 1;
        this.keysTested = 0;
        this.startTime = 0;
        this.lastReportTime = 0;
        this.bestScore = 0;
        this.bestKey = '';
        this.stuckCount = 0;
        this.mode = 'scan';
        this.lastImprovementTime = 0;
        this.targetText = 'BERLINCLOCK';
        this.targetTextFound = false;
        this.parallelWorkers = [];
        this.currentTask = null;
        this.optimizationCache = new Map();
        this.precomputedAlphabet = new Array(26).fill().map(() => new Uint8Array(26));

        // Precompute alphabet positions
        for (let i = 0; i < this.alphabet.length; i++) {
            this.alphabetCodes[i] = this.alphabet.charCodeAt(i);
            this.charMap[this.alphabet.charCodeAt(i)] = i;
        }

        // Precompute Vigenère decryption matrix
        for (let i = 0; i < 26; i++) {
            for (let j = 0; j < 26; j++) {
                this.precomputedAlphabet[i][j] = (i - j + 26) % 26;
            }
        }

        self.onmessage = (e) => {
            const msg = e.data;
            switch (msg.type) {
                case 'init':
                    this.ciphertext = msg.ciphertext;
                    this.cipherCodes = this.textToCodes(this.ciphertext);
                    this.keyLength = msg.keyLength;
                    this.workerId = msg.workerId || 0;
                    this.totalWorkers = msg.totalWorkers || 1;
                    this.keysTested = 0;
                    this.bestScore = 0;
                    this.bestKey = this.generateKey(0);
                    if (msg.targetText) {
                        this.targetText = msg.targetText.toUpperCase();
                    }
                    this.optimizationCache.clear();
                    break;
                case 'start':
                    if (!this.running) {
                        this.running = true;
                        this.startTime = performance.now();
                        this.lastImprovementTime = this.startTime;
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
                        this.lastImprovementTime = performance.now();
                    }
                    break;
                case 'updateTargetText':
                    this.targetText = msg.text.toUpperCase();
                    this.targetTextFound = false;
                    break;
            }
        };
    }

    textToCodes(text) {
        const codes = new Uint8Array(text.length);
        for (let i = 0; i < text.length; i++) {
            codes[i] = this.charMap[text.charCodeAt(i)];
        }
        return codes;
    }

    generateKey(num) {
        const key = new Uint8Array(this.keyLength);
        for (let i = this.keyLength - 1; i >= 0; i--) {
            key[i] = num % 26;
            num = Math.floor(num / 26);
        }
        return String.fromCharCode(...key.map(c => this.alphabetCodes[c]));
    }

    decrypt(keyCodes) {
        const plainCodes = new Uint8Array(this.cipherCodes.length);
        const keyLength = keyCodes.length;
        
        for (let i = 0; i < this.cipherCodes.length; i++) {
            const cipherChar = this.cipherCodes[i];
            const keyChar = keyCodes[i % keyLength];
            plainCodes[i] = this.precomputedAlphabet[cipherChar][keyChar];
        }
        
        return String.fromCharCode(...plainCodes.map(c => this.alphabetCodes[c]));
    }

    scoreText(text) {
        let score = 0;
        const upperText = text.toUpperCase();
        const freq = new Uint16Array(26);
        let totalLetters = 0;

        // Target text check
        if (this.targetText && !this.targetTextFound) {
            if (upperText.includes(this.targetText)) {
                this.targetTextFound = true;
                score += 1000;
            }
        }

        // Frequency analysis
        for (let i = 0; i < text.length; i++) {
            const code = text.charCodeAt(i) - 65;
            if (code >= 0 && code < 26) {
                freq[code]++;
                totalLetters++;
            }
        }

        if (totalLetters > 0) {
            for (let i = 0; i < 26; i++) {
                const expected = ENGLISH_FREQ[i];
                const actual = (freq[i] / totalLetters) * 100;
                score += 100 - Math.abs(expected - actual);
            }
        }

        // Pattern matching with sliding window
        const maxPatternLength = Math.max(...[...PATTERN_MAP.values()].map(v => v.length));
        const window = new Array(maxPatternLength).fill(0);
        
        for (let i = 0; i < upperText.length; i++) {
            window.shift();
            window.push(upperText.charCodeAt(i));
            
            for (let len = 3; len <= maxPatternLength; len++) {
                if (i < len - 1) continue;
                const substr = String.fromCharCode(...window.slice(-len));
                const pattern = PATTERN_MAP.get(substr);
                if (pattern) {
                    score += pattern.weight * len;
                }
            }
        }

        return Math.round(score);
    }

    async run() {
        const totalKeys = Math.pow(26, this.keyLength);
        const startKey = this.workerId * Math.floor(totalKeys / this.totalWorkers);
        const endKey = (this.workerId === this.totalWorkers - 1) ? totalKeys : startKey + Math.floor(totalKeys / this.totalWorkers);

        // Используем буферизованный batch processing
        const BATCH_SIZE = 5000;
        let batchPromises = [];
        
        while (this.running) {
            switch (this.mode) {
                case 'scan':
                    await this.optimizedBatchScan(startKey, endKey, BATCH_SIZE);
                    break;
                case 'optimize':
                    await this.optimizedKeyOptimization();
                    break;
                case 'explore':
                    await this.enhancedRandomExploration();
                    break;
                case 'target':
                    await this.parallelTargetSearch(startKey, endKey);
                    break;
            }
            this.checkProgress();
            await new Promise(resolve => setTimeout(resolve, 0));
        }
    }

    async optimizedBatchScan(start, end, batchSize) {
        const keyBuffer = new Uint8Array(this.keyLength);
        let localBest = {score: 0, key: ''};

        for (let keyNum = start; keyNum < end; keyNum += batchSize) {
            if (!this.running) break;

            const batchEnd = Math.min(keyNum + batchSize, end);
            const batchResults = [];
            
            for (let i = keyNum; i < batchEnd; i++) {
                this.numToKey(i, keyBuffer);
                const keyStr = String.fromCharCode(...keyBuffer.map(c => this.alphabetCodes[c]));
                const plaintext = this.decrypt(keyBuffer);
                const score = this.scoreText(plaintext);
                
                if (score > localBest.score) {
                    localBest = {score, key: keyStr};
                }
                
                this.keysTested++;
            }

            if (localBest.score > this.bestScore) {
                this.updateBest(localBest.score, localBest.key);
                localBest = {score: 0, key: ''};
            }

            await this.yieldToEventLoop();
        }
    }

    numToKey(num, buffer) {
        for (let i = this.keyLength - 1; i >= 0; i--) {
            buffer[i] = num % 26;
            num = Math.floor(num / 26);
        }
    }

    async optimizedKeyOptimization() {
        const currentKey = this.textToCodes(this.bestKey);
        const neighborOffsets = [-1, 1, -2, 2, -3, 3];
        const optimizationRounds = 3;

        for (let round = 0; round < optimizationRounds; round++) {
            if (!this.running) break;

            const modifiedKey = new Uint8Array(currentKey);
            let improved = false;

            for (let pos = 0; pos < this.keyLength; pos++) {
                if (!this.running) break;

                const original = modifiedKey[pos];
                const neighbors = this.shuffled(neighborOffsets);

                for (const delta of neighbors) {
                    modifiedKey[pos] = (original + delta + 26) % 26;
                    const cacheKey = modifiedKey.join(',');
                    
                    if (this.optimizationCache.has(cacheKey)) continue;
                    
                    const keyStr = String.fromCharCode(...modifiedKey.map(c => this.alphabetCodes[c]));
                    const plaintext = this.decrypt(modifiedKey);
                    const score = this.scoreText(plaintext);
                    this.keysTested++;
                    this.optimizationCache.set(cacheKey, score);

                    if (score > this.bestScore) {
                        this.updateBest(score, keyStr);
                        currentKey.set(modifiedKey);
                        improved = true;
                        break;
                    }
                }
                modifiedKey[pos] = original;
            }

            if (!improved) {
                this.stuckCount++;
                if (this.stuckCount > 2) {
                    this.mode = 'explore';
                    this.stuckCount = 0;
                    break;
                }
            }
            await this.yieldToEventLoop();
        }
    }

    async enhancedRandomExploration() {
        const EXPLORE_BATCH = 1000;
        const keyBuffer = new Uint8Array(this.keyLength);
        let localBest = {score: 0, key: ''};

        for (let i = 0; i < EXPLORE_BATCH; i++) {
            if (!this.running) break;

            crypto.getRandomValues(keyBuffer);
            keyBuffer.forEach((v, i) => keyBuffer[i] = v % 26);
            
            const keyStr = String.fromCharCode(...keyBuffer.map(c => this.alphabetCodes[c]));
            const plaintext = this.decrypt(keyBuffer);
            const score = this.scoreText(plaintext);
            this.keysTested++;

            if (score > localBest.score) {
                localBest = {score, key: keyStr};
            }
        }

        if (localBest.score > this.bestScore * 0.85) {
            this.updateBest(localBest.score, localBest.key);
            this.mode = 'optimize';
        }
    }

    updateBest(score, key) {
        this.bestScore = score;
        this.bestKey = key;
        this.lastImprovementTime = performance.now();
        self.postMessage({
            type: 'result',
            key: this.bestKey,
            plaintext: this.decrypt(this.textToCodes(key)),
            score: this.bestScore
        });
    }

    shuffled(array) {
        return array.sort(() => Math.random() - 0.5);
    }

    async yieldToEventLoop() {
        if (this.keysTested % 1000 === 0) {
            await new Promise(resolve => setTimeout(resolve, 0));
        }
    }

    checkProgress() {
        const now = performance.now();
        if (now - this.lastReportTime > 1000) {
            const kps = Math.round(this.keysTested / ((now - this.startTime) / 1000));
            self.postMessage({
                type: 'progress',
                keysTested: this.keysTested,
                kps: kps,
                mode: this.mode,
                targetTextFound: this.targetTextFound
            });
            this.lastReportTime = now;
        }
    }

    // Остальные методы (searchTargetText, generateKey и т.д.) остаются аналогичными оригиналу 
    // с заменой строковых операций на работу с буферами где это необходимо
}

new K4Worker();
