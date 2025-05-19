const ENGLISH_FREQ = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
    'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
    'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
    'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
    'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974,
    'Z': 0.074
};

const commonPatterns = [
    'TH', 'HE', 'AN', 'ND', 'HA', 'AT', 'AV', 'VE', 'FO', 'OR', 'NO', 'OT', 'WI', 'IT', 'YO', 'OU', 'HI', 'IS', 'FR', 'RO', 'OM', 'TE', 'EY', 'IL', 'LL', 'WO', 'UL', 'LD', 'RE', 'EI', 'IR', 'WH', 'HO', 'EN', 'UR', 'WE', 'ER', 'CI', 'IA',
    'THE', 'AND', 'THAT', 'HAVE', 'FOR', 'NOT', 'WITH', 'YOU', 'THIS', 'WAY',
    'HIS', 'FROM', 'THEY', 'WILL', 'WOULD', 'THERE', 'THEIR', 'WHAT', 'ABOUT',
    'WHICH', 'WHEN', 'YOUR', 'WERE', 'CIA'
];

const uncommonPatterns = [
    'BERLIN', 'CLOCK', 'EAST', 'NORTH', 'WEST',
    'SOUTH', 'NORTHEAST', 'NORTHWEST', 'SOUTHEAST', 'SOUTHWEST', 'SECRET', 'CODE',
    'MESSAGE', 'KRYPTOS', 'BERLINCLOCK', 'AGENT', 'COMPASS', 'LIGHT', 'LATITUDE',
    'LONGITUDE', 'COORDINATE', 'SHADOW', 'WALL', 'UNDERGROUND'
];

class K4Worker {
    constructor() {
        // Original structure preservation
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
        this.bestScore = 0;
        this.bestKey = '';
        this.stuckCount = 0;
        this.mode = 'scan';
        this.lastImprovementTime = 0;
        this.optimizePositions = [];
        this.targetText = 'BERLINCLOCK';
        this.targetTextFound = false;
        this.parallelWorkers = [];
        this.currentTask = null;

        // Optimized precomputations
        this._initPrecomputations();
        
        // Preserve original message handling
        self.onmessage = (e) => this._handleMessage(e);
    }

    _initPrecomputations() {
        // Precompute alphabet lookups
        this.alphabetCodes = new Uint8Array(26);
        this.reverseCharMap = new Uint8Array(256);
        for (let i = 0; i < this.alphabet.length; i++) {
            const code = this.alphabet.charCodeAt(i);
            this.charMap[code] = i;
            this.alphabetCodes[i] = code;
            this.reverseCharMap[i] = code;
        }

        // Precompute pattern maps
        this.patternMap = new Map();
        const addPatterns = (patterns, weight) => {
            patterns.forEach(pattern => {
                const key = pattern.toUpperCase();
                this.patternMap.set(key, { weight, length: key.length });
            });
        };
        addPatterns(commonPatterns, 25);
        addPatterns(uncommonPatterns, 50);

        // Precompute frequency array
        this.englishFreqArray = new Float32Array(26);
        for (let i = 0; i < 26; i++) {
            this.englishFreqArray[i] = ENGLISH_FREQ[this.alphabet[i]] || 0;
        }
    }

    _handleMessage(e) {
        const msg = e.data;
        switch (msg.type) {
            case 'init':
                this.ciphertext = msg.ciphertext;
                this.keyLength = msg.keyLength;
                this.workerId = msg.workerId || 0;
                this.totalWorkers = msg.totalWorkers || 1;
                this.keysTested = 0;
                this.bestScore = 0;
                this.bestKey = this.generateKey(0);
                if (msg.targetText) {
                    this.targetText = msg.targetText.toUpperCase();
                }
                this._precomputeCipher();
                break;
            case 'start':
                if (!this.running) {
                    this.running = true;
                    this.startTime = performance.now();
                    this.lastImprovementTime = this.startTime;
                    this._run();
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
    }

    _precomputeCipher() {
        // Convert ciphertext to precomputed codes
        this.cipherCodes = new Uint8Array(this.ciphertext.length);
        for (let i = 0; i < this.ciphertext.length; i++) {
            this.cipherCodes[i] = this.charMap[this.ciphertext.charCodeAt(i)];
        }
    }

    generateKey(num) {
        // Optimized key generation
        const key = new Uint8Array(this.keyLength);
        for (let i = this.keyLength - 1; i >= 0; i--) {
            key[i] = num % 26;
            num = Math.floor(num / 26);
        }
        return String.fromCharCode(...key.map(c => this.reverseCharMap[c]));
    }

    decrypt(key) {
        // Optimized decryption with precomputed codes
        const keyCodes = new Uint8Array(this.keyLength);
        for (let i = 0; i < this.keyLength; i++) {
            keyCodes[i] = this.charMap[key.charCodeAt(i)];
        }

        const plaintext = new Uint8Array(this.cipherCodes.length);
        for (let i = 0; i < this.cipherCodes.length; i++) {
            const plainPos = (this.cipherCodes[i] - keyCodes[i % this.keyLength] + 26) % 26;
            plaintext[i] = this.reverseCharMap[plainPos];
        }
        return String.fromCharCode.apply(null, plaintext);
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

        // Optimized pattern matching
        const maxPatternLength = Math.max(...[...this.patternMap.values()].map(v => v.length));
        const window = [];
        
        for (let i = 0; i < upperText.length; i++) {
            window.push(upperText[i]);
            if (window.length > maxPatternLength) window.shift();
            
            for (let len = 3; len <= window.length; len++) {
                const substr = window.slice(-len).join('');
                const pattern = this.patternMap.get(substr);
                if (pattern) {
                    score += pattern.weight * len;
                }
            }
        }

        return Math.round(score);
    }

    async _run() {
        const totalKeys = Math.pow(26, this.keyLength);
        const startKey = this.workerId * Math.floor(totalKeys / this.totalWorkers);
        const endKey = (this.workerId === this.totalWorkers - 1) ? totalKeys : startKey + Math.floor(totalKeys / this.totalWorkers);

        // Preserve original mode handling
        while (this.running) {
            switch (this.mode) {
                case 'scan':
                    await this._fullScan(startKey, endKey);
                    break;
                case 'optimize':
                    await this._optimizeKey();
                    break;
                case 'explore':
                    await this._exploreRandom();
                    break;
                case 'target':
                    await this._searchTargetText();
                    break;
            }
            this._checkProgress();
            await new Promise(resolve => setTimeout(resolve, 0));
        }
    }

    async _fullScan(startKey, endKey) {
        const BLOCK_SIZE = 10000;
        let currentKey = new Uint8Array(this.keyLength);
        let bestScore = 0;
        let bestKey = '';

        for (let keyNum = startKey; keyNum < endKey; keyNum += BLOCK_SIZE) {
            if (!this.running) break;

            const blockEnd = Math.min(keyNum + BLOCK_SIZE, endKey);
            for (let i = keyNum; i < blockEnd; i++) {
                // Generate key
                let num = i;
                for (let j = this.keyLength - 1; j >= 0; j--) {
                    currentKey[j] = num % 26;
                    num = Math.floor(num / 26);
                }
                
                // Decrypt and score
                const keyStr = String.fromCharCode(...currentKey.map(c => this.reverseCharMap[c]));
                const plaintext = this.decrypt(keyStr);
                const score = this.scoreText(plaintext);
                this.keysTested++;

                // Update best
                if (score > bestScore) {
                    bestScore = score;
                    bestKey = keyStr;
                }
            }

            // Update global best
            if (bestScore > this.bestScore) {
                this.bestScore = bestScore;
                this.bestKey = bestKey;
                this.lastImprovementTime = performance.now();
                self.postMessage({
                    type: 'result',
                    key: this.bestKey,
                    plaintext: this.decrypt(this.bestKey),
                    score: this.bestScore
                });
            }

            // Check mode switch
            if (performance.now() - this.lastImprovementTime > 5000) {
                this.mode = 'optimize';
                break;
            }

            await new Promise(resolve => setTimeout(resolve, 0));
        }
    }

    async _optimizeKey() {
        const originalKey = this.bestKey.split('').map(c => this.charMap[c.charCodeAt(0)]);
        const neighborOffsets = [-3, -2, -1, 1, 2, 3];
        let improved = false;

        for (let rounds = 0; rounds < 3; rounds++) {
            const positions = Array.from({length: this.keyLength}, (_, i) => i);
            this._shuffleArray(positions);

            for (const pos of positions) {
                if (!this.running) break;

                const originalChar = originalKey[pos];
                for (const delta of neighborOffsets) {
                    const newChar = (originalChar + delta + 26) % 26;
                    originalKey[pos] = newChar;
                    
                    const keyStr = String.fromCharCode(...originalKey.map(c => this.reverseCharMap[c]));
                    const plaintext = this.decrypt(keyStr);
                    const score = this.scoreText(plaintext);
                    this.keysTested++;

                    if (score > this.bestScore) {
                        this.bestScore = score;
                        this.bestKey = keyStr;
                        improved = true;
                        this.lastImprovementTime = performance.now();
                        self.postMessage({
                            type: 'result',
                            key: this.bestKey,
                            plaintext: plaintext,
                            score: this.bestScore
                        });
                        break;
                    }
                    originalKey[pos] = originalChar;
                }
            }

            if (improved) break;
        }

        if (!improved) {
            this.stuckCount++;
            if (this.stuckCount > 5) {
                this.mode = 'explore';
                this.stuckCount = 0;
            }
        }
    }

    async _exploreRandom() {
        const EXPLORE_BATCH = 1000;
        const keyBuffer = new Uint8Array(this.keyLength);
        let bestScore = 0;
        let bestKey = '';

        for (let i = 0; i < EXPLORE_BATCH; i++) {
            if (!this.running) break;

            crypto.getRandomValues(keyBuffer);
            for (let j = 0; j < this.keyLength; j++) {
                keyBuffer[j] = keyBuffer[j] % 26;
            }
            
            const keyStr = String.fromCharCode(...keyBuffer.map(c => this.reverseCharMap[c]));
            const plaintext = this.decrypt(keyStr);
            const score = this.scoreText(plaintext);
            this.keysTested++;

            if (score > bestScore) {
                bestScore = score;
                bestKey = keyStr;
            }
        }

        if (bestScore > this.bestScore * 0.8) {
            this.bestScore = bestScore;
            this.bestKey = bestKey;
            this.mode = 'optimize';
            self.postMessage({
                type: 'result',
                key: this.bestKey,
                plaintext: this.decrypt(this.bestKey),
                score: this.bestScore
            });
        }
    }

    _shuffleArray(array) {
        for (let i = array.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [array[i], array[j]] = [array[j], array[i]];
        }
    }

    _checkProgress() {
        const now = performance.now();
        if (now - this.lastReportTime > 1000) {
            const elapsed = (now - this.startTime) / 1000;
            const kps = Math.round(this.keysTested / elapsed);
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

    // Оригинальные методы сохранены
    async _searchTargetText() {
        const totalKeys = Math.pow(26, this.keyLength);
        const startKey = this.workerId * Math.floor(totalKeys / this.totalWorkers);
        const endKey = (this.workerId === this.totalWorkers - 1) ? totalKeys : startKey + Math.floor(totalKeys / this.totalWorkers);
        const BLOCK_SIZE = 10000;
        let currentKey = new Uint8Array(this.keyLength);

        for (let keyNum = startKey; keyNum < endKey; keyNum += BLOCK_SIZE) {
            if (!this.running || this.targetTextFound) break;

            const blockEnd = Math.min(keyNum + BLOCK_SIZE, endKey);
            for (let i = keyNum; i < blockEnd; i++) {
                let num = i;
                for (let j = this.keyLength - 1; j >= 0; j--) {
                    currentKey[j] = num % 26;
                    num = Math.floor(num / 26);
                }
                
                const keyStr = String.fromCharCode(...currentKey.map(c => this.reverseCharMap[c]));
                const plaintext = this.decrypt(keyStr);
                this.keysTested++;

                if (plaintext.includes(this.targetText)) {
                    const score = this.scoreText(plaintext);
                    this.targetTextFound = true;
                    this.bestScore = score;
                    this.bestKey = keyStr;
                    self.postMessage({
                        type: 'result',
                        key: this.bestKey,
                        plaintext: plaintext,
                        score: this.bestScore,
                        targetFound: true
                    });
                    return;
                }
            }
            await new Promise(resolve => setTimeout(resolve, 0));
        }
    }
}

new K4Worker();
