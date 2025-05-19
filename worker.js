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
    'WHICH', 'WHEN', 'YOUR', 'WERE', 'CIA', 'NSA', 'FBI', 'USA', 'UK', 'RUS',
    'AGENT', 'CODE', 'SECRET', 'MESSAGE', 'INFORMATION', 'INTELLIGENCE', 'GOVERNMENT',
    'WASHINGTON', 'LONDON', 'MOSCOW', 'BERLIN', 'PARIS', 'AMERICA', 'RUSSIA', 'ENGLAND',
    'GERMANY', 'FRANCE', 'EUROPE', 'WORLD', 'COUNTRY', 'CITY', 'TOWN', 'VILLAGE',
    'PERSON', 'MAN', 'WOMAN', 'CHILD', 'FAMILY', 'FRIEND', 'ENEMY', 'ALLY'
];

const uncommonPatterns = [
    'KRYPTOS', 'BERLINCLOCK', 'EAST', 'NORTH', 'WEST',
    'SOUTH', 'NORTHEAST', 'NORTHWEST', 'SOUTHEAST', 'SOUTHWEST', 'COMPASS', 'LIGHT',
    'LATITUDE', 'LONGITUDE', 'COORDINATE', 'SHADOW', 'WALL', 'UNDERGROUND', 'PALIMPSEST',
    'ABSCISSA', 'ILLUMINATION', 'CLOCKWISE', 'COUNTERCLOCKWISE', 'DIAGONAL', 'VERTICAL',
    'HORIZONTAL', 'OBELISK', 'PYRAMID', 'SCULPTURE', 'CIPHER', 'ENCRYPT', 'DECRYPT',
    'VIGENERE', 'SUBSTITUTION', 'TRANSPOSITION', 'ALPHABET', 'LETTER', 'SYMBOL', 'SLOWLY',
    'DESPARATELY', 'WEAKLY', 'IDBY', 'JIMSANBORN', 'SANBORN', 'SCRATCHES', 'SHADOWS',
    'LAYER', 'LAYERED', 'QUESTION', 'ANSWER', 'SOLUTION', 'MYSTER', 'HIDDEN', 'COVER',
    'UNCOVER', 'REVEAL', 'TRUTH', 'LIE', 'DECEPTION', 'OMISSION', 'REDACTED', 'CLASSIFIED',
    'TOP SECRET', 'CONFIDENTIAL', 'RESTRICTED', 'EYES ONLY', 'FOR YOUR EYES ONLY'
];

class K4Worker {
    constructor() {
        this.alphabet = 'ZXWVUQNMLJIHGFEDCBASOTPYRK';
        this.charMap = new Uint8Array(256);
        this.reverseCharMap = new Uint8Array(26);
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
        this.precomputedDecrypt = null;

        // Initialize character mappings
        for (let i = 0; i < this.alphabet.length; i++) {
            const code = this.alphabet.charCodeAt(i);
            this.charMap[code] = i;
            this.reverseCharMap[i] = code;
        }

        // Precompute pattern scores
        this.patternScores = {};
        const addPatterns = (patterns, weight) => {
            patterns.forEach(pattern => {
                const key = pattern.toUpperCase();
                this.patternScores[key] = weight * key.length;
            });
        };
        addPatterns(commonPatterns, 25);
        addPatterns(uncommonPatterns, 50);

        // Precompute frequency scores
        this.englishFreqScores = new Float32Array(26);
        for (let i = 0; i < 26; i++) {
            this.englishFreqScores[i] = ENGLISH_FREQ[this.alphabet[i]] || 0;
        }

        // Message handler
        self.onmessage = (e) => {
            const msg = e.data;
            switch (msg.type) {
                case 'init':
                    this._init(msg);
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
        };
    }

    _init(msg) {
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

        // Precompute cipher codes
        this.cipherCodes = new Uint8Array(this.ciphertext.length);
        for (let i = 0; i < this.ciphertext.length; i++) {
            this.cipherCodes[i] = this.charMap[this.ciphertext.charCodeAt(i)];
        }

        // Precompute decryption matrix
        this.precomputedDecrypt = new Array(26);
        for (let i = 0; i < 26; i++) {
            this.precomputedDecrypt[i] = new Uint8Array(26);
            for (let j = 0; j < 26; j++) {
                this.precomputedDecrypt[i][j] = (i - j + 26) % 26;
            }
        }
    }

    generateKey(num) {
        const key = new Uint8Array(this.keyLength);
        for (let i = this.keyLength - 1; i >= 0; i--) {
            key[i] = num % 26;
            num = Math.floor(num / 26);
        }
        return String.fromCharCode(...key.map(c => this.reverseCharMap[c]));
    }

    decrypt(key) {
        const keyCodes = new Uint8Array(this.keyLength);
        for (let i = 0; i < this.keyLength; i++) {
            keyCodes[i] = this.charMap[key.charCodeAt(i)];
        }

        const plaintext = new Uint8Array(this.cipherCodes.length);
        for (let i = 0; i < this.cipherCodes.length; i++) {
            plaintext[i] = this.precomputedDecrypt[this.cipherCodes[i]][keyCodes[i % this.keyLength]];
        }
        return String.fromCharCode(...plaintext.map(c => this.reverseCharMap[c]));
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
                const expected = this.englishFreqScores[i];
                const actual = (freq[i] / totalLetters) * 100;
                score += 100 - Math.abs(expected - actual);
            }
        }

        // Pattern matching
        for (const pattern in this.patternScores) {
            let pos = -1;
            while ((pos = upperText.indexOf(pattern, pos + 1)) !== -1) {
                score += this.patternScores[pattern];
            }
        }

        return Math.round(score);
    }

    async _run() {
        const totalKeys = Math.pow(26, this.keyLength);
        const startKey = this.workerId * Math.floor(totalKeys / this.totalWorkers);
        const endKey = (this.workerId === this.totalWorkers - 1) ? totalKeys : startKey + Math.floor(totalKeys / this.totalWorkers);

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
        const BLOCK_SIZE = 100000; // Increased block size for better performance
        const keyBuffer = new Uint8Array(this.keyLength);
        let localBestScore = 0;
        let localBestKey = '';

        for (let keyNum = startKey; keyNum < endKey; keyNum += BLOCK_SIZE) {
            if (!this.running) break;

            const blockEnd = Math.min(keyNum + BLOCK_SIZE, endKey);
            for (let i = keyNum; i < blockEnd; i++) {
                // Generate key
                let num = i;
                for (let j = this.keyLength - 1; j >= 0; j--) {
                    keyBuffer[j] = num % 26;
                    num = Math.floor(num / 26);
                }

                // Decrypt
                const plaintext = new Uint8Array(this.cipherCodes.length);
                for (let k = 0; k < this.cipherCodes.length; k++) {
                    plaintext[k] = this.precomputedDecrypt[this.cipherCodes[k]][keyBuffer[k % this.keyLength]];
                }

                // Score (simplified for speed)
                let score = 0;
                for (let k = 0; k < plaintext.length; k++) {
                    score += this.englishFreqScores[plaintext[k]];
                }

                // Update best
                if (score > localBestScore) {
                    localBestScore = score;
                    localBestKey = String.fromCharCode(...keyBuffer.map(c => this.reverseCharMap[c]));
                }

                this.keysTested++;
            }

            // Check if we found a better key
            if (localBestScore > this.bestScore) {
                const plaintext = String.fromCharCode(...this.cipherCodes.map((c, i) => 
                    this.reverseCharMap[this.precomputedDecrypt[c][this.charMap[localBestKey.charCodeAt(i % this.keyLength)]]]
                );
                const fullScore = this.scoreText(plaintext);
                
                if (fullScore > this.bestScore) {
                    this.bestScore = fullScore;
                    this.bestKey = localBestKey;
                    this.lastImprovementTime = performance.now();
                    self.postMessage({
                        type: 'result',
                        key: this.bestKey,
                        plaintext: plaintext,
                        score: this.bestScore
                    });
                }
            }

            // Switch mode if no improvement
            if (performance.now() - this.lastImprovementTime > 5000) {
                this.mode = 'optimize';
                break;
            }
        }
    }

    async _optimizeKey() {
        const currentKey = this.bestKey.split('').map(c => this.charMap[c.charCodeAt(0)]);
        const neighborOffsets = [-3, -2, -1, 1, 2, 3];
        let improved = false;

        for (let rounds = 0; rounds < 3; rounds++) {
            if (!this.running) break;

            for (let pos = 0; pos < this.keyLength; pos++) {
                if (!this.running) break;

                const original = currentKey[pos];
                for (const delta of neighborOffsets) {
                    currentKey[pos] = (original + delta + 26) % 26;
                    
                    // Fast decrypt and score
                    let score = 0;
                    for (let i = 0; i < this.cipherCodes.length; i++) {
                        score += this.englishFreqScores[this.precomputedDecrypt[this.cipherCodes[i]][currentKey[i % this.keyLength]]];
                    }

                    if (score > this.bestScore * 0.9) { // Lower threshold for optimization
                        const keyStr = String.fromCharCode(...currentKey.map(c => this.reverseCharMap[c]));
                        const plaintext = this.decrypt(keyStr);
                        const fullScore = this.scoreText(plaintext);
                        
                        if (fullScore > this.bestScore) {
                            this.bestScore = fullScore;
                            this.bestKey = keyStr;
                            improved = true;
                            this.lastImprovementTime = performance.now();
                            self.postMessage({
                                type: 'result',
                                key: this.bestKey,
                                plaintext: plaintext,
                                score: this.bestScore
                            });
                        }
                    }
                    currentKey[pos] = original;
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
        const EXPLORE_BATCH = 10000; // Larger batch for better performance
        const keyBuffer = new Uint8Array(this.keyLength);
        let bestScore = 0;
        let bestKey = '';

        for (let i = 0; i < EXPLORE_BATCH; i++) {
            if (!this.running) break;

            crypto.getRandomValues(keyBuffer);
            for (let j = 0; j < this.keyLength; j++) {
                keyBuffer[j] = keyBuffer[j] % 26;
            }

            // Fast score estimation
            let score = 0;
            for (let k = 0; k < this.cipherCodes.length; k++) {
                score += this.englishFreqScores[this.precomputedDecrypt[this.cipherCodes[k]][keyBuffer[k % this.keyLength]]];
            }

            if (score > bestScore) {
                bestScore = score;
                bestKey = String.fromCharCode(...keyBuffer.map(c => this.reverseCharMap[c]));
            }

            this.keysTested++;
        }

        if (bestScore > this.bestScore * 0.8) {
            const plaintext = this.decrypt(bestKey);
            const fullScore = this.scoreText(plaintext);
            
            if (fullScore > this.bestScore) {
                this.bestScore = fullScore;
                this.bestKey = bestKey;
                this.mode = 'optimize';
                self.postMessage({
                    type: 'result',
                    key: this.bestKey,
                    plaintext: plaintext,
                    score: this.bestScore
                });
            }
        } else if (performance.now() - this.lastImprovementTime > 10000) {
            this.mode = 'scan';
        }
    }

    async _searchTargetText() {
        const totalKeys = Math.pow(26, this.keyLength);
        const startKey = this.workerId * Math.floor(totalKeys / this.totalWorkers);
        const endKey = (this.workerId === this.totalWorkers - 1) ? totalKeys : startKey + Math.floor(totalKeys / this.totalWorkers);
        const BLOCK_SIZE = 100000;
        const keyBuffer = new Uint8Array(this.keyLength);
        const targetUpper = this.targetText.toUpperCase();

        for (let keyNum = startKey; keyNum < endKey; keyNum += BLOCK_SIZE) {
            if (!this.running || this.targetTextFound) break;

            const blockEnd = Math.min(keyNum + BLOCK_SIZE, endKey);
            for (let i = keyNum; i < blockEnd; i++) {
                let num = i;
                for (let j = this.keyLength - 1; j >= 0; j--) {
                    keyBuffer[j] = num % 26;
                    num = Math.floor(num / 26);
                }

                // Fast decrypt and check
                const plaintext = new Uint8Array(this.cipherCodes.length);
                for (let k = 0; k < this.cipherCodes.length; k++) {
                    plaintext[k] = this.precomputedDecrypt[this.cipherCodes[k]][keyBuffer[k % this.keyLength]];
                }
                const plainStr = String.fromCharCode(...plaintext.map(c => this.reverseCharMap[c]));
                
                if (plainStr.includes(targetUpper)) {
                    const keyStr = String.fromCharCode(...keyBuffer.map(c => this.reverseCharMap[c]));
                    const score = this.scoreText(plainStr);
                    this.targetTextFound = true;
                    this.bestScore = score;
                    this.bestKey = keyStr;
                    self.postMessage({
                        type: 'result',
                        key: this.bestKey,
                        plaintext: plainStr,
                        score: this.bestScore,
                        targetFound: true
                    });
                    return;
                }

                this.keysTested++;
            }
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
}

new K4Worker();
