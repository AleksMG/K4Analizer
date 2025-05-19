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
    'PERSON', 'MAN', 'ENEMY', 'ALLY'
];

const uncommonPatterns = [
    'KRYPTOS', 'BERLINCLOCK', 'EAST', 'NORTH', 'WEST',
    'SOUTH', 'NORTHEAST', 'NORTHWEST', 'SOUTHEAST', 'SOUTHWEST', 'COMPASS', 'LIGHT',
    'LATITUDE', 'LONGITUDE', 'COORDINATE', 'SHADOW', 'WALL', 'UNDERGROUND', 'PALIMPSEST',
    'ABSCISSA', 'CLOCKWISE', 'DIAGONAL', 'VERTICAL',
    'HORIZONTAL', 'OBELISK', 'PYRAMID', 'SCULPTURE', 'CIPHER', 'ENCRYPT', 'DECRYPT',
    'ALPHABET', 'LETTER', 'SYMBOL', 'SLOWLY', 'DESPARATELY', 'WEAKLY', 'SCRATCHES',
    'LAYER', 'QUESTION', 'ANSWER', 'SOLUTION', 'HIDDEN', 'COVER', 'REVEAL', 'TRUTH', 'MISSION'
];

class K4Worker {
    constructor() {
        this.alphabet = 'ZXWVUQNMLJIHGFEDCBASOTPYRK';
        this.charMap = {};
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
        this.completed = false;
        this.primaryTarget = 'BERLINCLOCK';
        this.primaryTargetFound = false;
        this.primaryResults = [];
        this.startKey = 0;
        this.endKey = 0;

        // Initialize charMap
        for (let i = 0; i < this.alphabet.length; i++) {
            this.charMap[this.alphabet[i]] = i;
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
                    this.completed = false;
                    this.primaryTargetFound = false;
                    this.primaryResults = [];
                    
                    // Fixed key distribution
                    const totalKeys = Math.pow(26, this.keyLength);
                    const keysPerWorker = Math.ceil(totalKeys / this.totalWorkers);
                    this.startKey = this.workerId * keysPerWorker;
                    this.endKey = Math.min(this.startKey + keysPerWorker, totalKeys);
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
        const keyLen = key.length;
        const cipherLen = this.ciphertext.length;
        
        for (let i = 0; i < cipherLen; i++) {
            const plainPos = (this.charMap[this.ciphertext[i]] - this.charMap[key[i % keyLen]] + 26) % 26;
            plaintext += this.alphabet[plainPos];
        }
        return plaintext;
    }

    scoreText(text) {
        const upperText = text.toUpperCase();
        if (!this.primaryTargetFound && upperText.includes(this.primaryTarget)) {
            return 1000;
        }

        let score = 0;
        const freq = new Array(26).fill(0);
        let totalLetters = 0;

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
                const expected = ENGLISH_FREQ[this.alphabet[i]] || 0;
                const actual = (freq[i] / totalLetters) * 100;
                score += 100 - Math.abs(expected - actual);
            }
        }

        // Common patterns
        for (const pattern of commonPatterns) {
            let pos = -1;
            while ((pos = upperText.indexOf(pattern, pos + 1)) !== -1) {
                if (pos === -1) break;
                score += pattern.length * 25;
            }
        }

        // Special patterns
        for (const pattern of uncommonPatterns) {
            let pos = -1;
            while ((pos = upperText.indexOf(pattern, pos + 1)) !== -1) {
                if (pos === -1) break;
                score += pattern.length * 50;
            }
        }

        return Math.round(score);
    }

    async run() {
        while (this.running && !this.completed) {
            switch (this.mode) {
                case 'scan':
                    await this.fullScan();
                    break;
                case 'optimize':
                    await this.optimizeKey();
                    break;
                case 'explore':
                    await this.exploreRandom();
                    break;
                case 'primarySearch':
                    await this.findPrimaryTargets();
                    this.mode = 'scan';
                    break;
            }
            
            if (this.keysTested >= (this.endKey - this.startKey)) {
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

    async fullScan() {
        const BLOCK_SIZE = 100000;
        let currentKey = this.startKey + this.keysTested;
        
        while (currentKey < this.endKey && this.running) {
            const blockEnd = Math.min(currentKey + BLOCK_SIZE, this.endKey);
            
            for (let i = currentKey; i < blockEnd; i++) {
                const key = this.generateKey(i);
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

                if (!this.primaryTargetFound && plaintext.includes(this.primaryTarget)) {
                    this.primaryResults.push({ key, plaintext, score });
                    self.postMessage({
                        type: 'primaryResult',
                        key: key,
                        plaintext: plaintext,
                        score: score
                    });
                }
            }
            
            currentKey = blockEnd;
            
            if (performance.now() - this.lastImprovementTime > 10000) {
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
            const originalPos = this.charMap[originalChar];
            
            for (const delta of [-1, 1, -2, 2, -3, 3]) {
                const newChar = this.alphabet[(originalPos + delta + 26) % 26];
                keyChars[pos] = newChar;
                const newKey = keyChars.join('');
                
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
            const randomKeyNum = Math.floor(Math.random() * (this.endKey - this.startKey)) + this.startKey;
            key = this.generateKey(randomKeyNum);
            attempts++;
        } while (attempts < maxAttempts && this.running);
        
        if (attempts >= maxAttempts || !this.running) {
            this.mode = 'scan';
            return;
        }
        
        const plaintext = this.decrypt(key);
        const score = this.scoreText(plaintext);
        this.keysTested++;

        if (score > this.bestScore * 0.8) {
            this.mode = 'optimize';
        } else if (performance.now() - this.lastImprovementTime > 10000) {
            this.mode = 'scan';
        }
    }

    checkProgress() {
        const now = performance.now();
        if (now - this.lastReportTime > 2000) {
            const elapsed = (now - this.startTime) / 1000;
            const kps = elapsed > 0 ? Math.round(this.keysTested / elapsed) : 0;
            const completion = Math.min(100, (this.keysTested / (this.endKey - this.startKey)) * 100);
            
            self.postMessage({
                type: 'progress',
                workerId: this.workerId,
                keysTested: this.keysTested,
                totalKeys: this.endKey - this.startKey,
                kps: kps,
                completion: completion.toFixed(2),
                mode: this.mode,
                bestScore: this.bestScore,
                bestKey: this.bestKey,
                bestPlaintext: this.bestPlaintext
            });
            
            this.lastReportTime = now;
        }
    }
}

new K4Worker();
