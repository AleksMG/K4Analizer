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
    'ALPHABET', 'LETTER', 'SYMBOL', 'SLOWLY', 'DESPARATELY', 'WEAKLY', 'SCRATCHES', 'SHADOWS',
    'LAYER', 'QUESTION', 'ANSWER', 'SOLUTION', 'HIDDEN', 'COVER', 'REVEAL', 'TRUTH', 'MISSION'
];

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
        this.bestScore = 0;
        this.bestKey = '';
        this.stuckCount = 0;
        this.mode = 'scan';
        this.lastImprovementTime = 0;
        this.maxKeys = 0;

        this.charMap.fill(255);
        for (let i = 0; i < this.alphabet.length; i++) {
            this.charMap[this.alphabet.charCodeAt(i)] = i;
        }

        self.onmessage = (e) => {
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
                    this.maxKeys = Math.pow(26, this.keyLength);
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

    scoreText(text) {
        const upperText = text.toUpperCase();
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
                const expected = ENGLISH_FREQ[this.alphabet[i]] || 0;
                const actual = (freq[i] / totalLetters) * 100;
                score += 100 - Math.abs(expected - actual);
            }
        }

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
        const totalKeys = Math.pow(26, this.keyLength);
        const startKey = this.workerId * Math.floor(totalKeys / this.totalWorkers);
        const endKey = (this.workerId === this.totalWorkers - 1) ? totalKeys : startKey + Math.floor(totalKeys / this.totalWorkers);

        while (this.running && this.keysTested < (endKey - startKey)) {
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
            }

            this.checkProgress();
        }

        if (this.keysTested >= (endKey - startKey)) {
            self.postMessage({
                type: 'completed',
                message: 'All keys have been tested'
            });
            this.running = false;
        }
    }

    async fullScan(startKey, endKey) {
        const BLOCK_SIZE = 10000;
        for (let keyNum = startKey; keyNum < endKey && this.running && this.keysTested < (endKey - startKey); keyNum += BLOCK_SIZE) {
            const blockEnd = Math.min(keyNum + BLOCK_SIZE, endKey);
            
            for (let i = keyNum; i < blockEnd; i++) {
                const key = this.generateKey(i);
                const plaintext = this.decrypt(key);
                const score = this.scoreText(plaintext);
                this.keysTested++;

                if (score > this.bestScore) {
                    this.bestScore = score;
                    this.bestKey = key;
                    this.lastImprovementTime = performance.now();
                    self.postMessage({
                        type: 'result',
                        key: this.bestKey,
                        plaintext: plaintext,
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
            for (const delta of [-1, 1, -2, 2, -3, 3, -4, 4]) {
                const newCharCode = (this.charMap[originalChar.charCodeAt(0)] + delta + 26) % 26;
                const newChar = this.alphabet[newCharCode];
                keyChars[pos] = newChar;
                const newKey = keyChars.join('');
                const plaintext = this.decrypt(newKey);
                const score = this.scoreText(plaintext);
                this.keysTested++;

                if (score > this.bestScore) {
                    this.bestScore = score;
                    this.bestKey = newKey;
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
        const totalKeys = Math.pow(26, this.keyLength);
        const randomKeyNum = Math.floor(Math.random() * totalKeys);
        const randomKey = this.generateKey(randomKeyNum);
        const plaintext = this.decrypt(randomKey);
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
        if (now - this.lastReportTime > 1000) {
            const elapsed = (now - this.startTime) / 1000;
            const kps = elapsed > 0 ? Math.round(this.keysTested / elapsed) : 0;
            
            self.postMessage({
                type: 'progress',
                keysTested: this.keysTested,
                kps: kps,
                mode: this.mode
            });
            
            this.lastReportTime = now;
        }
    }
}

new K4Worker();
