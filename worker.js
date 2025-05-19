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
        // Оптимизированная версия charMap - используем объект вместо Uint8Array
        this.charMap = this.createCharMap();
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

    createCharMap() {
        const map = {};
        for (let i = 0; i < this.alphabet.length; i++) {
            map[this.alphabet[i]] = i;
        }
        return map;
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
            const cipherChar = this.ciphertext[i];
            const keyChar = key[i % this.keyLength];
            const plainPos = (this.charMap[cipherChar] - this.charMap[keyChar] + 26) % 26;
            plaintext += this.alphabet[plainPos];
        }
        return plaintext;
    }

    scoreText(text) {
        let score = 0;
        const upperText = text.toUpperCase();
        const freq = new Uint16Array(26);
        let totalLetters = 0;

        // Частотный анализ
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

        // Поиск общих паттернов
        for (const pattern of commonPatterns) {
            let pos = -1;
            while ((pos = upperText.indexOf(pattern, pos + 1)) !== -1) {
                score += pattern.length * 25;
            }
        }

        // Поиск специальных паттернов
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

        while (this.running) {
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
            await new Promise(resolve => setTimeout(resolve, 0));
        }
    }

    async fullScan(startKey, endKey) {
        const BLOCK_SIZE = 20000;
        let localBestScore = 0;
        let localBestKey = '';

        for (let keyNum = startKey; keyNum < endKey; keyNum += BLOCK_SIZE) {
            if (!this.running) break;

            const blockEnd = Math.min(keyNum + BLOCK_SIZE, endKey);
            for (let i = keyNum; i < blockEnd; i++) {
                const key = this.generateKey(i);
                const plaintext = this.decrypt(key);
                const score = this.scoreText(plaintext);
                this.keysTested++;

                if (score > localBestScore) {
                    localBestScore = score;
                    localBestKey = key;

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
            }

            if (performance.now() - this.lastImprovementTime > 5000) {
                this.mode = 'optimize';
                break;
            }

            await new Promise(resolve => setTimeout(resolve, 0));
        }
    }

    async optimizeKey() {
        const keyChars = this.bestKey.split('');
        let improved = false;
        const optimizationRounds = 5;

        for (let round = 0; round < optimizationRounds; round++) {
            if (!this.running) break;

            const positions = Array.from({length: this.keyLength}, (_, i) => i);
            this.shuffleArray(positions);

            for (const pos of positions) {
                if (!this.running) break;

                const originalChar = keyChars[pos];
                const deltas = [-1, 1, -2, 2, -3, 3, -4, 4];
                this.shuffleArray(deltas);

                for (const delta of deltas) {
                    const newCharCode = (this.charMap[originalChar] + delta + 26) % 26;
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

            if (!improved && round === 0) {
                this.stuckCount++;
                if (this.stuckCount > 5) {
                    this.mode = 'explore';
                    this.stuckCount = 0;
                    break;
                }
            }
        }

        if (improved) {
            this.stuckCount = 0;
        } else {
            this.mode = 'scan';
        }
    }

    async exploreRandom() {
        const EXPLORE_BATCH_SIZE = 500;
        let bestInBatchScore = 0;
        let bestInBatchKey = '';

        for (let i = 0; i < EXPLORE_BATCH_SIZE; i++) {
            if (!this.running) break;

            const randomKey = this.generateKey(Math.floor(Math.random() * Math.pow(26, this.keyLength)));
            const plaintext = this.decrypt(randomKey);
            const score = this.scoreText(plaintext);
            this.keysTested++;

            if (score > bestInBatchScore) {
                bestInBatchScore = score;
                bestInBatchKey = randomKey;
            }

            if (score > this.bestScore * 0.9) {
                this.bestScore = score;
                this.bestKey = randomKey;
                this.lastImprovementTime = performance.now();
                self.postMessage({
                    type: 'result',
                    key: this.bestKey,
                    plaintext: plaintext,
                    score: this.bestScore
                });
                this.mode = 'optimize';
                return;
            }
        }

        if (bestInBatchScore > this.bestScore * 0.8) {
            this.bestScore = bestInBatchScore;
            this.bestKey = bestInBatchKey;
            this.mode = 'optimize';
        } else {
            this.mode = 'scan';
        }
    }

    shuffleArray(array) {
        for (let i = array.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [array[i], array[j]] = [array[j], array[i]];
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
                mode: this.mode
            });
            this.lastReportTime = now;
        }
    }
}

new K4Worker();
