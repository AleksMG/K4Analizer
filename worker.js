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
        this.charMap = this.createCharMap();
        this.running = false;
        this.ciphertext = '';
        this.keyLength = 0;
        this.workerId = 0;
        this.totalWorkers = 4;
        this.keysTested = 0;
        this.startTime = 0;
        this.lastReportTime = 0;
        this.bestScore = 0;
        this.bestKey = '';
        this.totalKeys = 0;
        this.keysProcessed = 0;
        this.keySpacePerWorker = 0;

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
        this.ciphertext = msg.ciphertext;
        this.keyLength = msg.keyLength;
        this.workerId = msg.workerId || 0;
        this.totalWorkers = msg.totalWorkers || 1;
        this.keysTested = 0;
        this.bestScore = 0;
        this.bestKey = this.generateKey(0);
        this.totalKeys = Math.pow(this.alphabet.length, this.keyLength);
        this.keySpacePerWorker = Math.ceil(this.totalKeys / this.totalWorkers);
        this.keysProcessed = 0;
    }

    handleStart() {
        if (!this.running) {
            this.running = true;
            this.startTime = performance.now();
            this.lastReportTime = this.startTime;
            this.run();
        }
    }

    handleStop() {
        this.running = false;
    }

    handleUpdateBestKey(msg) {
        if (msg.score > this.bestScore) {
            this.bestScore = msg.score;
            this.bestKey = msg.key;
        }
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
        const base = this.alphabet.length;
        for (let i = this.keyLength - 1; i >= 0; i--) {
            key[i] = this.alphabet[num % base];
            num = Math.floor(num / base);
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
        const freqCache = new Float32Array(26);
        let totalLetters = 0;

        for (let i = 0; i < upperText.length; i++) {
            const code = upperText.charCodeAt(i) - 65;
            if (code >= 0 && code < 26) {
                freqCache[code]++;
                totalLetters++;
            }
        }

        if (totalLetters > 0) {
            for (let i = 0; i < 26; i++) {
                const expected = ENGLISH_FREQ[this.alphabet[i]] || 0;
                const actual = (freqCache[i] / totalLetters) * 100;
                score += 100 - Math.abs(expected - actual);
            }
        }

        const allPatterns = [...commonPatterns, ...uncommonPatterns];
        for (const pattern of allPatterns) {
            let pos = -pattern.length;
            while ((pos = upperText.indexOf(pattern, pos + pattern.length)) !== -1) {
                score += pattern.length * (pattern.length > 3 ? 50 : 25);
            }
        }

        return Math.round(score);
    }

    async run() {
        const start = this.workerId * this.keySpacePerWorker;
        const end = Math.min(start + this.keySpacePerWorker, this.totalKeys);
        const BATCH_SIZE = 50000;

        for (let current = start; this.running && current < end; current += BATCH_SIZE) {
            const batchEnd = Math.min(current + BATCH_SIZE, end);
            await this.processBatch(current, batchEnd);
            this.reportProgress();
        }

        if (this.running) {
            this.reportCompletion();
            this.running = false;
        }
    }

    async processBatch(start, end) {
        for (let keyNum = start; keyNum < end; keyNum++) {
            const key = this.generateKey(keyNum);
            const plaintext = this.decrypt(key);
            const score = this.scoreText(plaintext);

            if (score > this.bestScore) {
                this.updateBest(key, score, plaintext);
            }
        }
        this.keysTested += end - start;
        this.keysProcessed = end - start;
        await new Promise(resolve => setTimeout(resolve, 0));
    }

    updateBest(key, score, plaintext) {
        this.bestScore = score;
        this.bestKey = key;
        self.postMessage({
            type: 'result',
            key: key,
            plaintext: plaintext,
            score: score
        });
    }

    reportProgress() {
        const elapsed = (performance.now() - this.startTime) / 1000;
        self.postMessage({
            type: 'progress',
            keysTested: this.keysTested,
            kps: Math.round(this.keysTested / elapsed),
            percent: ((this.keysProcessed / this.keySpacePerWorker) * 100).toFixed(2)
        });
    }

    reportCompletion() {
        self.postMessage({
            type: 'complete',
            totalTested: this.keysTested,
            bestKey: this.bestKey,
            bestScore: this.bestScore
        });
    }
}

// Экспорт для Web Workers
if (typeof self !== 'undefined') {
    new K4Worker();
}
