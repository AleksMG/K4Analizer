// worker.js
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
        this.totalKeysToTest = 0;
        this.completed = false;
        this.primaryTarget = 'BERLINCLOCK';
        this.primaryTargetFound = false;
        this.primaryResults = [];

        // Инициализация charMap
        this.charMap.fill(255);
        for (let i = 0; i < this.alphabet.length; i++) {
            this.charMap[this.alphabet.charCodeAt(i)] = i;
        }

        // Обработчик сообщений
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
                    this.totalKeysToTest = Math.pow(26, this.keyLength);
                    this.completed = false;
                    this.primaryTargetFound = false;
                    this.primaryResults = [];
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

    scoreText(text) {
        const upperText = text.toUpperCase();
        if (!this.primaryTargetFound && upperText.includes(this.primaryTarget)) {
            return 1000;
        }

        let score = 0;
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

        // Поиск паттернов
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
        const startKey = Math.floor(totalKeys * this.workerId / this.totalWorkers);
        const endKey = Math.floor(totalKeys * (this.workerId + 1) / this.totalWorkers);
        
        while (this.running && this.keysTested < (endKey - startKey)) {
            await this.processBlock(startKey, endKey);
            this.checkProgress();
        }
        
        this.running = false;
        self.postMessage({
            type: 'completed',
            keysTested: this.keysTested,
            bestScore: this.bestScore,
            bestKey: this.bestKey,
            bestPlaintext: this.bestPlaintext
        });
    }

    async processBlock(start, end, blockSize = 1000) {
        for (let keyNum = start; keyNum < end && this.running; keyNum += blockSize) {
            const blockEnd = Math.min(keyNum + blockSize, end);
            
            for (let i = keyNum; i < blockEnd; i++) {
                if (!this.running) break;
                
                const key = this.generateKey(i);
                if (this.testedKeys.has(key)) continue;
                this.testedKeys.add(key);
                
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
                
                if (i % 100 === 0) await new Promise(resolve => setTimeout(resolve, 0));
            }
        }
    }

    checkProgress() {
        const now = performance.now();
        if (now - this.lastReportTime > 1000) {
            const elapsed = (now - this.startTime) / 1000;
            const kps = elapsed > 0 ? Math.round(this.keysTested / elapsed) : 0;
            const completion = Math.min(100, (this.keysTested / (this.totalKeysToTest / this.totalWorkers)) * 100);
            
            self.postMessage({
                type: 'progress',
                keysTested: this.keysTested,
                totalKeys: this.totalKeysToTest,
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

// Обязательная инициализация воркера
new K4Worker();
