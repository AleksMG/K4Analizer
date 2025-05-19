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
    'WHICH', 'WHEN', 'YOUR', 'WERE', 'CIA'
];

const uncommonPatterns = [
    'BERLIN', 'CLOCK', 'EAST', 'NORTH', 'WEST', 'SOUTH', 'NORTHEAST', 
    'NORTHWEST', 'SOUTHEAST', 'SOUTHWEST', 'SECRET', 'CODE', 'MESSAGE', 
    'KRYPTOS', 'BERLINCLOCK', 'AGENT', 'COMPASS', 'LIGHT', 'LATITUDE',
    'LONGITUDE', 'COORDINATE', 'SHADOW', 'WALL', 'UNDERGROUND'
];

class K4Worker {
    constructor() {
        this.alphabet = 'ZXWVUQNMLJIHGFEDCBASOTPYRK';
        this.charMap = new Uint8Array(256);
        this.charMap.fill(255);
        for (let i = 0; i < this.alphabet.length; i++) {
            this.charMap[this.alphabet.charCodeAt(i)] = i;
        }

        this.running = false;
        this.ciphertext = '';
        this.keyLength = 0;
        this.workerId = 0;
        this.totalWorkers = 1;
        this.keysTested = 0;
        this.startTime = 0;
        this.bestScore = 0;
        this.bestKey = '';
        this.lastReportTime = 0;
        
        // Оптимизированные параметры
        this.keysPerBlock = 25000; // Увеличенный размер блока
        this.currentBase = 0;
        this.keySpace = 0;

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
                    this.running = false;
                    break;
            }
        };
    }

    handleInit(msg) {
        this.ciphertext = msg.ciphertext;
        this.keyLength = msg.keyLength;
        this.workerId = msg.workerId || 0;
        this.totalWorkers = msg.totalWorkers || 1;
        this.keySpace = Math.pow(26, this.keyLength);
        this.currentBase = this.workerId;
    }

    handleStart() {
        if (!this.running) {
            this.running = true;
            this.startTime = performance.now();
            this.run();
        }
    }

    async run() {
        while (this.running && this.currentBase < this.keySpace) {
            const blockStart = this.currentBase;
            const blockEnd = Math.min(blockStart + this.keysPerBlock * this.totalWorkers, this.keySpace);
            
            await this.processBlock(blockStart, blockEnd);
            
            this.currentBase += this.keysPerBlock * this.totalWorkers;
            this.reportProgress();
        }
        
        self.postMessage({
            type: 'complete',
            workerId: this.workerId,
            keysTested: this.keysTested
        });
    }

    async processBlock(blockStart, blockEnd) {
        const localBest = {score: -1, key: '', plaintext: ''};
        
        for (let keyNum = blockStart + this.workerId; keyNum < blockEnd; keyNum += this.totalWorkers) {
            const key = this.generateKey(keyNum);
            const plaintext = this.decrypt(key);
            const score = this.scoreText(plaintext);
            this.keysTested++;

            if (score > localBest.score) {
                localBest.score = score;
                localBest.key = key;
                localBest.plaintext = plaintext;
            }
        }
        
        if (localBest.score > this.bestScore) {
            this.bestScore = localBest.score;
            this.bestKey = localBest.key;
            
            self.postMessage({
                type: 'result',
                workerId: this.workerId,
                key: localBest.key,
                plaintext: localBest.plaintext,
                score: localBest.score,
                words: this.extractWords(localBest.plaintext)
            });
        }
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
        const keyCodes = new Uint8Array(this.keyLength);
        for (let i = 0; i < this.keyLength; i++) {
            keyCodes[i] = this.charMap[key.charCodeAt(i)];
        }

        for (let i = 0; i < this.ciphertext.length; i++) {
            const cipherCode = this.charMap[this.ciphertext.charCodeAt(i)];
            const keyCode = keyCodes[i % this.keyLength];
            const plainPos = (cipherCode - keyCode + 26) % 26;
            plaintext += String.fromCharCode(this.alphabet.charCodeAt(plainPos));
        }
        return plaintext;
    }

    scoreText(text) {
        let score = 0;
        const upperText = text.toUpperCase();
        const freq = new Uint16Array(26);
        let totalLetters = 0;

        // Частоты символов
        for (let i = 0; i < text.length; i++) {
            const code = text.charCodeAt(i) - 65;
            if (code >= 0 && code <= 25) {
                freq[code]++;
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

        // Паттерны
        for (const pattern of [...commonPatterns, ...uncommonPatterns]) {
            let pos = -1;
            while ((pos = upperText.indexOf(pattern, pos + 1)) !== -1) {
                score += pattern.length * (uncommonPatterns.includes(pattern) ? 50 : 25);
            }
        }

        return Math.round(score);
    }

    extractWords(text) {
        const upperText = text.toUpperCase();
        const foundWords = {};
        
        for (const pattern of [...commonPatterns, ...uncommonPatterns]) {
            let pos = -1;
            while ((pos = upperText.indexOf(pattern, pos + 1)) !== -1) {
                foundWords[pattern] = (foundWords[pattern] || 0) + 1;
            }
        }
        
        return foundWords;
    }

    reportProgress() {
        const now = performance.now();
        if (now - this.lastReportTime > 1000) {
            self.postMessage({
                type: 'progress',
                workerId: this.workerId,
                keysTested: this.keysTested,
                kps: Math.round(this.keysTested / ((now - this.startTime) / 1000)),
                progress: (this.currentBase / this.keySpace) * 100
            });
            this.lastReportTime = now;
        }
    }
}

new K4Worker();
