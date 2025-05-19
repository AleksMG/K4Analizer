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
    'BERLIN', 'CLOCK', 'EAST', 'NORTH', 'WEST',
    'SOUTH', 'NORTHEAST', 'NORTHWEST', 'SOUTHEAST', 'SOUTHWEST', 'SECRET', 'CODE',
    'MESSAGE', 'KRYPTOS', 'BERLINCLOCK', 'AGENT', 'COMPASS', 'LIGHT', 'LATITUDE',
    'LONGITUDE', 'COORDINATE', 'SHADOW', 'WALL', 'UNDERGROUND'
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
        this.optimizePositions = [];

        // Добавленные поля для поиска BERLINCLOCK
        this.primaryTarget = "BERLINCLOCK";
        this.isPrimaryWorker = false;
        this.primaryResults = [];
        this.primarySearchDone = false;
        this.targetCodes = Array.from(this.primaryTarget).map(c => this.charMap[c.charCodeAt(0)]);

        this.charMap.fill(255);
        for (let i = 0; i < this.alphabet.length; i++) {
            this.charMap[this.alphabet.charCodeAt(i)] = i;
        }

        self.onmessage = (e) => this.handleMessage(e.data);
    }

    handleMessage(msg) {
        switch (msg.type) {
            case 'init':
                this.ciphertext = msg.ciphertext;
                this.keyLength = msg.keyLength;
                this.workerId = msg.workerId || 0;
                this.totalWorkers = msg.totalWorkers || 1;
                this.isPrimaryWorker = msg.isPrimaryWorker || false;
                this.resetState();
                break;
            case 'start':
                if (!this.running) {
                    this.running = true;
                    this.startTime = performance.now();
                    this.run();
                }
                break;
            case 'stop':
                this.running = false;
                break;
        }
    }

    resetState() {
        this.keysTested = 0;
        this.bestScore = 0;
        this.bestKey = this.generateKey(0);
        this.primaryResults = [];
        this.primarySearchDone = false;
    }

    async run() {
        const totalKeys = Math.pow(26, this.keyLength);
        const startKey = this.workerId * Math.floor(totalKeys / this.totalWorkers);
        const endKey = (this.workerId === this.totalWorkers - 1) ? totalKeys : startKey + Math.floor(totalKeys / this.totalWorkers);

        if (this.isPrimaryWorker) {
            await this.findPrimaryTargets(startKey, endKey);
            this.primarySearchDone = true;
        }

        while (this.running) {
            switch (this.mode) {
                case 'scan': await this.fullScan(startKey, endKey); break;
                case 'optimize': await this.optimizeKey(); break;
                case 'explore': await this.exploreRandom(); break;
            }
            this.checkProgress();
        }
    }

    async findPrimaryTargets(startKey, endKey) {
        const targetLen = this.primaryTarget.length;
        const cipherLen = this.ciphertext.length;
        const BLOCK_SIZE = 100000;

        for (let keyNum = startKey; keyNum < endKey && this.running; keyNum += BLOCK_SIZE) {
            const blockEnd = Math.min(keyNum + BLOCK_SIZE, endKey);
            
            for (let i = keyNum; i < blockEnd; i++) {
                const key = this.generateKey(i);
                const keyCodes = Array.from(key).map(c => this.charMap[c.charCodeAt(0)]);

                for (let pos = 0; pos <= cipherLen - targetLen; pos++) {
                    let match = true;
                    for (let j = 0; j < targetLen; j++) {
                        const cipherCode = this.charMap[this.ciphertext.charCodeAt(pos + j)];
                        const keyCode = keyCodes[(pos + j) % this.keyLength];
                        const plainPos = (cipherCode - keyCode + 26) % 26;
                        
                        if (plainPos !== this.targetCodes[j]) {
                            match = false;
                            break;
                        }
                    }

                    if (match) {
                        const plaintext = this.decrypt(key);
                        this.primaryResults.push({key, plaintext});
                        self.postMessage({
                            type: 'primaryResult',
                            key: key,
                            plaintext: plaintext,
                            score: 1000,
                            workerId: this.workerId
                        });
                        break;
                    }
                }
            }
            this.keysTested += (blockEnd - keyNum);
            await new Promise(resolve => setTimeout(resolve, 0));
        }
    }

    // Ваши оригинальные методы (без изменений)
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
        let score = 0;
        const upperText = text.toUpperCase();
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

    async fullScan(startKey, endKey) {
        const BLOCK_SIZE = 10000;
        for (let keyNum = startKey; keyNum < endKey; keyNum += BLOCK_SIZE) {
            if (!this.running) break;
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

        for (let pos = 0; pos < this.keyLength; pos++) {
            if (!this.running) break;

            const originalChar = keyChars[pos];
            for (const delta of [-1, 1, -2, 2, -3, 3]) {
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
        const randomKey = this.generateKey(Math.floor(Math.random() * Math.pow(26, this.keyLength)));
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
            const kps = Math.round(this.keysTested / ((now - this.startTime) / 1000));
            self.postMessage({
                type: 'progress',
                keysTested: this.keysTested,
                kps: kps,
                mode: this.mode,
                isPrimaryWorker: this.isPrimaryWorker
            });
            this.lastReportTime = now;
        }
    }
}

new K4Worker();
