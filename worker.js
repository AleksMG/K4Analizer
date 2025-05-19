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
        this.alphabet = 'ZXWVUQNMLJIHGFEDCBASOTPYRK'; // Ваш оригинальный алфавит
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
        this.stuckCount = 0;
        this.mode = 'turbo'; // Новый режим
        this.lastImprovementTime = 0;
        this.forceOutputInterval = 250; // Принудительный вывод каждые 250мс
        this.knownPlaintext = '';

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
                    this.knownPlaintext = (msg.knownPlaintext || '').toUpperCase();
                    this.reset();
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
            }
        };
    }

    reset() {
        this.keysTested = 0;
        this.bestScore = -Infinity;
        this.bestKey = this.generateKey(0);
        this.startTime = 0;
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

    turboScore(text) {
        const upperText = text.toUpperCase();
        
        // 1. Молниеносная проверка известного текста
        if (this.knownPlaintext && upperText.includes(this.knownPlaintext)) {
            return 10000;
        }

        // 2. Быстрая проверка триграмм
        let score = 0;
        for (const pattern of uncommonPatterns) {
            if (upperText.includes(pattern)) {
                score += pattern.length * 100;
                if (score > 300) return score; // Ранний выход
            }
        }

        // 3. Проверка частых слов
        for (const pattern of commonPatterns) {
            if (upperText.includes(pattern)) {
                score += pattern.length * 50;
            }
        }

        return score > 0 ? score : this.fullScore(text); // Полный анализ только если нет совпадений
    }

    fullScore(text) {
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

        return Math.round(score);
    }

    async run() {
        const totalKeys = Math.pow(26, this.keyLength);
        const keysPerWorker = Math.floor(totalKeys / this.totalWorkers);
        const startKey = this.workerId * keysPerWorker;
        const endKey = (this.workerId === this.totalWorkers - 1) ? totalKeys : startKey + keysPerWorker;

        while (this.running) {
            await this.turboScan(startKey, endKey);
            this.checkProgress();
        }
    }

    async turboScan(startKey, endKey) {
        const BLOCK_SIZE = 1000000; // 1M ключей за итерацию
        for (let keyNum = startKey; keyNum < endKey && this.running; keyNum += BLOCK_SIZE) {
            const blockEnd = Math.min(keyNum + BLOCK_SIZE, endKey);
            
            for (let i = keyNum; i < blockEnd; i++) {
                const key = this.generateKey(i);
                const plaintext = this.decrypt(key);
                const score = this.turboScore(plaintext);
                this.keysTested++;

                if (score >= 200 || performance.now() - this.lastReportTime > this.forceOutputInterval) {
                    this.reportResult(key, plaintext, score);
                }
            }
        }
    }

    reportResult(key, plaintext, score) {
        if (score > this.bestScore) {
            this.bestScore = score;
            this.bestKey = key;
            this.lastImprovementTime = performance.now();
        }

        self.postMessage({
            type: 'result',
            key: key,
            plaintext: plaintext,
            score: score,
            isBest: score === this.bestScore,
            keysTested: this.keysTested
        });
    }

    checkProgress() {
        const now = performance.now();
        if (now - this.lastReportTime >= 1000) {
            const elapsed = (now - this.startTime) / 1000;
            const kps = Math.round(this.keysTested / elapsed);
            
            self.postMessage({
                type: 'progress',
                keysTested: this.keysTested,
                kps: kps,
                bestScore: this.bestScore,
                elapsed: elapsed.toFixed(1)
            });
            
            this.lastReportTime = now;
        }
    }
}

new K4Worker();
