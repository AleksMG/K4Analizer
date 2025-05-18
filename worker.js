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

        // Инициализация charMap
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
                    break;
                case 'start':
                    if (!this.running) {
                        this.running = true;
                        this.startTime = performance.now();
                        this.bruteForce();
                    }
                    break;
                case 'stop':
                    this.running = false;
                    break;
            }
        };
    }

    *keyGenerator(start, end, length) {
        const alphabet = this.alphabet;
        let current = BigInt(start);
        const endVal = BigInt(end);
        
        while (current < endVal) {
            let key = '';
            let num = current;
            for (let i = 0; i < length; i++) {
                key = alphabet[Number(num % 26n)] + key;
                num = num / 26n;
            }
            yield key;
            current++;
        }
    }

    bruteForce() {
        const totalKeys = BigInt(Math.pow(26, Math.min(this.keyLength, 10))) * (this.keyLength > 10 ? BigInt(Math.pow(26, this.keyLength - 10)) : 1n);
        const keysPerWorker = totalKeys / BigInt(this.totalWorkers);
        const startKey = BigInt(this.workerId) * keysPerWorker;
        const endKey = this.workerId === this.totalWorkers - 1 ? totalKeys : startKey + keysPerWorker;

        const cipherCodes = new Uint8Array(this.ciphertext.length);
        for (let i = 0; i < this.ciphertext.length; i++) {
            cipherCodes[i] = this.charMap[this.ciphertext.charCodeAt(i)];
        }

        const plaintextBuffer = new Uint8Array(this.ciphertext.length);
        const keys = this.keyGenerator(startKey, endKey, this.keyLength);
        let bestKey = '';
        let bestText = '';

        for (const key of keys) {
            if (!this.running) break;

            // Дешифровка
            for (let i = 0; i < cipherCodes.length; i++) {
                plaintextBuffer[i] = (cipherCodes[i] - this.charMap[key.charCodeAt(i % this.keyLength)] + 26) % 26;
            }

            // Оценка
            const score = this.scoreText(plaintextBuffer);
            this.keysTested++;

            if (score > this.bestScore) {
                this.bestScore = score;
                bestKey = key;
                bestText = Array.from(plaintextBuffer).map(i => this.alphabet[i]).join('');
                self.postMessage({
                    type: 'result',
                    key: bestKey,
                    plaintext: bestText,
                    score: this.bestScore
                });
            }

            // Отчет о прогрессе
            if (this.keysTested % 50000 === 0) {
                const now = performance.now();
                const elapsed = (now - this.startTime) / 1000;
                const kps = elapsed > 0 ? Math.round(this.keysTested / elapsed) : 0;
                self.postMessage({
                    type: 'progress',
                    keysTested: this.keysTested,
                    kps: kps
                });
            }
        }

        self.postMessage({ type: 'complete' });
    }

    scoreText(plainBuffer) {
        let score = 0;
        const textLen = plainBuffer.length;
        const freq = new Uint16Array(26);
        let totalLetters = 0;

        // Частотный анализ
        for (let i = 0; i < textLen; i++) {
            freq[plainBuffer[i]]++;
            totalLetters++;
        }

        if (totalLetters > 0) {
            const freqNormalizer = 100 / totalLetters;
            for (let i = 0; i < 26; i++) {
                const expected = ENGLISH_FREQ[this.alphabet[i]] || 0;
                const actual = freq[i] * freqNormalizer;
                score += 100 - Math.abs(expected - actual);
            }
        }

        // Проверка паттернов
        const plainText = Array.from(plainBuffer).map(i => this.alphabet[i]).join('').toUpperCase();
        
        // Общие паттерны
        for (const pattern of commonPatterns) {
            let pos = -1;
            while ((pos = plainText.indexOf(pattern, pos + 1)) !== -1) {
                score += pattern.length * 25;
            }
        }

        // Специальные паттерны
        for (const pattern of uncommonPatterns) {
            let pos = -1;
            while ((pos = plainText.indexOf(pattern, pos + 1)) !== -1) {
                score += pattern.length * 50;
            }
        }

        return Math.round(score);
    }
}

new K4Worker();
