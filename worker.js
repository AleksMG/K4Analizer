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
        this.alphabet = 'ZXWVUQNMLJIHGFEDCBASOTPYRK'; // Ваш алфавит
        this.charMap = new Uint8Array(256);
        this.running = false;
        this.ciphertext = '';
        this.keyLength = 0;
        this.workerId = 0;
        this.totalWorkers = 1;
        this.keysTested = 0;
        this.startTime = 0;
        this.currentKey = [];

        // Инициализация charMap
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
                this.currentKey = new Array(this.keyLength).fill(0);
                break;
            case 'start':
                this.running = true;
                this.startTime = performance.now();
                this.bruteForceAdvanced();
                break;
            case 'stop':
                this.running = false;
                break;
        }
    }

    bruteForceAdvanced() {
        const cipherCodes = new Uint8Array(this.ciphertext.length);
        for (let i = 0; i < this.ciphertext.length; i++) {
            cipherCodes[i] = this.charMap[this.ciphertext.charCodeAt(i)];
        }

        const totalSymbols = this.alphabet.length;
        const symbolsPerWorker = Math.ceil(totalSymbols / this.totalWorkers);
        const startSymbol = this.workerId * symbolsPerWorker;
        const endSymbol = Math.min(startSymbol + symbolsPerWorker, totalSymbols);

        let bestScore = 0;
        let bestKey = '';
        let bestText = '';

        // Каждый воркер начинает с своего символа
        this.currentKey[0] = startSymbol;

        while (this.running) {
            const key = this.currentKey.map(i => this.alphabet[i]).join('');
            
            // Дешифровка Виженера
            let plaintext = '';
            for (let i = 0; i < cipherCodes.length; i++) {
                const plainPos = (cipherCodes[i] - this.currentKey[i % this.keyLength] + 26) % 26;
                plaintext += this.alphabet[plainPos];
            }

            // Ваша оригинальная оценка
            const score = this.scoreText(plaintext);
            this.keysTested++;

            if (score > bestScore) {
                bestScore = score;
                bestKey = key;
                bestText = plaintext;
                self.postMessage({
                    type: 'result',
                    key: bestKey,
                    plaintext: bestText,
                    score: bestScore
                });
            }

            // Переход к следующему ключу
            if (!this.incrementKey()) break;

            // Отчет о прогрессе
            if (this.keysTested % 100000 === 0) {
                const now = performance.now();
                const kps = Math.round(this.keysTested / ((now - this.startTime) / 1000));
                self.postMessage({
                    type: 'progress',
                    keysTested: this.keysTested,
                    kps: kps
                });
            }
        }

        self.postMessage({ type: 'complete' });
    }

    incrementKey() {
        for (let i = this.keyLength - 1; i >= 0; i--) {
            this.currentKey[i]++;
            if (this.currentKey[i] < this.alphabet.length) return true;
            this.currentKey[i] = 0;
            if (i === 0) return false; // Все ключи перебраны
        }
        return true;
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

        // Проверка паттернов (ваши оригинальные веса)
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
}

new K4Worker();
