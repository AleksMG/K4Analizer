const ENGLISH_FREQ = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
    'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
    'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
    'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
    'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974,
    'Z': 0.074
};

const commonPatterns = [
    'THE', 'AND', 'OF', 'TO', 'ING', 'ION', 'ENT'
];

class K4Worker {
    constructor() {
        this.alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
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

    generateKey(num) {
        const key = new Array(this.keyLength);
        for (let i = this.keyLength - 1; i >= 0; i--) {
            key[i] = this.alphabet[num % 26];
            num = Math.floor(num / 26);
        }
        return key.join('');
    }

    bruteForce() {
        const totalKeys = Math.pow(26, this.keyLength);
        const keysPerWorker = Math.floor(totalKeys / this.totalWorkers);
        const startKey = this.workerId * keysPerWorker;
        const endKey = (this.workerId === this.totalWorkers - 1) 
            ? totalKeys 
            : startKey + keysPerWorker;

        const cipherLen = this.ciphertext.length;
        const cipherCodes = new Uint8Array(cipherLen);
        for (let i = 0; i < cipherLen; i++) {
            cipherCodes[i] = this.charMap[this.ciphertext.charCodeAt(i)];
        }

        let bestKey = '';
        let bestText = '';

        // Блочная обработка для плавной выдачи результатов
        const BLOCK_SIZE = 50000;
        let currentBlockStart = startKey;

        while (currentBlockStart < endKey && this.running) {
            const blockEnd = Math.min(currentBlockStart + BLOCK_SIZE, endKey);
            
            for (let keyNum = currentBlockStart; keyNum < blockEnd; keyNum++) {
                const key = this.generateKey(keyNum);
                let plaintext = '';
                
                // Дешифровка
                for (let i = 0; i < cipherLen; i++) {
                    const plainPos = (cipherCodes[i] - this.charMap[key.charCodeAt(i % this.keyLength)] + 26) % 26;
                    plaintext += this.alphabet[plainPos];
                }

                // Оценка
                const score = this.scoreText(plaintext);
                this.keysTested++;

                if (score > this.bestScore) {
                    this.bestScore = score;
                    bestKey = key;
                    bestText = plaintext;
                    self.postMessage({
                        type: 'result',
                        key: bestKey,
                        plaintext: bestText,
                        score: this.bestScore
                    });
                }
            }

            // Отчет о прогрессе
            const now = performance.now();
            if (now - this.lastReportTime > 5000) {
                const kps = Math.round(this.keysTested / ((now - this.startTime) / 1000));
                self.postMessage({
                    type: 'progress',
                    keysTested: this.keysTested,
                    kps: kps
                });
                this.lastReportTime = now;
            }

            currentBlockStart = blockEnd;
        }

        self.postMessage({ type: 'complete' });
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

        // Проверка паттернов
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
