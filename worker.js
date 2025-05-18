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
        this.bestKey = '';
        this.knownPlaintext = ''; // Для интеграции с вашим полем ввода
        this.foundPriorityMatch = false; // Флаг найденного приоритетного совпадения

        // Инициализация charMap
        this.charMap.fill(255);
        for (let i = 0; i < this.alphabet.length; i++) {
            this.charMap[this.alphabet.charCodeAt(i)] = i;
        }

        // Оригинальный обработчик сообщений с добавлением knownPlaintext
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
                        this.foundPriorityMatch = false;
                        this.runPrioritizedSearch();
                    }
                    break;
                case 'stop':
                    this.running = false;
                    break;
                case 'setPlaintext':
                    this.knownPlaintext = msg.text.toUpperCase();
                    break;
                case 'updateAlphabet':
                    this.alphabet = msg.alphabet;
                    this.charMap.fill(255);
                    for (let i = 0; i < this.alphabet.length; i++) {
                        this.charMap[this.alphabet.charCodeAt(i)] = i;
                    }
                    break;
            }
        };
    }

    // Полностью сохраненные оригинальные методы
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

    // Новый метод для приоритетного поиска
    async runPrioritizedSearch() {
        // 1. Сначала ищем точное совпадение с knownPlaintext
        if (this.knownPlaintext) {
            await this.searchExactMatch();
            if (this.foundPriorityMatch) return;
        }

        // 2. Затем продолжаем обычный bruteforce
        await this.runStandardBruteforce();
    }

    async searchExactMatch() {
        const target = this.knownPlaintext;
        const targetLength = target.length;
        const cipherLength = this.ciphertext.length;
        const maxAttempts = 1000000;

        for (let i = 0; i < maxAttempts && this.running && !this.foundPriorityMatch; i++) {
            const key = this.generateKey(Math.floor(Math.random() * Math.pow(26, this.keyLength)));
            const decrypted = this.decrypt(key);

            if (decrypted.includes(target)) {
                const score = 1000 + this.scoreText(decrypted); // Максимальный приоритет
                this.updateBestKey(key, score, decrypted);
                this.foundPriorityMatch = true;
                break;
            }

            if (i % 1000 === 0) await new Promise(r => setTimeout(r, 0));
        }
    }

    async runStandardBruteforce() {
        const totalKeys = Math.pow(26, this.keyLength);
        const keysPerWorker = Math.floor(totalKeys / this.totalWorkers);
        const startKey = this.workerId * keysPerWorker;
        const endKey = (this.workerId === this.totalWorkers - 1) ? totalKeys : startKey + keysPerWorker;

        for (let keyNum = startKey; keyNum < endKey && this.running && !this.foundPriorityMatch; keyNum++) {
            const key = this.generateKey(keyNum);
            const plaintext = this.decrypt(key);
            const score = this.scoreText(plaintext);

            if (score > this.bestScore) {
                this.updateBestKey(key, score, plaintext);
            }

            // Отчет о прогрессе
            if (keyNum % 1000 === 0) {
                await this.reportProgress();
            }
        }
    }

    async reportProgress() {
        const now = performance.now();
        if (now - this.lastReportTime > 1000) {
            const elapsed = (now - this.startTime) / 1000;
            const kps = Math.round(this.keysTested / elapsed);
            self.postMessage({
                type: 'progress',
                keysTested: this.keysTested,
                kps: kps,
                bestScore: this.bestScore
            });
            this.lastReportTime = now;
        }
        await new Promise(r => setTimeout(r, 0));
    }

    updateBestKey(key, score, plaintext) {
        this.keysTested++;
        if (score > this.bestScore) {
            this.bestScore = score;
            this.bestKey = key;
            self.postMessage({
                type: 'result',
                key: key,
                plaintext: plaintext,
                score: score
            });
        }
    }
}

new K4Worker();
