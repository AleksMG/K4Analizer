// █████████████████████████████████████████████████████████████████████████████████
// █ ВАШ ПОЛНЫЙ ОРИГИНАЛЬНЫЙ КОД (без изменений)
// █████████████████████████████████████████████████████████████████████████████████

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
        // █ ВАШ ОРИГИНАЛЬНЫЙ КОНСТРУКТОР (без изменений)
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

        // █ ДОБАВЛЕНО (3 строки)
        this.targetPhrase = 'BERLINCLOCK'; // Искомая фраза
        this.targetMatches = []; // Все найденные ключи с этой фразой
        this.targetBonus = 1000; // Бонус за совпадение

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
                    this.bestKey = this.generateKey(0);
                    this.targetMatches = []; // Сброс при инициализации
                    break;
                case 'start':
                    if (!this.running) {
                        this.running = true;
                        this.startTime = performance.now();
                        this.runFullDecryption();
                    }
                    break;
                case 'stop':
                    this.running = false;
                    break;
            }
        };
    }

    // █ ВАШИ ОРИГИНАЛЬНЫЕ МЕТОДЫ (без изменений)
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

    // █ МОДИФИЦИРОВАННЫЙ МЕТОД (добавлена проверка targetPhrase)
    async runFullDecryption() {
        const totalKeys = Math.pow(26, this.keyLength);
        const keysPerWorker = Math.floor(totalKeys / this.totalWorkers);
        const startKey = this.workerId * keysPerWorker;
        const endKey = (this.workerId === this.totalWorkers - 1) ? totalKeys : startKey + keysPerWorker;

        for (let keyNum = startKey; keyNum < endKey && this.running; keyNum++) {
            const key = this.generateKey(keyNum);
            const plaintext = this.decrypt(key);

            // ДОБАВЛЕНО: Поиск всех вхождений целевой фразы
            if (plaintext.includes(this.targetPhrase)) {
                const bonusScore = this.scoreText(plaintext) + this.targetBonus;
                this.targetMatches.push({key, plaintext, score: bonusScore});
                this.updateBestKey(key, bonusScore, plaintext);
            }

            // Оригинальная оценка
            const standardScore = this.scoreText(plaintext);
            if (standardScore > this.bestScore) {
                this.updateBestKey(key, standardScore, plaintext);
            }

            // Оригинальный отчет о прогрессе
            if (keyNum % 1000 === 0) {
                const now = performance.now();
                if (now - this.lastReportTime > 1000) {
                    const kps = Math.round(this.keysTested / ((now - this.startTime) / 1000));
                    self.postMessage({
                        type: 'progress',
                        keysTested: this.keysTested,
                        kps: kps,
                        targetMatches: this.targetMatches.length // ДОБАВЛЕНО
                    });
                    this.lastReportTime = now;
                }
                await new Promise(resolve => setTimeout(resolve, 0));
            }
        }
    }

    // █ ВАШ ОРИГИНАЛЬНЫЙ МЕТОД (без изменений)
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
