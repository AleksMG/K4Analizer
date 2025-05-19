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
        this.alphabet = 'ZXWVUQNMLJIHGFEDCBASOTPYRK'; // Ваш алфавит
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
        this.primaryTarget = 'BERLINCLOCK';
        this.testedKeysCache = new Set(); // Хэш-таблица для проверенных ключей

        // Инициализация charMap
        this.charMap.fill(255);
        for (let i = 0; i < this.alphabet.length; i++) {
            this.charMap[this.alphabet.charCodeAt(i)] = i;
        }

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
                    this.startTime = performance.now();
                    this.testedKeysCache.clear();
                    break;
                case 'start':
                    this.running = true;
                    this.run();
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

    decrypt(key) {
        let plaintext = '';
        const keyLen = this.keyLength;
        const ciphertext = this.ciphertext;
        const charMap = this.charMap;
        const alphabet = this.alphabet;

        for (let i = 0; i < ciphertext.length; i++) {
            const plainPos = (charMap[ciphertext.charCodeAt(i)] - charMap[key.charCodeAt(i % keyLen)] + 26) % 26;
            plaintext += alphabet[plainPos];
        }
        return plaintext;
    }

    scoreText(text) {
        let score = 0;
        const upperText = text.toUpperCase();

        if (upperText.includes(this.primaryTarget)) return 1000;

        // Быстрый поиск паттернов
        for (const pattern of uncommonPatterns) {
            if (upperText.includes(pattern)) score += pattern.length * 50;
        }
        for (const pattern of commonPatterns) {
            if (upperText.includes(pattern)) score += pattern.length * 25;
        }

        return score;
    }

    async run() {
        const totalKeys = Math.pow(26, this.keyLength);
        const keysPerWorker = Math.ceil(totalKeys / this.totalWorkers);
        const startKey = this.workerId * keysPerWorker;
        const endKey = Math.min(startKey + keysPerWorker, totalKeys);
        const BLOCK_SIZE = 50000; // Оптимальный размер блока для больших ключей

        // Метод "Разделяй и властвуй" для больших ключей
        for (let baseKeyNum = startKey; baseKeyNum < endKey && this.running; baseKeyNum += BLOCK_SIZE * 26) {
            const blockEnd = Math.min(baseKeyNum + BLOCK_SIZE * 26, endKey);
            
            // Параллельная обработка блоков
            const promises = [];
            for (let blockStart = baseKeyNum; blockStart < blockEnd; blockStart += BLOCK_SIZE) {
                promises.push(this.processBlock(blockStart, Math.min(blockStart + BLOCK_SIZE, blockEnd)));
            }
            await Promise.all(promises);
        }

        self.postMessage({ type: 'completed' });
    }

    async processBlock(startKey, endKey) {
        for (let keyNum = startKey; keyNum < endKey && this.running; keyNum++) {
            const key = this.generateKey(keyNum);
            
            // Пропуск проверенных ключей
            if (this.testedKeysCache.has(key)) continue;
            this.testedKeysCache.add(key);

            const plaintext = this.decrypt(key);
            const score = this.scoreText(plaintext);
            this.keysTested++;

            if (score > this.bestScore) {
                this.bestScore = score;
                this.bestKey = key;
                this.bestPlaintext = plaintext;
                self.postMessage({
                    type: 'result',
                    key: key,
                    plaintext: plaintext,
                    score: score
                });
            }
        }

        // Отчет о прогрессе
        if (performance.now() - this.lastReportTime > 1000) {
            self.postMessage({
                type: 'progress',
                keysTested: this.keysTested,
                kps: Math.round(this.keysTested / ((performance.now() - this.startTime) / 1000))
            });
            this.lastReportTime = performance.now();
        }
    }
}

new K4Worker();
