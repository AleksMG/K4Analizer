const ENGLISH_FREQ = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
    'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
    'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
    'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
    'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974,
    'Z': 0.074
};

// Ваши оригинальные паттерны (без изменений)
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
        this.alphabet = 'ZXWVUQNMLJIHGFEDCBASOTPYRK'; // Ваш алфавит (без изменений)
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
        this.totalKeysToTest = 0;
        this.completed = false;
        this.primaryTarget = 'BERLINCLOCK';
        this.primaryTargetFound = false;
        this.primaryResults = [];
        this.localOptimizeAttempts = 0;
        this.testedKeysCache = new Set(); // Кеш для избежания повторов

        // Инициализация charMap (без изменений)
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
                    this.totalKeysToTest = Math.pow(26, this.keyLength);
                    this.completed = false;
                    this.primaryTargetFound = false;
                    this.primaryResults = [];
                    this.testedKeysCache.clear();
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

    // Генерация ключа (без изменений)
    generateKey(num) {
        const key = new Array(this.keyLength);
        for (let i = this.keyLength - 1; i >= 0; i--) {
            key[i] = this.alphabet[num % 26];
            num = Math.floor(num / 26);
        }
        return key.join('');
    }

    // Ускоренный decrypt() для больших ключей
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

    // Упрощенный scoreText() для скорости
    scoreText(text) {
        let score = 0;
        const upperText = text.toUpperCase();

        // Быстрая проверка целевого фрагмента
        if (!this.primaryTargetFound && upperText.includes(this.primaryTarget)) {
            return 1000;
        }

        // Частотный анализ (упрощенный)
        for (let i = 0; i < text.length; i++) {
            const code = text.charCodeAt(i) - 65;
            if (code >= 0 && code < 26) {
                score += ENGLISH_FREQ[this.alphabet[code]] || 0;
            }
        }

        // Поиск паттернов (оптимизированный)
        for (const pattern of uncommonPatterns) {
            if (upperText.includes(pattern)) score += pattern.length * 50;
        }
        for (const pattern of commonPatterns) {
            if (upperText.includes(pattern)) score += pattern.length * 25;
        }

        return Math.round(score);
    }

    // Оптимизированный run() для больших ключей
    async run() {
        const keysPerWorker = Math.ceil(this.totalKeysToTest / this.totalWorkers);
        const startKey = this.workerId * keysPerWorker;
        const endKey = Math.min(startKey + keysPerWorker, this.totalKeysToTest);
        const BLOCK_SIZE = this.keyLength > 12 ? 500 : 1000; // Меньше блоки для длинных ключей

        while (this.running && !this.completed) {
            switch (this.mode) {
                case 'scan':
                    await this.fullScan(startKey, endKey, BLOCK_SIZE);
                    break;
                case 'optimize':
                    await this.optimizeKey();
                    break;
                case 'explore':
                    await this.exploreRandom();
                    break;
                case 'primarySearch':
                    await this.findPrimaryTargets(startKey, endKey, BLOCK_SIZE);
                    this.mode = 'scan';
                    break;
            }
            
            if (this.keysTested >= (endKey - startKey)) {
                this.completed = true;
                this.running = false;
                self.postMessage({
                    type: 'completed',
                    keysTested: this.keysTested,
                    bestScore: this.bestScore,
                    bestKey: this.bestKey,
                    bestPlaintext: this.bestPlaintext
                });
            }
            
            this.checkProgress();
        }
    }

    // Оптимизированный optimizeKey() для длинных ключей
    async optimizeKey() {
        const key = this.bestKey;
        let bestKey = key;
        let bestScore = this.bestScore;

        // Для ключей >12 символов проверяем только 3 случайные позиции
        const checkPositions = this.keyLength > 12 
            ? [...Array(3)].map(() => Math.floor(Math.random() * this.keyLength))
            : [...Array(this.keyLength).keys()];

        for (const pos of checkPositions) {
            const originalChar = key[pos];
            for (const delta of [-1, 1]) { // Проверяем только ±1 символ
                const newCharCode = (this.charMap[originalChar.charCodeAt(0)] + delta + 26) % 26;
                const newKey = key.substring(0, pos) + this.alphabet[newCharCode] + key.substring(pos + 1);

                if (this.testedKeysCache.has(newKey)) continue;
                this.testedKeysCache.add(newKey);

                const plaintext = this.decrypt(newKey);
                const score = this.scoreText(plaintext);
                this.keysTested++;

                if (score > bestScore) {
                    bestScore = score;
                    bestKey = newKey;
                }
            }
        }

        if (bestScore > this.bestScore) {
            this.bestScore = bestScore;
            this.bestKey = bestKey;
            this.stuckCount = 0;
        } else {
            this.stuckCount++;
            if (this.stuckCount > 10) {
                this.mode = 'explore'; // Переключаемся при застревании
                this.stuckCount = 0;
            }
        }
    }

    // Улучшенный exploreRandom() с приоритетом мутациям
    async exploreRandom() {
        const MAX_ATTEMPTS = this.keyLength > 12 ? 300 : 500;
        let attempts = 0;
        let bestLocalKey = '';
        let bestLocalScore = -Infinity;

        while (attempts < MAX_ATTEMPTS && this.running) {
            let key;
            
            // 80% - мутации лучшего ключа, 20% - полностью случайные
            if (Math.random() < 0.8 && this.bestKey) {
                const mutatePos = Math.floor(Math.random() * this.keyLength);
                const delta = Math.random() < 0.5 ? 1 : -1;
                const newCharCode = (this.charMap[this.bestKey.charCodeAt(mutatePos)] + delta + 26) % 26;
                key = this.bestKey.substring(0, mutatePos) + 
                      this.alphabet[newCharCode] + 
                      this.bestKey.substring(mutatePos + 1);
            } else {
                key = this.generateKey(Math.floor(Math.random() * this.totalKeysToTest));
            }

            if (this.testedKeysCache.has(key)) continue;
            this.testedKeysCache.add(key);

            const plaintext = this.decrypt(key);
            const score = this.scoreText(plaintext);
            this.keysTested++;
            attempts++;

            if (score > bestLocalScore) {
                bestLocalScore = score;
                bestLocalKey = key;
            }

            if (attempts % 20 === 0) {
                await new Promise(resolve => setTimeout(resolve, 0));
            }
        }

        if (bestLocalScore > this.bestScore * 0.85) {
            this.bestScore = bestLocalScore;
            this.bestKey = bestLocalKey;
            this.mode = 'optimize';
        } else {
            this.mode = 'scan';
        }
    }

    // Остальные методы без изменений
    async findPrimaryTargets(startKey, endKey, BLOCK_SIZE) { /* ... */ }
    async fullScan(startKey, endKey, BLOCK_SIZE) { /* ... */ }
    checkProgress() { /* ... */ }
}

new K4Worker();
