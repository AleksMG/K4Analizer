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
        // Инициализация алфавита и карты символов
        this.alphabet = 'ZXWVUQNMLJIHGFEDCBASOTPYRK';
        this.charMap = new Uint8Array(256);
        this.charMap.fill(255);
        for (let i = 0; i < this.alphabet.length; i++) {
            this.charMap[this.alphabet.charCodeAt(i)] = i;
        }

        // Состояние воркера
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

        // Параметры приоритетного поиска
        this.primaryTarget = 'CLOCK';
        this.primaryTargetLength = this.primaryTarget.length;
        this.primarySearchActive = true;
        this.primarySearchBatchSize = 5000; // Увеличенный размер батча
        this.lastPrimarySearchTime = 0;
        this.primarySearchInterval = 50; // Более частые проверки (мс)

        // Оптимизированные структуры данных
        this.alphabetCodes = new Uint8Array(26);
        for (let i = 0; i < 26; i++) {
            this.alphabetCodes[i] = this.alphabet.charCodeAt(i);
        }

        // Обработчик сообщений
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
                case 'updateBestKey':
                    this.handleUpdateBestKey(msg);
                    break;
                case 'togglePrimarySearch':
                    this.primarySearchActive = msg.active;
                    break;
            }
        };
    }

    handleInit(msg) {
        this.ciphertext = msg.ciphertext;
        this.keyLength = msg.keyLength;
        this.workerId = msg.workerId || 0;
        this.totalWorkers = msg.totalWorkers || 1;
        this.keysTested = 0;
        this.bestScore = 0;
        this.bestKey = this.generateKey(0);
        this.primarySearchActive = true;
    }

    handleStart() {
        if (!this.running) {
            this.running = true;
            this.startTime = performance.now();
            this.lastImprovementTime = this.startTime;
            this.run();
        }
    }

    handleUpdateBestKey(msg) {
        if (msg.score > this.bestScore) {
            this.bestScore = msg.score;
            this.bestKey = msg.key;
            this.lastImprovementTime = performance.now();
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
            plaintext += String.fromCharCode(this.alphabetCodes[plainPos]);
        }
        return plaintext;
    }

    scoreText(text) {
        const upperText = text.toUpperCase();
        
        // Приоритетная проверка
        if (this.primarySearchActive && upperText.includes(this.primaryTarget)) {
            return 1000 + (this.primaryTargetLength * 100);
        }

        let score = 0;
        const freq = new Uint16Array(26);
        let totalLetters = 0;

        // Быстрый подсчет частот
        for (let i = 0; i < text.length; i++) {
            const code = text.charCodeAt(i) - 65;
            if (code >= 0 && code <= 25) {
                freq[code]++;
                totalLetters++;
            }
        }

        // Расчет соответствия частотам
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

    async run() {
        const totalKeys = Math.pow(26, this.keyLength);
        const startKey = this.workerId * Math.floor(totalKeys / this.totalWorkers);
        const endKey = (this.workerId === this.totalWorkers - 1) ? totalKeys : startKey + Math.floor(totalKeys / this.totalWorkers);

        while (this.running) {
            // Параллельный приоритетный поиск
            if (this.primarySearchActive && 
                performance.now() - this.lastPrimarySearchTime > this.primarySearchInterval) {
                this.lastPrimarySearchTime = performance.now();
                await this.fastPrimarySearch(startKey, endKey);
            }

            // Основной алгоритм
            switch (this.mode) {
                case 'scan':
                    await this.optimizedScan(startKey, endKey);
                    break;
                case 'optimize':
                    await this.optimizeKey();
                    break;
                case 'explore':
                    await this.exploreRandom();
                    break;
            }

            this.reportProgress();
        }
    }

    async fastPrimarySearch(startKey, endKey) {
        const batchSize = this.primarySearchBatchSize;
        const keyRange = endKey - startKey;
        const target = this.primaryTarget;
        const targetCodes = new Uint8Array(target.length);
        
        // Преобразуем цель в коды
        for (let i = 0; i < target.length; i++) {
            targetCodes[i] = this.charMap[target.charCodeAt(i)];
        }

        for (let i = 0; i < batchSize && this.running; i++) {
            const keyNum = startKey + Math.floor(Math.random() * keyRange);
            const key = this.generateKey(keyNum);
            
            // Быстрая проверка без полного декодирования
            let found = false;
            for (let pos = 0; pos <= this.ciphertext.length - target.length; pos++) {
                let match = true;
                for (let j = 0; j < target.length; j++) {
                    const cipherPos = this.charMap[this.ciphertext.charCodeAt(pos + j)];
                    const keyPos = this.charMap[key.charCodeAt((pos + j) % this.keyLength)];
                    const plainPos = (cipherPos - keyPos + 26) % 26;
                    if (plainPos !== targetCodes[j]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    found = true;
                    break;
                }
            }

            if (found) {
                const plaintext = this.decrypt(key);
                self.postMessage({
                    type: 'primaryResult',
                    key: key,
                    plaintext: plaintext,
                    score: 1000 + (target.length * 100)
                });
            }

            this.keysTested++;
        }
    }

    async optimizedScan(startKey, endKey) {
        const BLOCK_SIZE = 20000; // Увеличенный размер блока
        const cipherLen = this.ciphertext.length;
        const keyBuffer = new Uint8Array(this.keyLength);

        for (let keyNum = startKey; keyNum < endKey && this.running; keyNum += BLOCK_SIZE) {
            const blockEnd = Math.min(keyNum + BLOCK_SIZE, endKey);
            
            for (let i = keyNum; i < blockEnd; i++) {
                // Генерация ключа в буфере
                let num = i;
                for (let j = this.keyLength - 1; j >= 0; j--) {
                    keyBuffer[j] = num % 26;
                    num = Math.floor(num / 26);
                }

                // Быстрое декодирование
                let plaintext = '';
                for (let k = 0; k < cipherLen; k++) {
                    const cipherPos = this.charMap[this.ciphertext.charCodeAt(k)];
                    const keyPos = keyBuffer[k % this.keyLength];
                    const plainPos = (cipherPos - keyPos + 26) % 26;
                    plaintext += String.fromCharCode(this.alphabetCodes[plainPos]);
                }

                const score = this.scoreText(plaintext);
                this.keysTested++;

                if (score > this.bestScore) {
                    this.bestScore = score;
                    this.bestKey = Array.from(keyBuffer, x => this.alphabet[x]).join('');
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
        const currentKey = Array.from(this.bestKey, c => this.charMap[c.charCodeAt(0)]);
        const keyBuffer = new Uint8Array(currentKey);
        let improved = false;

        for (let pos = 0; pos < this.keyLength && this.running; pos++) {
            const original = keyBuffer[pos];
            for (const delta of [-1, 1, -2, 2, -3, 3]) {
                keyBuffer[pos] = (original + delta + 26) % 26;
                
                let plaintext = '';
                for (let k = 0; k < this.ciphertext.length; k++) {
                    const cipherPos = this.charMap[this.ciphertext.charCodeAt(k)];
                    const keyPos = keyBuffer[k % this.keyLength];
                    const plainPos = (cipherPos - keyPos + 26) % 26;
                    plaintext += String.fromCharCode(this.alphabetCodes[plainPos]);
                }

                const score = this.scoreText(plaintext);
                this.keysTested++;

                if (score > this.bestScore) {
                    this.bestScore = score;
                    this.bestKey = Array.from(keyBuffer, x => this.alphabet[x]).join('');
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
            keyBuffer[pos] = original;
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
        const totalKeys = Math.pow(26, this.keyLength);
        const randomKeyNum = Math.floor(Math.random() * totalKeys);
        const randomKey = this.generateKey(randomKeyNum);
        const plaintext = this.decrypt(randomKey);
        const score = this.scoreText(plaintext);
        this.keysTested++;

        if (score > this.bestScore * 0.8) {
            this.mode = 'optimize';
        } else if (performance.now() - this.lastImprovementTime > 10000) {
            this.mode = 'scan';
        }
    }

    reportProgress() {
        const now = performance.now();
        if (now - this.lastReportTime > 1000) {
            const elapsed = (now - this.startTime) / 1000;
            const kps = elapsed > 0 ? Math.round(this.keysTested / elapsed) : 0;
            
            self.postMessage({
                type: 'progress',
                keysTested: this.keysTested,
                kps: kps,
                mode: this.mode,
                primarySearchActive: this.primarySearchActive
            });
            
            this.lastReportTime = now;
        }
    }
}

new K4Worker();
