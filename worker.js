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
        this.targetText = 'BERLINCLOCK'; // Новое поле для хранения целевого текста
        this.targetTextFound = false;
        this.parallelWorkers = [];
        this.currentTask = null;

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
                    this.bestKey = this.generateKey(0);
                    if (msg.targetText) {
                        this.targetText = msg.targetText.toUpperCase();
                    }
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
                case 'updateBestKey':
                    if (msg.score > this.bestScore) {
                        this.bestScore = msg.score;
                        this.bestKey = msg.key;
                        this.lastImprovementTime = performance.now();
                    }
                    break;
                case 'updateTargetText':
                    this.targetText = msg.text.toUpperCase();
                    this.targetTextFound = false;
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

        // Проверка на целевой текст (если задан)
        if (this.targetText && !this.targetTextFound) {
            if (upperText.includes(this.targetText)) {
                this.targetTextFound = true;
                score += 1000; // Очень высокий балл за нахождение целевого текста
            }
        }

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

        // Поиск общих паттернов
        for (const pattern of commonPatterns) {
            let pos = -1;
            while ((pos = upperText.indexOf(pattern, pos + 1)) !== -1) {
                score += pattern.length * 25;
            }
        }

        // Поиск специальных паттернов
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

        // Создаем несколько параллельных задач
        const parallelTasks = 4; // Оптимальное количество для большинства браузеров
        for (let i = 0; i < parallelTasks; i++) {
            this.parallelWorkers.push({
                running: true,
                task: this.createParallelTask(i, parallelTasks, startKey, endKey)
            });
        }

        // Запускаем все задачи
        await Promise.all(this.parallelWorkers.map(w => w.task));

        // Основной цикл
        while (this.running) {
            switch (this.mode) {
                case 'scan':
                    await this.fullScan(startKey, endKey);
                    break;
                case 'optimize':
                    await this.optimizeKey();
                    break;
                case 'explore':
                    await this.exploreRandom();
                    break;
                case 'target':
                    await this.searchTargetText();
                    break;
            }
            this.checkProgress();
            await new Promise(resolve => setTimeout(resolve, 0)); // Даем браузеру время на другие задачи
        }
    }

    createParallelTask(id, totalTasks, startKey, endKey) {
        return async () => {
            const taskRange = Math.floor((endKey - startKey) / totalTasks);
            const taskStart = startKey + id * taskRange;
            const taskEnd = id === totalTasks - 1 ? endKey : taskStart + taskRange;
            
            await this.fullScan(taskStart, taskEnd, true);
        };
    }

    async fullScan(startKey, endKey, isParallel = false) {
        const BLOCK_SIZE = 10000;
        let localBestScore = 0;
        let localBestKey = '';

        for (let keyNum = startKey; keyNum < endKey; keyNum += BLOCK_SIZE) {
            if (!this.running || (isParallel && !this.parallelWorkers.find(w => w.task && w.running)?.running)) {
                break;
            }

            const blockEnd = Math.min(keyNum + BLOCK_SIZE, endKey);
            for (let i = keyNum; i < blockEnd; i++) {
                const key = this.generateKey(i);
                const plaintext = this.decrypt(key);
                const score = this.scoreText(plaintext);
                this.keysTested++;

                if (score > localBestScore) {
                    localBestScore = score;
                    localBestKey = key;

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

                        // Если нашли целевой текст, переключаемся на оптимизацию
                        if (this.targetTextFound) {
                            this.mode = 'optimize';
                            return;
                        }
                    }
                }
            }

            // В параллельных задачах не меняем режим
            if (!isParallel && performance.now() - this.lastImprovementTime > 5000) {
                this.mode = 'optimize';
                break;
            }

            // Даем возможность обработать другие события
            if (keyNum % (BLOCK_SIZE * 10) === 0) {
                await new Promise(resolve => setTimeout(resolve, 0));
            }
        }

        // Для параллельных задач сообщаем о завершении
        if (isParallel) {
            this.parallelWorkers.find(w => w.task).running = false;
        }
    }

    async optimizeKey() {
        const keyChars = this.bestKey.split('');
        let improved = false;
        const optimizationRounds = 3; // Несколько раундов оптимизации

        for (let round = 0; round < optimizationRounds; round++) {
            if (!this.running) break;

            // Перемешиваем позиции для оптимизации
            const positions = Array.from({length: this.keyLength}, (_, i) => i);
            this.shuffleArray(positions);

            for (const pos of positions) {
                if (!this.running) break;

                const originalChar = keyChars[pos];
                // Проверяем соседние символы в случайном порядке
                const deltas = [-1, 1, -2, 2, -3, 3];
                this.shuffleArray(deltas);

                for (const delta of deltas) {
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

            if (!improved && round === 0) {
                this.stuckCount++;
                if (this.stuckCount > 5) {
                    this.mode = 'explore';
                    this.stuckCount = 0;
                    break;
                }
            }
        }

        if (improved) {
            this.stuckCount = 0;
        }
    }

    async exploreRandom() {
        const EXPLORE_BATCH_SIZE = 100;
        let bestInBatchScore = 0;
        let bestInBatchKey = '';

        for (let i = 0; i < EXPLORE_BATCH_SIZE; i++) {
            if (!this.running) break;

            const randomKey = this.generateKey(Math.floor(Math.random() * Math.pow(26, this.keyLength)));
            const plaintext = this.decrypt(randomKey);
            const score = this.scoreText(plaintext);
            this.keysTested++;

            if (score > bestInBatchScore) {
                bestInBatchScore = score;
                bestInBatchKey = randomKey;
            }

            // Если нашли что-то интересное, сообщаем
            if (score > this.bestScore * 0.9) {
                this.bestScore = score;
                this.bestKey = randomKey;
                this.lastImprovementTime = performance.now();
                self.postMessage({
                    type: 'result',
                    key: this.bestKey,
                    plaintext: plaintext,
                    score: this.bestScore
                });
                this.mode = 'optimize';
                return;
            }
        }

        // Если в этой партии ничего хорошего не нашли
        if (bestInBatchScore > this.bestScore * 0.8) {
            this.bestScore = bestInBatchScore;
            this.bestKey = bestInBatchKey;
            this.mode = 'optimize';
        } else if (performance.now() - this.lastImprovementTime > 10000) {
            this.mode = 'scan';
        }
    }

    async searchTargetText() {
        if (!this.targetText) {
            this.mode = 'scan';
            return;
        }

        const BLOCK_SIZE = 10000;
        const totalKeys = Math.pow(26, this.keyLength);
        const startKey = this.workerId * Math.floor(totalKeys / this.totalWorkers);
        const endKey = (this.workerId === this.totalWorkers - 1) ? totalKeys : startKey + Math.floor(totalKeys / this.totalWorkers);

        for (let keyNum = startKey; keyNum < endKey; keyNum += BLOCK_SIZE) {
            if (!this.running || this.targetTextFound) break;

            const blockEnd = Math.min(keyNum + BLOCK_SIZE, endKey);
            for (let i = keyNum; i < blockEnd; i++) {
                const key = this.generateKey(i);
                const plaintext = this.decrypt(key);
                const upperText = plaintext.toUpperCase();
                this.keysTested++;

                if (upperText.includes(this.targetText)) {
                    const score = this.scoreText(plaintext);
                    this.targetTextFound = true;
                    this.bestScore = score;
                    this.bestKey = key;
                    this.lastImprovementTime = performance.now();
                    self.postMessage({
                        type: 'result',
                        key: this.bestKey,
                        plaintext: plaintext,
                        score: this.bestScore,
                        targetFound: true
                    });
                    this.mode = 'optimize';
                    return;
                }
            }

            // Периодически проверяем, не нашли ли целевой текст в другом воркере
            if (keyNum % (BLOCK_SIZE * 10) === 0) {
                await new Promise(resolve => setTimeout(resolve, 0));
            }
        }

        // Если дошли до конца и не нашли
        if (!this.targetTextFound) {
            this.mode = 'scan';
        }
    }

    shuffleArray(array) {
        for (let i = array.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [array[i], array[j]] = [array[j], array[i]];
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
                targetTextFound: this.targetTextFound
            });
            this.lastReportTime = now;
        }
    }
}

new K4Worker();
