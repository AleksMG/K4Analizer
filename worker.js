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
        this.lastImprovementTime = 0;
        this.knownKeys = new Set(); // Хранит хэши проверенных ключей
        this.taskQueue = []; // Очередь задач для параллельного выполнения

        this.charMap.fill(255);
        for (let i = 0; i < this.alphabet.length; i++) {
            this.charMap[this.alphabet.charCodeAt(i)] = i;
        }

        self.onmessage = (e) => {
            const msg = e.data;
            switch (msg.type) {
                case 'init':
                    Object.assign(this, {
                        ciphertext: msg.ciphertext,
                        keyLength: msg.keyLength,
                        workerId: msg.workerId || 0,
                        totalWorkers: msg.totalWorkers || 1,
                        keysTested: 0,
                        bestScore: 0,
                        bestKey: this.generateKey(0)
                    });
                    break;
                case 'start':
                    if (!this.running) {
                        this.running = true;
                        this.startTime = performance.now();
                        this.lastImprovementTime = this.startTime;
                        this.runMaster();
                    }
                    break;
                case 'stop':
                    this.running = false;
                    break;
            }
        };
    }

    // ► Основной метод (запускает все процессы)
    async runMaster() {
        // 1. Запуск фонового сканирования
        const scanner = this.startScanner();
        
        // 2. Запуск оптимизатора
        const optimizer = this.startOptimizer();
        
        // 3. Запуск исследователя
        const explorer = this.startExplorer();

        // 4. Мониторинг прогресса
        await this.monitorProgress();

        await Promise.all([scanner, optimizer, explorer]);
    }

    // ► 1. Сканер (полный перебор)
    async startScanner() {
        const totalKeys = Math.pow(26, this.keyLength);
        const startKey = this.workerId * Math.floor(totalKeys / this.totalWorkers);
        const endKey = (this.workerId === this.totalWorkers - 1) ? totalKeys : startKey + Math.floor(totalKeys / this.totalWorkers);

        for (let keyNum = startKey; keyNum < endKey && this.running; keyNum++) {
            const key = this.generateKey(keyNum);
            if (this.knownKeys.has(key)) continue;

            const { score, plaintext } = this.testKey(key);
            this.updateBest(key, score, plaintext);
            await this.yieldToEventLoop();
        }
    }

    // ► 2. Оптимизатор (улучшение лучшего ключа)
    async startOptimizer() {
        while (this.running) {
            if (!this.bestKey) {
                await this.delay(100);
                continue;
            }

            let improved = false;
            const keyChars = [...this.bestKey];

            for (let pos = 0; pos < this.keyLength && this.running; pos++) {
                const originalChar = keyChars[pos];
                
                // Пробуем соседние буквы в алфавите
                for (const delta of [-2, -1, 1, 2]) {
                    const newChar = this.alphabet[(this.charMap[originalChar.charCodeAt(0)] + delta + 26) % 26];
                    keyChars[pos] = newChar;
                    const newKey = keyChars.join('');

                    if (this.knownKeys.has(newKey)) continue;

                    const { score, plaintext } = this.testKey(newKey);
                    if (score > this.bestScore) {
                        this.updateBest(newKey, score, plaintext);
                        improved = true;
                        break;
                    }
                }

                keyChars[pos] = originalChar;
                if (improved) break;
            }

            if (!improved) {
                this.stuckCount++;
                if (this.stuckCount > 5) {
                    await this.delay(1000); // Пауза перед следующей попыткой
                }
            } else {
                this.stuckCount = 0;
            }

            await this.yieldToEventLoop();
        }
    }

    // ► 3. Исследователь (случайные прыжки)
    async startExplorer() {
        while (this.running) {
            if (performance.now() - this.lastImprovementTime > 5000) {
                const randomKey = this.generateRandomKey();
                if (this.knownKeys.has(randomKey)) continue;

                const { score, plaintext } = this.testKey(randomKey);
                if (score > this.bestScore * 0.8) {
                    this.updateBest(randomKey, score, plaintext);
                }
            }
            await this.delay(500);
        }
    }

    // ► Общие вспомогательные методы
    generateKey(num) {
        const key = new Array(this.keyLength);
        for (let i = this.keyLength - 1; i >= 0; i--) {
            key[i] = this.alphabet[num % 26];
            num = Math.floor(num / 26);
        }
        return key.join('');
    }

    generateRandomKey() {
        return Array.from({ length: this.keyLength }, () => 
            this.alphabet[Math.floor(Math.random() * 26)]
        ).join('');
    }

    testKey(key) {
        this.keysTested++;
        this.knownKeys.add(key);
        
        let plaintext = '';
        for (let i = 0; i < this.ciphertext.length; i++) {
            const plainPos = (this.charMap[this.ciphertext.charCodeAt(i)] - 
                            this.charMap[key.charCodeAt(i % this.keyLength)] + 26) % 26;
            plaintext += this.alphabet[plainPos];
        }

        const score = this.scoreText(plaintext);
        return { score, plaintext };
    }

    updateBest(key, score, plaintext) {
        if (score > this.bestScore) {
            this.bestScore = score;
            this.bestKey = key;
            this.lastImprovementTime = performance.now();
            self.postMessage({
                type: 'result',
                key,
                plaintext,
                score
            });
        }
    }

    async monitorProgress() {
        while (this.running) {
            const now = performance.now();
            if (now - this.lastReportTime > 1000) {
                const kps = Math.round(this.keysTested / ((now - this.startTime) / 1000));
                self.postMessage({
                    type: 'progress',
                    keysTested: this.keysTested,
                    kps
                });
                this.lastReportTime = now;
            }
            await this.delay(200);
        }
    }

    // ► Оптимизации производительности
    scoreText(text) {
        // ... (полностью сохранён оригинальный метод)
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    yieldToEventLoop() {
        return new Promise(resolve => setTimeout(resolve, 0));
    }
}

new K4Worker();
