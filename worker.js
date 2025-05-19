const ENGLISH_FREQ = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
    'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
    'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
    'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
    'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974,
    'Z': 0.074
};

const commonPatterns = ['THE', 'AND', 'THAT', 'HAVE', 'FOR', 'NOT', 'WITH', 'YOU', 'THIS', 'WAY'];
const uncommonPatterns = ['BERLIN', 'CLOCK', 'EAST', 'NORTH', 'WEST', 'SOUTH'];

class K4Worker {
    constructor() {
        // Инициализация алфавита и таблицы символов
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
        this.bestScore = 0;
        this.bestKey = '';
        this.lastReportTime = 0;
        
        // Улучшенное распределение работы
        this.currentBaseKey = 0;
        this.totalSegments = 1000;
        this.segmentSize = 0;
        this.segmentsCompleted = 0;
        this.randomJumpCounter = 0;

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
                case 'updateSettings':
                    this.updateSettings(msg.settings);
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
        
        const totalKeys = Math.pow(26, this.keyLength);
        this.segmentSize = Math.ceil(totalKeys / this.totalSegments);
        this.currentBaseKey = this.workerId * this.segmentSize;
    }

    handleStart() {
        if (!this.running) {
            this.running = true;
            this.startTime = performance.now();
            this.run();
        }
    }

    updateSettings(settings) {
        if (settings.totalSegments) {
            this.totalSegments = settings.totalSegments;
            const totalKeys = Math.pow(26, this.keyLength);
            this.segmentSize = Math.ceil(totalKeys / this.totalSegments);
        }
        if (settings.keysPerBlock) {
            this.keysPerBlock = settings.keysPerBlock;
        }
    }

    async run() {
        const totalKeys = Math.pow(26, this.keyLength);
        
        while (this.running && this.segmentsCompleted < this.totalSegments) {
            const segmentStart = this.currentBaseKey;
            const segmentEnd = Math.min(segmentStart + this.segmentSize, totalKeys);
            
            await this.processSegment(segmentStart, segmentEnd);
            
            // Переход к следующему сегменту с учетом количества воркеров
            this.currentBaseKey += this.totalWorkers * this.segmentSize;
            this.segmentsCompleted++;
            this.randomJumpCounter++;
            
            // Периодический случайный прыжок для диверсификации
            if (this.randomJumpCounter >= 10) {
                this.currentBaseKey = Math.floor(Math.random() * totalKeys);
                this.randomJumpCounter = 0;
            }
        }
        
        self.postMessage({
            type: 'complete',
            workerId: this.workerId,
            keysTested: this.keysTested
        });
    }

    async processSegment(startKey, endKey) {
        const BLOCK_SIZE = 5000;
        const localBest = {score: -1, key: '', plaintext: ''};
        
        for (let keyNum = startKey; keyNum < endKey && this.running; keyNum += BLOCK_SIZE) {
            const blockEnd = Math.min(keyNum + BLOCK_SIZE, endKey);
            
            for (let i = keyNum; i < blockEnd; i++) {
                const key = this.generateKey(i);
                const plaintext = this.decrypt(key);
                const score = this.scoreText(plaintext);
                this.keysTested++;

                if (score > localBest.score) {
                    localBest.score = score;
                    localBest.key = key;
                    localBest.plaintext = plaintext;
                }
            }
            
            // Отправляем лучший результат из блока, если он лучше глобального
            if (localBest.score > this.bestScore) {
                this.bestScore = localBest.score;
                this.bestKey = localBest.key;
                
                const foundWords = this.extractWords(localBest.plaintext);
                self.postMessage({
                    type: 'result',
                    workerId: this.workerId,
                    key: localBest.key,
                    plaintext: localBest.plaintext,
                    score: localBest.score,
                    words: foundWords,
                    progress: this.getProgress()
                });
            }
            
            this.reportProgress();
            await new Promise(resolve => setTimeout(resolve, 0)); // Даем дыхать event loop
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
        
        // Проверка частот символов
        const freq = new Uint16Array(26);
        let totalLetters = 0;
        for (let i = 0; i < text.length; i++) {
            const code = text.charCodeAt(i) - 65;
            if (code >= 0 && code <= 25) {
                freq[code]++;
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
        for (const pattern of [...commonPatterns, ...uncommonPatterns]) {
            let pos = -1;
            while ((pos = upperText.indexOf(pattern, pos + 1)) !== -1) {
                score += pattern.length * (uncommonPatterns.includes(pattern) ? 50 : 25);
            }
        }
        
        return Math.round(score);
    }

    extractWords(text) {
        const upperText = text.toUpperCase();
        const foundWords = {};
        
        for (const pattern of [...commonPatterns, ...uncommonPatterns]) {
            let pos = -1;
            while ((pos = upperText.indexOf(pattern, pos + 1)) !== -1) {
                if (!foundWords[pattern]) foundWords[pattern] = 0;
                foundWords[pattern]++;
            }
        }
        
        return foundWords;
    }

    getProgress() {
        const totalKeys = Math.pow(26, this.keyLength);
        return this.keysTested / totalKeys;
    }

    reportProgress() {
        const now = performance.now();
        if (now - this.lastReportTime > 1000) {
            self.postMessage({
                type: 'progress',
                workerId: this.workerId,
                keysTested: this.keysTested,
                kps: Math.round(this.keysTested / ((now - this.startTime) / 1000)),
                segmentsCompleted: this.segmentsCompleted,
                currentBaseKey: this.currentBaseKey
            });
            this.lastReportTime = now;
        }
    }
}

new K4Worker();
