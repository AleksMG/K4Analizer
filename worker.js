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
        this.knownPlaintext = '';
        this.workerId = 0;
        this.totalWorkers = 1;
        this.keysTested = 0;
        this.startTime = 0;
        this.lastReportTime = 0;
        
        // Инициализация charMap с защитой от неопределенных символов
        this.charMap.fill(255); // Устанавливаем недопустимое значение по умолчанию
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
                this.knownPlaintext = msg.knownPlaintext || '';
                this.workerId = msg.workerId || 0;
                this.totalWorkers = msg.totalWorkers || 1;
                this.keysTested = 0;
                break;
                
            case 'start':
                this.running = true;
                this.startTime = performance.now();
                this.lastReportTime = this.startTime;
                this.bruteForce();
                break;
                
            case 'stop':
                this.running = false;
                break;
        }
    }

    bruteForce() {
        const totalKeys = Math.pow(26, this.keyLength);
        const keysPerWorker = Math.ceil(totalKeys / this.totalWorkers);
        const startKey = this.workerId * keysPerWorker;
        const endKey = Math.min(startKey + keysPerWorker, totalKeys);
        
        let bestScore = 0;
        let bestKey = null;
        let bestText = '';
        
        // Оптимизация: предварительно вычисляем коды символов
        const cipherLen = this.ciphertext.length;
        const cipherCodes = new Uint8Array(cipherLen);
        for (let i = 0; i < cipherLen; i++) {
            const code = this.ciphertext.charCodeAt(i);
            cipherCodes[i] = this.charMap[code] !== 255 ? this.charMap[code] : 0;
        }

        // Главный цикл перебора ключей
        for (let keyNum = startKey; keyNum < endKey && this.running; keyNum++) {
            const key = this.generateKey(keyNum);
            
            // Расшифровка
            let plaintext = '';
            for (let i = 0; i < cipherLen; i++) {
                const cipherPos = cipherCodes[i];
                const keyPos = this.charMap[key.charCodeAt(i % this.keyLength)];
                plaintext += this.alphabet[(cipherPos - keyPos + 26) % 26];
            }
            
            // Оценка текста
            const score = this.scoreText(plaintext);
            this.keysTested++;
            
            if (score > bestScore) {
                bestScore = score;
                bestKey = key;
                bestText = plaintext;
                self.postMessage({
                    type: 'result',
                    key,
                    plaintext,
                    score
                });
            }
            
            // Отчет о прогрессе
            if (this.keysTested % 1000000 === 0) {
                const now = performance.now();
                if (now - this.lastReportTime > 5000) { // Не чаще 1 раза в секунду
                    const kps = Math.round(this.keysTested / ((now - this.startTime) / 10000));
                    self.postMessage({
                        type: 'progress',
                        keysTested: this.keysTested,
                        kps
                    });
                    this.lastReportTime = now;
                }
            }
            
            // Проверка флага остановки между итерациями
            if (this.keysTested % 50000 === 0 && !this.running) break;
        }
        
        if (this.running) {
            self.postMessage({ type: 'complete' });
        }
    }

    generateKey(num) {
        let key = '';
        for (let i = 0; i < this.keyLength; i++) {
            key = this.alphabet[num % 26] + key;
            num = Math.floor(num / 26);
        }
        return key;
    }

    scoreText(text) {
        let score = 0;
        const upperText = text.toUpperCase();
        
        // 1. Проверка известного открытого текста
        if (this.knownPlaintext) {
            const knownUpper = this.knownPlaintext.toUpperCase();
            if (upperText.includes(knownUpper)) {
                score += 1000 * knownUpper.length;
            }
        }
        
        // 2. Частотный анализ
        const freq = new Uint16Array(26);
        let totalLetters = 0;
        
        for (let i = 0; i < text.length; i++) {
            const code = text.charCodeAt(i);
            if (code >= 65 && code <= 90) { // A-Z
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
        
        // 3. Поиск общих паттернов
        for (const pattern of commonPatterns) {
            let pos = -1;
            while ((pos = upperText.indexOf(pattern, pos + 1)) !== -1) {
                score += pattern.length * 25;
            }
        }
        
        // 4. Поиск специальных паттернов (с большим весом)
        for (const pattern of uncommonPatterns) {
            let pos = -1;
            while ((pos = upperText.indexOf(pattern, pos + 1)) !== -1) {
                score += pattern.length * 50;
            }
        }
        
        return Math.max(0, Math.round(score));
    }
}

new K4Worker();
