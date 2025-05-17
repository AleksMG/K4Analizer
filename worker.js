const ENGLISH_FREQ = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
    'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
    'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
    'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
    'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974,
    'Z': 0.074
};

const COMMON_PATTERNS = [
    'THE', 'AND', 'THAT', 'HAVE', 'FOR', 'NOT', 'WITH', 'YOU', 'THIS', 'BUT',
    'HIS', 'FROM', 'THEY', 'WILL', 'WOULD', 'THERE', 'THEIR', 'WHAT', 'ABOUT',
    'WHICH', 'WHEN', 'YOUR', 'WERE', 'BERLIN', 'CLOCK', 'EAST', 'NORTH', 'WEST',
    'SOUTH', 'NORTHEAST', 'NORTHWEST', 'SOUTHEAST', 'SOUTHWEST', 'SECRET', 'CODE',
    'MESSAGE', 'KRYPTOS', 'CIA', 'AGENT', 'COMPASS', 'DIRECTION', 'LATITUDE',
    'LONGITUDE', 'COORDINATE', 'GOVERNMENT', 'WALL', 'UNDERGROUND'
];

class K4Worker {
    constructor() {
        this.alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        this.charMap = new Uint8Array(256); // ASCII lookup table
        this.running = false;
        
        // Initialize character map (как у тебя)
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
        
        // 🔥 Оптимизация 1: Кешируем коды шифротекста
        const cipherCodes = new Uint8Array(this.ciphertext.length);
        for (let i = 0; i < this.ciphertext.length; i++) {
            cipherCodes[i] = this.charMap[this.ciphertext.charCodeAt(i)];
        }

        // 🔥 Оптимизация 2: Буфер для ключа (быстрее строк)
        const keyBuffer = new Uint8Array(this.keyLength);

        // 🔥 Оптимизация 3: Буфер для расшифрованного текста
        const plainBuffer = new Uint8Array(this.ciphertext.length);

        // Регулярки для knownPlaintext и COMMON_PATTERNS (как у тебя)
        const knownRegex = this.knownPlaintext ? new RegExp(this.knownPlaintext, 'g') : null;
        const patternRegexes = COMMON_PATTERNS.map(p => new RegExp(p, 'g'));

        for (let keyNum = startKey; keyNum < endKey && this.running; keyNum++) {
            // Генерация ключа (как у тебя, но через буфер)
            let temp = keyNum;
            for (let i = this.keyLength - 1; i >= 0; i--) {
                keyBuffer[i] = temp % 26;
                temp = Math.floor(temp / 26);
            }

            // Дешифровка (максимально быстро)
            for (let i = 0; i < this.ciphertext.length; i++) {
                plainBuffer[i] = (cipherCodes[i] - keyBuffer[i % this.keyLength] + 26) % 26;
            }

            // Конвертация в строку (одна операция)
            let plaintext = '';
            for (let i = 0; i < plainBuffer.length; i++) {
                plaintext += String.fromCharCode(plainBuffer[i] + 65);
            }

            // Подсчет очков (твой оригинальный метод)
            const score = this.scoreText(plaintext, knownRegex, patternRegexes);
            
            this.keysTested++;
            
            if (score > bestScore) {
                bestScore = score;
                bestKey = '';
                for (let i = 0; i < this.keyLength; i++) {
                    bestKey += String.fromCharCode(keyBuffer[i] + 65);
                }
                bestText = plaintext;
                self.postMessage({
                    type: 'result',
                    key: bestKey,
                    plaintext: bestText,
                    score
                });
            }
            
            // Отчет о прогрессе (реже, чтобы не тормозить)
            if (this.keysTested % 500000 === 0) { // Каждые 500k ключей
                const now = performance.now();
                const kps = Math.round(this.keysTested / ((now - this.startTime) / 1000));
                self.postMessage({
                    type: 'progress',
                    keysTested: this.keysTested,
                    kps
                });
            }
        }
        
        if (this.running) {
            self.postMessage({ type: 'complete' });
        }
    }

    // Твой оригинальный метод scoreText (без изменений)
    scoreText(text, knownRegex, patternRegexes) {
        let score = 0;
        
        // 1. Known plaintext check
        if (knownRegex && text.match(knownRegex)) {
            score += 1000 * this.knownPlaintext.length;
        }
        
        // 2. Frequency analysis
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
        
        // 3. Common patterns
        for (let i = 0; i < patternRegexes.length; i++) {
            const matches = text.match(patternRegexes[i]);
            if (matches) {
                score += COMMON_PATTERNS[i].length * 25 * matches.length;
            }
        }
        
        // 4. Spaces bonus
        let spaceCount = 0;
        for (let i = 0; i < text.length; i++) {
            if (text.charCodeAt(i) === 32) spaceCount++;
        }
        score += spaceCount * 15;
        
        // 5. Penalty for invalid chars
        let invalidChars = 0;
        for (let i = 0; i < text.length; i++) {
            const code = text.charCodeAt(i);
            if (!((code >= 65 && code <= 90) || code === 32)) {
                invalidChars++;
            }
        }
        score -= invalidChars * 10;
        
        return Math.max(0, Math.round(score));
    }
}

new K4Worker();
