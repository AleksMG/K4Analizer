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
    'MESSAGE', 'KRYPTOS', 'CIA', 'AGENT', 'COMPASS', 'LIGHT', 'LATITUDE',
    'LONGITUDE', 'COORDINATE', 'SHADOW', 'WALL', 'UNDERGROUND'
];

class K4Worker {
    constructor() {
        this.alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        this.charMap = {};
        for (let i = 0; i < this.alphabet.length; i++) {
            const char = this.alphabet[i];
            this.charMap[char] = i;
            this.charMap[char.toLowerCase()] = i;
        }

        this.running = false;
        this.ciphertext = '';
        this.keyLength = 0;
        this.knownPlaintext = '';
        this.workerId = 0;
        this.totalWorkers = 1;
        this.keysTested = 0;
        this.startTime = 0;
        
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
        let bestKey = '';
        let bestText = '';
        
        // Заранее преобразуем ciphertext в коды
        const cipherCodes = [];
        for (let i = 0; i < this.ciphertext.length; i++) {
            cipherCodes.push(this.charMap[this.ciphertext[i]]);
        }
        
        // Основной цикл
        for (let keyNum = startKey; keyNum < endKey && this.running; keyNum++) {
            const key = this.generateKey(keyNum);
            let plaintext = '';
            
            // Быстрое дешифрование
            for (let i = 0; i < this.ciphertext.length; i++) {
                const cipherPos = cipherCodes[i];
                const keyPos = this.charMap[key[i % this.keyLength]];
                plaintext += this.alphabet[(cipherPos - keyPos + 26) % 26];
            }
            
            // Ускоренный подсчёт score
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
            
            // Отчёт о прогрессе
            if (this.keysTested % 50000 === 0) {
                const kps = Math.round(this.keysTested / ((performance.now() - this.startTime) / 1000));
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
        const freq = {};
        let totalLetters = 0;
        
        // Частотный анализ
        for (const char of text) {
            if (char >= 'A' && char <= 'Z') {
                freq[char] = (freq[char] || 0) + 1;
                totalLetters++;
            }
        }
        
        for (const char in freq) {
            const expected = ENGLISH_FREQ[char] || 0;
            const actual = (freq[char] / totalLetters) * 100;
            score += 100 - Math.abs(expected - actual);
        }
        
        // Известный текст
        if (this.knownPlaintext && text.includes(this.knownPlaintext)) {
            score += 1000 * this.knownPlaintext.length;
        }
        
        // Паттерны
        for (const pattern of COMMON_PATTERNS) {
            let pos = -1;
            while ((pos = text.indexOf(pattern, pos + 1)) !== -1) {
                score += pattern.length * 25;
            }
        }
        
        return score;
    }
}

new K4Worker();
