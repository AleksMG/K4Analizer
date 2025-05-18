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
        this.targetPhrase = 'BERLINCLOCK';
        this.targetMatches = [];

        // Оптимизации
        this.cipherCodes = null;
        this.keyCache = null;
        this.alphabetCodes = new Uint8Array(26);

        this.charMap.fill(255);
        for (let i = 0; i < this.alphabet.length; i++) {
            const code = this.alphabet.charCodeAt(i);
            this.charMap[code] = i;
            this.alphabetCodes[i] = code;
        }

        self.onmessage = (e) => {
            const msg = e.data;
            switch (msg.type) {
                case 'init':
                    this.ciphertext = msg.ciphertext;
                    this.keyLength = msg.keyLength;
                    this.workerId = msg.workerId || 0;
                    this.totalWorkers = msg.totalWorkers || 1;
                    
                    // Инициализация оптимизаций
                    this.cipherCodes = new Uint8Array(this.ciphertext.length);
                    for (let i = 0; i < this.ciphertext.length; i++) {
                        this.cipherCodes[i] = this.charMap[this.ciphertext.charCodeAt(i)];
                    }
                    this.keyCache = new Uint8Array(this.keyLength);
                    
                    this.keysTested = 0;
                    this.bestScore = 0;
                    this.bestKey = this.generateKey(0);
                    this.targetMatches = [];
                    break;
                case 'start':
                    if (!this.running) {
                        this.running = true;
                        this.startTime = performance.now();
                        this.runOptimizedBruteforce();
                    }
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

    // Оптимизированный decrypt
    decrypt() {
        let plaintext = '';
        for (let i = 0; i < this.cipherCodes.length; i++) {
            const plainPos = (this.cipherCodes[i] - this.keyCache[i % this.keyLength] + 26) % 26;
            plaintext += String.fromCharCode(this.alphabetCodes[plainPos]);
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
                const expected = ENGLISH_FREQ[String.fromCharCode(65 + i)] || 0;
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

    async runOptimizedBruteforce() {
        const batchSize = 100000;
        let batchCount = 0;
        const startTime = performance.now();
        
        while (this.running) {
            // Генерация ключа
            for (let i = 0; i < this.keyLength; i++) {
                this.keyCache[i] = Math.floor(Math.random() * 26);
            }
            
            const plaintext = this.decrypt();
            this.keysTested++;
            batchCount++;

            // Проверка целевой фразы
            if (plaintext.includes(this.targetPhrase)) {
                const score = this.scoreText(plaintext) + 10000;
                this.targetMatches.push({
                    key: Array.from(this.keyCache).map(i => this.alphabet[i]).join(''),
                    plaintext: plaintext,
                    score: score
                });
                this.updateBestKey(this.targetMatches[this.targetMatches.length - 1].key, score, plaintext);
            }

            // Отчет о прогрессе
            if (batchCount >= batchSize) {
                const now = performance.now();
                const elapsed = (now - startTime) / 1000;
                const kps = Math.round(this.keysTested / elapsed);
                
                self.postMessage({
                    type: 'progress',
                    keysTested: this.keysTested,
                    kps: kps,
                    targetMatches: this.targetMatches.length
                });
                
                batchCount = 0;
                await new Promise(resolve => setTimeout(resolve, 0));
            }
        }
    }

    updateBestKey(key, score, plaintext) {
        if (score > this.bestScore) {
            this.bestScore = score;
            this.bestKey = key;
            self.postMessage({
                type: 'result',
                key: key,
                plaintext: plaintext,
                score: score,
                isTarget: score >= 10000
            });
        }
    }
}

new K4Worker();
