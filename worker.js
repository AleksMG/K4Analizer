const ENGLISH_FREQ = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
    'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
    'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
    'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
    'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974,
    'Z': 0.074
};

const commonPatterns = ['THE', 'AND', 'THAT', 'HAVE', 'FOR', 'NOT', 'WITH', 'YOU', 'THIS', 'WAY', 'HIS', 'FROM', 'THEY', 'WILL', 'WOULD', 'THERE', 'THEIR', 'WHAT', 'ABOUT', 'WHICH', 'WHEN', 'YOUR', 'WERE', 'CIA'];
const uncommonPatterns = ['BERLIN', 'CLOCK', 'EAST', 'NORTH', 'WEST', 'SOUTH', 'NORTHEAST', 'NORTHWEST', 'SOUTHEAST', 'SOUTHWEST', 'SECRET', 'CODE', 'MESSAGE', 'KRYPTOS', 'BERLINCLOCK', 'AGENT', 'COMPASS', 'LIGHT', 'LATITUDE', 'LONGITUDE', 'COORDINATE', 'SHADOW', 'WALL', 'UNDERGROUND'];

class K4Worker {
    constructor() {
        this.alphabet = 'ZXWVUQNMLJIHGFEDCBASOTPYRK';
        this.charMap = new Uint8Array(256);
        this.charMap.fill(255);
        for (let i = 0; i < this.alphabet.length; i++) {
            this.charMap[this.alphabet.charCodeAt(i)] = i;
        }

        this.running = false;
        this.keysTested = 0;
        this.startTime = 0;
        this.bestScore = 0;

        self.onmessage = (e) => this.handleMessage(e.data);
    }

    handleMessage(msg) {
        switch (msg.type) {
            case 'init':
                Object.assign(this, {
                    ciphertext: msg.ciphertext,
                    keyLength: msg.keyLength,
                    workerId: msg.workerId || 0,
                    totalWorkers: msg.totalWorkers || 1
                });
                break;
            case 'start':
                if (!this.running) {
                    this.running = true;
                    this.startTime = performance.now();
                    this.bruteForceOptimized();
                }
                break;
            case 'stop':
                this.running = false;
                break;
        }
    }

    bruteForceOptimized() {
        const cipherCodes = new Uint8Array(this.ciphertext.length);
        for (let i = 0; i < this.ciphertext.length; i++) {
            cipherCodes[i] = this.charMap[this.ciphertext.charCodeAt(i)];
        }

        const totalKeys = this.keyLength <= 10 
            ? Math.pow(26, this.keyLength)
            : Infinity; // Для ключей >10 символов - особый режим

        const keysPerWorker = Math.floor(totalKeys / this.totalWorkers);
        const startKey = this.workerId * keysPerWorker;
        const endKey = (this.workerId === this.totalWorkers - 1) 
            ? totalKeys 
            : startKey + keysPerWorker;

        let bestKey = '';
        let bestText = '';
        const plaintextBuffer = new Uint8Array(this.ciphertext.length);

        // Режим для ключей ≤10 символов (максимальная скорость)
        if (this.keyLength <= 10) {
            for (let keyNum = startKey; keyNum < endKey && this.running; keyNum++) {
                this.processKey(keyNum, cipherCodes, plaintextBuffer);
            }
        } 
        // Режим для ключей >10 символов (поддержка BigInt)
        else {
            const bigStart = BigInt(startKey);
            const bigEnd = BigInt(endKey);
            let current = bigStart;
            
            while (current < bigEnd && this.running) {
                this.processBigKey(current, cipherCodes, plaintextBuffer);
                current++;
            }
        }

        self.postMessage({ type: 'complete' });
    }

    processKey(keyNum, cipherCodes, plaintextBuffer) {
        // Генерация ключа (оптимизированная для ≤10 символов)
        let remaining = keyNum;
        const key = new Array(this.keyLength);
        for (let i = this.keyLength - 1; i >= 0; i--) {
            key[i] = this.alphabet[remaining % 26];
            remaining = Math.floor(remaining / 26);
        }
        const keyStr = key.join('');

        // Дешифровка
        for (let i = 0; i < cipherCodes.length; i++) {
            plaintextBuffer[i] = (cipherCodes[i] - this.charMap[keyStr.charCodeAt(i % this.keyLength)] + 26) % 26;
        }

        this.evaluateResult(plaintextBuffer, keyStr);
    }

    processBigKey(keyNum, cipherCodes, plaintextBuffer) {
        // Генерация ключа через BigInt
        let remaining = keyNum;
        const key = new Array(this.keyLength);
        for (let i = this.keyLength - 1; i >= 0; i--) {
            key[i] = this.alphabet[Number(remaining % 26n)];
            remaining = remaining / 26n;
        }
        const keyStr = key.join('');

        // Дешифровка
        for (let i = 0; i < cipherCodes.length; i++) {
            plaintextBuffer[i] = (cipherCodes[i] - this.charMap[keyStr.charCodeAt(i % this.keyLength)] + 26) % 26;
        }

        this.evaluateResult(plaintextBuffer, keyStr);
    }

    evaluateResult(plaintextBuffer, keyStr) {
        const plainText = Array.from(plaintextBuffer).map(i => this.alphabet[i]).join('');
        const score = this.scoreText(plainText);
        this.keysTested++;

        if (score > this.bestScore) {
            this.bestScore = score;
            self.postMessage({
                type: 'result',
                key: keyStr,
                plaintext: plainText,
                score: score
            });
        }

        if (this.keysTested % 50000 === 0) {
            const kps = Math.round(this.keysTested / ((performance.now() - this.startTime) / 1000));
            self.postMessage({
                type: 'progress',
                keysTested: this.keysTested,
                kps: kps
            });
        }
    }

    scoreText(text) {
        let score = 0;
        const upperText = text.toUpperCase();
        const freq = new Uint16Array(26);
        let totalLetters = 0;

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
}

new K4Worker();
