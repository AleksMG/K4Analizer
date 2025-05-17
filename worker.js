const ENGLISH_FREQ = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
    'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
    'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
    'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
    'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974,
    'Z': 0.074
};

// Предварительные вычисления для оптимизации
const ENGLISH_FREQ_ARRAY = new Float32Array(Object.values(ENGLISH_FREQ));
const COMMON_REGEX = [
    'THE', 'AND', 'THAT', 'HAVE', 'FOR', 'NOT', 'WITH', 'YOU', 'THIS', 'BUT',
    'HIS', 'FROM', 'THEY', 'WILL', 'WOULD', 'THERE', 'THEIR', 'WHAT', 'ABOUT',
    'WHICH', 'WHEN', 'YOUR', 'WERE', 'BERLIN', 'CLOCK', 'EAST', 'NORTH', 'WEST',
    'SOUTH', 'NORTHEAST', 'NORTHWEST', 'SOUTHEAST', 'SOUTHWEST', 'SECRET', 'CODE',
    'MESSAGE', 'KRYPTOS', 'CIA', 'AGENT', 'COMPASS', 'LIGHT', 'LATITUDE',
    'LONGITUDE', 'COORDINATE', 'SHADOW', 'WALL', 'UNDERGROUND'
].map(p => new RegExp(p, 'g'));

// Предрасчитанная таблица модуля 26
const MOD26 = new Int8Array(512);
for (let i = 0; i < MOD26.length; i++) {
    MOD26[i] = (i % 26 + 26) % 26;
}

class K4Worker {
    constructor() {
        this.alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
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
        
        // Инициализация charMap (оптимизировано)
        const A = 'A'.charCodeAt(0);
        for (let i = 0; i < 26; i++) {
            this.charMap[A + i] = i;
        }

        self.onmessage = (e) => this.handleMessage(e.data);
    }

    handleMessage(msg) {
        switch (msg.type) {
            case 'init':
                Object.assign(this, msg);
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
        const totalKeys = 26 ** this.keyLength;
        const keysPerWorker = Math.ceil(totalKeys / this.totalWorkers);
        const startKey = this.workerId * keysPerWorker;
        const endKey = Math.min(startKey + keysPerWorker, totalKeys);
        const cipherLen = this.ciphertext.length;
        const cipherCodes = this.precomputeCipher();
        const keyBuffer = new Uint8Array(this.keyLength);
        const plainCodes = new Uint8Array(cipherLen);
        const checkKnown = this.knownPlaintext.length > 0;
        const knownPattern = checkKnown ? new RegExp(this.knownPlaintext) : null;
        
        let bestScore = 0;
        let bestKey = '';
        const CHUNK_SIZE = 100000;
        let currentKey = startKey;

        while (this.running && currentKey < endKey) {
            const chunkEnd = Math.min(currentKey + CHUNK_SIZE, endKey);
            
            for (let keyNum = currentKey; keyNum < chunkEnd; keyNum++) {
                const key = this.generateKeyOptimized(keyNum, keyBuffer);
                this.decryptOptimized(cipherCodes, key, plainCodes);
                
                const plaintext = String.fromCharCode(...plainCodes);
                const score = this.scoreOptimized(plaintext, checkKnown, knownPattern);
                
                this.keysTested++;
                
                if (score > bestScore) {
                    bestScore = score;
                    bestKey = key;
                    self.postMessage({
                        type: 'result',
                        key,
                        plaintext,
                        score
                    });
                }
            }
            
            this.reportProgressIfNeeded();
            currentKey = chunkEnd;
        }
        
        if (this.running) {
            self.postMessage({ type: 'complete' });
        }
    }

    precomputeCipher() {
        const cipherCodes = new Uint8Array(this.ciphertext.length);
        const A = 'A'.charCodeAt(0);
        for (let i = 0; i < this.ciphertext.length; i++) {
            cipherCodes[i] = this.ciphertext.charCodeAt(i) - A;
        }
        return cipherCodes;
    }

    generateKeyOptimized(num, buffer) {
        let remaining = num;
        for (let i = this.keyLength - 1; i >= 0; i--) {
            buffer[i] = remaining % 26;
            remaining = Math.floor(remaining / 26);
        }
        return String.fromCharCode(...buffer.map(c => c + 65));
    }

    decryptOptimized(cipherCodes, key, plainCodes) {
        const keyCodes = new Uint8Array(key.length);
        const A = 'A'.charCodeAt(0);
        for (let i = 0; i < key.length; i++) {
            keyCodes[i] = key.charCodeAt(i) - A;
        }
        
        const keyLen = key.length;
        for (let i = 0; i < cipherCodes.length; i++) {
            plainCodes[i] = MOD26[cipherCodes[i] - keyCodes[i % keyLen] + 26];
        }
        
        for (let i = 0; i < plainCodes.length; i++) {
            plainCodes[i] += 65;
        }
    }

    scoreOptimized(text, checkKnown, knownPattern) {
        if (checkKnown && !knownPattern.test(text)) return 0;
        
        let score = 0;
        const freq = new Uint16Array(26);
        let totalLetters = 0;
        const len = text.length;
        
        // Частотный анализ
        for (let i = 0; i < len; i++) {
            const code = text.charCodeAt(i) - 65;
            if (code < 0 || code > 25) continue;
            freq[code]++;
            totalLetters++;
        }
        
        if (totalLetters > 0) {
            const multiplier = 100 / totalLetters;
            for (let i = 0; i < 26; i++) {
                score += 100 - Math.abs(ENGLISH_FREQ_ARRAY[i] - freq[i] * multiplier);
            }
        }
        
        // Проверка паттернов
        for (const re of COMMON_REGEX) {
            re.lastIndex = 0;
            let count = 0;
            while (re.test(text)) count++;
            score += count * re.source.length * 25;
        }
        
        if (checkKnown) {
            score += 1000 * this.knownPlaintext.length;
        }
        
        return score | 0;
    }

    reportProgressIfNeeded() {
        const now = performance.now();
        if (now - this.lastReportTime > 1000) {
            this.lastReportTime = now;
            const kps = (this.keysTested / ((now - this.startTime) / 1000)) | 0;
            self.postMessage({
                type: 'progress',
                keysTested: this.keysTested,
                kps
            });
        }
    }
}

new K4Worker();
