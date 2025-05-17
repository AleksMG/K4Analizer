const ENGLISH_FREQ = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
    'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
    'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
    'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
    'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974,
    'Z': 0.074
};

// Hyper-optimized precomputed data
const FREQ_VECTOR = new Float32Array(Object.values(ENGLISH_FREQ));
const PATTERNS = new Map([
    [3, ['THE', 'AND', 'YOU', 'BUT', 'HIS', 'HER', 'WAS', 'FOR', 'NOT']],
    [4, ['THAT', 'WITH', 'HAVE', 'THIS', 'WILL', 'YOUR', 'FROM', 'THEY']],
    [5, ['WHICH', 'THERE', 'THEIR', 'ABOUT', 'WOULD', 'COULD', 'SHOULD']],
    [6, ['BECAUSE', 'PEOPLE', 'NUMBER', 'SYSTEM', 'SECRET', 'KRYPTOS']]
]);

class K4TurboWorker {
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
        
        // Precompute character map
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
        const cipherCodes = this.precomputeCipher();
        const cipherLen = cipherCodes.length;
        const keyBuffer = new Uint8Array(this.keyLength);
        const plainBuffer = new Uint8Array(cipherLen);
        const keySpace = 26 ** this.keyLength;
        const chunkSize = this.calculateChunkSize();

        let bestScore = 0;
        let baseKey = this.workerId;

        while (this.running && baseKey < keySpace) {
            this.processChunk(baseKey, Math.min(baseKey + chunkSize, keySpace), 
                cipherCodes, keyBuffer, plainBuffer);
            baseKey += chunkSize * this.totalWorkers;
        }

        self.postMessage({ type: 'complete' });
    }

    processChunk(start, end, cipherCodes, keyBuffer, plainBuffer) {
        const keyCodes = new Uint8Array(this.keyLength);
        const kpCheck = this.knownPlaintext ? 
            new Uint8Array(this.knownPlaintext.split('').map(c => c.charCodeAt(0))) : null;

        for (let keyNum = start; keyNum < end && this.running; keyNum++) {
            this.generateKey(keyNum, keyBuffer);
            this.decrypt(cipherCodes, keyBuffer, plainBuffer);
            
            const score = this.quantumScore(plainBuffer, kpCheck);
            this.keysTested++;

            if (score > bestScore) {
                bestScore = score;
                const key = String.fromCharCode(...keyBuffer.map(c => c + 65));
                const plaintext = String.fromCharCode(...plainBuffer);
                self.postMessage({ type: 'result', key, plaintext, score });
            }

            if (performance.now() - this.startTime > 1000) {
                this.reportProgress();
                this.startTime = performance.now();
            }
        }
    }

    precomputeCipher() {
        const codes = new Uint8Array(this.ciphertext.length);
        const A = 'A'.charCodeAt(0);
        for (let i = 0; i < codes.length; i++) {
            codes[i] = this.ciphertext.charCodeAt(i) - A;
        }
        return codes;
    }

    generateKey(num, buffer) {
        let n = num;
        for (let i = this.keyLength - 1; i >= 0; i--) {
            buffer[i] = n % 26;
            n = Math.floor(n / 26);
        }
    }

    decrypt(cipher, key, output) {
        const keyLen = key.length;
        for (let i = 0; i < cipher.length; i++) {
            output[i] = (cipher[i] - key[i % keyLen] + 26) % 26 + 65;
        }
    }

    quantumScore(buffer, kpCheck) {
        let score = 0;
        const len = buffer.length;
        const freq = new Uint16Array(26);
        
        // 1. Known plaintext check
        if (kpCheck) {
            let found = false;
            outer: for (let i = 0; i <= len - kpCheck.length; i++) {
                for (let j = 0; j < kpCheck.length; j++) {
                    if (buffer[i + j] !== kpCheck[j]) continue outer;
                }
                found = true;
                break;
            }
            if (!found) return 0;
            score += 1000 * kpCheck.length;
        }

        // 2. Frequency analysis
        let total = 0;
        for (let i = 0; i < len; i++) {
            const c = buffer[i] - 65;
            if (c < 0 || c > 25) continue;
            freq[c]++;
            total++;
        }

        if (total > 0) {
            const multiplier = 100 / total;
            for (let i = 0; i < 26; i++) {
                score += 100 - Math.abs(FREQ_VECTOR[i] - freq[i] * multiplier);
            }
        }

        // 3. Pattern matching
        const str = String.fromCharCode(...buffer);
        for (const [len, patterns] of PATTERNS) {
            for (const p of patterns) {
                let pos = -1;
                while ((pos = str.indexOf(p, pos + 1)) !== -1) {
                    score += len * 50;
                }
            }
        }

        return Math.round(score);
    }

    calculateChunkSize() {
        // Динамический размер чанка на основе длины ключа
        return this.keyLength <= 5 ? 1e5 : 
               this.keyLength <= 7 ? 1e4 : 
               this.keyLength <= 9 ? 1e3 : 100;
    }

    reportProgress() {
        self.postMessage({
            type: 'progress',
            keysTested: this.keysTested,
            kps: Math.round(this.keysTested / ((performance.now() - this.startTime) / 1000))
        });
    }
}

new K4TurboWorker();
