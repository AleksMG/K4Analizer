// English letter frequencies (percentages)
const ENGLISH_FREQ = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
    'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
    'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
    'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
    'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974,
    'Z': 0.074
};

// Common English words and patterns
const COMMON_PATTERNS = [
    'THE', 'AND', 'THAT', 'HAVE', 'FOR', 'NOT', 'WITH', 'YOU', 'THIS', 'BUT',
    'HIS', 'FROM', 'THEY', 'WILL', 'WOULD', 'THERE', 'THEIR', 'WHAT', 'ABOUT',
    'WHICH', 'WHEN', 'YOUR', 'WERE', 'BERLIN', 'CLOCK', 'EAST', 'NORTH', 'WEST',
    'SOUTH', 'NORTHEAST', 'NORTHWEST', 'SOUTHEAST', 'SOUTHWEST', 'SECRET', 'CODE',
    'MESSAGE', 'KRYPTOS', 'CIA', 'AGENT', 'COMPASS', 'DIRECTION', 'LATITUDE',
    'LONGITUDE', 'COORDINATES', 'GOVERNMENT', 'INTELLIGENCE', 'WASHINGTON'
];

class K4Worker {
    constructor() {
        this.alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        this.running = false;
        this.keysTested = 0;
        this.lastReportTime = 0;
        this.bestScore = 0;
        this.keyGenerator = null;
        this.workerId = 0;
        this.totalWorkers = 1;
        this.reportInterval = 500; // ms
        this.keysPerBatch = 10000;
        
        self.onmessage = (e) => this.handleMessage(e.data);
    }

    handleMessage(message) {
        switch (message.type) {
            case 'init':
                this.alphabet = message.alphabet || this.alphabet;
                this.ciphertext = message.ciphertext;
                this.keyLength = message.keyLength;
                this.knownPlaintext = message.knownPlaintext;
                this.workerId = message.workerId;
                this.totalWorkers = message.totalWorkers;
                this.keyGenerator = this.createKeyGenerator();
                break;
                
            case 'start':
                if (!this.keyGenerator) {
                    self.postMessage({ type: 'error', message: 'Worker not initialized' });
                    return;
                }
                this.running = true;
                this.startTime = performance.now();
                this.lastReportTime = this.startTime;
                this.processKeys();
                break;
                
            case 'stop':
                this.running = false;
                break;
        }
    }

    *createKeyGenerator() {
        const alphabetLength = this.alphabet.length;
        const indices = new Array(this.keyLength).fill(0);
        
        // Initialize starting position for this worker
        let carry = this.workerId;
        for (let i = 0; i < this.keyLength && carry > 0; i++) {
            indices[i] = carry % alphabetLength;
            carry = Math.floor(carry / alphabetLength);
        }
        
        while (true) {
            // Convert indices to key
            const key = indices.map(i => this.alphabet[i]).join('');
            yield key;
            
            // Increment key with worker distribution
            let pos = 0;
            let increment = this.totalWorkers;
            while (increment > 0 && pos < this.keyLength) {
                const sum = indices[pos] + increment;
                indices[pos] = sum % alphabetLength;
                increment = Math.floor(sum / alphabetLength);
                pos++;
            }
            
            if (increment > 0) break; // We've exhausted all keys
        }
    }

    processKeys() {
        if (!this.running) return;
        
        let batchCount = 0;
        let now = performance.now();
        
        while (batchCount < this.keysPerBatch) {
            const { value: key, done } = this.keyGenerator.next();
            if (done) {
                self.postMessage({ type: 'complete', keysTested: this.keysTested });
                this.running = false;
                return;
            }
            
            const plaintext = this.decrypt(key);
            const scoreInfo = this.scorePlaintext(plaintext);
            
            // Only report meaningful results
            if (scoreInfo.score > 50 || 
                (this.knownPlaintext && scoreInfo.method === 'known-text')) {
                self.postMessage({
                    type: 'result',
                    key,
                    plaintext,
                    score: scoreInfo.score,
                    method: scoreInfo.method
                });
            }
            
            this.keysTested++;
            batchCount++;
            
            // Throttle progress updates
            now = performance.now();
            if (now - this.lastReportTime >= this.reportInterval) {
                self.postMessage({
                    type: 'progress',
                    keysTested: this.keysTested
                });
                this.lastReportTime = now;
            }
        }
        
        // Use setTimeout(0) to yield to event loop and prevent UI freeze
        setTimeout(() => this.processKeys(), 0);
    }

    decrypt(key) {
        let plaintext = '';
        const keyLength = key.length;
        const alphabetLength = this.alphabet.length;
        
        for (let i = 0; i < this.ciphertext.length; i++) {
            const cipherChar = this.ciphertext[i];
            const keyChar = key[i % keyLength];
            
            const cipherIndex = this.alphabet.indexOf(cipherChar);
            const keyIndex = this.alphabet.indexOf(keyChar);
            
            if (cipherIndex === -1 || keyIndex === -1) {
                plaintext += '?';
                continue;
            }
            
            let plainIndex = (cipherIndex - keyIndex + alphabetLength) % alphabetLength;
            plaintext += this.alphabet[plainIndex];
        }
        
        return plaintext;
    }

    scorePlaintext(plaintext) {
        let score = 0;
        let method = 'basic';
        
        // 1. Known plaintext match (highest priority)
        if (this.knownPlaintext && this.knownPlaintext.length > 0) {
            const regex = new RegExp(this.knownPlaintext, 'g');
            const matches = plaintext.match(regex);
            if (matches) {
                score += 1000 * this.knownPlaintext.length * matches.length;
                method = 'known-text';
            }
        }
        
        // 2. Frequency analysis (only if standard alphabet)
        if (this.alphabet === 'ABCDEFGHIJKLMNOPQRSTUVWXYZ') {
            const freq = {};
            const totalLetters = plaintext.replace(/[^A-Z]/g, '').length || 1;
            
            for (const char of plaintext) {
                if (this.alphabet.includes(char)) {
                    freq[char] = (freq[char] || 0) + 1;
                }
            }
            
            let freqScore = 0;
            for (const char in freq) {
                const expected = ENGLISH_FREQ[char] || 0;
                const actual = (freq[char] / totalLetters) * 100;
                freqScore += 100 - Math.abs(expected - actual);
            }
            
            score += freqScore;
            if (freqScore > 500 && method === 'basic') {
                method = 'frequency';
            }
        }
        
        // 3. Common pattern matches
        let patternScore = 0;
        for (const pattern of COMMON_PATTERNS) {
            const regex = new RegExp(pattern, 'g');
            const matches = plaintext.match(regex);
            if (matches) {
                patternScore += pattern.length * 25 * matches.length;
            }
        }
        score += patternScore;
        
        if (patternScore > 100 && method === 'basic') {
            method = 'patterns';
        }
        
        // 4. Word boundaries (spaces)
        const spaceCount = (plaintext.match(/ /g) || []).length;
        score += spaceCount * 15;
        
        // 5. Penalty for non-alphabet characters
        const invalidChars = plaintext.replace(new RegExp(`[${this.alphabet} ]`, 'g'), '').length;
        score -= invalidChars * 10;
        
        return { score: Math.max(0, score), method };
    }
}

// Start the worker
new K4Worker();
