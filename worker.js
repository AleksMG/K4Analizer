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
        
        self.onmessage = (e) => this.handleMessage(e.data);
    }

    handleMessage(message) {
        switch (message.type) {
            case 'start':
                this.alphabet = message.alphabet || this.alphabet;
                this.startAttack(
                    message.ciphertext,
                    message.keyLength,
                    message.knownPlaintext,
                    message.workerId,
                    message.totalWorkers
                );
                break;
                
            case 'stop':
                this.running = false;
                break;
        }
    }

    startAttack(ciphertext, keyLength, knownPlaintext, workerId, totalWorkers) {
        this.running = true;
        this.ciphertext = ciphertext;
        this.keyLength = keyLength;
        this.knownPlaintext = knownPlaintext;
        this.workerId = workerId;
        this.totalWorkers = totalWorkers;
        this.bestScore = 0;
        
        this.startTime = performance.now();
        this.lastReportTime = this.startTime;
        this.keysTested = 0;
        
        this.generateAndTestKeys();
    }

    *keyGenerator() {
        const alphabetLength = this.alphabet.length;
        const indices = new Array(this.keyLength).fill(0);
        
        // Distribute work among workers
        for (let i = 0; i < this.workerId; i++) {
            indices[0] = (indices[0] + 1) % alphabetLength;
            if (indices[0] !== 0) break;
        }
        
        while (this.running) {
            // Convert indices to key
            const key = indices.map(i => this.alphabet[i]).join('');
            yield key;
            
            // Increment key (like an odometer)
            let pos = this.keyLength - 1;
            while (pos >= 0) {
                indices[pos] = (indices[pos] + this.totalWorkers) % alphabetLength;
                if (indices[pos] >= this.totalWorkers) break;
                pos--;
            }
            
            if (pos < 0) break;
        }
    }

    generateAndTestKeys() {
        const generator = this.keyGenerator();
        const reportInterval = 1000; // ms
        const keysPerBatch = 5000;
        
        const processBatch = () => {
            if (!this.running) return;
            
            let batchCount = 0;
            let result = generator.next();
            
            while (!result.done && batchCount < keysPerBatch) {
                const key = result.value;
                const plaintext = this.decrypt(key);
                const scoreInfo = this.scorePlaintext(plaintext);
                
                if (scoreInfo.score > this.bestScore * 0.9 || scoreInfo.score > 50) {
                    if (scoreInfo.score > this.bestScore) {
                        this.bestScore = scoreInfo.score;
                    }
                    
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
                result = generator.next();
            }
            
            // Report progress
            const now = performance.now();
            if (now - this.lastReportTime >= reportInterval) {
                self.postMessage({
                    type: 'progress',
                    keysTested: this.keysTested
                });
                this.lastReportTime = now;
            }
            
            if (result.done) {
                self.postMessage({
                    type: 'complete',
                    keysTested: this.keysTested
                });
                this.running = false;
            } else {
                setTimeout(processBatch, 0);
            }
        };
        
        processBatch();
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
            const matchIndex = plaintext.indexOf(this.knownPlaintext);
            if (matchIndex >= 0) {
                score += 1000 * this.knownPlaintext.length;
                method = 'known-text';
                
                // Extra bonus for position
                if (matchIndex === 0) score += 500;
                if (matchIndex < 10) score += 200;
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
