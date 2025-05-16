// English letter frequencies (percentages)
const ENGLISH_FREQ = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
    'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
    'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
    'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
    'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974,
    'Z': 0.074
};

// Common English words and patterns that might appear in K4
const COMMON_PATTERNS = [
    'THE', 'AND', 'THAT', 'HAVE', 'FOR', 'NOT', 'WITH', 'YOU', 'THIS', 'BUT',
    'HIS', 'FROM', 'THEY', 'WILL', 'WOULD', 'THERE', 'THEIR', 'WHAT', 'ABOUT',
    'WHICH', 'WHEN', 'YOUR', 'WERE', 'BERLIN', 'CLOCK', 'EAST', 'NORTH', 'WEST',
    'SOUTH', 'NORTHEAST', 'NORTHWEST', 'SOUTHEAST', 'SOUTHWEST'
];

class K4Worker {
    constructor() {
        this.alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        this.running = false;
        this.keysTested = 0;
        this.lastReportTime = 0;
        
        self.onmessage = (e) => this.handleMessage(e.data);
    }

    handleMessage(message) {
        switch (message.type) {
            case 'start':
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
        
        this.startTime = performance.now();
        this.lastReportTime = this.startTime;
        this.keysTested = 0;
        
        this.generateAndTestKeys();
    }

    *keyGenerator() {
        const indices = new Array(this.keyLength).fill(0);
        
        while (this.running) {
            // Convert indices to key
            const key = indices.map(i => this.alphabet[i]).join('');
            yield key;
            
            // Increment key (like an odometer)
            let pos = this.keyLength - 1;
            while (pos >= 0) {
                indices[pos]++;
                if (indices[pos] < 26) break;
                indices[pos] = 0;
                pos--;
            }
            
            // If we've rolled over, we're done
            if (pos < 0) break;
        }
    }

    generateAndTestKeys() {
        const generator = this.keyGenerator();
        const reportInterval = 1000; // ms
        const keysPerBatch = 1000;
        
        const processBatch = () => {
            if (!this.running) return;
            
            let batchCount = 0;
            let result = generator.next();
            
            while (!result.done && batchCount < keysPerBatch) {
                const key = result.value;
                const plaintext = this.decrypt(key);
                const score = this.scorePlaintext(plaintext);
                
                if (score > 50) { // Threshold for reporting
                    self.postMessage({
                        type: 'result',
                        key,
                        plaintext,
                        score
                    });
                }
                
                this.keysTested++;
                batchCount++;
                result = generator.next();
            }
            
            // Report progress periodically
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
                setTimeout(processBatch, 0); // Yield to event loop
            }
        };
        
        processBatch();
    }

    decrypt(key) {
        let plaintext = '';
        const keyLength = key.length;
        
        for (let i = 0; i < this.ciphertext.length; i++) {
            const cipherChar = this.ciphertext[i];
            const keyChar = key[i % keyLength];
            
            const cipherIndex = this.alphabet.indexOf(cipherChar);
            const keyIndex = this.alphabet.indexOf(keyChar);
            
            let plainIndex = (cipherIndex - keyIndex + 26) % 26;
            plaintext += this.alphabet[plainIndex];
        }
        
        return plaintext;
    }

    scorePlaintext(plaintext) {
        let score = 0;
        
        // 1. Frequency analysis
        const freq = {};
        for (const char of plaintext) {
            freq[char] = (freq[char] || 0) + 1;
        }
        
        for (const char in freq) {
            const expected = ENGLISH_FREQ[char] || 0;
            const actual = (freq[char] / plaintext.length) * 100;
            score += 100 - Math.abs(expected - actual);
        }
        
        // 2. Known plaintext bonus
        if (this.knownPlaintext && plaintext.includes(this.knownPlaintext)) {
            score += this.knownPlaintext.length * 50;
        }
        
        // 3. Common pattern bonus
        for (const pattern of COMMON_PATTERNS) {
            if (plaintext.includes(pattern)) {
                score += pattern.length * 20;
            }
        }
        
        // 4. Word boundaries bonus (spaces would be helpful)
        if (plaintext.includes(' ')) {
            score += 50;
        }
        
        return score;
    }
}

// Start the worker
new K4Worker();
