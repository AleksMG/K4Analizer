const ENGLISH_FREQ = new Float32Array([
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153,
    0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056,
    2.758, 0.978, 2.360, 0.150, 1.974, 0.074
]);

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
        this.charMap = new Uint8Array(256);
        this.running = false;
        this.keysTested = 0;
        this.startTime = 0;
        this.lastReportTime = 0;
        
        // Initialize character map
        for (let i = 0; i < this.alphabet.length; i++) {
            this.charMap[this.alphabet.charCodeAt(i)] = i;
        }

        // Precompile regexes
        this.patternRegexes = COMMON_PATTERNS.map(p => new RegExp(p, 'g'));
        
        self.onmessage = (e) => this.handleMessage(e.data);
    }

    handleMessage(msg) {
        switch (msg.type) {
            case 'init':
                this.ciphertext = msg.ciphertext;
                this.ciphertextCodes = new Uint8Array(this.ciphertext.length);
                for (let i = 0; i < this.ciphertext.length; i++) {
                    this.ciphertextCodes[i] = this.charMap[this.ciphertext.charCodeAt(i)];
                }
                this.keyLength = msg.keyLength;
                this.knownPlaintext = msg.knownPlaintext || '';
                this.knownRegex = this.knownPlaintext ? new RegExp(this.knownPlaintext, 'g') : null;
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
        let bestKey = '';
        let bestText = '';
        
        // Pre-allocate arrays
        const keyCodes = new Uint8Array(this.keyLength);
        const plaintextCodes = new Uint8Array(this.ciphertext.length);
        
        for (let keyNum = startKey; keyNum < endKey && this.running; keyNum++) {
            // Generate key codes directly
            let temp = keyNum;
            for (let i = this.keyLength - 1; i >= 0; i--) {
                keyCodes[i] = temp % 26;
                temp = Math.floor(temp / 26);
            }
            
            // Fast decrypt
            for (let i = 0; i < this.ciphertext.length; i++) {
                plaintextCodes[i] = (this.ciphertextCodes[i] - keyCodes[i % this.keyLength] + 26) % 26;
            }
            
            // Convert to string only once for scoring
            const plaintext = String.fromCharCode(...plaintextCodes.map(c => c + 65));
            
            const score = this.scoreText(plaintext);
            
            this.keysTested++;
            
            if (score > bestScore) {
                bestScore = score;
                bestKey = plaintext.slice(0, this.keyLength);
                bestText = plaintext;
                self.postMessage({
                    type: 'result',
                    key: bestKey,
                    plaintext: bestText,
                    score
                });
            }
            
            // Report progress every 100k keys (reduced frequency for better performance)
            if (this.keysTested % 100000 === 0) {
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

    scoreText(text) {
        let score = 0;
        
        // 1. Known plaintext check
        if (this.knownRegex && text.match(this.knownRegex)) {
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
                const expected = ENGLISH_FREQ[i];
                const actual = (freq[i] / totalLetters) * 100;
                score += 100 - Math.abs(expected - actual);
            }
        }
        
        // 3. Common patterns
        for (let i = 0; i < this.patternRegexes.length; i++) {
            const matches = text.match(this.patternRegexes[i]);
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
