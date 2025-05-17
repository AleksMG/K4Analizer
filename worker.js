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
        this.alphabetCodes = new Uint8Array(26);
        for (let i = 0; i < 26; i++) {
            this.alphabetCodes[i] = 65 + i;
        }
        
        this.charMap = new Uint8Array(256);
        for (let i = 0; i < this.alphabet.length; i++) {
            this.charMap[this.alphabet.charCodeAt(i)] = i;
            this.charMap[this.alphabet.toLowerCase().charCodeAt(i)] = i;
        }

        this.running = false;
        this.ciphertext = '';
        this.cipherCodes = null;
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
                this.knownPlaintext = (msg.knownPlaintext || '').toUpperCase();
                this.workerId = msg.workerId || 0;
                this.totalWorkers = msg.totalWorkers || 1;
                this.keysTested = 0;
                
                // Preprocess ciphertext once
                this.cipherCodes = new Uint8Array(this.ciphertext.length);
                for (let i = 0; i < this.ciphertext.length; i++) {
                    const code = this.ciphertext.charCodeAt(i);
                    this.cipherCodes[i] = this.charMap[code] ?? 255; // 255 for non-alphabet
                }
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
        const keyCodes = new Uint8Array(this.keyLength);
        const plaintextCodes = new Uint8Array(this.cipherCodes.length);
        
        // Main optimized loop
        for (let keyNum = startKey; keyNum < endKey && this.running; keyNum++) {
            // Generate key codes directly
            let remaining = keyNum;
            for (let i = this.keyLength - 1; i >= 0; i--) {
                keyCodes[i] = remaining % 26;
                remaining = Math.floor(remaining / 26);
            }
            
            // Decrypt
            for (let i = 0; i < this.cipherCodes.length; i++) {
                const cipherCode = this.cipherCodes[i];
                plaintextCodes[i] = cipherCode < 26 
                    ? (cipherCode - keyCodes[i % this.keyLength] + 26) % 26
                    : cipherCode; // Keep non-alphabet chars
            }
            
            // Score
            const score = this.scoreText(plaintextCodes);
            this.keysTested++;
            
            if (score > bestScore) {
                bestScore = score;
                bestKey = Array.from(keyCodes).map(c => String.fromCharCode(c + 65)).join('');
                
                // Convert to string only for the best candidate
                let plaintext = '';
                for (let i = 0; i < plaintextCodes.length; i++) {
                    const code = plaintextCodes[i];
                    plaintext += code < 26 
                        ? String.fromCharCode(code + 65) 
                        : String.fromCharCode(code);
                }
                bestText = plaintext;
                
                self.postMessage({
                    type: 'result',
                    key: bestKey,
                    plaintext: bestText,
                    score: bestScore
                });
            }
            
            // Progress reporting
            if (this.keysTested % 50000 === 0) {
                const now = performance.now();
                const elapsed = (now - this.startTime) / 1000;
                const kps = Math.round(this.keysTested / elapsed);
                
                self.postMessage({
                    type: 'progress',
                    keysTested: this.keysTested,
                    kps: kps
                });
            }
        }
        
        if (this.running) {
            self.postMessage({ type: 'complete' });
        }
    }

    scoreText(plaintextCodes) {
        let score = 0;
        const freq = new Uint16Array(26);
        let totalLetters = 0;
        
        // Frequency analysis
        for (let i = 0; i < plaintextCodes.length; i++) {
            const code = plaintextCodes[i];
            if (code < 26) {
                freq[code]++;
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
        
        // Known plaintext check
        if (this.knownPlaintext && this.knownPlaintext.length > 0) {
            const plaintext = Array.from(plaintextCodes)
                .map(c => c < 26 ? String.fromCharCode(c + 65) : '')
                .join('');
            
            if (plaintext.includes(this.knownPlaintext)) {
                score += 1000 * this.knownPlaintext.length;
            }
        }
        
        // Common patterns (optimized)
        const plaintextLetters = Array.from(plaintextCodes)
            .filter(c => c < 26)
            .map(c => String.fromCharCode(c + 65))
            .join('');
        
        for (const pattern of COMMON_PATTERNS) {
            let pos = -1;
            while ((pos = plaintextLetters.indexOf(pattern, pos + 1)) !== -1) {
                score += pattern.length * 25;
            }
        }
        
        return Math.round(score);
    }
}

new K4Worker();
