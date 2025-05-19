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
    'WHICH', 'WHEN', 'YOUR', 'WERE', 'CIA', 'NASA', 'FBI', 'USA', 'RUS',
    'AGENT', 'CODE', 'SECRET', 'MESSAGE', 'WORLD', 'COUNTRY', 'CITY', 'TOWN',
    'PERSON', 'MAN', 'ENEMY', 'ALLY'
];

const uncommonPatterns = [
    'KRYPTOS', 'BERLINCLOCK', 'EAST', 'NORTH', 'WEST',
    'SOUTH', 'NORTHEAST', 'NORTHWEST', 'SOUTHEAST', 'SOUTHWEST', 'COMPASS', 'LIGHT',
    'LATITUDE', 'LONGITUDE', 'COORDINATE', 'SHADOW', 'WALL', 'UNDERGROUND', 'PALIMPSEST',
    'ABSCISSA', 'CLOCKWISE', 'DIAGONAL', 'VERTICAL',
    'HORIZONTAL', 'OBELISK', 'PYRAMID', 'SCULPTURE', 'CIPHER', 'ENCRYPT', 'DECRYPT',
    'ALPHABET', 'LETTER', 'SYMBOL', 'SLOWLY', 'DESPARATELY', 'WEAKLY', 'SCRATCHES',
    'LAYER', 'QUESTION', 'ANSWER', 'SOLUTION', 'HIDDEN', 'COVER', 'REVEAL', 'TRUTH', 'MISSION'
];

class K4Worker {
    constructor() {
        this.alphabet = 'ZXWVUQNMLJIHGFEDCBASOTPYRK';
        this.charMap = {};
        this.running = false;
        this.ciphertext = '';
        this.keyLength = 0;
        this.workerId = 0;
        this.totalWorkers = 1;
        this.keysTested = 0;
        this.bestScore = -Infinity;
        this.bestKey = '';
        this.bestPlaintext = '';

        // Initialize charMap
        for (let i = 0; i < this.alphabet.length; i++) {
            this.charMap[this.alphabet[i]] = i;
        }

        self.onmessage = (e) => {
            const msg = e.data;
            switch (msg.type) {
                case 'init':
                    this.initialize(msg);
                    break;
                case 'start':
                    this.start();
                    break;
                case 'stop':
                    this.stop();
                    break;
            }
        };
    }

    initialize(msg) {
        this.ciphertext = msg.ciphertext.toUpperCase();
        this.keyLength = parseInt(msg.keyLength);
        this.workerId = parseInt(msg.workerId) || 0;
        this.totalWorkers = parseInt(msg.totalWorkers) || 1;
        this.resetState();
    }

    resetState() {
        this.keysTested = 0;
        this.bestScore = -Infinity;
        this.bestKey = '';
        this.bestPlaintext = '';
        this.running = false;
    }

    start() {
        if (!this.running) {
            this.running = true;
            this.startTime = performance.now();
            this.processKeys();
        }
    }

    stop() {
        this.running = false;
    }

    generateKey(num) {
        const key = new Array(this.keyLength);
        for (let i = this.keyLength - 1; i >= 0; i--) {
            key[i] = this.alphabet[num % 26];
            num = Math.floor(num / 26);
        }
        return key.join('');
    }

    decrypt(key) {
        let plaintext = '';
        for (let i = 0; i < this.ciphertext.length; i++) {
            const plainPos = (this.charMap[this.ciphertext[i]] - this.charMap[key[i % key.length]] + 26) % 26;
            plaintext += this.alphabet[plainPos];
        }
        return plaintext;
    }

    scoreText(text) {
        const upperText = text.toUpperCase();
        let score = 0;

        // Frequency analysis
        const freq = new Array(26).fill(0);
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
                const expected = ENGLISH_FREQ[this.alphabet[i]] || 0;
                const actual = (freq[i] / totalLetters) * 100;
                score += 100 - Math.abs(expected - actual);
            }
        }

        // Check patterns
        const checkPatterns = (patterns, multiplier) => {
            for (const pattern of patterns) {
                let pos = -1;
                while ((pos = upperText.indexOf(pattern, pos + 1)) !== -1) {
                    score += pattern.length * multiplier;
                }
            }
        };

        checkPatterns(commonPatterns, 25);
        checkPatterns(uncommonPatterns, 50);

        // Special bonus for primary target
        if (upperText.includes('BERLINCLOCK')) {
            score += 1000;
        }

        return Math.round(score);
    }

    async processKeys() {
        const totalKeys = Math.pow(26, this.keyLength);
        const keysPerWorker = Math.ceil(totalKeys / this.totalWorkers);
        const startKey = this.workerId * keysPerWorker;
        const endKey = Math.min(startKey + keysPerWorker, totalKeys);
        const reportInterval = 1000; // ms
        let lastReportTime = 0;

        for (let keyNum = startKey; keyNum < endKey && this.running; keyNum++) {
            const key = this.generateKey(keyNum);
            const plaintext = this.decrypt(key);
            const score = this.scoreText(plaintext);
            this.keysTested++;

            if (score > this.bestScore) {
                this.bestScore = score;
                this.bestKey = key;
                this.bestPlaintext = plaintext;
                self.postMessage({
                    type: 'result',
                    key: key,
                    plaintext: plaintext,
                    score: score
                });
            }

            // Periodic progress reports
            const now = performance.now();
            if (now - lastReportTime > reportInterval) {
                lastReportTime = now;
                const elapsed = (now - this.startTime) / 1000;
                const kps = elapsed > 0 ? Math.round(this.keysTested / elapsed) : 0;
                const completion = ((keyNum - startKey) / (endKey - startKey)) * 100;

                self.postMessage({
                    type: 'progress',
                    workerId: this.workerId,
                    keysTested: this.keysTested,
                    kps: kps,
                    completion: completion.toFixed(2)
                });

                // Prevent UI freeze
                await new Promise(resolve => setTimeout(resolve, 0));
            }
        }

        if (this.running) {
            self.postMessage({
                type: 'completed',
                workerId: this.workerId,
                keysTested: this.keysTested
            });
        }
    }
}

new K4Worker();
