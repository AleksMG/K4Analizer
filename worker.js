// file: K4Worker.js
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
    'PERSON', 'KEY', 'ENEMY', 'ALLY', 'OF', 'TO'
];

const uncommonPatterns = [
    'KRYPTOS', 'BERLINCLOCK', 'EAST', 'NORTH', 'WEST', 'BERLIN', 'CLOCK',
    'SOUTH', 'NORTHEAST', 'NORTHWEST', 'SOUTHEAST', 'SOUTHWEST', 'COMPASS', 'LIGHT',
    'LATITUDE', 'LONGITUDE', 'COORDINATE', 'SHADOW', 'WALL', 'UNDERGROUND', 'PALIMPSEST',
    'ABSCISSA', 'CLOCKWISE', 'DIAGONAL', 'VERTICAL',
    'HORIZONTAL', 'OBELISK', 'PYRAMID', 'SCULPTURE', 'CIPHER', 'ENCRYPT', 'DECRYPT',
    'ALPHABET', 'LETTER', 'SYMBOL', 'SLOWLY', 'DESPARATELY', 'WEAKLY', 'DEEP',
    'LAYER', 'QUESTION', 'ANSWER', 'SOLUTION', 'HIDDEN', 'COVER', 'REVEAL', 'TRUTH', 'MISSION'
];

class OptimizedK4Worker {
    constructor() {
        // Original properties
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
        this.bestScore = -Infinity;
        this.bestKey = '';
        this.bestPlaintext = '';
        this.testedKeys = new Set();
        this.totalKeysToTest = 0;
        this.completed = false;
        this.primaryTarget = 'BERLINCLOCK';
        this.primaryTargetFound = false;
        this.primaryResults = [];

        // Optimization enhancements
        this.adaptiveBlockSize = 50000;
        this.currentStrategy = 'hybrid';
        this.keyMutationRate = 0.2;
        this.bloomFilter = null;
        this.useBloom = false;
        this.lastStrategies = [];
        this.strategyWeights = {
            fullScan: 4,
            genetic: 3,
            optimize: 2
        };

        // Initialize character map
        this.charMap.fill(255);
        for (let i = 0; i < this.alphabet.length; i++) {
            this.charMap[this.alphabet.charCodeAt(i)] = i;
        }

        // Message handler (preserve original interface)
        self.onmessage = (e) => {
            const msg = e.data;
            switch (msg.type) {
                case 'init':
                    this.handleInit(msg);
                    break;
                case 'start':
                    this.handleStart();
                    break;
                case 'stop':
                    this.running = false;
                    break;
                case 'updateBestKey':
                    if (msg.score > this.bestScore) {
                        this.bestScore = msg.score;
                        this.bestKey = msg.key;
                        this.bestPlaintext = msg.plaintext;
                    }
                    break;
            }
        };
    }

    handleInit(msg) {
        this.ciphertext = msg.ciphertext.toUpperCase();
        this.keyLength = parseInt(msg.keyLength);
        this.workerId = msg.workerId || 0;
        this.totalWorkers = msg.totalWorkers || 1;
        this.keysTested = 0;
        this.bestScore = -Infinity;
        this.bestKey = this.generateKey(0);
        this.testedKeys.clear();
        this.totalKeysToTest = Math.pow(26, this.keyLength);
        this.completed = false;
        this.primaryTargetFound = false;
        this.primaryResults = [];
        this.useBloom = this.keyLength > 5;
        if (this.useBloom) this.initBloomFilter();
    }

    handleStart() {
        if (!this.running && !this.completed) {
            this.running = true;
            this.startTime = performance.now();
            this.lastImprovementTime = this.startTime;
            this.run();
        }
    }

    initBloomFilter() {
        this.bloomFilter = {
            buckets: new Uint32Array(1024),
            add: function(key) {
                const h = this.hash(key);
                this.buckets[h % 1024] |= 1 << (h % 32);
            },
            has: function(key) {
                const h = this.hash(key);
                return !!(this.buckets[h % 1024] & (1 << (h % 32)));
            },
            hash: function(key) {
                let hash = 0;
                for (let i = 0; i < key.length; i++) {
                    hash = (hash << 5) - hash + key.charCodeAt(i);
                }
                return Math.abs(hash);
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

    decrypt(key) {
        let plaintext = '';
        for (let i = 0; i < this.ciphertext.length; i++) {
            const plainPos = (this.charMap[this.ciphertext.charCodeAt(i)] - 
                           this.charMap[key.charCodeAt(i % this.keyLength)] + 26) % 26;
            plaintext += this.alphabet[plainPos];
        }
        return plaintext;
    }

    async run() {
        const startKey = this.workerId * Math.floor(this.totalKeysToTest / this.totalWorkers);
        const endKey = (this.workerId === this.totalWorkers - 1)
            ? this.totalKeysToTest
            : startKey + Math.floor(this.totalKeysToTest / this.totalWorkers);

        if (this.keyLength > 8) {
            await this.geneticSearch();
        } else {
            await this.adaptiveScan(startKey, endKey);
        }

        if (!this.running) return;
        
        this.completed = true;
        self.postMessage({
            type: 'completed',
            keysTested: this.keysTested,
            bestScore: this.bestScore,
            bestKey: this.bestKey,
            bestPlaintext: this.bestPlaintext
        });
    }

    async adaptiveScan(start, end) {
        const blockSize = Math.min(this.adaptiveBlockSize, end - start);
        let current = start;
        
        while (current < end && this.running) {
            const blockEnd = Math.min(current + blockSize, end);
            await this.processBlock(current, blockEnd);
            current = blockEnd;
            this.updateStrategy();
            this.checkProgress();
        }
    }

    async processBlock(start, end) {
        for (let i = start; i < end; i++) {
            if (!this.running) break;
            
            const key = this.generateKey(i);
            if (this.isKeyTested(key)) continue;
            this.markKeyTested(key);
            
            const plaintext = this.decrypt(key);
            const score = this.scoreText(plaintext);
            this.keysTested++;
            
            if (score > this.bestScore) {
                this.updateBest(key, plaintext, score);
            }
        }
    }

    isKeyTested(key) {
        return this.useBloom
            ? this.bloomFilter.has(key)
            : this.testedKeys.has(key);
    }

    markKeyTested(key) {
        if (this.useBloom) {
            this.bloomFilter.add(key);
        } else {
            this.testedKeys.add(key);
        }
    }

    scoreText(text) {
        // Original scoring logic
        let score = 0;
        const upperText = text.toUpperCase();
        
        // Frequency analysis
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
                const expected = ENGLISH_FREQ[this.alphabet[i]] || 0;
                const actual = (freq[i] / totalLetters) * 100;
                score += 100 - Math.abs(expected - actual);
            }
        }

        // Pattern matching
        for (const pattern of [...commonPatterns, ...uncommonPatterns]) {
            let pos = -1;
            while ((pos = upperText.indexOf(pattern, pos + 1)) !== -1) {
                score += pattern.length * (commonPatterns.includes(pattern) ? 25 : 50);
            }
        }

        // New heuristics
        const wordBonus = (text.match(/[A-Z]{3,}/g) || []).length * 10;
        const repeatPenalty = (text.match(/([A-Z])\1{2,}/g) || []).length * 15;
        
        return Math.round(score + wordBonus - repeatPenalty);
    }

    async geneticSearch() {
        let population = Array.from({length: 50}, () => this.generateRandomKey());
        
        while (this.running) {
            const results = await Promise.all(
                population.map(key => this.evaluateKey(key))
            );
            
            const best = results.reduce((a, b) => a.score > b.score ? a : b);
            if (best.score > this.bestScore) {
                this.updateBest(best.key, best.plaintext, best.score);
            }
            
            population = this.createNextGeneration(population, results);
            this.checkProgress();
        }
    }

    async evaluateKey(key) {
        const plaintext = this.decrypt(key);
        return {
            key,
            plaintext,
            score: this.scoreText(plaintext)
        };
    }

    createNextGeneration(population, results) {
        const sorted = [...results].sort((a, b) => b.score - a.score);
        const top10 = sorted.slice(0, 10);
        
        return [
            ...top10.map(i => i.key),
            ...top10.flatMap(i => [
                this.mutateKey(i.key),
                this.crossover(i.key, top10[Math.floor(Math.random() * 10)].key)
            ]),
            ...Array.from({length: 10}, () => this.generateRandomKey())
        ];
    }

    generateRandomKey() {
        return Array.from({length: this.keyLength}, 
            () => this.alphabet[Math.floor(Math.random() * 26)]).join('');
    }

    mutateKey(key) {
        return key.split('').map((c, i) => 
            Math.random() < this.keyMutationRate
                ? this.alphabet[Math.floor(Math.random() * 26)]
                : c
        ).join('');
    }

    crossover(key1, key2) {
        const point = Math.floor(Math.random() * this.keyLength);
        return key1.slice(0, point) + key2.slice(point);
    }

    updateBest(key, plaintext, score) {
        this.bestScore = score;
        this.bestKey = key;
        this.bestPlaintext = plaintext;
        this.lastImprovementTime = performance.now();
        
        self.postMessage({
            type: 'result',
            key: this.bestKey,
            plaintext: this.bestPlaintext,
            score: this.bestScore
        });
    }

    updateStrategy() {
        const timeSinceImprovement = performance.now() - this.lastImprovementTime;
        
        if (timeSinceImprovement > 10000) {
            this.currentStrategy = this.chooseNewStrategy();
            this.adaptiveBlockSize = Math.max(1000, 
                Math.min(100000, Math.round(this.adaptiveBlockSize * 0.8)));
        }
    }

    chooseNewStrategy() {
        const strategies = Object.keys(this.strategyWeights);
        const weights = Object.values(this.strategyWeights);
        const total = weights.reduce((a, b) => a + b, 0);
        let random = Math.random() * total;
        
        for (let i = 0; i < strategies.length; i++) {
            if (random < weights[i]) return strategies[i];
            random -= weights[i];
        }
        return strategies[0];
    }

    checkProgress() {
        const now = performance.now();
        if (now - this.lastReportTime > 1000) {
            const elapsed = (now - this.startTime) / 1000;
            const kps = elapsed > 0 ? Math.round(this.keysTested / elapsed) : 0;
            const completion = Math.min(100, 
                (this.keysTested / (this.totalKeysToTest / this.totalWorkers)) * 100);
            
            // Preserve original message format
            self.postMessage({
                type: 'progress',
                keysTested: this.keysTested,
                totalKeys: this.totalKeysToTest,
                kps: kps,
                completion: completion.toFixed(2),
                bestScore: this.bestScore,
                bestKey: this.bestKey,
                bestPlaintext: this.bestPlaintext
            });
            
            this.lastReportTime = now;
        }
    }
}

// Start worker
new OptimizedK4Worker();
