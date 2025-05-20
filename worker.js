// worker.js
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

class OptimizedK4Worker {
    constructor() {
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
        this.primaryTarget = 'BERLINCLOCK';
        this.currentStrategy = 'genetic';
        this.population = [];
        this.populationSize = 50;
        this.mutationRate = 0.1;
        this.crossoverRate = 0.7;
        this.keySpace = {};
        this.workQueue = [];
        this.workBatchSize = 10000;
        this.patternsRegex = this.buildPatternsRegex();

        // Initialize charMap
        this.charMap.fill(255);
        for (let i = 0; i < this.alphabet.length; i++) {
            this.charMap[this.alphabet.charCodeAt(i)] = i;
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
                case 'newWork':
                    this.addWorkToQueue(msg.work);
                    break;
            }
        };
    }

    initialize(msg) {
        this.ciphertext = msg.ciphertext.toUpperCase();
        this.keyLength = parseInt(msg.keyLength);
        this.workerId = msg.workerId || 0;
        this.totalWorkers = msg.totalWorkers || 1;
        this.keysTested = 0;
        this.bestScore = -Infinity;
        this.startTime = performance.now();
        this.initializeKeySpace();
        
        if (this.workerId === 0) {
            this.initializePopulation();
        }
    }

    initializeKeySpace() {
        this.keySpace = {
            nextKeyIndex: this.workerId,
            workerCount: this.totalWorkers,
            keysGenerated: 0
        };
    }

    buildPatternsRegex() {
        const allPatterns = [...uncommonPatterns, ...commonPatterns, this.primaryTarget];
        const escapedPatterns = allPatterns.map(p => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
        return new RegExp(escapedPatterns.join('|'), 'gi');
    }

    start() {
        this.running = true;
        this.run();
    }

    stop() {
        this.running = false;
    }

    addWorkToQueue(work) {
        this.workQueue.push(...work);
    }

    async run() {
        while (this.running) {
            if (this.workQueue.length > 0) {
                await this.processWorkQueue();
            } else {
                await this.generateNewWork();
            }
            
            if (performance.now() - this.lastReportTime > 1000) {
                this.reportProgress();
                this.lastReportTime = performance.now();
            }
            
            // Small delay to prevent blocking
            await new Promise(resolve => setTimeout(resolve, 0));
        }
    }

    async processWorkQueue() {
        const batch = this.workQueue.splice(0, this.workBatchSize);
        let bestInBatch = { score: -Infinity };

        for (const key of batch) {
            const plaintext = this.decrypt(key);
            const score = this.scoreText(plaintext);
            this.keysTested++;

            if (score > bestInBatch.score) {
                bestInBatch = { key, plaintext, score };
            }
        }

        if (bestInBatch.score > this.bestScore) {
            this.bestScore = bestInBatch.score;
            this.bestKey = bestInBatch.key;
            this.bestPlaintext = bestInBatch.plaintext;
            this.postResult(bestInBatch);
        }
    }

    async generateNewWork() {
        switch (this.currentStrategy) {
            case 'genetic':
                await this.runGeneticAlgorithm();
                break;
            case 'montecarlo':
                await this.runMonteCarlo();
                break;
            case 'hillclimbing':
                await this.runHillClimbing();
                break;
            default:
                await this.runRandomSearch();
        }
    }

    async runGeneticAlgorithm() {
        if (this.population.length === 0) {
            this.initializePopulation();
        }

        // Selection
        const parents = this.selectParents();

        // Crossover
        const offspring = this.crossover(parents);

        // Mutation
        const mutatedOffspring = this.mutate(offspring);

        // Evaluation
        const evaluated = await this.evaluatePopulation(mutatedOffspring);

        // Replacement
        this.replacePopulation(evaluated);

        // Add to work queue
        this.workQueue.push(...this.population.map(ind => ind.key));
    }

    initializePopulation() {
        this.population = [];
        for (let i = 0; i < this.populationSize; i++) {
            const key = this.generateRandomKey();
            this.population.push({
                key,
                score: -Infinity
            });
        }
    }

    generateRandomKey() {
        let key = '';
        for (let i = 0; i < this.keyLength; i++) {
            key += this.alphabet[Math.floor(Math.random() * this.alphabet.length)];
        }
        return key;
    }

    selectParents() {
        // Tournament selection
        const tournamentSize = 5;
        const parents = [];
        
        for (let i = 0; i < 2; i++) {
            let best = null;
            for (let j = 0; j < tournamentSize; j++) {
                const candidate = this.population[Math.floor(Math.random() * this.population.length)];
                if (!best || candidate.score > best.score) {
                    best = candidate;
                }
            }
            parents.push(best);
        }
        
        return parents;
    }

    crossover(parents) {
        if (Math.random() > this.crossoverRate) {
            return parents.map(p => ({ ...p }));
        }

        const crossoverPoint = Math.floor(Math.random() * (this.keyLength - 1)) + 1;
        const child1 = {
            key: parents[0].key.substring(0, crossoverPoint) + 
                 parents[1].key.substring(crossoverPoint),
            score: -Infinity
        };
        
        const child2 = {
            key: parents[1].key.substring(0, crossoverPoint) + 
                 parents[0].key.substring(crossoverPoint),
            score: -Infinity
        };
        
        return [child1, child2];
    }

    mutate(offspring) {
        return offspring.map(child => {
            if (Math.random() > this.mutationRate) return child;
            
            const mutationPoint = Math.floor(Math.random() * this.keyLength);
            const newChar = this.alphabet[Math.floor(Math.random() * this.alphabet.length)];
            const mutatedKey = child.key.substring(0, mutationPoint) + 
                              newChar + 
                              child.key.substring(mutationPoint + 1);
            
            return {
                key: mutatedKey,
                score: -Infinity
            };
        });
    }

    async evaluatePopulation(population) {
        const evaluated = [];
        
        for (const individual of population) {
            const plaintext = this.decrypt(individual.key);
            individual.score = this.scoreText(plaintext);
            evaluated.push(individual);
            
            if (individual.score > this.bestScore) {
                this.bestScore = individual.score;
                this.bestKey = individual.key;
                this.bestPlaintext = plaintext;
                this.postResult(individual);
            }
            
            this.keysTested++;
            
            // Small delay to prevent blocking
            await new Promise(resolve => setTimeout(resolve, 0));
        }
        
        return evaluated;
    }

    replacePopulation(newIndividuals) {
        // Combine and sort
        const combined = [...this.population, ...newIndividuals];
        combined.sort((a, b) => b.score - a.score);
        
        // Keep top performers
        this.population = combined.slice(0, this.populationSize);
    }

    async runMonteCarlo() {
        const batch = [];
        const batchSize = 100;
        
        for (let i = 0; i < batchSize; i++) {
            batch.push(this.generateRandomKey());
        }
        
        this.workQueue.push(...batch);
    }

    async runHillClimbing() {
        if (!this.bestKey || this.bestKey.length !== this.keyLength) {
            this.bestKey = this.generateRandomKey();
        }
        
        const neighbors = this.generateNeighbors(this.bestKey, 10);
        this.workQueue.push(...neighbors);
    }

    generateNeighbors(key, count) {
        const neighbors = [];
        
        for (let i = 0; i < count; i++) {
            const neighbor = key.split('');
            const pos = Math.floor(Math.random() * this.keyLength);
            neighbor[pos] = this.alphabet[Math.floor(Math.random() * this.alphabet.length)];
            neighbors.push(neighbor.join(''));
        }
        
        return neighbors;
    }

    async runRandomSearch() {
        const batch = [];
        const batchSize = 100;
        
        for (let i = 0; i < batchSize; i++) {
            batch.push(this.generateRandomKey());
        }
        
        this.workQueue.push(...batch);
    }

    decrypt(key) {
        let plaintext = '';
        const keyLen = this.keyLength;
        const ciphertext = this.ciphertext;
        const charMap = this.charMap;
        const alphabet = this.alphabet;

        for (let i = 0; i < ciphertext.length; i++) {
            const plainPos = (charMap[ciphertext.charCodeAt(i)] - charMap[key.charCodeAt(i % keyLen)] + 26) % 26;
            plaintext += alphabet[plainPos];
        }
        return plaintext;
    }

    scoreText(text) {
        let score = 0;
        const upperText = text.toUpperCase();

        // Fast pattern matching
        const matches = upperText.match(this.patternsRegex);
        if (!matches) return score;

        for (const match of matches) {
            const upperMatch = match.toUpperCase();
            if (upperMatch === this.primaryTarget) return 1000;
            if (uncommonPatterns.includes(upperMatch)) score += upperMatch.length * 50;
            else if (commonPatterns.includes(upperMatch)) score += upperMatch.length * 25;
        }

        // Add frequency score
        for (let i = 0; i < text.length; i++) {
            const char = text[i].toUpperCase();
            if (ENGLISH_FREQ[char]) {
                score += ENGLISH_FREQ[char] * 0.1;
            }
        }

        return score;
    }

    postResult(result) {
        self.postMessage({
            type: 'result',
            key: result.key,
            plaintext: result.plaintext,
            score: result.score
        });
    }

    reportProgress() {
        const now = performance.now();
        const elapsed = (now - this.startTime) / 1000;
        self.postMessage({
            type: 'progress',
            keysTested: this.keysTested,
            kps: Math.round(this.keysTested / elapsed),
            bestScore: this.bestScore,
            strategy: this.currentStrategy
        });
    }

    generateKey(num) {
        const key = new Array(this.keyLength);
        for (let i = this.keyLength - 1; i >= 0; i--) {
            key[i] = this.alphabet[num % 26];
            num = Math.floor(num / 26);
        }
        return key.join('');
    }
}

new OptimizedK4Worker();
