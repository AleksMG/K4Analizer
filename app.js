class K4Breaker {
    constructor() {
        this.workers = [];
        this.isRunning = false;
        this.startTime = null;
        this.keysProcessed = 0;
        this.bestScore = 0;
        this.currentTimeout = null;

        this.initControls();
        this.initWorkers();
    }

    initControls() {
        document.getElementById('startBtn').addEventListener('click', () => this.start());
        document.getElementById('stopBtn').addEventListener('click', () => this.stop());
        document.getElementById('workersSlider').addEventListener('input', (e) => {
            document.getElementById('workersValue').textContent = e.target.value;
        });
    }

    initWorkers() {
        const workerCount = parseInt(document.getElementById('workersSlider').value);
        this.workers = Array.from({ length: workerCount }, () => {
            const worker = new Worker('worker.js');
            worker.onmessage = (e) => this.handleWorkerMessage(e);
            return worker;
        });
    }

    start() {
        if (this.isRunning) return;
        
        this.resetState();
        this.isRunning = true;
        const config = this.getConfig();
        
        this.workers.forEach(worker => {
            worker.postMessage({
                type: 'START',
                config: {
                    ciphertext: config.ciphertext,
                    alphabet: config.alphabet,
                    keyLength: this.calculateKeyLength(config.ciphertext),
                    knownText: config.knownText,
                    timeout: config.timeout
                }
            });
        });

        this.startTime = performance.now();
        this.updateUI();
    }

    getConfig() {
        return {
            ciphertext: document.getElementById('ciphertext').value.toUpperCase().replace(/[^A-Z]/g, ''),
            alphabet: this.validateAlphabet(document.getElementById('customAlphabet').value),
            knownText: document.getElementById('knownText').value.toUpperCase(),
            timeout: parseInt(document.getElementById('timeout').value) * 1000
        };
    }

    validateAlphabet(alphabet) {
        if (alphabet.length !== 26) throw new Error('Alphabet must be 26 characters');
        return [...new Set(alphabet)].join('').toUpperCase();
    }

    calculateKeyLength(ciphertext) {
        const factors = this.kasiskiTest(ciphertext);
        return factors.length > 0 ? factors[0] : 8;
    }

    kasiskiTest(text, minSeqLength = 3) {
        const sequences = new Map();
        
        // Find repeating sequences
        for (let i = 0; i <= text.length - minSeqLength; i++) {
            const seq = text.substr(i, minSeqLength);
            if (!sequences.has(seq)) {
                sequences.set(seq, []);
            }
            sequences.get(seq).push(i);
        }

        // Calculate distances
        const distances = [];
        for (const [seq, positions] of sequences.entries()) {
            if (positions.length > 1) {
                for (let i = 1; i < positions.length; i++) {
                    distances.push(positions[i] - positions[i - 1]);
                }
            }
        }

        // Factor analysis
        const factorCounts = new Map();
        for (const distance of distances) {
            const factors = this.primeFactors(distance);
            factors.forEach(factor => {
                factorCounts.set(factor, (factorCounts.get(factor) || 0) + 1);
            });
        }

        return Array.from(factorCounts.entries())
            .sort((a, b) => b[1] - a[1])
            .map(([factor]) => factor);
    }

    primeFactors(n) {
        const factors = new Set();
        while (n % 2 === 0) {
            factors.add(2);
            n /= 2;
        }
        for (let i = 3; i <= Math.sqrt(n); i += 2) {
            while (n % i === 0) {
                factors.add(i);
                n /= i;
            }
        }
        if (n > 2) factors.add(n);
        return Array.from(factors);
    }

    handleWorkerMessage(event) {
        if (!this.isRunning) return;

        const { type, data } = event.data;
        switch (type) {
            case 'PROGRESS':
                this.keysProcessed += data.keysProcessed;
                break;
            
            case 'RESULT':
                this.processResult(data);
                break;
        }
    }

    processResult(result) {
        if (result.score > this.bestScore) {
            this.bestScore = result.score;
            this.displayResult(result);
            this.checkKnownTextMatch(result.text);
        }
    }

    displayResult(result) {
        const resultElement = document.createElement('div');
        resultElement.className = 'result-item';
        resultElement.innerHTML = `
            <div class="key">${result.key}</div>
            <div class="text">${result.text.substring(0, 60)}</div>
            <div class="score">${result.score.toFixed(1)}</
