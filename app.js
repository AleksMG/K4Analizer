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
            this.initWorkers();
        });
    }

    initWorkers() {
        this.workers.forEach(worker => worker.terminate());
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
        this.currentTimeout = setTimeout(() => this.stop(), config.timeout);
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
        if (alphabet.length !== 26) {
            alert('Alphabet must be exactly 26 characters!');
            throw new Error('Invalid alphabet length');
        }
        return [...new Set(alphabet)].join('').toUpperCase();
    }

    calculateKeyLength(ciphertext) {
        const factors = this.kasiskiTest(ciphertext);
        return factors.length > 0 ? factors[0] : 8;
    }

    kasiskiTest(text, minSeqLength = 3) {
        const sequences = new Map();
        
        for (let i = 0; i <= text.length - minSeqLength; i++) {
            const seq = text.substr(i, minSeqLength);
            sequences.set(seq, [...(sequences.get(seq) || [], i]);
        }

        const distances = [];
        for (const [seq, positions] of sequences.entries()) {
            if (positions.length > 1) {
                for (let i = 1; i < positions.length; i++) {
                    distances.push(positions[i] - positions[i - 1]);
                }
            }
        }

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
            <div class="score">${result.score.toFixed(1)}</div>
        `;
        document.getElementById('resultsList').prepend(resultElement);
    }

    checkKnownTextMatch(text) {
        const knownText = document.getElementById('knownText').value.toUpperCase();
        if (!knownText || !text.includes(knownText)) return;

        const highlighted = text.replace(
            new RegExp(knownText, 'gi'),
            '<span class="highlight-match">$&</span>'
        );

        document.getElementById('textComparison').innerHTML = `
            <div class="match-alert">🎉 Match Found!</div>
            <div class="comparison-text">${highlighted}</div>
        `;
    }

    updateUI() {
        if (!this.isRunning) return;

        const elapsed = (performance.now() - this.startTime) / 1000;
        const keysPerSecond = (this.keysProcessed / elapsed).toFixed(1);

        document.getElementById('elapsedTime').textContent = `${elapsed.toFixed(1)}s`;
        document.getElementById('keysTried').textContent = this.keysProcessed.toLocaleString();
        document.getElementById('keysPerSec').textContent = keysPerSecond;
        document.getElementById('bestScore').textContent = this.bestScore.toFixed(1);
        document.getElementById('progressBar').style.width = 
            `${Math.min(100, (elapsed / (this.getConfig().timeout / 1000)) * 100}%`;

        requestAnimationFrame(() => this.updateUI());
    }

    stop() {
        this.isRunning = false;
        this.workers.forEach(worker => worker.postMessage({ type: 'STOP' }));
        clearTimeout(this.currentTimeout);
        document.getElementById('startBtn').disabled = false;
    }

    resetState() {
        this.keysProcessed = 0;
        this.bestScore = 0;
        document.getElementById('resultsList').innerHTML = '';
        document.getElementById('textComparison').innerHTML = '';
        document.getElementById('progressBar').style.width = '0%';
    }
}

window.addEventListener('load', () => new K4Breaker());
