class K4Decryptor {
    constructor() {
        this.workers = [];
        this.isRunning = false;
        this.startTime = null;
        this.keysTested = 0;
        this.keysPerSecond = 0;
        this.lastUpdateTime = 0;
        this.bestScore = 0;
        this.bestResult = null;
        this.totalKeys = 0;
        this.alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        this.alphabetShift = 0;
        this.workerStatus = {};
        this.lastProgressUpdate = 0;
        this.resultsCache = new Set();

        this.initElements();
        this.initEventListeners();
        this.updateTotalKeys();
    }

    initElements() {
        this.elements = {
            startBtn: document.getElementById('startBtn'),
            stopBtn: document.getElementById('stopBtn'),
            shuffleBtn: document.getElementById('shuffleBtn'),
            resetBtn: document.getElementById('resetBtn'),
            ciphertext: document.getElementById('ciphertext'),
            knownPlaintext: document.getElementById('knownPlaintext'),
            keyLength: document.getElementById('keyLength'),
            workers: document.getElementById('workers'),
            workersValue: document.getElementById('workersValue'),
            alphabet: document.getElementById('alphabet'),
            alphabetShift: document.getElementById('alphabetShift'),
            elapsed: document.getElementById('elapsed'),
            keysTested: document.getElementById('keysTested'),
            totalKeys: document.getElementById('totalKeys'),
            keysPerSec: document.getElementById('keysPerSec'),
            bestScore: document.getElementById('bestScore'),
            completion: document.getElementById('completion'),
            progressBar: document.getElementById('progressBar'),
            topResults: document.getElementById('topResults'),
            decryptedText: document.getElementById('decryptedText')
        };
    }

    initEventListeners() {
        this.elements.startBtn.addEventListener('click', () => this.start());
        this.elements.stopBtn.addEventListener('click', () => this.stop());
        this.elements.workers.addEventListener('input', () => {
            this.elements.workersValue.textContent = this.elements.workers.value;
        });
        this.elements.shuffleBtn.addEventListener('click', () => this.shuffleAlphabet());
        this.elements.resetBtn.addEventListener('click', () => this.resetAlphabet());
        this.elements.keyLength.addEventListener('change', () => this.updateTotalKeys());
        this.elements.alphabet.addEventListener('input', () => this.validateAlphabet());
        this.elements.alphabetShift.addEventListener('change', () => this.applyAlphabetShift());
    }

    validateAlphabet() {
        let alphabet = this.elements.alphabet.value.toUpperCase();
        alphabet = [...new Set(alphabet.split(''))].join('').replace(/[^A-Z]/g, '');
        this.elements.alphabet.value = alphabet;
        this.alphabet = alphabet;
        this.updateTotalKeys();
    }

    shuffleAlphabet() {
        let alphabetArray = this.alphabet.split('');
        for (let i = alphabetArray.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [alphabetArray[i], alphabetArray[j]] = [alphabetArray[j], alphabetArray[i]];
        }
        this.alphabet = alphabetArray.join('');
        this.elements.alphabet.value = this.alphabet;
    }

    resetAlphabet() {
        this.alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        this.elements.alphabet.value = this.alphabet;
        this.elements.alphabetShift.value = 0;
        this.alphabetShift = 0;
    }

    applyAlphabetShift() {
        const shift = parseInt(this.elements.alphabetShift.value);
        if (isNaN(shift)) return;
        
        this.alphabetShift = shift;
        if (shift === 0) return;
        
        const alphabet = this.alphabet;
        const shifted = alphabet.slice(shift) + alphabet.slice(0, shift);
        this.alphabet = shifted;
        this.elements.alphabet.value = shifted;
    }

    updateTotalKeys() {
        const keyLength = parseInt(this.elements.keyLength.value);
        this.totalKeys = Math.pow(this.alphabet.length, keyLength);
        this.elements.totalKeys.textContent = this.formatLargeNumber(this.totalKeys);
    }

    start() {
        if (this.isRunning) return;

        const ciphertext = this.elements.ciphertext.value.trim().toUpperCase();
        if (!this.validateCiphertext(ciphertext)) {
            alert('Invalid ciphertext! Must be exactly 97 uppercase letters (A-Z)');
            return;
        }

        if (this.alphabet.length < 26) {
            alert(`Alphabet must contain at least 26 unique letters (currently ${this.alphabet.length})`);
            return;
        }

        this.resetState();
        this.isRunning = true;
        this.startTime = performance.now();
        this.lastUpdateTime = this.startTime;
        this.updateButtonStates();

        this.initWorkers(ciphertext);
        this.updateUI();
    }

    validateCiphertext(text) {
        return text.length === 97 && /^[A-Z]+$/.test(text);
    }

    resetState() {
        this.keysTested = 0;
        this.keysPerSecond = 0;
        this.bestScore = 0;
        this.bestResult = null;
        this.workerStatus = {};
        this.resultsCache.clear();
        this.elements.topResults.innerHTML = '';
        this.elements.decryptedText.textContent = '';
        this.elements.progressBar.style.width = '0%';
        this.elements.completion.textContent = '0%';
        this.elements.bestScore.textContent = '0';
    }

    updateButtonStates() {
        this.elements.startBtn.disabled = this.isRunning;
        this.elements.stopBtn.disabled = !this.isRunning;
        this.elements.shuffleBtn.disabled = this.isRunning;
        this.elements.resetBtn.disabled = this.isRunning;
    }

    initWorkers(ciphertext) {
        const workerCount = parseInt(this.elements.workers.value);
        const keyLength = parseInt(this.elements.keyLength.value);
        const knownPlaintext = this.elements.knownPlaintext.value.trim().toUpperCase();

        this.workers = [];
        for (let i = 0; i < workerCount; i++) {
            const worker = new Worker('worker.js');
            worker.onmessage = (e) => this.handleWorkerMessage(e.data, i);
            worker.postMessage({
                type: 'init',
                ciphertext,
                keyLength,
                knownPlaintext,
                alphabet: this.alphabet,
                workerId: i,
                totalWorkers: workerCount
            });
            this.workers.push(worker);
            this.workerStatus[i] = { active: true, keysTested: 0 };
        }

        // Start workers after initialization
        setTimeout(() => {
            this.workers.forEach(worker => {
                worker.postMessage({ type: 'start' });
            });
        }, 100);
    }

    handleWorkerMessage(data, workerId) {
        if (!this.isRunning) return;

        switch (data.type) {
            case 'progress':
                this.workerStatus[workerId].keysTested = data.keysTested;
                this.updateProgress();
                break;

            case 'result':
                // Only show results with known plaintext match or high score
                if (data.score > 100 || (this.elements.knownPlaintext.value && data.score > 50)) {
                    if (!this.resultsCache.has(data.key)) {
                        this.resultsCache.add(data.key);
                        if (data.score > this.bestScore) {
                            this.bestScore = data.score;
                            this.bestResult = data;
                            this.elements.bestScore.textContent = Math.round(data.score);
                        }
                        this.displayResult(data);
                    }
                }
                break;

            case 'error':
                console.error(`Worker ${workerId} error:`, data.message);
                this.stop();
                alert(`Worker error: ${data.message}`);
                break;

            case 'complete':
                this.workerStatus[workerId].active = false;
                if (Object.values(this.workerStatus).every(w => !w.active)) {
                    this.stop();
                }
                break;
        }
    }

    updateProgress() {
        const now = performance.now();
        if (now - this.lastProgressUpdate < 200) return; // Throttle updates
        this.lastProgressUpdate = now;

        this.keysTested = Object.values(this.workerStatus).reduce((sum, w) => sum + w.keysTested, 0);
        
        // Update keys/sec calculation
        const elapsedSeconds = (now - this.startTime) / 1000;
        this.keysPerSecond = elapsedSeconds > 0 ? Math.round(this.keysTested / elapsedSeconds) : 0;
        
        // Update progress percentage
        const progressPercent = Math.min(100, (this.keysTested / this.totalKeys) * 100);
        this.elements.progressBar.style.width = `${progressPercent}%`;
        this.elements.completion.textContent = `${progressPercent.toFixed(2)}%`;
    }

    displayResult(result) {
        const resultElement = document.createElement('div');
        resultElement.className = 'result-item';
        resultElement.innerHTML = `
            <div class="result-key">Key: ${result.key}</div>
            <div>${result.plaintext.substring(0, 80)}${result.plaintext.length > 80 ? '...' : ''}</div>
            <div class="result-score">Score: ${Math.round(result.score)} (${result.method})</div>
        `;
        this.elements.topResults.prepend(resultElement);

        // Keep only top 20 results
        while (this.elements.topResults.children.length > 20) {
            this.elements.topResults.removeChild(this.elements.topResults.lastChild);
        }

        // Update decrypted text preview for best result
        if (result.score === this.bestScore) {
            this.elements.decryptedText.textContent = result.plaintext;
        }
    }

    updateUI() {
        if (!this.isRunning) return;

        // Update elapsed time
        const elapsedSeconds = (performance.now() - this.startTime) / 1000;
        this.elements.elapsed.textContent = elapsedSeconds >= 60 
            ? `${Math.floor(elapsedSeconds / 60)}m ${Math.floor(elapsedSeconds % 60)}s`
            : `${elapsedSeconds.toFixed(1)}s`;

        // Update keys tested
        this.elements.keysTested.textContent = this.formatLargeNumber(this.keysTested);

        // Update keys per second
        this.elements.keysPerSec.textContent = this.formatLargeNumber(this.keysPerSecond);

        requestAnimationFrame(() => this.updateUI());
    }

    stop() {
        if (!this.isRunning) return;

        this.isRunning = false;
        this.workers.forEach(worker => {
            worker.postMessage({ type: 'stop' });
            worker.terminate();
        });
        this.workers = [];
        this.updateButtonStates();
    }

    formatLargeNumber(num) {
        if (num >= 1000000000) return (num / 1000000000).toFixed(1) + 'B';
        if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
        if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
        return num.toString();
    }
}

// Initialize when page loads
document.addEventListener('DOMContentLoaded', () => {
    window.decryptor = new K4Decryptor();
});
