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

        this.initElements();
        this.initEventListeners();
    }

    initElements() {
        this.elements = {
            startBtn: document.getElementById('startBtn'),
            stopBtn: document.getElementById('stopBtn'),
            ciphertext: document.getElementById('ciphertext'),
            knownPlaintext: document.getElementById('knownPlaintext'),
            keyLength: document.getElementById('keyLength'),
            workers: document.getElementById('workers'),
            workersValue: document.getElementById('workersValue'),
            elapsed: document.getElementById('elapsed'),
            keysTested: document.getElementById('keysTested'),
            keysPerSec: document.getElementById('keysPerSec'),
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
    }

    start() {
        if (this.isRunning) return;

        const ciphertext = this.elements.ciphertext.value.trim().toUpperCase();
        if (!this.validateCiphertext(ciphertext)) {
            alert('Invalid ciphertext! Must be 97 uppercase letters (A-Z)');
            return;
        }

        this.resetState();
        this.isRunning = true;
        this.startTime = performance.now();
        this.lastUpdateTime = this.startTime;
        this.elements.startBtn.disabled = true;
        this.elements.stopBtn.disabled = false;

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
        this.elements.topResults.innerHTML = '';
        this.elements.decryptedText.textContent = '';
        this.elements.progressBar.style.width = '0%';
    }

    initWorkers(ciphertext) {
        const workerCount = parseInt(this.elements.workers.value);
        const keyLength = parseInt(this.elements.keyLength.value);
        const knownPlaintext = this.elements.knownPlaintext.value.trim().toUpperCase();

        // Calculate total possible keys (26^keyLength)
        this.totalKeys = Math.pow(26, keyLength);

        this.workers = [];
        for (let i = 0; i < workerCount; i++) {
            const worker = new Worker('worker.js');
            worker.onmessage = (e) => this.handleWorkerMessage(e.data);
            worker.postMessage({
                type: 'start',
                ciphertext,
                keyLength,
                knownPlaintext,
                workerId: i,
                totalWorkers: workerCount
            });
            this.workers.push(worker);
        }
    }

    handleWorkerMessage(data) {
        if (!this.isRunning) return;

        switch (data.type) {
            case 'progress':
                this.keysTested += data.keysTested;
                this.updateKeysPerSecond();
                break;

            case 'result':
                if (data.score > this.bestScore) {
                    this.bestScore = data.score;
                    this.bestResult = data;
                    this.displayResult(data);
                }
                break;

            case 'error':
                console.error('Worker error:', data.message);
                break;
        }
    }

    updateKeysPerSecond() {
        const now = performance.now();
        const elapsedSeconds = (now - this.lastUpdateTime) / 1000;
        
        if (elapsedSeconds >= 1) {
            this.keysPerSecond = Math.round(this.keysTested / (now - this.startTime) * 1000);
            this.lastUpdateTime = now;
        }
    }

    displayResult(result) {
        // Update top results
        const resultElement = document.createElement('div');
        resultElement.className = 'result-item';
        resultElement.innerHTML = `
            <div class="result-key">${result.key}</div>
            <div>${result.plaintext.substring(0, 60)}...</div>
            <div class="result-score">Score: ${result.score.toFixed(2)}</div>
        `;
        this.elements.topResults.prepend(resultElement);

        // Update decrypted text preview
        this.elements.decryptedText.textContent = result.plaintext;
    }

    updateUI() {
        if (!this.isRunning) return;

        // Update elapsed time
        const elapsedSeconds = (performance.now() - this.startTime) / 1000;
        this.elements.elapsed.textContent = `${elapsedSeconds.toFixed(1)}s`;

        // Update keys tested
        this.elements.keysTested.textContent = this.keysTested.toLocaleString();

        // Update keys per second
        this.elements.keysPerSec.textContent = this.keysPerSecond.toLocaleString();

        // Update progress bar
        const progressPercent = Math.min(100, (this.keysTested / this.totalKeys) * 100);
        this.elements.progressBar.style.width = `${progressPercent}%`;

        requestAnimationFrame(() => this.updateUI());
    }

    stop() {
        if (!this.isRunning) return;

        this.isRunning = false;
        this.workers.forEach(worker => {
            worker.terminate();
        });
        this.workers = [];

        this.elements.startBtn.disabled = false;
        this.elements.stopBtn.disabled = true;
    }
}

// Initialize the decryptor when the page loads
window.addEventListener('DOMContentLoaded', () => {
    window.decryptor = new K4Decryptor();
});
