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

        this.initElements();
        this.initEventListeners();
    }

    initElements() {
        this.elements = {
            startBtn: document.getElementById('startBtn'),
            stopBtn: document.getElementById('stopBtn'),
            shuffleAlphabetBtn: document.getElementById('shuffleAlphabetBtn'),
            ciphertext: document.getElementById('ciphertext'),
            knownPlaintext: document.getElementById('knownPlaintext'),
            keyLength: document.getElementById('keyLength'),
            workers: document.getElementById('workers'),
            workersValue: document.getElementById('workersValue'),
            alphabet: document.getElementById('alphabet'),
            elapsed: document.getElementById('elapsed'),
            keysTested: document.getElementById('keysTested'),
            totalKeys: document.getElementById('totalKeys'),
            keysPerSec: document.getElementById('keysPerSec'),
            bestScore: document.getElementById('bestScore'),
            progressBar: document.getElementById('progressBar'),
            progressPercent: document.getElementById('progressPercent'),
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
        this.elements.shuffleAlphabetBtn.addEventListener('click', () => this.shuffleAlphabet());
        this.elements.alphabet.addEventListener('change', () => this.validateAlphabet());
    }

    validateAlphabet() {
        let alphabet = this.elements.alphabet.value.toUpperCase();
        // Remove duplicates
        alphabet = [...new Set(alphabet.split(''))].join('');
        // Remove non-letters
        alphabet = alphabet.replace(/[^A-Z]/g, '');
        this.elements.alphabet.value = alphabet;
        this.alphabet = alphabet;
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

    start() {
        if (this.isRunning) return;

        const ciphertext = this.elements.ciphertext.value.trim().toUpperCase();
        if (!this.validateCiphertext(ciphertext)) {
            alert('Invalid ciphertext! Must be 97 uppercase letters (A-Z)');
            return;
        }

        this.validateAlphabet();
        if (this.alphabet.length < 26) {
            alert('Alphabet must contain at least 26 unique letters');
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
        this.elements.progressPercent.textContent = '0%';
        this.elements.bestScore.textContent = '0';
    }

    initWorkers(ciphertext) {
        const workerCount = parseInt(this.elements.workers.value);
        const keyLength = parseInt(this.elements.keyLength.value);
        const knownPlaintext = this.elements.knownPlaintext.value.trim().toUpperCase();

        // Calculate total possible keys (alphabetLength^keyLength)
        this.totalKeys = Math.pow(this.alphabet.length, keyLength);
        this.elements.totalKeys.textContent = this.formatLargeNumber(this.totalKeys);

        this.workers = [];
        for (let i = 0; i < workerCount; i++) {
            const worker = new Worker('worker.js');
            worker.onmessage = (e) => this.handleWorkerMessage(e.data);
            worker.postMessage({
                type: 'start',
                ciphertext,
                keyLength,
                knownPlaintext,
                alphabet: this.alphabet,
                workerId: i,
                totalWorkers: workerCount
            });
            this.workers.push(worker);
        }
    }

    formatLargeNumber(num) {
        if (num >= 1000000000) {
            return (num / 1000000000).toFixed(1) + 'B';
        }
        if (num >= 1000000) {
            return (num / 1000000).toFixed(1) + 'M';
        }
        if (num >= 1000) {
            return (num / 1000).toFixed(1) + 'K';
        }
        return num.toString();
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
                    this.elements.bestScore.textContent = Math.round(data.score);
                    this.displayResult(data);
                }
                break;

            case 'error':
                console.error('Worker error:', data.message);
                this.stop();
                alert('Worker error: ' + data.message);
                break;

            case 'complete':
                this.keysTested += data.keysTested;
                this.stop();
                break;
        }
    }

    updateKeysPerSecond() {
        const now = performance.now();
        const elapsedSeconds = (now - this.lastUpdateTime) / 1000;
        
        if (elapsedSeconds >= 0.5) { // Update more frequently for smoother display
            this.keysPerSecond = Math.round(this.keysTested / ((now - this.startTime) / 1000));
            this.lastUpdateTime = now;
        }
    }

    displayResult(result) {
        // Update top results
        const resultElement = document.createElement('div');
        resultElement.className = 'result-item';
        resultElement.innerHTML = `
            <div class="result-key">Key: ${result.key}</div>
            <div>${result.plaintext.substring(0, 60)}${result.plaintext.length > 60 ? '...' : ''}</div>
            <div class="result-score">Score: ${Math.round(result.score)}</div>
        `;
        this.elements.topResults.prepend(resultElement);

        // Keep only top 20 results
        while (this.elements.topResults.children.length > 20) {
            this.elements.topResults.removeChild(this.elements.topResults.lastChild);
        }

        // Update decrypted text preview
        this.elements.decryptedText.textContent = result.plaintext;
    }

    updateUI() {
        if (!this.isRunning) return;

        // Update elapsed time
        const elapsedSeconds = (performance.now() - this.startTime) / 1000;
        this.elements.elapsed.textContent = elapsedSeconds >= 60 
            ? `${Math.floor(elapsedSeconds / 60)}m ${Math.floor(elapsedSeconds % 60)}s`
            : `${elapsedSeconds.toFixed(1)}s`;

        // Update keys tested
        this.elements.keysTested.textContent = this.keysTested.toLocaleString();

        // Update keys per second
        this.elements.keysPerSec.textContent = this.keysPerSecond.toLocaleString();

        // Update progress bar and percentage
        const progressPercent = Math.min(100, (this.keysTested / this.totalKeys) * 100);
        this.elements.progressBar.style.width = `${progressPercent}%`;
        this.elements.progressPercent.textContent = `${progressPercent.toFixed(2)}%`;

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
