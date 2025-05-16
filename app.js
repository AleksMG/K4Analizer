class K4Decryptor {
    constructor() {
        this.workers = [];
        this.isRunning = false;
        this.startTime = null;
        this.totalKeys = 0;
        this.keysProcessed = 0;
        this.bestScore = 0;
        this.currentKey = '';
        this.maxTime = 5 * 60 * 1000; // 5 минут
        this.timeoutId = null;

        this.initControls();
        this.updateUI();
    }

    initControls() {
        document.getElementById('startBtn').addEventListener('click', () => this.start());
        document.getElementById('stopBtn').addEventListener('click', () => this.stop());
        document.getElementById('workers').addEventListener('input', e => {
            document.getElementById('workersValue').textContent = e.target.value;
        });
        document.getElementById('maxTime').addEventListener('change', e => {
            this.maxTime = e.target.value * 60 * 1000;
        });
    }

    start() {
        if (this.isRunning) return;
        
        const ciphertext = document.getElementById('ciphertext').value
            .toUpperCase()
            .replace(/[^A-Z]/g, '');

        if (ciphertext.length !== 97) {
            this.showError('Invalid K4 cipher! Must be exactly 97 characters.');
            return;
        }

        this.initializeWorkers(ciphertext);
        this.isRunning = true;
        this.startTime = performance.now();
        this.timeoutId = setTimeout(() => this.stop(), this.maxTime);
        requestAnimationFrame(() => this.updateUI());
    }

    initializeWorkers(ciphertext) {
        const workerCount = parseInt(document.getElementById('workers').value);
        const keyLength = parseInt(document.getElementById('keyLength').value);
        const alphabetSize = 25; // KRYPTOS alphabet (25 букв)
        this.totalKeys = Math.pow(alphabetSize, keyLength);
        
        this.workers = Array.from({length: workerCount}, (_, i) => {
            const worker = new Worker(window.workerUrl);
            worker.onmessage = e => this.handleWorkerMessage(e.data);
            worker.postMessage({
                type: 'INIT',
                ciphertext,
                alphabet: 'KRYPTOSABCDEFGHIJLMNQUVWXZ',
                keyLength,
                workerId: i
            });
            return worker;
        });
    }

    handleWorkerMessage(data) {
        if (!this.isRunning) return;

        switch(data.type) {
            case 'PROGRESS':
                this.keysProcessed += data.keysProcessed;
                break;
            
            case 'RESULT':
                if (data.score > this.bestScore) {
                    this.bestScore = data.score;
                    this.currentKey = data.key;
                    this.displayResult(data);
                    this.updateLivePreview(data.text);
                }
                break;
            
            case 'ERROR':
                this.showError(data.message);
                this.stop();
                break;
        }
    }

    displayResult(result) {
        const resultElement = document.createElement('div');
        resultElement.className = 'result-card';
        resultElement.innerHTML = `
            <div class="key">KEY: <strong>${result.key}</strong></div>
            <div class="text">${this.highlightPatterns(result.text)}</div>
            <div class="stats">
                <span>Score: ${result.score.toFixed(1)}</span>
                <span>Entropy: ${result.entropy.toFixed(2)}</span>
            </div>
        `;
        document.getElementById('topResults').prepend(resultElement);
    }

    highlightPatterns(text) {
        const patterns = ['BERLIN', 'CLOCK', 'NORTHEAST'];
        let highlighted = text;
        patterns.forEach(pattern => {
            const regex = new RegExp(`(${pattern})`, 'gi');
            highlighted = highlighted.replace(regex, '<mark>$1</mark>');
        });
        return highlighted;
    }

    updateLivePreview(text) {
        const preview = document.getElementById('livePreview');
        preview.innerHTML = this.highlightPatterns(text);
        preview.scrollTop = preview.scrollHeight;
    }

    updateUI() {
        if (!this.isRunning) return;

        const elapsed = (performance.now() - this.startTime) / 1000;
        const keysPerSec = (this.keysProcessed / elapsed || 0).toFixed(0);

        document.getElementById('elapsed').textContent = `${elapsed.toFixed(1)}s`;
        document.getElementById('keysPerSec').textContent = keysPerSec;
        document.getElementById('topScore').textContent = this.bestScore.toFixed(1);
        document.getElementById('currentKey').textContent = this.currentKey;
        document.getElementById('progressBar').style.width = 
            `${Math.min(100, (this.keysProcessed / this.totalKeys) * 100)}%`;

        requestAnimationFrame(() => this.updateUI());
    }

    stop() {
        if (!this.isRunning) return;

        this.isRunning = false;
        clearTimeout(this.timeoutId);
        this.workers.forEach(worker => {
            worker.postMessage({type: 'TERMINATE'});
            worker.terminate();
        });
        this.workers = [];
        
        this.showResultSummary();
    }

    showResultSummary() {
        const summary = document.createElement('div');
        summary.className = 'result-summary';
        summary.innerHTML = `
            <h3>🔚 Final Results</h3>
            <p>Total keys processed: ${this.keysProcessed.toLocaleString()}</p>
            <p>Best key found: <strong>${this.currentKey}</strong></p>
            <p>Execution time: ${(performance.now() - this.startTime).toFixed(1)}ms</p>
        `;
        document.body.appendChild(summary);
    }

    showError(message) {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'error-message';
        errorDiv.textContent = `❗ ${message}`;
        document.body.prepend(errorDiv);
        setTimeout(() => errorDiv.remove(), 5000);
    }
}

window.k4 = new K4Decryptor();
