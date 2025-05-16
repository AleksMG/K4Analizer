const K4_CONFIG = {
    BASE_KEYS: ['BERLIN','CLOCK','NORTHEAST','WEST','EAST','NORTH','SOUTH'],
    DICTIONARY: ['THE','AND','THAT','WITH','FOR','WAS','HIS','ARE','FROM','HAVE'],
    KRYPTOS_FREQ: {K:12.5,R:10.2,Y:8.1,P:7.9,T:7.5,O:6.8,S:6.5,A:5.9,B:5.3},
    WORKER_FILE: 'worker.js'
};

class K4App {
    constructor() {
        this.workers = [];
        this.results = [];
        this.keysTested = 0;
        this.totalKeys = 0;
        
        this.initWorkers();
        this.bindEvents();
    }

    initWorkers() {
        const workerCount = Math.min(navigator.hardwareConcurrency || 4, 8);
        document.getElementById('workers').value = workerCount;
        
        this.workers = Array.from({length: workerCount}, () => {
            const worker = new Worker(K4_CONFIG.WORKER_FILE);
            worker.onmessage = (e) => this.handleWorkerResponse(e);
            return worker;
        });
    }

    bindEvents() {
        document.getElementById('analyzeBtn').addEventListener('click', () => this.startAnalysis());
    }

    startAnalysis() {
        const ciphertext = document.getElementById('ciphertext').value
            .toUpperCase().replace(/[^A-Z]/g, '');
        
        const maxKeyLength = parseInt(document.getElementById('maxKeyLength').value);
        const keys = K4Analyzer.generateKeys(K4_CONFIG.BASE_KEYS, maxKeyLength);
        
        this.totalKeys = keys.length;
        this.keysTested = 0;
        this.results = [];
        document.getElementById('results').innerHTML = '';
        
        this.distributeWork(keys, ciphertext);
    }

    distributeWork(keys, ciphertext) {
        const chunkSize = Math.ceil(keys.length / this.workers.length);
        
        this.workers.forEach((worker, i) => {
            const start = i * chunkSize;
            const end = start + chunkSize;
            worker.postMessage({
                keys: keys.slice(start, end),
                ciphertext,
                freqData: K4_CONFIG.KRYPTOS_FREQ,
                dictionary: K4_CONFIG.DICTIONARY
            });
        });
    }

    handleWorkerResponse(e) {
        this.keysTested += e.data.processed;
        this.results.push(...e.data.results);
        
        this.updateProgress();
        this.displayResults();
    }

    updateProgress() {
        const percent = ((this.keysTested / this.totalKeys) * 100).toFixed(1);
        document.getElementById('progress').textContent = `${percent}%`;
        document.getElementById('keysTested').textContent = this.keysTested;
    }

    displayResults() {
        const sorted = this.results
            .sort((a, b) => b.score - a.score || a.entropy - b.entropy)
            .slice(0, 50);
        
        const resultsHTML = sorted.map(res => `
            <div class="result-item">
                <span><strong>${res.key}</strong></span>
                <span>${res.text.substring(0,40)}</span>
                <span>${res.score.toFixed(1)}</span>
                <span>${res.entropy.toFixed(2)}</span>
            </div>
        `).join('');
        
        document.getElementById('results').innerHTML = resultsHTML;
        document.getElementById('topScore').textContent = sorted[0]?.score.toFixed(1) || '-';
    }
}

// Инициализация приложения
new K4App();
