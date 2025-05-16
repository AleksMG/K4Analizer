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
        this.topResults = new Map();
        this.resultsCache = new Set();
        this.knownWords = [];
        this.commonPatterns = [
            'THE', 'AND', 'THAT', 'HAVE', 'FOR', 'NOT', 'WITH', 'YOU', 'THIS', 'BUT',
            'HIS', 'FROM', 'THEY', 'WILL', 'WOULD', 'THERE', 'THEIR', 'WHAT', 'ABOUT',
            'WHICH', 'WHEN', 'YOUR', 'WERE', 'BERLIN', 'CLOCK', 'EAST', 'NORTH', 'WEST',
            'SOUTH', 'NORTHEAST', 'NORTHWEST', 'SOUTHEAST', 'SOUTHWEST', 'SECRET', 'CODE',
            'MESSAGE', 'KRYPTOS', 'CIA', 'AGENT', 'COMPASS', 'DIRECTION', 'LATITUDE',
            'LONGITUDE', 'COORDINATES', 'GOVERNMENT', 'INTELLIGENCE', 'WASHINGTON'
        ];

        // Оптимизация: Предварительное создание карты алфавита (НОВОЕ)
        this.alphabetIndexMap = this.createAlphabetMap(this.alphabet);
        this.workerSpeedCache = {};
    }

    createAlphabetMap(alphabet) {
        const map = {};
        for (let i = 0; i < alphabet.length; i++) {
            map[alphabet[i]] = i;
        }
        return map;
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
        this.elements.knownPlaintext.addEventListener('input', () => this.updateKnownWords());
    }

    validateAlphabet() {
        let alphabet = this.elements.alphabet.value.toUpperCase();
        alphabet = [...new Set(alphabet.split(''))].join('').replace(/[^A-Z]/g, '');
        this.elements.alphabet.value = alphabet;
        this.alphabet = alphabet;
        this.alphabetIndexMap = this.createAlphabetMap(alphabet); // Обновляем карту (НОВОЕ)
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
        this.alphabetIndexMap = this.createAlphabetMap(this.alphabet); // Обновляем карту (НОВОЕ)
    }

    resetAlphabet() {
        this.alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        this.elements.alphabet.value = this.alphabet;
        this.elements.alphabetShift.value = 0;
        this.alphabetShift = 0;
        this.alphabetIndexMap = this.createAlphabetMap(this.alphabet); // Обновляем карту (НОВОЕ)
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
        this.alphabetIndexMap = this.createAlphabetMap(shifted); // Обновляем карту (НОВОЕ)
    }

    updateTotalKeys() {
        const keyLength = parseInt(this.elements.keyLength.value);
        this.totalKeys = Math.pow(this.alphabet.length, keyLength);
        this.elements.totalKeys.textContent = this.formatLargeNumber(this.totalKeys);
    }

    updateKnownWords() {
        const knownText = this.elements.knownPlaintext.value.trim().toUpperCase();
        this.knownWords = knownText ? [knownText] : [];
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
        this.topResults.clear();
        this.resultsCache.clear();
        this.workerSpeedCache = {}; // Очищаем кеш (НОВОЕ)
        
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
            
            // Оптимизация: Увеличенные параметры (НОВОЕ)
            worker.postMessage({
                type: 'init',
                ciphertext,
                keyLength,
                knownPlaintext,
                alphabet: this.alphabet,
                alphabetIndexMap: this.alphabetIndexMap, // Передаём карту (НОВОЕ)
                workerId: i,
                totalWorkers: workerCount,
                batchSize: 500000,  // Было: ~5000 (НОВОЕ)
                reportInterval: 2000 // Было: 1000 (НОВОЕ)
            });
            
            this.workers.push(worker);
            this.workerStatus[i] = { 
                active: true, 
                keysTested: 0,
                lastReportedKeys: 0, // Для точного расчёта скорости (НОВОЕ)
                lastReportTime: performance.now() 
            };
        }

        setTimeout(() => {
            this.workers.forEach(worker => worker.postMessage({ type: 'start' }));
        }, 50);
    }

    handleWorkerMessage(data, workerId) {
        if (!this.isRunning) return;

        switch (data.type) {
            case 'progress':
                // Точный расчёт скорости (НОВОЕ)
                const now = performance.now();
                const timeDiff = (now - this.workerStatus[workerId].lastReportTime) / 1000;
                const keysDiff = data.keysTested - this.workerStatus[workerId].lastReportedKeys;
                
                this.workerStatus[workerId].keysTested = data.keysTested;
                this.workerStatus[workerId].lastReportedKeys = data.keysTested;
                this.workerStatus[workerId].lastReportTime = now;
                this.workerSpeedCache[workerId] = Math.round(keysDiff / timeDiff); // Кешируем скорость
                
                this.updateProgress();
                break;

            case 'result':
                if (data.score > 0 && !this.resultsCache.has(data.key)) {
                    this.resultsCache.add(data.key);
                    
                    // Оптимизация: Быстрый расчёт score (НОВОЕ)
                    const score = this.quickScoreCalculation(data);
                    
                    if (score > this.bestScore * 0.8 || data.hasKnownWord) {
                        const result = {
                            ...data,
                            score,
                            plaintextShort: data.plaintext.substring(0, 60) + (data.plaintext.length > 60 ? '...' : '')
                        };

                        if (score > this.bestScore) {
                            this.bestScore = score;
                            this.bestResult = result;
                            this.elements.bestScore.textContent = Math.round(score);
                            this.updateDecryptedText();
                        }

                        this.addToTopResults(result);
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

    quickScoreCalculation(result) {
        // Упрощённая версия оригинального calculateScore (НОВОЕ)
        let score = result.baseScore || 0;
        
        if (result.hasKnownWord) {
            score += 5000 * (this.knownWords[0]?.length || 0);
        }
        
        if (result.wordCount > 3) score += 500;
        if (result.wordCount > 5) score += 1000;
        
        return Math.round(score);
    }

    updateProgress() {
        const now = performance.now();
        if (now - this.lastProgressUpdate < 500) return; // Реже обновляем UI (НОВОЕ)
        
        this.lastProgressUpdate = now;
        
        // Агрегируем данные (НОВОЕ)
        this.keysTested = Object.values(this.workerStatus).reduce((sum, w) => sum + w.keysTested, 0);
        this.keysPerSecond = Object.values(this.workerSpeedCache).reduce((sum, speed) => sum + speed, 0);
        
        const elapsedSeconds = (now - this.startTime) / 1000;
        const progressPercent = this.totalKeys > 0 
            ? Math.min(100, (this.keysTested / this.totalKeys) * 100)
            : 0;

        // Группируем обновления DOM (НОВОЕ)
        requestAnimationFrame(() => {
            this.elements.progressBar.style.width = `${progressPercent}%`;
            this.elements.completion.textContent = `${progressPercent.toFixed(2)}%`;
            this.elements.keysTested.textContent = this.formatLargeNumber(this.keysTested);
            this.elements.keysPerSec.textContent = this.formatLargeNumber(this.keysPerSecond);
            this.elements.elapsed.textContent = elapsedSeconds >= 60 
                ? `${Math.floor(elapsedSeconds / 60)}m ${Math.floor(elapsedSeconds % 60)}s`
                : `${elapsedSeconds.toFixed(1)}s`;
        });
    }

    analyzeText(text) {
        const foundWords = [];
        
        // Проверяем известные слова
        for (const word of this.knownWords) {
            const regex = new RegExp(word, 'g');
            const matches = text.match(regex);
            if (matches) {
                foundWords.push({
                    word,
                    score: 100 * word.length * matches.length,
                    isKnown: true
                });
            }
        }

        // Проверяем общие паттерны
        for (const pattern of this.commonPatterns) {
            const regex = new RegExp(pattern, 'g');
            const matches = text.match(regex);
            if (matches) {
                foundWords.push({
                    word: pattern,
                    score: 25 * pattern.length * matches.length,
                    isKnown: false
                });
            }
        }

        return foundWords.sort((a, b) => b.word.length - a.word.length);
    }

    calculateScore(plaintext, foundWords) {
        let score = foundWords.reduce((sum, word) => sum + word.score, 0);
        
        // Бонус за количество пробелов (слов)
        const spaceCount = (plaintext.match(/ /g) || []).length;
        score += spaceCount * 10;
        
        // Бонус за длину текста без неалфавитных символов
        const cleanText = plaintext.replace(new RegExp(`[^${this.alphabet} ]`, 'g'), '');
        score += cleanText.length * 0.5;
        
        return Math.round(score);
    }

    addToTopResults(result) {
        this.topResults.set(result.key, result);

        // Удаляем худший результат если превысили лимит
        if (this.topResults.size > 20) {
            const minScore = Math.min(...Array.from(this.topResults.values()).map(r => r.score));
            for (const [key, res] of this.topResults) {
                if (res.score === minScore) {
                    this.topResults.delete(key);
                    break;
                }
            }
        }

        this.displayTopResults();
    }

    updateDecryptedText() {
        if (!this.bestResult) return;

        let html = this.bestResult.plaintext;
        const uniqueWords = [...new Set(this.bestResult.foundWords.map(w => w.word))];
        
        for (const word of uniqueWords) {
            const regex = new RegExp(word, 'g');
            html = html.replace(regex, `<span class="highlight-word">${word}</span>`);
        }

        this.elements.decryptedText.innerHTML = html;
    }

    displayTopResults() {
        const sortedResults = Array.from(this.topResults.values())
            .sort((a, b) => b.score - a.score)
            .slice(0, 20);

        this.elements.topResults.innerHTML = '';

        sortedResults.forEach(result => {
            const wordsList = result.foundWords
                .slice(0, 5)
                .map(word => `${word.word}(${word.isKnown ? 'known' : word.score})`)
                .join(', ');

            const resultElement = document.createElement('div');
            resultElement.className = 'result-item';
            resultElement.innerHTML = `
                <div class="result-key">Key: ${result.key}</div>
                <div class="result-text">${result.plaintextShort}</div>
                <div class="result-words">Words: ${wordsList}</div>
                <div class="result-score">Score: ${Math.round(result.score)}</div>
            `;
            this.elements.topResults.appendChild(resultElement);
        });
    }

    updateUI() {
        if (!this.isRunning) return;

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

document.addEventListener('DOMContentLoaded', () => {
    window.decryptor = new K4Decryptor();
});
