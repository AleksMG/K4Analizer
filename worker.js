const ENGLISH_FREQ = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
    'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
    'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
    'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
    'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974,
    'Z': 0.074
};

const commonPatterns = ['THE', 'AND', 'THAT', 'HAVE', 'FOR', 'NOT', 'WITH', 'YOU', 'THIS', 'WAY'];
const uncommonPatterns = ['BERLIN', 'CLOCK', 'EAST', 'NORTH', 'WEST', 'SOUTH'];

class K4Worker {
    constructor() {
        this.alphabet = 'ZXWVUQNMLJIHGFEDCBASOTPYRK';
        this.charMap = new Uint8Array(256);
        this.charMap.fill(255);
        for (let i = 0; i < this.alphabet.length; i++) {
            this.charMap[this.alphabet.charCodeAt(i)] = i;
        }

        this.running = false;
        this.ciphertext = '';
        this.keyLength = 0;
        this.workerId = 0;
        this.totalWorkers = 1;
        this.keysTested = 0;
        this.startTime = 0;
        this.bestScore = 0;
        this.bestKey = '';
        
        // Параметры для полного перебора
        this.currentKeyNum = 0;
        this.keySpaceSize = 0;
        this.keysPerBlock = 10000;
        this.lastReportTime = 0;

        self.onmessage = (e) => {
            const msg = e.data;
            switch (msg.type) {
                case 'init':
                    this.ciphertext = msg.ciphertext;
                    this.keyLength = msg.keyLength;
                    this.workerId = msg.workerId || 0;
                    this.totalWorkers = msg.totalWorkers || 1;
                    this.keySpaceSize = Math.pow(26, this.keyLength);
                    this.currentKeyNum = this.workerId * Math.floor(this.keySpaceSize / this.totalWorkers);
                    break;
                case 'start':
                    if (!this.running) {
                        this.running = true;
                        this.startTime = performance.now();
                        this.run();
                    }
                    break;
                case 'stop':
                    this.running = false;
                    break;
            }
        };
    }

    async run() {
        const endKeyNum = (this.workerId === this.totalWorkers - 1) 
            ? this.keySpaceSize 
            : (this.workerId + 1) * Math.floor(this.keySpaceSize / this.totalWorkers);

        while (this.running && this.currentKeyNum < endKeyNum) {
            const blockEnd = Math.min(this.currentKeyNum + this.keysPerBlock, endKeyNum);
            
            for (let i = this.currentKeyNum; i < blockEnd; i++) {
                const key = this.generateKey(i);
                const plaintext = this.decrypt(key);
                const score = this.scoreText(plaintext);
                this.keysTested++;

                if (score > this.bestScore) {
                    this.bestScore = score;
                    this.bestKey = key;
                    
                    const foundWords = this.extractWords(plaintext);
                    self.postMessage({
                        type: 'result',
                        key: key,
                        plaintext: plaintext,
                        score: score,
                        words: foundWords,
                        progress: this.getProgress()
                    });
                }
            }
            
            this.currentKeyNum = blockEnd;
            this.reportProgress();
            
            // Даем возможность обработать другие события
            await new Promise(resolve => setTimeout(resolve, 0));
        }
        
        self.postMessage({type: 'complete', progress: 1});
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

    scoreText(text) {
        let score = 0;
        const upperText = text.toUpperCase();
        
        // Проверка паттернов
        for (const pattern of [...commonPatterns, ...uncommonPatterns]) {
            let pos = -1;
            while ((pos = upperText.indexOf(pattern, pos + 1)) !== -1) {
                score += pattern.length * (uncommonPatterns.includes(pattern) ? 50 : 25);
            }
        }
        
        return score;
    }

    extractWords(text) {
        const upperText = text.toUpperCase();
        const found = {};
        for (const pattern of [...commonPatterns, ...uncommonPatterns]) {
            let pos = -1;
            while ((pos = upperText.indexOf(pattern, pos + 1)) !== -1) {
                found[pattern] = (found[pattern] || 0) + 1;
            }
        }
        return found;
    }

    getProgress() {
        return this.currentKeyNum / this.keySpaceSize;
    }

    reportProgress() {
        const now = performance.now();
        if (now - this.lastReportTime > 1000) {
            self.postMessage({
                type: 'progress',
                keysTested: this.keysTested,
                progress: this.getProgress(),
                kps: Math.round(this.keysTested / ((now - this.startTime) / 1000))
            });
            this.lastReportTime = now;
        }
    }
}

new K4Worker();
