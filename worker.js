const ENGLISH_FREQ = new Float32Array([
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153,
    0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056,
    2.758, 0.978, 2.360, 0.150, 1.974, 0.074
]);

const COMMON_PATTERNS = [
    'THE', 'AND', 'THAT', 'HAVE', 'FOR', 'NOT', 'WITH', 'YOU', 'THIS', 'BUT',
    'HIS', 'FROM', 'THEY', 'WILL', 'WOULD', 'THERE', 'THEIR', 'WHAT', 'ABOUT',
    'WHICH', 'WHEN', 'YOUR', 'WERE', 'BERLIN', 'CLOCK', 'EAST', 'NORTH', 'WEST',
    'SOUTH', 'NORTHEAST', 'NORTHWEST', 'SOUTHEAST', 'SOUTHWEST', 'SECRET', 'CODE',
    'MESSAGE', 'KRYPTOS', 'CIA', 'AGENT', 'COMPASS', 'LIGHT', 'LATITUDE',
    'LONGITUDE', 'COORDINATE', 'SHADOW', 'WALL', 'UNDERGROUND'
].map(s => {
    const arr = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) arr[i] = s.charCodeAt(i) - 65;
    return arr;
});

class K4Worker {
    constructor() {
        this.alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        this.charMap = new Uint8Array(256);
        for (let i = 0; i < this.alphabet.length; i++) {
            const code = this.alphabet.charCodeAt(i);
            this.charMap[code] = i;
            this.charMap[code + 32] = i; // lowercase
        }

        this.running = false;
        this.ciphertext = '';
        this.cipherCodes = null;
        this.keyLength = 0;
        this.knownPlaintext = null;
        this.workerId = 0;
        this.totalWorkers = 1;
        this.keysTested = 0;
        this.startTime = 0;
        
        self.onmessage = (e) => this.handleMessage(e.data);
    }

    handleMessage(msg) {
        switch (msg.type) {
            case 'init':
                this.ciphertext = msg.ciphertext;
                this.keyLength = msg.keyLength;
                if (msg.knownPlaintext) {
                    this.knownPlaintext = new Uint8Array(msg.knownPlaintext.length);
                    for (let i = 0; i < msg.knownPlaintext.length; i++) {
                        this.knownPlaintext[i] = this.charMap[msg.knownPlaintext.charCodeAt(i)];
                    }
                }
                this.workerId = msg.workerId || 0;
                this.totalWorkers = msg.totalWorkers || 1;
                this.keysTested = 0;
                
                // Преобразуем ciphertext в коды один раз
                this.cipherCodes = new Uint8Array(this.ciphertext.length);
                for (let i = 0; i < this.ciphertext.length; i++) {
                    this.cipherCodes[i] = this.charMap[this.ciphertext.charCodeAt(i)] ?? 255;
                }
                break;
                
            case 'start':
                this.running = true;
                this.startTime = performance.now();
                this.bruteForce();
                break;
                
            case 'stop':
                this.running = false;
                break;
        }
    }

    bruteForce() {
        const totalKeys = Math.pow(26, this.keyLength);
        const keysPerWorker = Math.ceil(totalKeys / this.totalWorkers);
        const startKey = this.workerId * keysPerWorker;
        const endKey = Math.min(startKey + keysPerWorker, totalKeys);
        
        let bestScore = -Infinity;
        let bestKey = '';
        const keyCodes = new Uint8Array(this.keyLength);
        const plaintext = new Uint8Array(this.cipherCodes.length);
        
        for (let keyNum = startKey; keyNum < endKey && this.running; keyNum++) {
            // Генерация ключа через числовые операции
            let remaining = keyNum;
            for (let i = this.keyLength - 1; i >= 0; i--) {
                keyCodes[i] = remaining % 26;
                remaining = Math.floor(remaining / 26);
            }
            
            // Дешифровка
            for (let i = 0; i < this.cipherCodes.length; i++) {
                const cipherCode = this.cipherCodes[i];
                plaintext[i] = cipherCode < 26 
                    ? (cipherCode - keyCodes[i % this.keyLength] + 26) % 26
                    : cipherCode;
            }
            
            // Подсчет score
            const score = this.scoreText(plaintext);
            this.keysTested++;
            
            if (score > bestScore) {
                bestScore = score;
                bestKey = String.fromCharCode(...keyCodes.map(c => c + 65));
                
                self.postMessage({
                    type: 'result',
                    key: bestKey,
                    plaintext: this.codesToString(plaintext),
                    score: Math.round(score)
                });
            }
            
            // Отчет о прогрессе
            if (this.keysTested % 50000 === 0) {
                const kps = Math.round(this.keysTested / ((performance.now() - this.startTime) / 1000));
                self.postMessage({
                    type: 'progress',
                    keysTested: this.keysTested,
                    kps: kps
                });
            }
        }
        
        if (this.running) {
            self.postMessage({ type: 'complete' });
        }
    }

    codesToString(codes) {
        let str = '';
        for (let i = 0; i < codes.length; i++) {
            str += codes[i] < 26 
                ? String.fromCharCode(codes[i] + 65) 
                : String.fromCharCode(codes[i]);
        }
        return str;
    }

    scoreText(codes) {
        let score = 0;
        const freq = new Uint16Array(26);
        let totalLetters = 0;
        
        // Частотный анализ
        for (let i = 0; i < codes.length; i++) {
            const code = codes[i];
            if (code < 26) {
                freq[code]++;
                totalLetters++;
            }
        }
        
        if (totalLetters > 0) {
            for (let i = 0; i < 26; i++) {
                const diff = Math.abs(ENGLISH_FREQ[i] - (freq[i] / totalLetters) * 100);
                score += 100 - diff;
            }
        }
        
        // Проверка известного текста
        if (this.knownPlaintext) {
            outer: for (let i = 0; i <= codes.length - this.knownPlaintext.length; i++) {
                for (let j = 0; j < this.knownPlaintext.length; j++) {
                    if (codes[i + j] !== this.knownPlaintext[j]) continue outer;
                }
                score += 1000 * this.knownPlaintext.length;
                break;
            }
        }
        
        // Поиск паттернов
        for (const pattern of COMMON_PATTERNS) {
            outer: for (let i = 0; i <= codes.length - pattern.length; i++) {
                for (let j = 0; j < pattern.length; j++) {
                    if (codes[i + j] !== pattern[j]) continue outer;
                }
                score += pattern.length * 25;
            }
        }
        
        return score;
    }
}

new K4Worker();
