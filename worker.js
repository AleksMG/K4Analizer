const ENGLISH_FREQ = {
    'A':8.167,'B':1.492,'C':2.782,'D':4.253,'E':12.702,
    'F':2.228,'G':2.015,'H':6.094,'I':6.966,'J':0.153,
    'K':0.772,'L':4.025,'M':2.406,'N':6.749,'O':7.507,
    'P':1.929,'Q':0.095,'R':5.987,'S':6.327,'T':9.056,
    'U':2.758,'V':0.978,'W':2.360,'X':0.150,'Y':1.974,
    'Z':0.074
};

const PATTERNS = {
    COMMON: ['THE','AND','THAT','HAVE','FOR','NOT','WITH','YOU','THIS','WAY','HIS','FROM','THEY','WILL','WOULD','THERE','THEIR','WHAT','ABOUT','WHICH','WHEN','YOUR','WERE','CIA'],
    RARE: ['BERLIN','CLOCK','EAST','NORTH','WEST','SOUTH','NORTHEAST','NORTHWEST','SOUTHEAST','SOUTHWEST','SECRET','CODE','MESSAGE','KRYPTOS','BERLINCLOCK','AGENT','COMPASS','LIGHT','LATITUDE','LONGITUDE','COORDINATE','SHADOW','WALL','UNDERGROUND']
};

class K4BruteForce {
    constructor() {
        this.alphabet = 'ZXWVUQNMLJIHGFEDCBASOTPYRK';
        this.charMap = new Uint8Array(256).fill(255);
        for (let i = 0; i < this.alphabet.length; i++) {
            this.charMap[this.alphabet.charCodeAt(i)] = i;
        }

        this.patterns = [
            ...PATTERNS.COMMON.map(p => ({p, w:25})),
            ...PATTERNS.RARE.map(p => ({p, w:50}))
        ];

        self.onmessage = (e) => this.handleMessage(e.data);
    }

    handleMessage(msg) {
        switch(msg.type) {
            case 'init':
                Object.assign(this, {
                    ciphertext: msg.ciphertext,
                    keyLength: msg.keyLength,
                    workerId: msg.workerId || 0,
                    totalWorkers: msg.totalWorkers || 1
                });
                break;
            case 'start':
                this.start();
                break;
            case 'stop':
                this.running = false;
                break;
        }
    }

    async start() {
        this.running = true;
        this.keysTested = 0;
        this.startTime = performance.now();

        const cipherCodes = new Uint8Array(this.ciphertext.length);
        for (let i = 0; i < this.ciphertext.length; i++) {
            cipherCodes[i] = this.charMap[this.ciphertext.charCodeAt(i)];
        }

        const totalKeys = Math.pow(26, this.keyLength);
        const keysPerWorker = Math.ceil(totalKeys / this.totalWorkers);
        const startKey = this.workerId * keysPerWorker;
        const endKey = Math.min(startKey + keysPerWorker, totalKeys);

        await this.processKeys(startKey, endKey, cipherCodes);
        self.postMessage({type: 'complete'});
    }

    async processKeys(startKey, endKey, cipherCodes) {
        const keyBuffer = new Uint8Array(this.keyLength);
        const plainBuffer = new Uint8Array(cipherCodes.length);
        const freq = new Uint16Array(26);
        let bestScore = 0;
        let bestKey = '';

        for (let keyNum = startKey; keyNum < endKey && this.running; keyNum++) {
            // Генерация ключа
            for (let i = 0, num = keyNum; i < this.keyLength; i++, num = Math.floor(num / 26)) {
                keyBuffer[i] = num % 26;
            }

            // Расшифровка
            freq.fill(0);
            for (let i = 0; i < cipherCodes.length; i++) {
                plainBuffer[i] = (cipherCodes[i] - keyBuffer[i % this.keyLength] + 26) % 26;
                freq[plainBuffer[i]]++;
            }

            // Оценка
            const score = this.calcScore(plainBuffer, freq);
            this.keysTested++;

            if (score > bestScore) {
                bestScore = score;
                bestKey = Array.from(keyBuffer).map(i => this.alphabet[i]).reverse().join('');
                self.postMessage({
                    type: 'result',
                    key: bestKey,
                    plaintext: Array.from(plainBuffer).map(i => this.alphabet[i]).join(''),
                    score
                });
            }

            if (this.keysTested % 1000000 === 0) {
                const kps = Math.round(this.keysTested / ((performance.now() - this.startTime) / 1000));
                self.postMessage({
                    type: 'progress',
                    keysTested: this.keysTested,
                    kps
                });
                await new Promise(r => setTimeout(r, 0)); // Даем дыхать event loop
            }
        }
    }

    calcScore(plainBuffer, freq) {
        let score = 0;
        const totalLetters = plainBuffer.length;
        const plainText = Array.from(plainBuffer).map(i => this.alphabet[i]).join('');
        const upperText = plainText.toUpperCase();

        // Частотный анализ
        for (let i = 0; i < 26; i++) {
            const expected = ENGLISH_FREQ[this.alphabet[i]] || 0;
            const actual = (freq[i] / totalLetters) * 100;
            score += 100 - Math.abs(expected - actual);
        }

        // Паттерны
        for (const {p, w} of this.patterns) {
            let pos = -1;
            while ((pos = upperText.indexOf(p, pos + 1)) !== -1) {
                score += p.length * w;
            }
        }

        return Math.round(score);
    }
}

new K4BruteForce();
