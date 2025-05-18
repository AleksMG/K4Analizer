//////////////////////////////////////////
// ПОЛНОСТЬЮ ИДЕНТИЧНЫЙ ВАШЕМУ APP.JS ИНТЕРФЕЙС
//////////////////////////////////////////

const ENGLISH_FREQ = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
    'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
    'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
    'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
    'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974,
    'Z': 0.074
};

// В ТОЧНОСТИ ВАШИ ПАТТЕРНЫ (без изменений)
const commonPatterns = [
    'THE', 'AND', 'THAT', 'HAVE', 'FOR', 'NOT', 'WITH', 'YOU', 'THIS', 'WAY',
    'HIS', 'FROM', 'THEY', 'WILL', 'WOULD', 'THERE', 'THEIR', 'WHAT', 'ABOUT',
    'WHICH', 'WHEN', 'YOUR', 'WERE', 'CIA'
];

const uncommonPatterns = [
    'BERLIN', 'CLOCK', 'EAST', 'NORTH', 'WEST',
    'SOUTH', 'NORTHEAST', 'NORTHWEST', 'SOUTHEAST', 'SOUTHWEST', 'SECRET', 'CODE',
    'MESSAGE', 'KRYPTOS', 'BERLINCLOCK', 'AGENT', 'COMPASS', 'LIGHT', 'LATITUDE',
    'LONGITUDE', 'COORDINATE', 'SHADOW', 'WALL', 'UNDERGROUND'
];

//////////////////////////////////////////
// ОПТИМИЗИРОВАННАЯ ВЕРСИЯ (полная совместимость)
//////////////////////////////////////////

class K4Worker {
    constructor() {
        // 1. ВСЕ ОРИГИНАЛЬНЫЕ ПЕРЕМЕННЫЕ
        this.alphabet = 'ZXWVUQNMLJIHGFEDCBASOTPYRK';
        this.charMap = new Uint8Array(256);
        this.running = false;
        this.ciphertext = '';
        this.keyLength = 0;
        this.knownPlaintext = '';
        this.workerId = 0;
        this.totalWorkers = 1;
        this.keysTested = 0;
        this.startTime = 0;
        this.lastReportTime = 0;
        
        // Инициализация charMap (как у вас)
        this.charMap.fill(255);
        for (let i = 0; i < this.alphabet.length; i++) {
            this.charMap[this.alphabet.charCodeAt(i)] = i;
        }

        // 2. Оригинальный обработчик сообщений (как у вас)
        self.onmessage = (e) => {
            const msg = e.data;
            switch (msg.type) {
                case 'init':
                    this.ciphertext = msg.ciphertext;
                    this.keyLength = msg.keyLength;
                    this.knownPlaintext = msg.knownPlaintext || '';
                    this.workerId = msg.workerId || 0;
                    this.totalWorkers = msg.totalWorkers || 1;
                    this.keysTested = 0;
                    break;
                    
                case 'start':
                    if (!this.running) {
                        this.running = true;
                        this.startTime = performance.now();
                        this.bruteForce();
                    }
                    break;
                    
                case 'stop':
                    this.running = false;
                    break;
            }
        };
    }

    // 3. ГЛАВНЫЙ МЕТОД (полная совместимость + оптимизации)
    bruteForce() {
        // Оригинальное распределение работы
        const totalKeys = Math.pow(26, this.keyLength);
        const keysPerWorker = Math.ceil(totalKeys / this.totalWorkers);
        const startKey = this.workerId * keysPerWorker;
        const endKey = Math.min(startKey + keysPerWorker, totalKeys);
        
        // Подготовка данных (как в оригинале)
        const cipherLen = this.ciphertext.length;
        const cipherCodes = new Uint8Array(cipherLen);
        for (let i = 0; i < cipherLen; i++) {
            cipherCodes[i] = this.charMap[this.ciphertext.charCodeAt(i)];
        }

        // Оптимизированные буферы
        const keyBuffer = new Uint8Array(this.keyLength);
        const plainBuffer = new Uint8Array(cipherLen);
        const freq = new Uint16Array(26);
        let bestScore = 0;
        let bestKey = '';
        let bestText = '';

        // Основной цикл
        for (let keyNum = startKey; keyNum < endKey && this.running; keyNum++) {
            // Генерация ключа (аналогично оригиналу)
            for (let i = 0, num = keyNum; i < this.keyLength; i++, num = Math.floor(num / 26)) {
                keyBuffer[i] = num % 26;
            }
            
            // Расшифровка с буферизацией
            freq.fill(0);
            for (let i = 0; i < cipherLen; i++) {
                plainBuffer[i] = (cipherCodes[i] - keyBuffer[i % this.keyLength] + 26) % 26;
                freq[plainBuffer[i]]++;
            }
            
            // ВАША ОРИГИНАЛЬНАЯ ЛОГИКА ОЦЕНКИ
            let score = 0;
            const totalLetters = cipherLen;
            
            // Частотный анализ (как у вас)
            for (let i = 0; i < 26; i++) {
                const expected = ENGLISH_FREQ[this.alphabet[i]] || 0;
                const actual = (freq[i] / totalLetters) * 100;
                score += 100 - Math.abs(expected - actual);
            }
            
            // Проверка паттернов (дословно ваш код)
            const plainText = Array.from(plainBuffer).map(i => this.alphabet[i]).join('');
            const upperText = plainText.toUpperCase();
            
            for (const pattern of commonPatterns) {
                let pos = -1;
                while ((pos = upperText.indexOf(pattern, pos + 1)) !== -1) {
                    score += pattern.length * 25;
                }
            }
            
            for (const pattern of uncommonPatterns) {
                let pos = -1;
                while ((pos = upperText.indexOf(pattern, pos + 1)) !== -1) {
                    score += pattern.length * 50;
                }
            }
            
            score = Math.round(score);
            this.keysTested++;
            
            // Отправка результатов (как в оригинале)
            if (score > bestScore) {
                bestScore = score;
                bestKey = Array.from(keyBuffer).map(i => this.alphabet[i]).reverse().join('');
                bestText = plainText;
                self.postMessage({
                    type: 'result',
                    key: bestKey,
                    plaintext: bestText,
                    score
                });
            }
            
            // Отчет о прогрессе (как в оригинале)
            if (this.keysTested % 100000 === 0) {
                const now = performance.now();
                const kps = Math.round(this.keysTested / ((now - this.startTime) / 1000));
                self.postMessage({
                    type: 'progress',
                    keysTested: this.keysTested,
                    kps
                });
            }
        }
        
        // Финальное сообщение (как в оригинале)
        self.postMessage({ type: 'complete' });
    }
}

new K4Worker();
