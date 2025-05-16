class K4Worker {
    constructor() {
        this.terminate = false;
        this.alphabet = 'KRYPTOSABCDEFGHIJLMNQUVWXZ';
        this.knownText = '';
        this.keyGenerator = null;
        this.expectedFreq = {
            K: 12.5, R: 10.2, Y: 8.1, P: 7.9, 
            T: 7.5, O: 6.8, S: 6.5, A: 5.9, B: 5.3
        };

        self.onmessage = (e) => this.handleMessage(e.data);
    }

    handleMessage(msg) {
        switch (msg.type) {
            case 'START':
                this.terminate = false;
                this.alphabet = msg.config.alphabet;
                this.knownText = msg.config.knownText;
                this.startAttack(msg.config);
                break;
                
            case 'STOP':
                this.terminate = true;
                break;
        }
    }

    async startAttack(config) {
        const startTime = Date.now();
        let keysProcessed = 0;
        
        this.keyGenerator = this.generateKeys(config.keyLength);
        
        while (!this.terminate && (Date.now() - startTime) < config.timeout) {
            const { value: key, done } = this.keyGenerator.next();
            if (done) break;

            const result = this.processKey(key, config.ciphertext);
            keysProcessed++;
            
            if (result.score > 50) {
                self.postMessage({
                    type: 'RESULT',
                    data: result
                });
            }

            if (keysProcessed % 100 === 0) {
                self.postMessage({
                    type: 'PROGRESS',
                    data: { keysProcessed }
                });
                keysProcessed = 0;
            }
        }
    }

    *generateKeys(keyLength) {
        const baseChars = this.alphabet.split('');
        
        function* generate(index, current) {
            if (index === keyLength) {
                yield current.join('');
                return;
            }
            for (const char of baseChars) {
                current[index] = char;
                yield* generate(index + 1, current);
            }
        }

        yield* generate(0, new Array(keyLength));
    }

    processKey(key, ciphertext) {
        const decrypted = this.vigenereDecrypt(ciphertext, key);
        return {
            key,
            text: decrypted,
            score: this.calculateScore(decrypted)
        };
    }

    vigenereDecrypt(text, key) {
        return Array.from(text, (c, i) => {
            const textIndex = this.alphabet.indexOf(c);
            const keyIndex = this.alphabet.indexOf(key[i % key.length]);
            if (textIndex === -1 || keyIndex === -1) return c;
            return this.alphabet[(textIndex - keyIndex + 26) % 26];
        }).join('');
    }

    calculateScore(text) {
        let score = 0;
        const textLength = text.length;
        
        // Частотный анализ
        const freqMap = {};
        for (const c of text) {
            freqMap[c] = (freqMap[c] || 0) + 1;
        }
        
        // Сравнение с ожидаемой частотой
        for (const [char, expected] of Object.entries(this.expectedFreq)) {
            const actual = ((freqMap[char] || 0) / textLength) * 100;
            score += Math.max(0, 100 - Math.abs(actual - expected));
        }

        // Совпадение с известным текстом
        if (this.knownText && text.includes(this.knownText)) {
            score += 200;
        }

        // Проверка паттернов Kryptos
        const patterns = [/BERLIN/, /CLOCK/, /NORTHEAST/, /WEST/, /EAST/];
        patterns.forEach(pattern => {
            if (pattern.test(text)) {
                score += 150;
            }
        });

        // Штраф за редкие комбинации
        const rarePatterns = [/Q{2,}/, /Z{2,}/, /X{2,}/];
        rarePatterns.forEach(pattern => {
            if (pattern.test(text)) {
                score -= 100;
            }
        });

        return Math.round(score);
    }
}

// Инициализация воркера
new K4Worker();
