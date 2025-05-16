class K4Worker {
    constructor() {
        this.terminate = false;
        this.alphabet = 'KRYPTOSABCDEFGHIJLMNQUVWXZ';
        this.knownText = '';
        this.keyGenerator = null;

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
        
        // Генерация всех возможных комбинаций
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
        
        // Частотный анализ
        const charCount = text.length;
        const freqScore = [...text].reduce((acc, c) => 
            acc + (this.alphabet.includes(c) ? 1 : -2), 0);
        score += freqScore / charCount * 100;

        // Совпадение с известным текстом
        if (this.knownText && text.includes(this.knownText)) {
            score += 200;
        }

        // Шаблоны Kryptos
        const patterns = [/BERLIN/, /CLOCK/, /NORTHEAST/];
        patterns.forEach(pattern => {
            if (pattern.test(text
