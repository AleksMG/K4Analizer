const KRYPTOS_ALPHABET = 'KRYPTOSABCDEFGHIJLMNQUVWXZ';
const ENGLISH_FREQ = {
    E: 12.70, T: 9.10, A: 8.20, O: 7.50, I: 6.90,
    N: 6.70, S: 6.30, H: 6.10, R: 6.00, D: 4.30,
    L: 3.50, C: 2.80, U: 2.80, M: 2.40, W: 2.40,
    F: 2.20, G: 2.00, Y: 2.00, P: 1.90, B: 1.50,
    V: 1.00, K: 0.80, J: 0.20, X: 0.20, Q: 0.10,
    Z: 0.10
};
const KNOWN_PATTERNS = ['BERLIN', 'CLOCK', 'NORTHEAST'];

class K4Cracker {
    constructor(config) {
        this.ciphertext = config.ciphertext;
        this.alphabet = config.alphabet;
        this.keyLength = config.keyLength;
        this.workerId = config.workerId;
        this.keysGenerated = 0;
        this.running = true;
    }

    start() {
        try {
            const keyGenerator = this.generateKeys();
            
            for (const key of keyGenerator) {
                if (!this.running) break;
                
                this.keysGenerated++;
                const decrypted = this.vigenereDecrypt(key);
                const score = this.calculateScore(decrypted);
                
                if (score > 85) {
                    self.postMessage({
                        type: 'RESULT',
                        key,
                        text: decrypted,
                        score,
                        entropy: this.calculateEntropy(decrypted)
                    });
                }

                if (this.keysGenerated % 100 === 0) {
                    self.postMessage({
                        type: 'PROGRESS',
                        keysProcessed: this.keysGenerated
                    });
                }
            }
        } catch (error) {
            self.postMessage({
                type: 'ERROR',
                message: `Worker ${this.workerId} crashed: ${error.message}`
            });
        }
    }

    *generateKeys() {
        const chars = this.alphabet.split('');
        const key = new Array(this.keyLength).fill(chars[0]);
        
        while (this.running) {
            yield key.join('');
            
            let i = this.keyLength - 1;
            while (i >= 0) {
                const currentIndex = chars.indexOf(key[i]);
                if (currentIndex < chars.length - 1) {
                    key[i] = chars[currentIndex + 1];
                    break;
                } else {
                    key[i] = chars[0];
                    i--;
                }
            }
            if (i < 0) break;
        }
    }

    vigenereDecrypt(key) {
        return Array.from(this.ciphertext, (char, index) => {
            const textIndex = this.alphabet.indexOf(char);
            const keyIndex = this.alphabet.indexOf(key[index % key.length]);
            return this.alphabet[(textIndex - keyIndex + 26) % 26];
        }).join('');
    }

    calculateScore(text) {
        let score = 0;
        
        // Частотный анализ
        score += [...text].reduce((sum, char) => 
            sum + (ENGLISH_FREQ[char] || 0), 0);
        
        // Известные паттерны
        score += KNOWN_PATTERNS.reduce((sum, pattern) => 
            text.includes(pattern) ? sum + 150 : sum, 0);
        
        // Энтропия
        score -= this.calculateEntropy(text) * 10;
        
        return score;
    }

    calculateEntropy(text) {
        const freq = {};
        const len = text.length;
        [...text].forEach(c => freq[c] = (freq[c] || 0) + 1);
        return -Object.values(freq).reduce((sum, count) => {
            const p = count / len;
            return sum + p * Math.log2(p);
        }, 0);
    }
}

self.onmessage = function(e) {
    if (e.data.type === 'INIT') {
        const cracker = new K4Cracker(e.data);
        cracker.start();
    }
    if (e.data.type === 'TERMINATE') {
        cracker.running = false;
    }
};
