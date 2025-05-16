class K4Analyzer {
    static ALPHABET = 'KRYPTOSABCDEFGHIJLMNQUVWXZ';
    static CIPHER_TYPES = ['vigenere', 'transposition'];

    static generateKeys(baseKeys, maxLength = 12) {
        return baseKeys.flatMap(key => {
            const variants = [];
            for(let len = 1; len <= maxLength; len++) {
                const base = key.slice(0, len);
                const repeat = Math.ceil(len / base.length);
                variants.push(
                    base.padEnd(len, base).slice(0, len),
                    base.toUpperCase(),
                    base.toLowerCase()
                );
            }
            return [...new Set(variants)];
        });
    }

    static decrypt(text, key, method = 'vigenere') {
        switch(method) {
            case 'vigenere':
                return this.vigenereDecrypt(text, key);
            case 'transposition':
                return this.transpositionDecrypt(text, key);
            default:
                throw new Error('Unknown cipher method');
        }
    }

    static vigenereDecrypt(text, key) {
        return [...text].map((c, i) => {
            const textIdx = this.ALPHABET.indexOf(c);
            const keyIdx = this.ALPHABET.indexOf(key[i % key.length].toUpperCase());
            if(textIdx === -1) return c;
            const decryptedIdx = (textIdx - keyIdx + 26) % 26;
            return this.ALPHABET[decryptedIdx];
        }).join('');
    }

    static transpositionDecrypt(text, key) {
        const keyOrder = [...key].map((c, i) => ({ c, i }))
            .sort((a, b) => a.c.localeCompare(b.c))
            .map(({ i }) => i);
        
        const cols = key.length;
        const rows = Math.ceil(text.length / cols);
        const matrix = Array.from({ length: rows }, () => new Array(cols));
        
        let index = 0;
        keyOrder.forEach(col => {
            for(let row = 0; row < rows; row++) {
                if(index < text.length) {
                    matrix[row][col] = text[index++];
                }
            }
        });
        
        return matrix.flat().join('');
    }

    static analyze(text, dictionary) {
        return {
            score: this.calculateScore(text, dictionary),
            entropy: this.calculateEntropy(text)
        };
    }

    static calculateScore(text, dict) {
        const wordScore = dict.reduce((sum, word) => 
            sum + (text.includes(word) ? 100 : 0), 0);
        
        const freqScore = Object.entries(this.freqData).reduce((sum, [char, expected]) => {
            const actual = ([...text].filter(c => c === char).length / text.length * 100);
            return sum + Math.max(0, 100 - Math.abs(actual - expected));
        }, 0);
        
        const structureScore = (text.match(/(.)\1{2}/g) || []).length * -20;
        
        return wordScore + freqScore * 0.8 + structureScore;
    }

    static calculateEntropy(text) {
        const freq = [...text].reduce((acc, c) => 
            (acc[c] = (acc[c] || 0) + 1, acc), {});
        return -Object.values(freq).reduce((sum, count) => {
            const p = count / text.length;
            return sum + (p * Math.log2(p));
        }, 0);
    }
}
