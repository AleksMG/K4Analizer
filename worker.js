importScripts('kryptos-lib.js');

class K4Worker {
    constructor() {
        this.freqData = null;
        this.dictionary = [];
        
        self.onmessage = (e) => this.handleMessage(e);
    }

    handleMessage(e) {
        const { keys, ciphertext, freqData, dictionary } = e.data;
        this.freqData = freqData;
        this.dictionary = dictionary;
        
        const results = [];
        let processed = 0;
        
        keys.forEach(key => {
            const decrypted = K4Analyzer.decrypt(ciphertext, key, 'vigenere');
            const analysis = K4Analyzer.analyze(decrypted, this.dictionary);
            
            if(analysis.score > 65) {
                results.push({ 
                    key, 
                    text: decrypted,
                    score: analysis.score,
                    entropy: analysis.entropy
                });
            }
            
            processed++;
            
            if(processed % 100 === 0) {
                self.postMessage({ processed, results: [] });
            }
        });
        
        self.postMessage({ processed, results });
    }
}

new K4Worker();
