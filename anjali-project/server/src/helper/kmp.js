function KMPsearch(input, pattern) {
    const prefixArray = calculatePrefixArray(pattern);
    let i = 0; // Index for input
    let j = 0; // Index for pattern

    while (i < input.length) {
        if (pattern[j] === input[i]) {
            i++;
            j++;
        }

        if (j === pattern.length) {
            return i - j; // Pattern found at index (i - j) in the input string
        } else if (i < input.length && pattern[j] !== input[i]) {
            if (j !== 0) {
                j = prefixArray[j - 1];
            } else {
                i++;
            }
        }
    }

    return -1; // Pattern not found in the input string
}

// Function to calculate the prefix array for the Knuth-Morris-Pratt algorithm
function calculatePrefixArray(pattern) {
    const prefixArray = [0];
    let len = 0; // Length of the previous longest prefix suffix

    for (let i = 1; i < pattern.length; i++) {
        if (pattern[i] === pattern[len]) {
            len++;
            prefixArray[i] = len;
        } else {
            if (len !== 0) {
                len = prefixArray[len - 1];
                i--; // Decrement i to recheck the current character in the next iteration
            } else {
                prefixArray[i] = 0;
            }
        }
    }

    return prefixArray;
}

export default KMPsearch;
