const keywords = [
    "SELECT",
    "UPDATE",
    "DELETE",
    "INSERT",
    "DROP",
    "ALTER",
    "CREATE",
    "EXEC",
    "EXECUTE",
    "MERGE",
    "TRUNCATE",
    "UNION",
    "JOIN",
    "WHERE",
    "FROM",
    "AND",
    "OR",
    "HAVING",
    "GROUP BY",
    "ORDER BY",
    "CASE",
    ";",
    "CHAR",
    "NCHAR",
    "VARCHAR",
    "NVARCHAR",
    "INT",
    "BIGINT",
    "SMALLINT",
    "TINYINT",
    "BIT",
    "FLOAT",
    "REAL",
    "DECIMAL",
    "NUMERIC",
    "MONEY",
    "SMALLMONEY",
    "DATETIME",
    "SMALLDATETIME",
    "DATE",
    "TIME",
    "TIMESTAMP",
    "GETDATE",
    "CURRENT_TIMESTAMP",
    "CURRENT_USER",
    "CURRENT_ROLE",
    "USER_NAME",
    "SYSTEM_USER",
    "SESSION_USER",
    "HOST_NAME",
    "HOST_ID",
    "@@VERSION",
    "=",
    "ADMIN",
    "'",
    '"',
    "=",
    "<",
    ">",
    "(",
    ")",
    "{",
    "}",
    "[",
    "]",
    "%",
    "!",
    "#",
    "$",
    "&",
    "*",
    "+",
    ",",
    ".",
    "/",
    ":",
    ";",
    "<",
    "=",
    ">",
    "?",
    "@",
    "^",
    "_",
    "`",
    "|",
    "~",
    "-",
];

const xssKeywords = [
    "<script>",
    "<img>",
    "<iframe>",
    "onerror",
    "onload",
    "javascript:",
    "alert()",
    "prompt()",
    "confirm()",
    "document.cookie",
    "document.location",
    "window.location",
    "eval()",
    "setTimeout()",
    "setInterval()",
    "XMLHttpRequest()",
    "fetch()",
    "new Function()",
    "innerHTML",
    "innerText",
    "textContent",
    "onclick",
    "onmouseover",
    "onmouseout",
    "onfocus",
    "onblur",
];

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

function detectSqlInjection(username, password) {
    const inputFields = [username, password];

    const result = [];

    inputFields.forEach((input) => {
        keywords.forEach((keyword) => {
            if (
                KMPsearch(input, keyword) > -1 ||
                KMPsearch(input.toLowerCase(), keyword) > -1 ||
                KMPsearch(input.toUpperCase(), keyword) > -1 ||
                KMPsearch(input.replace(/ /g, ""), keyword) > -1 ||
                KMPsearch(input.replace(/ /g, "").toLowerCase(), keyword) >
                    -1 ||
                KMPsearch(input.replace(/ /g, "").toUpperCase(), keyword) >
                    -1 ||
                KMPsearch(input.replace(/ /g, "_"), keyword) > -1 ||
                KMPsearch(input.replace(/ /g, "_").toLowerCase(), keyword) >
                    -1 ||
                KMPsearch(input.replace(/ /g, "_").toUpperCase(), keyword) > -1
            ) {
                result.push({
                    field: input === username ? "username" : "password",
                    keyword,
                });
            }
        });
    });

    return result;
}

function detectXSS(username, password) {
    const inputFields = [username, password];

    const result = [];

    inputFields.forEach((input) => {
        xssKeywords.forEach((keyword) => {
            if (
                KMPsearch(input, keyword) > -1 ||
                KMPsearch(input.toLowerCase(), keyword) > -1 ||
                KMPsearch(input.toUpperCase(), keyword) > -1 ||
                KMPsearch(input.replace(/ /g, ""), keyword) > -1 ||
                KMPsearch(input.replace(/ /g, "").toLowerCase(), keyword) >
                    -1 ||
                KMPsearch(input.replace(/ /g, "").toUpperCase(), keyword) >
                    -1 ||
                KMPsearch(input.replace(/ /g, "_"), keyword) > -1 ||
                KMPsearch(input.replace(/ /g, "_").toLowerCase(), keyword) >
                    -1 ||
                KMPsearch(input.replace(/ /g, "_").toUpperCase(), keyword) > -1
            ) {
                result.push({
                    field: input === username ? "username" : "password",
                    keyword,
                });
            }
        });
    });

    return result;
}

const sanitiseData = (data) => {
    let { email, password } = data;
    console.log("email : ", email);
    console.log("password : ", password);
    const sqlInjection = detectSqlInjection(email, password);
    const xss = detectXSS(email, password);
    if (sqlInjection.length > 0 || xss.length > 0) {
        return false;
    }
    return true;
};

let myForm = document.getElementById("myForm");

myForm.addEventListener("submit", async function (event) {
    event.preventDefault();

    let username = document.getElementById("username");
    let password = document.getElementById("password");
    let Username = username.value;
    let Password = password.value;

    if (Username === "" || Password === "") {
        alert("Please fill all the fields");
        return false;
    }

    if (Password.length < 8) {
        alert("Password should be atleast 8 characters long");
        return false;
    }

    let reqData = {
        email: Username,
        password: Password,
    };

    console.log(reqData);

    // const apiUrl = "http://localhost:3000/submit";
    // const url = new URL(apiUrl);
    // Object.keys(reqData).forEach((key) =>
    //     url.searchParams.append(key, reqData[key])
    // );

    // const response = await fetch(url);

    // const data = await response.json();
    // console.log(data);

    const isSanitised = sanitiseData({
        email: reqData.email,
        password: reqData.password,
    });

    console.log("isSanitised : ", isSanitised);

    if (!isSanitised) {
        console.log("Forbidden!!");
        alert("Forbidden!!");
    }
    else{
    console.log("Data received successfully!!");
    alert("User Authenticated successfully!!");}
});
