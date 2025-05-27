import KMPsearch from "./kmp.js";

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

export default sanitiseData;
