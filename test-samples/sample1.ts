// sample with several issues
var legacy = 1;
const api_key = 'abcd1234';
async function loadData() {
  fetch('http://insecure.example.com/data').then(r => r.json()).then(d => console.log(d));
}

function unusedFunc() { return 1; }

console.log('token=', api_key);
