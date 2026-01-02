// sample showing eval and insecure storage
const secret = "s3cr3t";
eval("console.log('bad')");
localStorage.setItem('token', secret);
