var http = require('http')
var server = http.createServer()
server.on('request',function(request,response){
    response.write("�Ұ���","latin1")
    response.end()
})
server.listen(3000,function(){
    console.log('ccc')
})
