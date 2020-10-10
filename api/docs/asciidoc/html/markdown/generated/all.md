# APIs for Test


<a name="overview"></a>
## Overview
HTTP Status Code:
- 200: The request has succeeded. The information returned with the response is dependent on the method used in the request
- 201: The request has been fulfilled and resulted in a new resource being created
- 204: The server has fulfilled the request but does not need to return an entity-body
- 400: The request could not be understood by the server due to malformed syntax
- 401: The request requires user authentication
- 403: The server understood the request, but is refusing to fulfill it
- 404: The server has not found anything matching the Request-URI
- 409: The request could not be completed due to a conflict with the current state of the resource
- 500: The server encountered an unexpected condition which prevented it from fulfilling the request


### Version information
*Version* : 0.0.1-SNAPSHOT


### URI scheme
*Host* : localhost:8084  
*BasePath* : /


### Tags

* 描述 : Swagger Controller




<a name="paths"></a>
## Resources

<a name="cf9084b7770f9422dd60e4ef9c680097"></a>
### 描述
Swagger Controller


<a name="testusingpost"></a>
#### 创建任务
```
POST /test/hello
```


##### Description
注意id为必填项


##### Parameters

|Type|Name|Description|Schema|
|---|---|---|---|
|**Body**|**scanTaskRequest**  <br>*required*|Created user object|[ScanTaskRequest](#scantaskrequest)|


##### Responses

|HTTP Code|Description|Schema|
|---|---|---|
|**200**|success|[RestMessage](#restmessage)|
|**201**|Created|No Content|
|**401**|Unauthorized|No Content|
|**403**|Forbidden|No Content|
|**404**|Not Found|No Content|


##### Consumes

* `application/json`


##### Produces

* `\*/*`


##### Example HTTP request

###### Request path
```
/test/hello
```


###### Request body
```json
{
  "appId" : 0,
  "id" : 0
}
```


##### Example HTTP response

###### Response 200
```json
{
  "data" : "object",
  "errCode" : 0,
  "message" : "string",
  "success" : true
}
```


<a name="test3usingput"></a>
#### 测试@ApiImplicitParam注解
```
PUT /test/hello
```


##### Description
putMapping一般用于修改


##### Parameters

|Type|Name|Description|Schema|Default|
|---|---|---|---|---|
|**Header**|**name**  <br>*required*|名字|string|`"head china cant solve"`|


##### Responses

|HTTP Code|Description|Schema|
|---|---|---|
|**200**|OK|[RestMessage](#restmessage)|
|**201**|Created|No Content|
|**401**|Unauthorized|No Content|
|**403**|Forbidden|No Content|
|**404**|Not Found|No Content|


##### Consumes

* `application/json`


##### Produces

* `\*/*`


##### Example HTTP request

###### Request path
```
/test/hello
```


###### Request header
```json
"string"
```


##### Example HTTP response

###### Response 200
```json
{
  "data" : "object",
  "errCode" : 0,
  "message" : "string",
  "success" : true
}
```


<a name="test2usingget"></a>
#### 说明方法的用途
```
GET /test/hello/{phone}
```


##### Description
方法的备注说明


##### Parameters

|Type|Name|Description|Schema|
|---|---|---|---|
|**Path**|**phone**  <br>*required*|phone|integer (int32)|


##### Responses

|HTTP Code|Description|Schema|
|---|---|---|
|**200**|success|[RestMessage](#restmessage)|
|**400**|请求参数没填好|No Content|
|**401**|Unauthorized|No Content|
|**403**|Forbidden|No Content|
|**404**|请求路径没有或页面跳转路径不对|No Content|


##### Produces

* `\*/*`


##### Example HTTP request

###### Request path
```
/test/hello/0
```


##### Example HTTP response

###### Response 200
```json
{
  "data" : "object",
  "errCode" : 0,
  "message" : "string",
  "success" : true
}
```




<a name="definitions"></a>
## Definitions

<a name="restmessage"></a>
### RestMessage
返回响应数据


|Name|Description|Schema|
|---|---|---|
|**data**  <br>*optional*|返回对象  <br>**Example** : `"object"`|object|
|**errCode**  <br>*optional*|错误编号  <br>**Example** : `0`|integer (int32)|
|**message**  <br>*optional*|错误信息  <br>**Example** : `"string"`|string|
|**success**  <br>*optional*|是否成功  <br>**Example** : `true`|boolean|


<a name="scantaskrequest"></a>
### ScanTaskRequest

|Name|Description|Schema|
|---|---|---|
|**appId**  <br>*optional*|**Example** : `0`|integer (int64)|
|**id**  <br>*optional*|**Example** : `0`|integer (int64)|





