
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



